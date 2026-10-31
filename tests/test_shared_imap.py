import socket
import importlib.util
import ipaddress
import ssl
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from core import imap_mail_client as imap, protocol_traffic
from core.imap_deadline import ImapDeadline
from tests.test_imap_bounded_reads import fixture, message, Mailbox, SHARED


class SharedImapTests(unittest.TestCase):
    def setUp(self):
        imap.close_shared_imap_connections()

    def tearDown(self):
        imap.close_shared_imap_connections()

    def context(self, server, email, *, username=SHARED, password="fixture"):
        return imap.ImapEmailAccount(email, password, "127.0.0.1", server.server_address[1],
                                     username=username, use_ssl=False, forwarded=True)

    def read(self, email, *, wait=3, after=None):
        return imap.fetch_latest_otp(email, after_ts=after or time.time(), max_wait=wait,
                                    poll_interval=1, settle_seconds=0)

    def test_sequential_recipients_share_login_search_and_header_download(self):
        data = {b"1": message(to="a@example.test", subject="Verification code is 111111"),
                b"2": message(to="b@example.test", subject="Verification code is 222222")}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            self.assertEqual(self.read("a@example.test"), "111111")
            self.assertEqual(self.read("b@example.test"), "222222")
            self.assertEqual(server.commands.count("LOGIN"), 1)
            self.assertEqual(server.commands.count("EXAMINE"), 1)
            self.assertEqual(server.searches, 1)
            self.assertEqual(server.header_fetches, 2)  # Two literals, one FETCH command.
            self.assertEqual(server.body_fetches, 0)

    def test_five_parallel_recipients_keep_codes_isolated_on_one_connection(self):
        expected = {f"alias{i}@example.test": str(100000 + i) for i in range(5)}
        data = {str(i + 1).encode(): message(to=email, subject="Verification code is " + code)
                for i, (email, code) in enumerate(expected.items())}

        def read(email):
            meter = protocol_traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
            token = protocol_traffic._ACTIVE.set(meter)
            try:
                return email, self.read(email), meter.snapshot()
            finally:
                protocol_traffic._ACTIVE.reset(token)

        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
             ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(read, expected))
            self.assertEqual(server.commands.count("LOGIN"), 1)
            self.assertEqual(server.header_fetches, 5)
            self.assertEqual(server.body_fetches, 0)
        self.assertEqual({email: code for email, code, _ in results}, expected)
        self.assertEqual(sum(metrics["mail_request_count"] for _, _, metrics in results), 1)
        self.assertGreater(sum(metrics["mail_transfer_bytes"] for _, _, metrics in results), 0)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "optional TLS fixture certificate generator missing")
    def test_five_parallel_tls_queries_use_one_verified_connection(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost IMAP fixture")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                    .not_valid_after(now + timedelta(days=1)).add_extension(
                        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                    .sign(key, hashes.SHA256()))
            cert_path, key_path = folder / "cert.pem", folder / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(str(cert_path), str(key_path))
            client_ctx = ssl.create_default_context(cafile=str(cert_path))
            client_ctx.keylog_filename = None
            expected = {f"tls{i}@example.test": str(100000 + i) for i in range(5)}
            data = {str(i + 1).encode(): message(to=email, subject="Verification code is " + code)
                    for i, (email, code) in enumerate(expected.items())}
            original = imap.DeadlineIMAP4SSL

            def connect(host, port, *, deadline):
                return original(host, port, deadline=deadline, ssl_context=client_ctx)

            with fixture(messages=data, ssl_context=server_ctx) as server:
                def context(email):
                    account = self.context(server, email)
                    account.use_ssl = True
                    return account
                with patch.object(imap, "get_account_context", side_effect=context), \
                     patch.object(imap, "DeadlineIMAP4SSL", side_effect=connect) as factory, \
                     ThreadPoolExecutor(max_workers=5) as executor:
                    results = dict(zip(expected, executor.map(self.read, expected)))
                    later = {f"later{i}@example.test": str(200000 + i) for i in range(5)}
                    server.messages.update({str(i + 20).encode(): message(to=email, subject="Verification code is " + code)
                                            for i, (email, code) in enumerate(later.items())})
                    next(iter(imap._SHARED_INBOXES.values())).state.last_scan = 0
                    self.assertEqual(dict(zip(later, executor.map(self.read, later))), later)
                self.assertEqual(results, expected)
                self.assertEqual(server.commands.count("LOGIN"), 1)
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(server.header_fetches, 10)
                self.assertTrue(any("UID 6:*" in query for query in server.search_criteria))
                self.assertTrue(client_ctx.check_hostname)
                self.assertEqual(client_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_manual_forwards_reuse_decoded_bodies_without_consuming_other_recipient(self):
        data = {b"1": message(to=SHARED, body=b"To: a@example.test\nYour code is 111111"),
                b"2": message(to=SHARED, body=b"To: b@example.test\nYour code is 222222")}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            self.assertEqual(self.read("a@example.test"), "111111")
            self.assertEqual(self.read("b@example.test"), "222222")
            self.assertEqual(server.commands.count("LOGIN"), 1)
            self.assertEqual(server.body_fetches, 2)

    def test_cache_does_not_ignore_each_query_time_window(self):
        with fixture(messages={b"1": message(to="a@example.test", subject="Verification code is 111111")}) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            self.assertEqual(self.read("a@example.test"), "111111")
            with self.assertRaises(imap.ImapMailError):
                self.read("a@example.test", wait=1, after=time.time() + 120)
            self.assertEqual(self.read("a@example.test"), "111111")
            self.assertEqual(server.commands.count("LOGIN"), 1)

    def test_waiting_query_timeout_cannot_close_active_reader_socket(self):
        data = {b"1": message(to="a@example.test")}
        with fixture(messages=data, stall="body") as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
             ThreadPoolExecutor(max_workers=1) as executor:
            active = executor.submit(self.read, "a@example.test", wait=3)
            self.assertTrue(server.stage_entered.wait(1))
            start = time.monotonic()
            with self.assertRaises(imap.ImapMailError):
                self.read("b@example.test", wait=1)
            self.assertLess(time.monotonic() - start, 1.7)
            self.assertFalse(active.done())
            self.assertEqual(server.commands.count("LOGIN"), 1)
            with self.assertRaises(imap.ImapMailError):
                active.result(timeout=4)

    def test_previous_query_deadline_does_not_close_next_read(self):
        data = {b"1": message(to="a@example.test", subject="Verification code is 111111"),
                b"2": message(to="b@example.test")}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
             ThreadPoolExecutor(max_workers=1) as executor:
            self.assertEqual(self.read("a@example.test", wait=1), "111111")
            # Isolate socket-timer ownership from the receiver refresh cadence.
            next(iter(imap._SHARED_INBOXES.values())).next_refresh = 0
            server.stall = "body"
            active = executor.submit(self.read, "b@example.test", wait=2)
            self.assertTrue(server.stage_entered.wait(1))
            time.sleep(1.15)
            self.assertFalse(active.done())
            self.assertEqual(server.commands.count("LOGIN"), 1)
            with self.assertRaises(imap.ImapMailError):
                active.result(timeout=3)

    def test_quota_is_shared_across_aliases_without_reconnecting(self):
        with fixture(quota=True) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            for recipient in ("a@example.test", "b@example.test", "c@example.test"):
                with self.assertRaises(imap.ImapFetchLimitError):
                    self.read(recipient)
            self.assertEqual(server.commands.count("LOGIN"), 1)
            self.assertEqual(server.header_fetches, 1)

    def test_distinct_mailbox_identities_do_not_share_cache_or_connection(self):
        with fixture(messages={b"1": message(to="a@example.test", subject="Verification code is 111111")}) as server:
            with patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email, username="inbox1@example.test")):
                self.assertEqual(self.read("a@example.test"), "111111")
            server.messages[b"1"] = message(to="a@example.test", subject="Verification code is 222222")
            with patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email, username="inbox2@example.test")):
                self.assertEqual(self.read("a@example.test"), "222222")
            self.assertEqual(server.commands.count("LOGIN"), 2)

    def test_password_change_replaces_connection_and_cache(self):
        with fixture(messages={b"1": message(to="a@example.test", subject="Verification code is 111111")}) as server:
            with patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
                self.assertEqual(self.read("a@example.test"), "111111")
            server.messages[b"1"] = message(to="a@example.test", subject="Verification code is 222222")
            with patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email, password="new-fixture")):
                self.assertEqual(self.read("a@example.test"), "222222")
            self.assertEqual(server.commands.count("LOGIN"), 2)

    def test_stale_credential_claim_cannot_close_new_generation_connection(self):
        a = imap.ImapEmailAccount("a@example.test", "old", "imap.example.test", username=SHARED)
        b = imap.ImapEmailAccount("b@example.test", "new", "imap.example.test", username=SHARED)
        inbox, first = imap._claim_shared_inbox(a)
        newer, second = imap._claim_shared_inbox(b)
        self.assertIs(inbox, newer)
        mail = Mock()
        try:
            with patch.object(imap, "_connect", return_value=mail):
                with ImapDeadline(2) as deadline, imap._shared_connection(inbox, second, b, deadline):
                    pass
            with ImapDeadline(2) as deadline:
                with self.assertRaises(imap.ImapSharedStateError):
                    with imap._shared_connection(inbox, first, a, deadline):
                        self.fail("stale claim was accepted")
            mail.shutdown.assert_not_called()
        finally:
            imap._release_shared_inbox(inbox)
            imap._release_shared_inbox(newer)

    def test_dropped_connection_reconnects_without_repeating_old_header_fetches(self):
        with fixture(messages={b"1": message(to="a@example.test", subject="Verification code is 111111")}) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            self.assertEqual(self.read("a@example.test"), "111111")
            inbox = next(iter(imap._SHARED_INBOXES.values()))
            inbox.mail.sock.shutdown(socket.SHUT_RDWR)
            inbox.state.last_scan = 0
            server.messages[b"2"] = message(to="b@example.test", subject="Verification code is 222222")
            self.assertEqual(self.read("b@example.test"), "222222")
            self.assertEqual(server.commands.count("LOGIN"), 2)
            self.assertEqual(server.header_fetches, 2)

    def test_close_all_interrupts_active_read_without_a_late_reconnect(self):
        with fixture(messages={b"1": message(to="a@example.test")}, stall="body") as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
             ThreadPoolExecutor(max_workers=1) as executor:
            active = executor.submit(self.read, "a@example.test", wait=20)
            self.assertTrue(server.stage_entered.wait(1))
            imap.close_shared_imap_connections()
            with self.assertRaises(imap.ImapMailError):
                active.result(timeout=2)
            self.assertEqual(server.commands.count("LOGIN"), 1)

    def test_headers_can_report_uid_after_literal(self):
        header, body = message(to="a@example.test", subject="Verification code is 111111")
        mail = Mailbox({b"1": (header, body)})
        original = mail.uid

        def uid(command, *args):
            if command == "FETCH":
                return "OK", [(b"1 (BODY[HEADER] {100}", header), b" UID 1)"]
            return original(command, *args)

        mail.uid = uid
        account = imap.ImapEmailAccount("a@example.test", "fixture", "imap.example.test")
        result = imap._search_messages(mail, datetime.now(timezone.utc) - timedelta(seconds=30),
                                       account=account, state=imap._SearchState())
        self.assertEqual(imap.extract_otp(result[0]), "111111")

    def test_active_mailbox_registry_is_bounded(self):
        claims = []
        try:
            for i in range(imap._SHARED_LIMIT):
                account = imap.ImapEmailAccount(f"user{i}@example.test", "fixture", "imap.example.test")
                claims.append(imap._claim_shared_inbox(account)[0])
            with self.assertRaises(imap.ImapSharedStateError):
                imap._claim_shared_inbox(imap.ImapEmailAccount("extra@example.test", "fixture", "imap.example.test"))
        finally:
            for inbox in claims:
                imap._release_shared_inbox(inbox)

    def test_cross_midnight_searches_keep_cached_bodies_without_replaying_stale_mail(self):
        header, body = message(to="a@example.test", age=86400)
        mail = Mailbox({b"1": (header, body)})
        original = mail.uid
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        def uid(command, *args):
            if command == "SEARCH" and today.strftime("%d-%b-%Y") in args[1]:
                mail.requests.append((command, args))
                return "OK", [b""]
            return original(command, *args)

        mail.uid = uid
        account = imap.ImapEmailAccount("a@example.test", "fixture", "imap.example.test")
        state = imap._SearchState()
        yesterday = today - timedelta(days=1)
        self.assertEqual(imap.extract_otp(imap._search_messages(mail, yesterday, account=account, state=state)[0]), "123456")
        self.assertEqual(imap._search_messages(mail, today, account=account, state=state), [])
        self.assertEqual(imap.extract_otp(imap._search_messages(mail, yesterday, account=account, state=state)[0]), "123456")
        self.assertEqual(sum(command == "FETCH" for command, _ in mail.requests), 2)


if __name__ == "__main__":
    unittest.main()
