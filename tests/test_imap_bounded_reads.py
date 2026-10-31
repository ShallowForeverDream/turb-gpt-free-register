import re
import socket
import socketserver
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, parsedate_to_datetime
from unittest.mock import patch

from core import imap_mail_client as client, protocol_traffic
from core.imap_deadline import DeadlineIMAP4, ImapDeadline, ImapDeadlineExpired


TARGET = "recipient@example.test"
SHARED = "shared@example.test"


def message(to=TARGET, subject="Verification code", body=b"Your verification code is 123456", age=0):
    stamp = datetime.now(timezone.utc) - timedelta(seconds=age)
    header = (f"From: no-reply@example.test\r\nTo: {to}\r\nSubject: {subject}\r\n"
              f"Date: {format_datetime(stamp)}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode()
    return header, body


def search_uids(messages, criteria, internal_dates=None):
    """Local fixture implements UID ranges (including reversed *) and SINCE."""
    if isinstance(criteria, bytes):
        criteria = criteria.decode("ascii")
    ids = sorted(list(messages), key=int)
    uid_range = re.search(r"\bUID (\d+):\*", criteria)
    if uid_range and ids:
        low, high = sorted((int(uid_range.group(1)), int(ids[-1])))
        ids = [uid for uid in ids if low <= int(uid) <= high]
    since = re.search(r"\bSINCE (\d{1,2}-[A-Za-z]{3}-\d{4})", criteria)
    if since:
        day = datetime.strptime(since.group(1), "%d-%b-%Y").date()
        matches = []
        for uid in ids:
            header = messages[uid][0]
            date = (internal_dates or {}).get(uid)
            if date is None:
                raw = re.search(rb"(?im)^Date: ([^\r\n]+)", header)
                date = parsedate_to_datetime(raw.group(1).decode()).date()
            if date >= day:
                matches.append(uid)
        ids = matches
    return ids


class Mailbox:
    def __init__(self, messages, validity=b"1"):
        self.messages = messages
        self.validity = validity
        self.requests = []
        self.fail_text = False
        self.untagged_responses = {}

    def response(self, key):
        return key, [self.validity]

    def uid(self, command, *args):
        self.requests.append((command, args))
        if command == "SEARCH":
            return "OK", [b" ".join(search_uids(self.messages, args[1]))]
        ids, query = args
        parts = []
        for uid in ids.split(b","):
            header, body = self.messages[uid]
            if "HEADER.FIELDS" in query:
                content = header
            else:
                if self.fail_text:
                    self.fail_text = False
                    return "NO", []
                limit = int(re.search(r"<0\.(\d+)>", query).group(1))
                content = body[:limit]
            parts.append((b"1 (UID " + uid + b" BODY[] {" + str(len(content)).encode() + b"}", content))
        return "OK", parts


class HeaderAndUidTests(unittest.TestCase):
    def setUp(self):
        self.account = client.ImapEmailAccount(TARGET, "fixture", "imap.example.test", username=SHARED, forwarded=True)
        self.after = datetime.now(timezone.utc) - timedelta(seconds=30)
        self.state = client._SearchState()

    def search(self, mailbox):
        return client._search_messages(mailbox, self.after, account=self.account, state=self.state, limit=100)

    def test_same_uids_never_download_again_and_new_uid_is_read(self):
        mail = Mailbox({b"1": message(subject="Verification code is 123456")})
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "123456")
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "123456")
        mail.messages[b"2"] = message(subject="Verification code is 654321")
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "654321")
        fetches = [args for command, args in mail.requests if command == "FETCH"]
        self.assertEqual([args[0] for args in fetches], [b"1", b"2"])
        self.assertTrue(all("HEADER.FIELDS" in args[1] for args in fetches))

    def test_old_mail_and_other_recipient_need_no_text_download(self):
        mail = Mailbox({b"1": message(age=600), b"2": message(to="someone-else@example.test")})
        self.assertEqual(self.search(mail), [])
        self.assertEqual(self.search(mail), [])
        self.assertEqual(sum(command == "FETCH" for command, _ in mail.requests), 1)

    def test_shared_inbox_manual_forward_checks_body_recipient_exactly_once(self):
        mail = Mailbox({
            b"1": message(to=SHARED, body=b"To: someone-else@example.test\nYour code is 111111"),
            b"2": message(to=SHARED, body=b"To: recipient@example.test\nYour code is 654321"),
        })
        items = self.search(mail)
        matching = [item for item in items if client._matches_recipient(item, TARGET, forwarded=True)]
        self.assertEqual(len(matching), 1)
        self.assertEqual(client.extract_otp(matching[0]), "654321")
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "654321")
        text_fetches = [args for command, args in mail.requests if command == "FETCH" and "TEXT" in args[1]]
        self.assertEqual(len(text_fetches), 2)
        self.assertTrue(all("<0.65536>" in args[1] for args in text_fetches))

    def test_text_prefix_is_bounded_and_no_rfc822_or_attachment_fetch(self):
        mail = Mailbox({b"1": message(body=b"Your code is 123456\n" + b"x" * 2000000)})
        item = self.search(mail)[0]
        self.assertLessEqual(len(item["text"].encode()), client._TEXT_LIMIT)
        self.assertEqual(client.extract_otp(item), "123456")
        self.assertNotIn("RFC822", str(mail.requests))
        self.assertNotIn("BODY.PEEK[]", str(mail.requests))

    def test_reconnect_same_uidvalidity_keeps_cache_changed_validity_clears_it(self):
        first = Mailbox({b"1": message(subject="Verification code is 123456")})
        self.search(first)
        same = Mailbox(first.messages)
        self.assertEqual(client.extract_otp(self.search(same)[0]), "123456")
        self.assertFalse(any(command == "FETCH" for command, _ in same.requests))
        changed = Mailbox({b"1": message(subject="Verification code is 654321")}, validity=b"2")
        self.assertEqual(client.extract_otp(self.search(changed)[0]), "654321")

    def test_failed_text_fetch_is_retried_not_cached_as_processed(self):
        mail = Mailbox({b"1": message()})
        mail.fail_text = True
        with self.assertRaises(client.ImapMailError):
            self.search(mail)
        self.assertNotIn(b"1", self.state.body_uids)
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "123456")

    def test_new_query_does_not_share_another_query_cache(self):
        mail = Mailbox({b"1": message(subject="Verification code is 123456")})
        self.search(mail)
        self.state = client._SearchState()
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "123456")

    def test_bounded_text_preserves_base64_and_multipart_decoding(self):
        for multipart in (False, True):
            with self.subTest(multipart=multipart):
                msg = EmailMessage()
                msg["From"] = "no-reply@example.test"
                msg["To"] = SHARED
                msg["Subject"] = "Forwarded verification code"
                msg["Date"] = format_datetime(datetime.now(timezone.utc))
                msg.set_content("To: recipient@example.test\nYour verification code is 654321", cte="base64")
                if multipart:
                    msg.add_attachment(b"x" * 2000000, maintype="application", subtype="octet-stream", filename="large.bin")
                header, body = msg.as_bytes(policy=SMTP).split(b"\r\n\r\n", 1)
                mail = Mailbox({b"1": (header + b"\r\n\r\n", body)})
                self.state = client._SearchState()
                item = self.search(mail)[0]
                self.assertTrue(client._matches_recipient(item, TARGET, forwarded=True))
                self.assertEqual(client.extract_otp(item), "654321")

    def test_original_recipient_header_needs_no_shared_inbox_body_scan(self):
        header, body = message(to=SHARED, subject="Verification code is 654321")
        header = b"X-Forwarded-To: recipient@example.test\r\n" + header
        mail = Mailbox({b"1": (header, body)})
        self.assertEqual(client.extract_otp(self.search(mail)[0]), "654321")
        self.assertFalse(any("TEXT" in args[1] for command, args in mail.requests if command == "FETCH"))


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, address = super().get_request()
        if getattr(self, "ssl_context", None) is not None:
            sock = self.ssl_context.wrap_socket(sock, server_side=True)
        return sock, address


class _Handler(socketserver.StreamRequestHandler):
    def reply(self, data):
        self.wfile.write(data)
        self.wfile.flush()
        self.server.sent += len(data)

    def stalled(self, stage):
        if self.server.stall == stage:
            self.server.stage_entered.set()
            self.server.stop.wait(4)
            return True
        return False

    def handle(self):
        try:
            if self.stalled("greeting") or self.stalled("tls"):
                return
            if self.server.stall == "dribble":
                for char in b"* OK fixture ready\r\n":
                    self.reply(bytes([char]))
                    if self.server.stop.wait(0.12):
                        return
            else:
                self.reply(b"* OK fixture ready\r\n")
            while line := self.rfile.readline():
                tag, command, *args = line.strip().split(b" ", 2)
                command = command.upper()
                self.server.commands.append(command.decode())
                stage = command.decode().lower()
                if command == b"UID":
                    stage = "search" if args[0].startswith(b"SEARCH") else "header" if b"HEADER.FIELDS" in args[0] else "body"
                if self.stalled(stage):
                    return
                if command == b"CAPABILITY":
                    self.reply(b"* CAPABILITY IMAP4rev1\r\n")
                elif command == b"EXAMINE":
                    self.reply(b"* 100 EXISTS\r\n* OK [UIDVALIDITY " + self.server.uid_validity + b"] fixture\r\n")
                elif command == b"UID":
                    if stage == "search":
                        self.server.searches += 1
                        criteria = args[0][len(b"SEARCH "):]
                        self.server.search_criteria.append(criteria.decode("ascii"))
                        ids = search_uids(self.server.messages, criteria, self.server.internal_dates)
                        if self.server.searches <= self.server.empty_polls:
                            ids = []
                        self.server.search_results.append(list(ids))
                        if self.server.on_search is not None:
                            self.server.on_search(self.server, criteria)
                        self.reply(b"* SEARCH " + b" ".join(ids) + b"\r\n")
                    else:
                        uid_set = args[0].split(b" ")[1]
                        for uid in uid_set.split(b","):
                            pair = self.server.messages.get(uid)
                            if pair is None:
                                continue
                            header, body = pair
                            if stage == "header":
                                self.server.header_fetches += 1
                                if self.server.quota:
                                    self.reply(tag + b" NO FETCH Fetch volume limit exceed\r\n")
                                    return
                                content, section = header, b"HEADER"
                            else:
                                self.server.body_fetches += 1
                                content, section = body[:client._TEXT_LIMIT], b"TEXT"
                                if self.server.oversized:
                                    self.reply(b"* 1 FETCH (UID " + uid + b" BODY[TEXT] {2000000}\r\n")
                                    return
                            self.reply(b"* 1 FETCH (UID " + uid + b" BODY[" + section + b"] {" + str(len(content)).encode() + b"}\r\n" + content + b")\r\n")
                self.reply(tag + b" OK completed\r\n")
        except (OSError, ConnectionError):
            pass


@contextmanager
def fixture(*, messages=None, stall="", empty_polls=0, oversized=False, quota=False, ssl_context=None,
            refresh_interval=1):
    # Short clocks keep wire/deadline regressions fast. Production's exact
    # sixty-second cadence is covered separately with a virtual clock.
    with patch.object(client, "_REMOTE_REFRESH_SECONDS", refresh_interval), \
         _Server(("127.0.0.1", 0), _Handler) as server:
        server.messages = messages if messages is not None else {b"1": message(subject="Verification code is 123456")}
        server.stall = stall
        server.empty_polls = empty_polls
        server.oversized = oversized
        server.quota = quota
        server.ssl_context = ssl_context
        server.stage_entered = threading.Event()
        server.stop = threading.Event()
        server.commands = []
        server.uid_validity = b"1"
        server.internal_dates = {}
        server.search_criteria, server.search_results = [], []
        server.on_search = None
        server.sent = server.body_fetches = server.header_fetches = server.searches = 0
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
        thread.start()
        try:
            yield server
        finally:
            client.close_shared_imap_connections()
            server.stop.set()
            server.shutdown()
            thread.join(2)


class DeadlineWireTests(unittest.TestCase):
    def account(self, server, *, ssl=False):
        return client.ImapEmailAccount(TARGET, "fixture", "127.0.0.1", server.server_address[1],
                                       use_ssl=ssl, username=SHARED, forwarded=True)

    def test_real_wire_scans_headers_without_downloading_100_bodies(self):
        messages = {str(n).encode(): message(to="other@example.test", body=b"x" * 65536) for n in range(1, 100)}
        messages[b"100"] = message(subject="Verification code is 123456", body=b"x" * 2000000)
        with fixture(messages=messages) as server:
            meter = protocol_traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
            token = protocol_traffic._ACTIVE.set(meter)
            try:
                with patch.object(client, "get_account_context", return_value=self.account(server)):
                    code = client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=3, settle_seconds=0)
            finally:
                protocol_traffic._ACTIVE.reset(token)
            self.assertEqual(code, "123456")
            self.assertEqual(server.body_fetches, 0)
            self.assertLess(server.sent, 50000)
            self.assertLess(meter.snapshot()["mail_transfer_bytes"], 50000)
            self.assertEqual(meter.mail_requests, 1)
            self.assertIn("EXAMINE", server.commands)
            self.assertNotIn("SELECT", server.commands)

    def test_polling_reuses_one_connection(self):
        with fixture(empty_polls=1) as server, \
             patch.object(client, "get_account_context", return_value=self.account(server)):
            code = client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=3, poll_interval=1, settle_seconds=0)
            self.assertEqual(code, "123456")
            self.assertEqual(server.commands.count("LOGIN"), 1)
            self.assertEqual(server.commands.count("EXAMINE"), 1)
            self.assertEqual(server.searches, 2)

    def test_deadline_covers_greeting_login_select_search_headers_body_and_dribble(self):
        for stage in ("greeting", "login", "examine", "search", "header", "body", "dribble", "tls"):
            with self.subTest(stage=stage), fixture(stall=stage, messages={b"1": message()}) as server, \
                 patch.object(client, "get_account_context", return_value=self.account(server, ssl=stage == "tls")):
                start = time.monotonic()
                with self.assertRaises(client.ImapMailError):
                    client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=1, poll_interval=20)
                self.assertLess(time.monotonic() - start, 1.7)

    def test_sleep_never_exceeds_remaining_budget(self):
        with fixture(messages={b"1": message(to="other@example.test")}) as server, \
             patch.object(client, "get_account_context", return_value=self.account(server)):
            start = time.monotonic()
            with self.assertRaises(client.ImapMailError):
                client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=1, poll_interval=60)
            self.assertLess(time.monotonic() - start, 1.7)

    def test_zero_budget_never_opens_a_connection(self):
        account = client.ImapEmailAccount(TARGET, "fixture", "imap.example.test")
        with patch.object(client, "get_account_context", return_value=account), \
             patch.object(client, "_connect") as connect:
            with self.assertRaises(client.ImapMailError):
                client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=0)
        connect.assert_not_called()

    def test_settle_wait_is_capped_by_deadline_and_preserves_found_candidate(self):
        with fixture() as server, patch.object(client, "get_account_context", return_value=self.account(server)):
            start = time.monotonic()
            code = client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=1, settle_seconds=20)
            self.assertEqual(code, "123456")
            self.assertLess(time.monotonic() - start, 1.7)
            self.assertEqual(server.commands.count("LOGIN"), 1)

    def test_unexpected_large_literal_is_rejected_without_downloading_it(self):
        with fixture(messages={b"1": message()}, oversized=True) as server, \
             patch.object(client, "get_account_context", return_value=self.account(server)):
            with self.assertRaises(client.ImapMailError):
                client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=1)
            self.assertLess(server.sent, 10000)

    def test_concurrent_mail_queries_share_one_connection_without_double_counting(self):
        def read():
            meter = protocol_traffic.ProtocolTraffic(low_traffic=False, budget_bytes=1000000)
            token = protocol_traffic._ACTIVE.set(meter)
            try:
                code = client.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=3, settle_seconds=0)
                return code, meter.mail_requests, meter.snapshot()["mail_transfer_bytes"]
            finally:
                protocol_traffic._ACTIVE.reset(token)

        with fixture() as server, \
             patch.object(client, "get_account_context", return_value=self.account(server)), \
             ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(lambda _: read(), range(5)))
            self.assertEqual(server.commands.count("LOGIN"), 1)
        self.assertTrue(all(code == "123456" for code, _, _ in results))
        self.assertEqual(sum(connections for _, connections, _ in results), 1)
        self.assertGreater(sum(size for _, _, size in results), 0)

    def test_dns_deadline_returns_without_late_connect(self):
        release = threading.Event()
        done = threading.Event()

        def slow_dns(*args, **kwargs):
            release.wait(2)
            done.set()
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))]

        with patch("core.imap_deadline.socket.getaddrinfo", side_effect=slow_dns), \
             patch("core.imap_deadline.socket.socket") as sock:
            start = time.monotonic()
            try:
                with ImapDeadline(0.15) as deadline:
                    with self.assertRaises(ImapDeadlineExpired):
                        DeadlineIMAP4("imap.example.test", 143, deadline=deadline)
            finally:
                release.set()
                done.wait(1)
            self.assertLess(time.monotonic() - start, 0.7)
            sock.assert_not_called()

    def test_stuck_dns_workers_cannot_accumulate_unbounded_threads(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch("core.imap_deadline._DNS_SLOTS", slots), \
             patch("core.imap_deadline.socket.getaddrinfo") as resolve:
            try:
                with ImapDeadline(0.15) as deadline:
                    with self.assertRaises(ImapDeadlineExpired):
                        DeadlineIMAP4("imap.example.test", 143, deadline=deadline)
            finally:
                slots.release()
        resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
