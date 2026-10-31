import re
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch

from core import imap_mail_client as imap
from tests.test_imap_bounded_reads import Mailbox, SHARED, TARGET, fixture, message


class IncrementalUidTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
        self.after = self.now - timedelta(seconds=30)
        self.state = imap._SearchState()
        self.account = imap.ImapEmailAccount(TARGET, "fixture", "imap.example.test", username=SHARED, forwarded=True)

    def mail(self, *, to=TARGET, code="123456", age=0):
        header, body = message(to=to, subject="Verification code is " + code)
        stamp = format_datetime(self.now - timedelta(seconds=age)).encode()
        return re.sub(rb"(?m)^Date: [^\r\n]+", b"Date: " + stamp, header), body

    def scan(self, mail, *, after=None, limit=100):
        return imap._search_messages(mail, after or self.after, account=self.account, state=self.state, limit=limit)

    def searches(self, mail):
        return [args[1] for command, args in mail.requests if command == "SEARCH"]

    def test_bootstrap_once_then_only_uid_incremental_searches(self):
        mail = Mailbox({str(i).encode(): self.mail() for i in range(1, 601)})
        self.scan(mail)
        for _ in range(20):
            self.scan(mail)
        searches = self.searches(mail)
        self.assertNotIn("UID ", searches[0])
        self.assertTrue(all("UID 601:*" in query for query in searches[1:]))
        self.assertEqual(self.state.highest_uid, 600)
        self.assertEqual(sum(command == "FETCH" for command, _ in mail.requests), 1)

    def test_star_range_old_last_uid_cannot_move_cursor_back_or_refetch(self):
        mail = Mailbox({b"500": self.mail()})
        self.scan(mail)
        self.scan(mail)  # Compliant server returns 500 for UID 501:*.
        self.assertEqual(self.state.highest_uid, 500)
        self.assertEqual(self.state.window, [b"500"])
        self.assertEqual(sum(command == "FETCH" for command, _ in mail.requests), 1)
        mail.messages[b"900"] = self.mail(code="654321", age=5)
        self.assertEqual(imap.extract_otp(self.scan(mail)[0]), "654321")

    def test_initially_empty_mailbox_still_finds_first_arrival(self):
        mail = Mailbox({})
        self.assertEqual(self.scan(mail), [])
        self.assertEqual(self.scan(mail), [])
        mail.messages[b"800"] = self.mail()
        self.assertEqual(imap.extract_otp(self.scan(mail)[0]), "123456")
        self.assertEqual(self.state.highest_uid, 800)
        self.assertIn("UID 1:*", self.searches(mail)[-1])

    def test_arrival_after_search_snapshot_is_not_skipped_by_future_uidnext(self):
        mail = Mailbox({b"1": self.mail(to="other@example.test")})
        original = mail.uid

        def uid(command, *args):
            result = original(command, *args)
            if command == "SEARCH" and b"90" not in mail.messages:
                mail.messages[b"90"] = self.mail()
            return result

        mail.uid = uid
        self.assertEqual(self.scan(mail), [])
        self.assertEqual(self.state.highest_uid, 1)
        self.assertEqual(imap.extract_otp(self.scan(mail)[0]), "123456")
        self.assertIn("UID 2:*", self.searches(mail)[-1])

    def test_failed_search_does_not_advance_cursor(self):
        mail = Mailbox({b"1": self.mail()})
        self.scan(mail)
        with patch.object(mail, "uid", return_value=("NO", [])):
            with self.assertRaises(imap.ImapMailError):
                self.scan(mail)
        self.assertEqual(self.state.highest_uid, 1)
        mail.messages[b"9"] = self.mail(code="654321")
        self.assertEqual(imap.extract_otp(self.scan(mail)[0]), "654321")
        self.assertIn("UID 2:*", self.searches(mail)[-1])

    def test_partial_header_response_is_retried_even_after_cursor_advanced(self):
        mail = Mailbox({b"1": self.mail(to="other@example.test")})
        self.scan(mail)
        mail.messages[b"2"] = self.mail()
        original = mail.uid

        def uid(command, *args):
            if command == "FETCH":
                return "OK", []
            return original(command, *args)

        with patch.object(mail, "uid", side_effect=uid):
            self.assertEqual(self.scan(mail), [])
        self.assertEqual(self.state.highest_uid, 2)
        self.assertNotIn(b"2", self.state.headers)
        self.assertEqual(imap.extract_otp(self.scan(mail)[0]), "123456")

    def test_earlier_query_broadens_once_later_query_cannot_shrink_shared_cursor(self):
        yesterday = self.now.replace(hour=0) - timedelta(days=1)
        mail = Mailbox({b"1": self.mail(age=86400), b"2": self.mail(to="other@example.test")})
        self.assertEqual(self.scan(mail), [])
        self.assertEqual(imap.extract_otp(self.scan(mail, after=yesterday)[0]), "123456")
        for _ in range(3):
            self.assertEqual(self.scan(mail), [])
            self.assertEqual(imap.extract_otp(self.scan(mail, after=yesterday)[0]), "123456")
        full = [query for query in self.searches(mail) if "UID " not in query]
        self.assertEqual(len(full), 2)
        self.assertEqual(self.state.since_day, yesterday.date())

    def test_expanding_window_backfills_old_uids_without_redownloading_recent_headers(self):
        mail = Mailbox({str(i).encode(): self.mail() for i in range(1, 101)})
        self.scan(mail, limit=20)
        self.scan(mail, limit=100)
        fetches = [args[0].split(b",") for command, args in mail.requests if command == "FETCH"]
        self.assertEqual([len(ids) for ids in fetches], [20, 80])
        self.assertTrue(set(fetches[0]).isdisjoint(fetches[1]))

    def test_reconnect_resyncs_membership_but_keeps_completed_uid_cache(self):
        first = Mailbox({b"1": self.mail(), b"2": self.mail()})
        self.scan(first)
        reconnect = Mailbox({b"1": first.messages[b"1"], b"3": self.mail(code="654321")})
        self.assertEqual(imap.extract_otp(self.scan(reconnect)[0]), "654321")
        self.assertEqual(self.state.window, [b"1", b"3"])
        self.assertEqual([args[0] for command, args in reconnect.requests if command == "FETCH"], [b"3"])
        self.assertNotIn("UID ", self.searches(reconnect)[0])

    def test_new_uidvalidity_resets_highwater_even_with_reused_lower_uids(self):
        self.scan(Mailbox({b"500": self.mail()}))
        changed = Mailbox({b"1": self.mail(code="654321")}, validity=b"2")
        self.assertEqual(imap.extract_otp(self.scan(changed)[0]), "654321")
        self.assertEqual(self.state.highest_uid, 1)
        self.assertEqual(self.state.window, [b"1"])

    def test_expunge_received_during_incremental_search_reconciles_before_returning(self):
        mail = Mailbox({b"1": self.mail(), b"2": self.mail(to="other@example.test")})
        self.scan(mail)
        original = mail.uid

        def uid(command, *args):
            if command == "SEARCH" and "UID " in args[1]:
                mail.messages.pop(b"1", None)
                mail.untagged_responses["EXPUNGE"] = [b"1"]
            return original(command, *args)

        mail.uid = uid
        self.assertEqual(self.scan(mail), [])
        self.assertEqual(self.state.window, [b"2"])
        self.assertNotIn("UID ", self.searches(mail)[-1])


class IncrementalWireTests(unittest.TestCase):
    def setUp(self):
        imap.close_shared_imap_connections()

    def tearDown(self):
        imap.close_shared_imap_connections()

    def context(self, server, email):
        return imap.ImapEmailAccount(email, "fixture", "127.0.0.1", server.server_address[1],
                                     username=SHARED, use_ssl=False, forwarded=True)

    def read(self, email, *, wait=6, after=None):
        return imap.fetch_latest_otp(email, after_ts=after or time.time(), max_wait=wait,
                                    poll_interval=1, settle_seconds=0)

    def test_large_inbox_warm_queries_return_only_incremental_uid_payload(self):
        data = {str(i).encode(): message(to=TARGET, subject="Verification code is 123456")
                for i in range(1, 6001)}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            self.assertEqual(self.read(TARGET), "123456")
            for _ in range(20):
                next(iter(imap._SHARED_INBOXES.values())).state.last_scan = 0
                self.assertEqual(self.read(TARGET), "123456")
            self.assertEqual(sum("UID " not in query for query in server.search_criteria), 1)
            self.assertTrue(all("UID 6001:*" in query for query in server.search_criteria[1:]))
            self.assertTrue(all(len(ids) <= 1 for ids in server.search_results[1:]))
            self.assertEqual(server.header_fetches, 100)
            self.assertEqual(server.body_fetches, 0)
            self.assertEqual(server.commands.count("LOGIN"), 1)

    def test_wire_arrival_after_search_snapshot_is_found_on_next_increment(self):
        data = {b"1": message(to="other@example.test", subject="Verification code is 111111")}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)):
            def arrived(server, criteria):
                if server.searches == 1:
                    server.messages[b"99"] = message(subject="Verification code is 123456")
            server.on_search = arrived
            self.assertEqual(self.read(TARGET), "123456")
            self.assertEqual(server.search_results[:2], [[b"1"], [b"99"]])
            self.assertIn("UID 2:*", server.search_criteria[1])
            self.assertEqual(server.header_fetches, 2)

    def test_five_active_recipients_receive_their_own_late_arrivals(self):
        expected = {name + "@example.test": str(100000 + i)
                    for i, name in enumerate(("a", "aa", "a+tag", "b", "c"))}
        for manual in (False, True):
            with self.subTest(manual_forward=manual), fixture(messages={
                b"100": message(to="seed@example.test", subject="Verification code is 999999")
            }) as server, patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
                 ThreadPoolExecutor(max_workers=5) as executor:
                self.assertEqual(self.read("seed@example.test"), "999999")
                searching = threading.Event()
                server.on_search = lambda _server, criteria: searching.set() if b"UID " in criteria else None
                barrier = threading.Barrier(6)

                def waiting(email):
                    barrier.wait(timeout=3)
                    return self.read(email)

                pending = {email: executor.submit(waiting, email) for email in expected}
                barrier.wait(timeout=3)
                self.assertTrue(searching.wait(3))
                inbox = next(iter(imap._SHARED_INBOXES.values()))
                self.assertEqual(inbox.users, 5)  # All requests genuinely overlap.
                for i, (email, code) in enumerate(expected.items(), 101):
                    server.messages[str(i).encode()] = message(
                        to=SHARED if manual else email,
                        subject="Forwarded verification code" if manual else "Verification code is " + code,
                        body=f"To: {email}\nYour verification code is {code}".encode(),
                    )
                self.assertEqual({email: task.result(timeout=6) for email, task in pending.items()}, expected)
                self.assertEqual(server.commands.count("LOGIN"), 1)
                self.assertEqual(server.header_fetches, 6)
                self.assertEqual(server.body_fetches, 5 if manual else 0)
                self.assertEqual(sum("UID " not in query for query in server.search_criteria), 1)

    def test_one_callers_newer_time_window_does_not_hide_another_callers_mail(self):
        data = {b"1": message(to="a@example.test", subject="Verification code is 111111"),
                b"2": message(to="b@example.test", subject="Verification code is 222222")}
        with fixture(messages=data) as server, \
             patch.object(imap, "get_account_context", side_effect=lambda email: self.context(server, email)), \
             ThreadPoolExecutor(max_workers=2) as executor:
            future_window = executor.submit(self.read, "b@example.test", wait=1, after=time.time() + 120)
            available = executor.submit(self.read, "a@example.test")
            self.assertEqual(available.result(timeout=3), "111111")
            with self.assertRaises(imap.ImapMailError):
                future_window.result(timeout=3)
            self.assertEqual(server.commands.count("LOGIN"), 1)


if __name__ == "__main__":
    unittest.main()
