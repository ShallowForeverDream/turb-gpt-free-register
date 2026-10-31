# -*- coding: utf-8 -*-
import unittest
import tempfile
from pathlib import Path
from core import db
from tests.test_forwarded_imap_and_account_import import storage
from unittest.mock import Mock, patch

from config import email as email_config
from core import smsbower_mail_client as client


class SmsBowerMailClientTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)), _DATA_DIR=Path(root.name), _LOG_DIR=Path(root.name)/"logs")
        state.start()
        self.addCleanup(state.stop)
        client._CONTEXT_CACHE.clear()
        self.addCleanup(client._CONTEXT_CACHE.clear)

    def _config(self):
        return patch.multiple(
            email_config,
            SMSBOWER_MAIL_API_BASE="https://smsbower.page/api/mail",
            SMSBOWER_MAIL_SERVICE="dr",
            SMSBOWER_MAIL_DOMAIN="gmail.com",
            SMSBOWER_MAIL_ALIAS_LENGTH=0,
            SMSBOWER_MAIL_ACTIVATION_WAIT=0,
            SMSBOWER_MAIL_ACTIVATION_RETRY_INTERVAL=1,
            SMSBOWER_MAIL_REQUEST_TIMEOUT=5,
            SMSBOWER_MAIL_API_KEY="fixture-key",
            create=True,
        )

    @patch("core.smsbower_mail_client.requests.request")
    def test_pick_account_uses_mail_activation_contract(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 1, "mail": "fresh@gmail.com", "mailId": 4}
        request.return_value = response

        with self._config():
            account = client.pick_account()

        self.assertEqual(account.email, "fresh@gmail.com")
        self.assertEqual(account.mail_id, "4")
        self.assertIs(client.get_account_context("FRESH@GMAIL.COM"), account)
        self.assertEqual(request.call_args.kwargs["params"], {
            "api_key": "fixture-key", "service": "dr", "domain": "gmail.com",
        })

    @patch("core.smsbower_mail_client.requests.request")
    def test_fetch_latest_otp_uses_mail_id_and_advances_status(self, request):
        response = Mock(status_code=200)
        response.json.side_effect = [
            {"status": 1, "code": "012345"},
            {"status": 1, "message": "ok"},
        ]
        request.return_value = response
        account = client.SmsBowerMailAccount(email="fresh@gmail.com", mail_id="4")
        client._CONTEXT_CACHE["fresh@gmail.com"] = account

        with self._config():
            code = client.fetch_latest_otp("fresh@gmail.com", max_wait=1, poll_interval=1)

        self.assertEqual(code, "012345")
        self.assertEqual(request.call_args_list[0].kwargs["params"], {
            "api_key": "fixture-key", "mailId": "4",
        })
        self.assertEqual(request.call_args_list[1].kwargs["params"], {
            "api_key": "fixture-key", "id": "4", "status": "5",
        })
        self.assertEqual(account.codes_used, {"012345"})
        self.assertEqual(len(account.code_digests), 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_no_stock_retries_then_times_out(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 0, "error": "No mails yet"}
        request.return_value = response

        with self._config():
            with self.assertRaises(client.SmsBowerMailNoStock):
                client.pick_account()

    @patch("core.smsbower_mail_client.requests.request")
    def test_insufficient_balance_is_not_retried_as_no_stock(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 0, "error": "Insufficient balance"}
        request.return_value = response

        with self._config():
            with self.assertRaises(client.SmsBowerMailNoBalance):
                client.pick_account()

        self.assertEqual(request.call_count, 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_uncertain_set_status_blocks_replay(self, request):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("not json")
        request.return_value = response
        account = client.SmsBowerMailAccount(email="fresh@gmail.com", mail_id="4")

        with self._config():
            with self.assertRaises(client.SmsBowerMailError):
                client.set_status(account, 3)
            with self.assertRaisesRegex(client.SmsBowerMailError, "结果未确认"):
                client.set_status(account, 2)

        self.assertEqual(request.call_count, 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_failed_release_cancels_when_no_account_recorded(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 1, "message": "ok"}
        request.return_value = response
        account = client.SmsBowerMailAccount(email="fresh@gmail.com", mail_id="4")
        client._CONTEXT_CACHE["fresh@gmail.com"] = account

        with self._config():
            client.release_account("fresh@gmail.com", status="failed")

        self.assertEqual(request.call_args.kwargs["params"]["status"], "2")

    @patch("core.smsbower_mail_client.requests.request")
    def test_failed_created_release_keeps_activation_for_manual_review(self, request):
        account = client.SmsBowerMailAccount(email="fresh@gmail.com", mail_id="4")
        client._CONTEXT_CACHE["fresh@gmail.com"] = account

        with self._config():
            client.release_account("fresh@gmail.com", status="failed_created")

        request.assert_not_called()
        self.assertIs(client.get_account_context("fresh@gmail.com"), account)

    @patch("core.smsbower_mail_client.requests.request")
    def test_available_release_cancels(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 1, "message": "ok"}
        request.return_value = response
        account = client.SmsBowerMailAccount(email="fresh@gmail.com", mail_id="4")
        client._CONTEXT_CACHE["fresh@gmail.com"] = account

        with self._config():
            client.release_account("fresh@gmail.com", status="available")

        self.assertEqual(request.call_args.kwargs["params"]["status"], "2")

    def test_alias_length_must_be_zero_or_three_to_sixteen(self):
        with patch.object(email_config, "SMSBOWER_MAIL_ALIAS_LENGTH", 2, create=True):
            with self.assertRaisesRegex(client.SmsBowerMailError, "3~16"):
                client._alias_length()

    def _response(self, payload, status=200):
        response = Mock(status_code=status)
        response.json.return_value = payload
        return response

    def _acquire(self, request):
        request.return_value = self._response({"status": 1, "mail": "fresh@gmail.com", "mailId": 4})
        return client.pick_account()

    @patch("core.smsbower_mail_client.requests.request")
    def test_invalid_config_is_checked_before_purchase(self, request):
        with self._config(), patch.object(email_config, "SMSBOWER_MAIL_ALIAS_LENGTH", 2):
            with self.assertRaises(client.SmsBowerMailError):
                client.pick_account()
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_terminal_activation_is_not_reopened_after_restart(self, request):
        with self._config():
            account = self._acquire(request)
            request.return_value = self._response({"status": 1})
            self.assertEqual(client.mark_success_closed(account.email), "closed")
            client._CONTEXT_CACHE.clear()
            request.reset_mock()
            self.assertEqual(client.mark_success_closed(account.email), "closed")
            with self.assertRaisesRegex(client.SmsBowerMailError, "关闭"):
                client.fetch_latest_otp(account.email, max_wait=1)
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_uncertain_write_survives_restart(self, request):
        with self._config():
            account = self._acquire(request)
            request.return_value.json.side_effect = ValueError("not json")
            with self.assertRaises(client.SmsBowerMailError):
                client.set_status(account, 3)
            client._CONTEXT_CACHE.clear()
            restored = client.restore_account_context(account.email)
            request.reset_mock()
            with self.assertRaisesRegex(client.SmsBowerMailError, "未确认"):
                client.set_status(restored, 2)
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_ambiguous_purchase_blocks_another_after_restart(self, request):
        import requests
        request.side_effect = requests.Timeout("contains fixture-key but must not be logged")
        with self._config():
            with self.assertRaises(client.SmsBowerMailError):
                client.pick_account()
            client._CONTEXT_CACHE.clear()
            with self.assertRaisesRegex(client.SmsBowerMailError, "不自动重新购买"):
                client.pick_account()
        self.assertEqual(request.call_count, 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_two_round_codes_are_deduplicated_after_restart(self, request):
        with self._config(), patch.object(client, "_sleep"):
            account = self._acquire(request)
            request.side_effect = [self._response(x) for x in (
                {"status": 1, "code": "012345"}, {"status": 1},
                {"status": 1, "code": "012345"}, {"status": "1", "code": "654321"}, {"status": "1"},
            )]
            self.assertEqual(client.fetch_latest_otp(account.email, max_wait=1), "012345")
            client._CONTEXT_CACHE.clear()
            self.assertEqual(client.fetch_latest_otp(account.email, max_wait=1), "654321")
            self.assertEqual(len(client.restore_account_context(account.email).code_digests), 2)

    @patch("core.smsbower_mail_client.requests.request")
    def test_access_refusal_is_not_polled_repeatedly(self, request):
        with self._config():
            account = self._acquire(request)
            request.reset_mock()
            request.return_value = self._response({}, status=429)
            with self.assertRaisesRegex(client.SmsBowerMailError, "429"):
                client.fetch_latest_otp(account.email, max_wait=1)
        self.assertEqual(request.call_count, 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_creation_marker_blocks_failure_cleanup_after_restart(self, request):
        with self._config():
            account = self._acquire(request)
            client.release_account(account.email, status="failed_created")
            client._CONTEXT_CACHE.clear()
            request.reset_mock()
            self.assertEqual(client.release_account(account.email, status="available"), "pending")
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_duplicate_activation_cannot_replace_owner(self, request):
        with self._config():
            account = self._acquire(request)
            with self.assertRaisesRegex(client.SmsBowerMailError, "重复"):
                client.pick_account()
            self.assertIs(client.get_account_context(account.email), account)

    @patch("core.smsbower_mail_client.requests.request")
    def test_key_change_does_not_read_another_activation(self, request):
        with self._config():
            account = self._acquire(request)
            request.reset_mock()
            with patch.object(email_config, "SMSBOWER_MAIL_API_KEY", "another-key"):
                with self.assertRaisesRegex(client.SmsBowerMailError, "变化"):
                    client.fetch_latest_otp(account.email, max_wait=1)
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_zero_wait_makes_no_poll_request(self, request):
        with self._config():
            account = self._acquire(request)
            request.reset_mock()
            with self.assertRaises(client.SmsBowerMailTimeout):
                client.fetch_latest_otp(account.email, max_wait=0)
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_malformed_purchase_status_is_not_treated_as_no_stock(self, request):
        request.return_value = self._response({"status": True, "error": "No mails yet"})
        with self._config():
            with self.assertRaisesRegex(client.SmsBowerMailError, "不明确"):
                client.pick_account()
            with self.assertRaisesRegex(client.SmsBowerMailError, "不自动重新购买"):
                client.pick_account()
        self.assertEqual(request.call_count, 1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_set_status_failure_never_returns_or_replays_code(self, request):
        with self._config():
            account = self._acquire(request)
            unreadable = Mock(status_code=200)
            unreadable.json.side_effect = ValueError("broken")
            request.side_effect = [self._response({"status": 1, "code": "012345"}), unreadable]
            with self.assertRaises(client.SmsBowerMailError):
                client.fetch_latest_otp(account.email, max_wait=1)
            self.assertTrue(account.code_digests)
            client._CONTEXT_CACHE.clear()
            request.reset_mock()
            with self.assertRaisesRegex(client.SmsBowerMailError, "未确认"):
                client.fetch_latest_otp(account.email, max_wait=1)
        request.assert_not_called()

    @patch("core.smsbower_mail_client.requests.request")
    def test_stop_requested_aborts_poll_without_network(self, request):
        with self._config():
            account = self._acquire(request)
            request.reset_mock()
            from core.registration_service import StopRequested
            with patch.object(client, "_check_stop", side_effect=StopRequested("stop")):
                with self.assertRaises(StopRequested):
                    client.fetch_latest_otp(account.email, max_wait=1)
        request.assert_not_called()

    def test_stale_snapshot_cannot_clear_another_pending_write(self):
        from core import mail_activation_store as store
        account = client.SmsBowerMailAccount("fresh@gmail.com", "4")
        record = client._record(account)
        store.save(record)
        store.claim_action(record, "setStatus=3")
        with self.assertRaisesRegex(ValueError, "未确认"):
            store.save(record)

    def test_code_consumption_is_atomic_across_independent_snapshots(self):
        from core import mail_activation_store as store
        account = client.SmsBowerMailAccount("fresh@gmail.com", "4")
        record = client._record(account)
        store.save(record)
        self.assertTrue(store.consume_code(dict(record), "fixture-code-digest"))
        self.assertFalse(store.consume_code(dict(record), "fixture-code-digest"))

    def test_legacy_context_is_not_silently_reopened(self):
        import json
        db.insert_account(email="old@gmail.com", access_token="", email_source="smsbower_mail",
                          extra={"email_service": {"source": "smsbower_mail", "email": "old@gmail.com", "mail_id": "old"}})
        with self._config():
            with self.assertRaisesRegex(client.SmsBowerMailError, "未确认"):
                client.fetch_latest_otp("old@gmail.com", max_wait=1)

    @patch("core.smsbower_mail_client.requests.request")
    def test_alias_does_not_hide_duplicate_underlying_gmail(self, request):
        with self._config(), patch.object(email_config, "SMSBOWER_MAIL_ALIAS_LENGTH", 6):
            self._acquire(request)
            request.return_value = self._response({"status": 1, "mail": "fresh@gmail.com", "mailId": 5})
            with self.assertRaisesRegex(client.SmsBowerMailError, "重复"):
                client.pick_account()

    @patch("core.smsbower_mail_client.requests.request")
    def test_excluded_code_is_not_submitted_again(self, request):
        with self._config(), patch.object(client, "_sleep"):
            account = self._acquire(request)
            request.side_effect = [self._response(x) for x in (
                {"status": 1, "code": "012345"}, {"status": 1, "code": "654321"}, {"status": 1},
            )]
            self.assertEqual(client.fetch_latest_otp(account.email, max_wait=1, exclude_codes={"012345"}), "654321")

    @patch("core.smsbower_mail_client.requests.request")
    def test_parallel_jobs_wait_for_inflight_purchase_without_sharing_activation(self, request):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        entered, release = threading.Event(), threading.Event()
        calls = []

        def respond(*args, **kwargs):
            calls.append(len(calls) + 1)
            n = calls[-1]
            if n == 1:
                entered.set()
                if not release.wait(3):
                    raise AssertionError("fixture purchase not released")
            return self._response({"status": 1, "mail": f"fixture{n}@gmail.com", "mailId": n})

        request.side_effect = respond
        with self._config(), ThreadPoolExecutor(max_workers=2) as pool:
            one = pool.submit(client.pick_account)
            self.assertTrue(entered.wait(3))
            two = pool.submit(client.pick_account)
            release.set()
            accounts = [one.result(3), two.result(3)]
        self.assertEqual({a.mail_id for a in accounts}, {"1", "2"})
        self.assertEqual(len({a.email for a in accounts}), 2)


if __name__ == "__main__":
    unittest.main()
