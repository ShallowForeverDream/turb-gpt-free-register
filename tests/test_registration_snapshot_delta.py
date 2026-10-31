"""Registration-to-mail integration with a fake clock and mailbox responses only."""
import json
import socket
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main
from core import email_provider, generic_api_mail_client as mail
from core.otp_freshness import OtpFreshnessError, new_mail_baseline, verify_mail_freshness


class RegistrationSnapshotDeltaTests(unittest.TestCase):
    email = "fixture@example.test"
    url = "https://mail.example.test/code"

    def test_registration_snapshots_before_automatic_delivery_then_reads_after_60_seconds(self):
        clock = [100.0]
        events = []
        account = mail.GenericApiEmailAccount(self.email, self.url)
        baseline_response = Mock(status_code=200)
        baseline_response.json.return_value = {
            "status": 1, "code": "001234", "all_codes": ["001234", "005555"],
            "email": self.email,
        }
        baseline_session = Mock()
        baseline_session.get.return_value = baseline_response
        baseline = [None]
        responses = iter([
            {"status": 1, "code": "001234", "all_codes": ["001234", "005555"]},
            {"status": 1, "code": "006789", "all_codes": ["006789", "001234", "005555"]},
        ])
        polls = []

        def capture_before_send():
            events.append(("snapshot", clock[0]))
            baseline[0] = mail.capture_mail_baseline(self.email)

        def poll_payload(**_kwargs):
            polls.append(clock[0])
            return None, None, SimpleNamespace(status_code=200), json.dumps(next(responses))

        def navigate_for_five_seconds(*_args):
            events.append(("authorize", clock[0]))
            clock[0] += 5
            return "https://auth.openai.com/email-verification"

        with patch.object(socket.socket, "connect", side_effect=AssertionError("network not allowed")), \
             patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_new_http_session", return_value=baseline_session), \
             patch.object(mail, "_fetch_poll_payload", side_effect=poll_payload), \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""), \
             patch.object(mail._email_cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(email_provider, "_registered_email_source", return_value="generic_api"), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
             patch.object(main, "send_email_otp") as send, \
             patch.object(main, "follow_authorize", side_effect=navigate_for_five_seconds):
            capture_before_send()
            issued_after = clock[0]
            final_url = main.follow_authorize(object(), "https://auth.openai.com/authorize")
            password, after_ts = main._prepare_registration_otp(
                object(), self.email, final_url, before_send=capture_before_send,
                issued_after=issued_after,
            )
            code = email_provider.wait_for_otp(
                self.email, after_ts=after_ts, mail_baseline=baseline[0],
                first_read_delay_seconds=60, first_read_anchor_ts=clock[0],
                max_wait=70, poll_interval=1, settle_seconds=0,
            )
        self.assertIsNone(password)
        send.assert_not_called()
        self.assertEqual(events, [("snapshot", 100.0), ("authorize", 100.0)])
        self.assertEqual(after_ts, 100.0)
        self.assertEqual(polls, [165.0, 166.0])
        self.assertEqual(code, "006789")
        self.assertEqual(len(baseline[0].code_fingerprints), 2)
        self.assertNotIn("001234", repr(baseline[0]))

    def test_code_only_baseline_may_be_known_empty_but_not_unknown(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 1, "code": None, "all_codes": []}
        session = Mock()
        session.get.return_value = response
        account = mail.GenericApiEmailAccount(self.email, self.url)
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_new_http_session", return_value=session):
            baseline = mail.capture_mail_baseline(self.email)
        self.assertEqual(baseline.code_fingerprints, frozenset())
        self.assertEqual(verify_mail_freshness(
            {}, email=self.email, url=self.url, after_ts=baseline.observed_at + 1,
            now=baseline.observed_at + 61, baseline=baseline, candidate_code="001234",
        ), "new_code_since_snapshot")
        with self.assertRaises(OtpFreshnessError):
            verify_mail_freshness({}, email=self.email, url=self.url,
                                  after_ts=100, now=160, candidate_code="001234")

    def test_old_code_and_other_recipient_are_not_selected(self):
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=None, codes=("001234",))
        with self.assertRaises(OtpFreshnessError) as old:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
                                  now=160, baseline=baseline, candidate_code="001234")
        self.assertEqual(old.exception.reason, "unchanged_code_set")
        with self.assertRaises(OtpFreshnessError) as wrong:
            verify_mail_freshness({"recipient": "other@example.test"}, email=self.email,
                                  url=self.url, after_ts=100, now=160,
                                  baseline=baseline, candidate_code="006789")
        self.assertEqual(wrong.exception.reason, "recipient_mismatch")

    def test_snapshot_old_value_is_excluded_even_with_new_mail_metadata(self):
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=frozenset({"old-id"}),
                                     codes=("001234",))
        with self.assertRaises(OtpFreshnessError) as old:
            verify_mail_freshness({"mail_id": "new-id", "received_at": 101},
                email=self.email, url=self.url, after_ts=100, now=160,
                baseline=baseline, candidate_code="001234")
        self.assertEqual(old.exception.reason, "unchanged_code_set")

    def test_short_deadline_is_reported_without_mail_poll(self):
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=None, codes=("001234",))
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_fetch_poll_payload") as fetch, \
             patch.object(mail.time, "time", return_value=100):
            with self.assertRaisesRegex(mail.GenericApiMailError, "等待期限不足"):
                mail.fetch_latest_otp(self.email, after_ts=100, max_wait=30,
                                      mail_baseline=baseline, first_read_delay_seconds=60)
        fetch.assert_not_called()

    def test_unique_history_delta_is_used_when_top_level_code_is_stale(self):
        clock = [100.0]
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=None, codes=("001234",))
        response = SimpleNamespace(status_code=200)
        payload = json.dumps({"status": 1, "code": "001234",
                              "all_codes": ["001234", "006789"]})
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_fetch_poll_payload", return_value=(None, None, response, payload)) as fetch, \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            code = mail.fetch_latest_otp(self.email, after_ts=100, mail_baseline=baseline,
                first_read_delay_seconds=60, first_read_anchor_ts=105,
                max_wait=70, poll_interval=1, settle_seconds=0)
        self.assertEqual(code, "006789")
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(clock[0], 165)

    def test_multiple_history_deltas_do_not_silently_pick_one(self):
        clock = [100.0]
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=None, codes=("001234",))
        response = SimpleNamespace(status_code=200)
        payload = json.dumps({"status": 1, "code": "001234",
                              "all_codes": ["001234", "006789", "009999"]})
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_fetch_poll_payload", return_value=(None, None, response, payload)), \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaises(OtpFreshnessError) as error:
                mail.fetch_latest_otp(self.email, after_ts=100, mail_baseline=baseline,
                    first_read_delay_seconds=60, first_read_anchor_ts=100,
                    max_wait=61, poll_interval=1, settle_seconds=0)
        self.assertEqual(error.exception.reason, "multiple_new_codes")

    def test_other_mail_sources_do_not_inherit_generic_api_delay(self):
        from core import imap_mail_client
        with patch.object(mail._email_cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(imap_mail_client, "fetch_latest_otp", return_value="001234") as fetch:
            code = email_provider.wait_for_otp(self.email, after_ts=100,
                email_source="imap", force_service=True,
                first_read_delay_seconds=60, first_read_anchor_ts=105)
        self.assertEqual(code, "001234")
        self.assertNotIn("first_read_delay_seconds", fetch.call_args.kwargs)
        self.assertNotIn("first_read_anchor_ts", fetch.call_args.kwargs)

    def test_loopback_http_fixture_exercises_the_real_mail_transport(self):
        responses = [
            {"status": 1, "code": "001234", "all_codes": ["001234"]},
            {"status": 1, "code": "001234", "all_codes": ["001234", "006789"]},
        ]
        visits = []

        class FixtureHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                visits.append(self.path)
                body = json.dumps(responses[min(len(visits) - 1, len(responses) - 1)]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        account = mail.GenericApiEmailAccount(
            self.email, f"http://127.0.0.1:{server.server_port}/code",
        )
        clock = [100.0]
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            baseline = mail.capture_mail_baseline(self.email)
            clock[0] = 105.0
            result = mail.fetch_latest_otp(self.email, after_ts=100,
                mail_baseline=baseline, first_read_delay_seconds=60,
                first_read_anchor_ts=105, max_wait=70, poll_interval=1,
                settle_seconds=0)
        self.assertEqual(result, "006789")
        self.assertEqual(len(visits), 2)
        self.assertGreaterEqual(clock[0], 165)

    def test_real_registration_entry_passes_snapshot_and_delay_to_mail_provider(self):
        events = []
        baseline = new_mail_baseline(email=self.email, url=self.url,
                                     observed_at=99, mail_ids=None, codes=("001234",))
        session = SimpleNamespace(proxy=None, device_id="fixture-device",
                                  auth_session_logging_id="fixture-auth", sentinel_sid="fixture-sid",
                                  browser_profile={})
        validated = {"continue_url": "https://auth.openai.com/workspace",
                     "page": {"type": "workspace"},
                     "oai-client-auth-session": {"workspaces": []}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(socket.socket, "connect",
                                             side_effect=AssertionError("network not allowed")))
            stack.enter_context(patch("core.workflow_driver.require_driver_ready", return_value="protocol"))
            stack.enter_context(patch("core.registration_completion.finish_account",
                                      return_value={"status": "success"}))
            stack.enter_context(patch("core.protocol_traffic.current_traffic"))
            stack.enter_context(patch("core.db.update_account_flow"))
            stack.enter_context(patch.object(main, "BrowserSession", return_value=session))
            stack.enter_context(patch.object(main, "network_preflight"))
            stack.enter_context(patch.object(main, "get_providers", return_value={}))
            stack.enter_context(patch.object(main, "get_csrf_token", return_value="csrf"))
            stack.enter_context(patch.object(main, "signin_openai", return_value="authorize"))
            stack.enter_context(patch.object(main, "follow_authorize",
                side_effect=lambda *args: events.append("authorize") or "https://auth.openai.com/email-verification"))
            prepare = stack.enter_context(patch.object(main, "prepare_otp_mail_baseline",
                side_effect=lambda *args: events.append("snapshot") or baseline))
            send = stack.enter_context(patch.object(main, "send_email_otp"))
            wait = stack.enter_context(patch.object(main, "wait_for_otp",
                                                    side_effect=["006789", "009999"]))
            validate = stack.enter_context(patch.object(main, "validate_email_otp", side_effect=[
                main.EmailOtpInvalidError("wrong_email_otp_code"), validated,
            ]))
            stack.enter_context(patch.object(main, "human_delay"))
            stack.enter_context(patch.object(main, "close_browser_session"))
            stack.enter_context(patch.object(main, "save_account_data", return_value=7))
            stack.enter_context(patch("core.account_liveness._select_workspace_and_fetch",
                                      return_value={"accessToken": "fixture-at", "user": {}, "account": {}}))
            stack.enter_context(patch.object(main._email_cfg, "USE_EMAIL_SERVICE", True))
            stack.enter_context(patch.object(main._protocol_cfg, "CHATGPT_ANON_BOOTSTRAP_ENABLED", False))
            stack.enter_context(patch.object(main._protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False))
            main.run_registration(self.email, "Fixture User", "1990-01-01")
        prepare.assert_called_once_with(self.email)
        self.assertEqual(events, ["snapshot", "authorize"])
        send.assert_not_called()
        self.assertEqual(wait.call_count, 2)
        self.assertEqual([call.args[1] for call in validate.call_args_list], ["006789", "009999"])
        for call in wait.call_args_list:
            self.assertIs(call.kwargs["mail_baseline"], baseline)
            self.assertEqual(call.kwargs["first_read_delay_seconds"], 60)
            self.assertGreaterEqual(call.kwargs["first_read_anchor_ts"], call.kwargs["after_ts"])
        self.assertNotIn("exclude_codes", wait.call_args_list[0].kwargs)
        self.assertEqual(wait.call_args_list[1].kwargs["exclude_codes"], {"006789"})


if __name__ == "__main__":
    unittest.main()
