"""Fixed ICAPI policy: 30-second waits, at most three GETs, no pre-send read."""
import unittest
from unittest.mock import Mock, patch

from core import generic_api_mail_client as mail, email_provider
from config import email as cfg


class IcapiDirectPollingTests(unittest.TestCase):
    url = "https://icapi.oaibx.com/api?token=fixture-private-token"
    email = "fixture@icloud.com"

    def response(self, code="", *, status=200, ok=1):
        response = Mock(status_code=status)
        response.json.return_value = {"code": ok, "msg": "ok", "data": {
            "code": code, "code_time": "2000-01-01 00:00:00", "expired_date": "",
        }}
        return response

    def run_poll(self, responses, **kwargs):
        clock, visits, waits = [100.0], [], []
        http = Mock()
        queue = iter(responses)

        def get(*args, **options):
            visits.append((clock[0], args, options))
            value = next(queue)
            if isinstance(value, Exception):
                raise value
            return value

        def wait(seconds):
            waits.append(seconds)
            clock[0] += seconds

        http.get.side_effect = get
        account = mail.GenericApiEmailAccount(self.email, self.url)
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_new_http_session", return_value=http), \
             patch.object(mail, "_wait_icapi_delay", side_effect=wait), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail, "_fetch_poll_payload", side_effect=AssertionError("generic snapshot path used")), \
             patch.object(mail, "verify_mail_freshness", side_effect=AssertionError("freshness gate used")):
            try:
                result = mail.fetch_latest_otp(self.email, **kwargs)
            except Exception as exc:
                result = exc
        http.close.assert_called_once()
        return result, visits, waits

    def test_first_code_is_used_without_baseline_settle_or_timestamp_gate(self):
        result, visits, waits = self.run_poll([self.response("012345")], after_ts=9999999999,
            first_read_delay_seconds=60, settle_seconds=999, max_wait=1, first_read_anchor_ts=100)
        self.assertEqual(result, "012345")
        self.assertEqual([v[0] for v in visits], [130])
        self.assertEqual(waits, [30])
        self.assertEqual(visits[0][1][0], self.url)
        self.assertTrue(visits[0][2]["verify"])
        self.assertFalse(visits[0][2]["allow_redirects"])

    def test_empty_then_success_waits_30_seconds_each_time(self):
        result, visits, waits = self.run_poll([self.response(), self.response("654321")])
        self.assertEqual(result, "654321")
        self.assertEqual([v[0] for v in visits], [130, 160])
        self.assertEqual(waits, [30, 30])

    def test_three_failures_raise_exact_error_without_fourth_read(self):
        result, visits, waits = self.run_poll([self.response()] * 3)
        self.assertIsInstance(result, mail.GenericApiMailError)
        self.assertEqual(str(result), "验证码未获取")
        self.assertEqual([v[0] for v in visits], [130, 160, 190])
        self.assertEqual(waits, [30, 30, 30])

    def test_network_failure_and_bad_json_still_have_only_three_requests(self):
        import requests
        bad = self.response()
        bad.json.side_effect = ValueError("private response")
        result, visits, waits = self.run_poll([requests.Timeout("private-token"), bad, self.response("123456")])
        self.assertEqual(result, "123456")
        self.assertEqual(len(visits), 3)
        self.assertEqual(waits, [30, 30, 30])

    def test_business_error_or_non_six_digit_code_is_not_used(self):
        result, visits, _ = self.run_poll([
            self.response("012345", ok=0), self.response("12345"), self.response("abcdef"),
        ])
        self.assertEqual(str(result), "验证码未获取")
        self.assertEqual(len(visits), 3)

    def test_empty_api_diagnostic_has_status_but_no_token_body_or_code(self):
        response = self.response("", ok=0)
        response.json.return_value["msg"] = "private-response"
        with self.assertLogs(mail.logger, "INFO") as logs:
            result, _, _ = self.run_poll([response, self.response("012345")])
        self.assertEqual(result, "012345")
        output = "\n".join(logs.output)
        self.assertIn("业务状态=0", output)
        for private in ("private-response", "012345", "fixture-private-token"):
            self.assertNotIn(private, output)

    def test_outer_status_cannot_be_misread_as_an_otp(self):
        response = Mock(status_code=200)
        response.json.return_value = {"code": 123456, "data": {"code": ""}}
        result, visits, _ = self.run_poll([response] * 3)
        self.assertEqual(str(result), "验证码未获取")

    def test_baseline_capture_makes_no_request_for_icapi(self):
        account = mail.GenericApiEmailAccount(self.email, self.url)
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_new_http_session") as http:
            self.assertIsNone(mail.capture_mail_baseline(self.email))
        http.assert_not_called()

    def test_non_icapi_endpoints_do_not_get_the_exception(self):
        for url in ("https://icapi.oaibx.com.attacker.test/api?token=fixture", "https://other.test/api",
                    "https://icapi.oaibx.com/other", "http://icapi.oaibx.com/api"):
            self.assertFalse(mail.is_direct_icapi_url(url))

    def test_access_refusal_stops_without_replaying(self):
        result, visits, waits = self.run_poll([self.response(status=429)])
        self.assertIsInstance(result, mail.GenericApiMailError)
        self.assertIn("429", str(result))
        self.assertEqual(len(visits), 1)

    def test_page_ready_anchor_does_not_add_an_extra_30s_after_local_processing(self):
        result, visits, waits = self.run_poll([self.response("012345")], first_read_anchor_ts=95)
        self.assertEqual(waits, [25])
        self.assertEqual(visits[0][0], 125)

    def test_dispatcher_forwards_ready_anchor_even_without_generic_delay(self):
        with patch.object(cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(mail, "fetch_latest_otp", return_value="012345") as fetch:
            result = email_provider.wait_for_otp(self.email, after_ts=10, email_source="generic_api",
                                                 first_read_anchor_ts=100)
        self.assertEqual(result, "012345")
        self.assertEqual(fetch.call_args.kwargs["first_read_anchor_ts"], 100)

    def test_real_registration_waits_from_page_ready_without_snapshot_or_resend(self):
        self._run_registration_fixture()

    def test_real_registration_waits_30s_after_pending_initial_send_completes(self):
        self._run_registration_fixture(pending=True)

    def _run_registration_fixture(self, pending=False):
        import main
        import socket
        from contextlib import ExitStack
        from types import SimpleNamespace
        clock, visits = [100.0], []
        session = SimpleNamespace(proxy=None, device_id="fixture", auth_session_logging_id="fixture",
                                  sentinel_sid="fixture", browser_profile={})
        session.get_auth_headers = Mock(return_value={})
        def initial_send(*args, **kwargs):
            clock[0] = 115
            response = Mock(status_code=200)
            response.json.return_value = {"page": {"type": "email_otp_verification"}}
            return response
        session.post = Mock(side_effect=initial_send)
        account = mail.GenericApiEmailAccount(self.email, self.url)
        http = Mock()
        http.get.side_effect = lambda *a, **kw: visits.append(clock[0]) or self.response("012345")
        with ExitStack() as stack:
            def patch_in(target, **kwargs):
                return stack.enter_context(patch(target, **kwargs))
            patch_in("socket.socket.connect", side_effect=AssertionError("real network forbidden"))
            patch_in("core.workflow_driver.require_driver_ready", return_value="protocol")
            patch_in("core.email_provider.resolve_email_source", return_value="generic_api")
            patch_in("core.generic_api_mail_client.get_account_context", return_value=account)
            patch_in("core.generic_api_mail_client._new_http_session", return_value=http)
            patch_in("core.generic_api_mail_client._wait_icapi_delay",
                     side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds))
            patch_in("main.BrowserSession", return_value=session)
            patch_in("main.network_preflight")
            patch_in("main.get_providers", return_value={})
            patch_in("main.get_csrf_token", return_value="fixture-csrf")
            patch_in("main.signin_openai", return_value="https://auth.openai.com/authorize")
            def follow(*args):
                clock[0] = 105
                if pending:
                    session._registration_auth_page_state = {"session_id": "fixture", "email": self.email,
                        "passwordless_email_otp_send_pending": True, "email_verification_mode": "passwordless_login"}
                    session._registration_auth_page_url = "https://auth.openai.com/email-verification"
                return "https://auth.openai.com/email-verification"
            patch_in("main.follow_authorize", side_effect=follow)
            snapshot = patch_in("main.prepare_otp_mail_baseline")
            send = patch_in("main.send_email_otp")
            patch_in("main.human_delay")
            patch_in("main.close_browser_session")
            patch_in("main.time.time", side_effect=lambda: clock[0])
            patch_in("main.validate_email_otp", return_value={"page": {"type": "workspace"}})
            patch_in("core.openai_auth.request_sentinel_token", return_value={})
            patch_in("core.openai_auth.build_sentinel_header", return_value=("fixture", None))
            patch_in("core.account_liveness._select_workspace_and_fetch", return_value={"accessToken": "fixture-at"})
            patch_in("main.save_account_data", return_value=77)
            patch_in("core.registration_completion.finish_account", return_value={"status": "success"})
            patch_in("core.db.get_account", return_value={"email_source": "generic_api"})
            patch_in("core.db.update_account_flow")
            patch_in("config.email.USE_EMAIL_SERVICE", new=True)
            patch_in("config.openai_protocol.CHATGPT_ANON_BOOTSTRAP_ENABLED", new=False)
            patch_in("config.openai_protocol.SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", new=False)
            result = main.run_registration(self.email, "Fixture User", "1990-01-01")
        self.assertTrue(result["success"])
        self.assertEqual(visits, [145 if pending else 135])
        self.assertEqual(session.post.call_count, 1 if pending else 0)
        snapshot.assert_not_called()
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
