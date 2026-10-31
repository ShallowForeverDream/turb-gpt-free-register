"""Synthetic OTPs and fake clocks only; no provider or registration traffic."""
import unittest
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import generic_api_mail_client as mail, email_provider, account_export


class SignaturePollingTests(unittest.TestCase):
    email = "signature-fixture@gmail.com"
    url = "https://smsbower.page/api/mail/getCodeBySignature?s=fixture-private-signature"

    def response(self, code="", status=1, http_status=200):
        response = Mock(status_code=http_status)
        response.json.return_value = {"status": status, "code": code, "all_codes": ["987654"]}
        return response

    @contextmanager
    def fixture(self, responses, now=100):
        clock, reads = [float(now)], []
        http = Mock()
        queue = iter(responses)
        account = mail.GenericApiEmailAccount(self.email, self.url)
        def get(*args, **kwargs):
            reads.append((clock[0], args, kwargs))
            response = next(queue)
            if isinstance(response, Exception):
                raise response
            return response
        http.get.side_effect = get
        with ExitStack() as stack:
            for target, kwargs in [
                ("socket.socket.connect", {"side_effect": AssertionError("real network forbidden")}),
                ("core.generic_api_mail_client.get_account_context", {"return_value": account}),
                ("core.email_provider.resolve_email_source", {"return_value": "generic_api"}),
                ("core.email_provider._registered_email_source", {"return_value": None}),
                ("core.generic_api_mail_client._new_http_session", {"return_value": http}),
                ("core.generic_api_mail_client._wait_icapi_delay", {"side_effect": lambda n: clock.__setitem__(0, clock[0]+n)}),
                ("core.generic_api_mail_client.time.time", {"side_effect": lambda: clock[0]}),
                ("core.generic_api_mail_client.time.monotonic", {"side_effect": lambda: clock[0]}),
                ("core.generic_api_mail_client.verify_mail_freshness", {"side_effect": AssertionError("baseline filter used")}),
                ("core.generic_api_mail_client._fetch_poll_payload", {"side_effect": AssertionError("generic poll used")}),
            ]:
                stack.enter_context(patch(target, **kwargs))
            yield clock, reads, http

    def test_exact_endpoint_only(self):
        self.assertTrue(mail.is_smsbower_signature_url(self.url))
        for value in (self.url.replace("https:", "http:"), self.url.replace("smsbower.page", "smsbower.page.evil.test"),
                      self.url.replace("smsbower.page", "evil@smsbower.page"), self.url.replace("?s=", "/extra?s="),
                      self.url+"&s=duplicate", self.url+"&s=", self.url.split("?")[0], self.url.replace("smsbower.page", "smsbower.page:444")):
            self.assertFalse(mail.is_smsbower_signature_url(value), value)

    def test_baseline_makes_zero_http_requests(self):
        account = mail.GenericApiEmailAccount(self.email, self.url)
        with patch.object(mail, "get_account_context", return_value=account), patch.object(mail, "_new_http_session") as http:
            self.assertIsNone(mail.capture_mail_baseline(self.email))
        http.assert_not_called()

    def test_reads_top_level_code_not_history_with_no_freshness_or_settle(self):
        with self.fixture([self.response("012345")]) as (clock, reads, http):
            code = mail.fetch_latest_otp(self.email, after_ts=999999, settle_seconds=999,
                                         first_read_delay_seconds=60, first_read_anchor_ts=95, max_wait=1)
        self.assertEqual(code, "012345")
        self.assertEqual([r[0] for r in reads], [125])
        self.assertEqual(reads[0][1], (self.url,))
        self.assertTrue(reads[0][2]["verify"])
        self.assertFalse(reads[0][2]["allow_redirects"])
        http.close.assert_called_once()

    def test_empty_bad_json_and_network_error_share_three_read_limit(self):
        import requests
        bad = self.response()
        bad.json.side_effect = ValueError("private-json")
        with self.fixture([self.response(), bad, requests.Timeout("private-url")]) as (_, reads, _http):
            with self.assertRaisesRegex(mail.GenericApiMailError, "^验证码未获取$"):
                mail.fetch_latest_otp(self.email)
        self.assertEqual([r[0] for r in reads], [130, 160, 190])

    def test_business_error_and_history_only_are_not_accepted(self):
        response = self.response()
        response.json.return_value = {"status": 1, "all_codes": ["123456"]}
        with self.fixture([self.response("012345", status=0), response, self.response("abcdef")]) as (_, reads, _):
            with self.assertRaisesRegex(mail.GenericApiMailError, "验证码未获取"):
                mail.fetch_latest_otp(self.email)
        self.assertEqual(len(reads), 3)

    def test_refusal_stops_without_replay_or_routing_fallback(self):
        for status in (401, 403, 429):
            with self.fixture([self.response(http_status=status)]) as (_, reads, _):
                with self.assertRaisesRegex(mail.GenericApiMailError, str(status)):
                    mail.fetch_latest_otp(self.email)
            self.assertEqual(len(reads), 1)

    def test_validation_rejection_waits_30s_from_rejection_with_same_total_budget(self):
        with self.fixture([self.response("012345"), self.response(), self.response("654321")]) as (clock, reads, _):
            state = mail.create_signature_poll_state(self.email, ready_at=100)
            self.assertEqual(mail.fetch_latest_otp(self.email, signature_poll_state=state), "012345")
            clock[0] += 10
            state.defer_after_rejection()
            self.assertEqual(mail.fetch_latest_otp(self.email, signature_poll_state=state), "654321")
            self.assertFalse(state.can_retry)
            with self.assertRaisesRegex(mail.GenericApiMailError, "验证码未获取"):
                mail.fetch_latest_otp(self.email, signature_poll_state=state)
        self.assertEqual([r[0] for r in reads], [130, 170, 200])

    def test_poll_state_is_not_reused_for_another_mailbox_or_url(self):
        with self.fixture([]) as (_, reads, _):
            state = mail.SignatureOtpPollState("wrong-binding")
            with self.assertRaisesRegex(mail.GenericApiMailError, "上下文不匹配"):
                mail.fetch_latest_otp(self.email, signature_poll_state=state)
        self.assertEqual(reads, [])

    def test_dispatcher_forwards_state_only_to_generic_adapter(self):
        state = mail.SignatureOtpPollState("fixture")
        with patch("config.email.USE_EMAIL_SERVICE", True), patch.object(mail, "fetch_latest_otp", return_value="012345") as fetch:
            email_provider.wait_for_otp(self.email, after_ts=100, email_source="generic_api", signature_poll_state=state)
        self.assertIs(fetch.call_args.kwargs["signature_poll_state"], state)

    def test_logs_hide_signature_body_and_otp(self):
        response = self.response("012345")
        response.json.return_value["msg"] = "private-response"
        with self.fixture([response]), self.assertLogs(mail.logger, "INFO") as logs:
            mail.fetch_latest_otp(self.email)
        for secret in ("fixture-private-signature", "private-response", "012345", "987654"):
            self.assertNotIn(secret, "\n".join(logs.output))

    def test_twofa_rejection_uses_remaining_reads_not_a_new_three_read_budget(self):
        from curl_cffi.requests.exceptions import HTTPError
        response = Mock(status_code=401)
        response.json.return_value = {"error": {"code": "wrong_email_otp_code"}}
        error = HTTPError("fixture OTP rejected", response=response)
        with self.fixture([self.response(), self.response("012345"), self.response("654321")]) as (_, reads, _):
            state = mail.create_signature_poll_state(self.email, ready_at=100)
            first = mail.fetch_latest_otp(self.email, signature_poll_state=state)
            with patch.object(account_export, "_validate_reauth_otp", side_effect=[error, error]) as validate, \
                 patch("config.email.USE_EMAIL_SERVICE", True):
                with self.assertRaises(HTTPError):
                    account_export._validate_reauth_otp_with_retry(object(), self.email, first, 100,
                                                                  signature_poll_state=state)
        self.assertEqual(len(reads), 3)
        self.assertEqual(validate.call_count, 2)

    def test_twofa_non_otp_401_or_access_refusal_does_not_retry(self):
        from curl_cffi.requests.exceptions import HTTPError
        for status, code in ((401, "session_expired"), (429, "rate_limit_exceeded"), (403, "access_denied")):
            response = Mock(status_code=status)
            response.json.return_value = {"error": {"code": code}}
            error = HTTPError("fixture refusal", response=response)
            with patch.object(account_export, "_validate_reauth_otp", side_effect=error) as validate, \
                 patch.object(email_provider, "wait_for_otp") as wait:
                with self.assertRaises(HTTPError):
                    account_export._validate_reauth_otp_with_retry(object(), self.email, "012345", 100,
                        signature_poll_state=mail.SignatureOtpPollState("fixture", attempts=1))
            validate.assert_called_once()
            wait.assert_not_called()

    def test_invalid_session_is_not_misclassified_as_a_wrong_otp(self):
        from core.openai_auth import is_email_otp_rejection, validate_email_otp, EmailOtpInvalidError
        for code in ("invalid_auth_step", "session_expired", "invalid_token"):
            response = Mock(status_code=401, text="invalid code session private-response")
            response.json.return_value = {"error": {"code": code}}
            response.raise_for_status.side_effect = RuntimeError("HTTP 401")
            self.assertFalse(is_email_otp_rejection(response))
            session = Mock()
            session.post.return_value = response
            with self.assertRaises(RuntimeError) as error:
                validate_email_otp(session, "012345")
            self.assertNotIsInstance(error.exception, EmailOtpInvalidError)

    def registration(self, responses, invalid_count=0):
        import main
        from core.openai_auth import EmailOtpInvalidError
        with self.fixture(responses) as (clock, reads, _http), ExitStack() as stack:
            p = lambda target, **kw: stack.enter_context(patch(target, **kw))
            session = SimpleNamespace(proxy=None, device_id="fixture", auth_session_logging_id="fixture",
                                      sentinel_sid="fixture", browser_profile={})
            p("core.workflow_driver.require_driver_ready", return_value="protocol")
            p("core.email_provider.resolve_email_source", return_value="generic_api")
            p("main.BrowserSession", return_value=session)
            p("main.network_preflight")
            p("main.get_providers", return_value={})
            p("main.get_csrf_token", return_value="fixture")
            p("main.signin_openai", return_value="https://auth.openai.com/oauth/authorize")
            def follow(*_):
                clock[0] = 105
                return "https://auth.openai.com/email-verification"
            p("main.follow_authorize", side_effect=follow)
            baseline = p("main.prepare_otp_mail_baseline", side_effect=AssertionError("baseline forbidden"))
            resend = p("main.send_email_otp", side_effect=AssertionError("resend forbidden"))
            p("main.human_delay")
            p("main.close_browser_session")
            p("core.email_provider.release_email")
            def validate(*_):
                clock[0] += 10
                if validate_mock.call_count <= invalid_count:
                    raise EmailOtpInvalidError("fixture invalid OTP")
                return {"page": {"type": "workspace"}}
            validate_mock = p("main.validate_email_otp", side_effect=validate)
            p("core.account_liveness._select_workspace_and_fetch", return_value={"accessToken": "fixture"})
            p("main.save_account_data", return_value=77)
            p("core.registration_completion.finish_account", return_value={"status": "success"})
            p("core.db.get_account", return_value={"email_source": "generic_api"})
            p("core.db.update_account_flow")
            p("config.email.USE_EMAIL_SERVICE", new=True)
            p("config.openai_protocol.CHATGPT_ANON_BOOTSTRAP_ENABLED", new=False)
            p("config.openai_protocol.SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", new=False)
            result = main.run_registration(self.email, "Fixture User", "1990-01-01")
        baseline.assert_not_called()
        resend.assert_not_called()
        return result, [r[0] for r in reads], validate_mock.call_count

    def test_registration_uses_one_budget_across_empty_read_and_rejected_code(self):
        result, reads, validations = self.registration([self.response("012345"), self.response(), self.response("654321")], invalid_count=1)
        self.assertTrue(result["success"])
        self.assertEqual(reads, [135, 175, 205])
        self.assertEqual(validations, 2)

    def test_registration_three_invalid_submissions_stop_without_fourth_read(self):
        result, reads, validations = self.registration([self.response("012345")]*3, invalid_count=3)
        self.assertFalse(result["success"])
        self.assertEqual(reads, [135, 175, 215])
        self.assertEqual(validations, 3)
        self.assertIn("3轮上限", result["error"])

    def test_registration_three_empty_reads_do_not_become_nine(self):
        result, reads, validations = self.registration([self.response()]*3)
        self.assertFalse(result["success"])
        self.assertEqual(reads, [135, 165, 195])
        self.assertEqual(validations, 0)
        self.assertEqual(result["error"], "验证码未获取")


if __name__ == "__main__":
    unittest.main()
