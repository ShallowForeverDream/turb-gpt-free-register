"""No network/mail: 2FA follows the page's one-time initial delivery contract."""
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import account_export as export, openai_auth
from tests.test_auth_page_initial_delivery import document


class TwofaInitialDeliveryTests(unittest.TestCase):
    email = "fixture@example.test"
    url = "https://auth.openai.com/email-verification?auth_page=private-fixture"

    def test_navigation_records_its_own_page_state_not_previous_registration(self):
        state = {"session_id": "new", "email": self.email, "passwordless_email_otp_send_pending": True}
        response = Mock(url=self.url, text=document(state))
        session = SimpleNamespace(get_auth_navigate_headers=Mock(return_value={}),
                                  get=Mock(return_value=response), _registration_initial_otp_attempted=True,
                                  _registration_otp_ready_at=10)
        with self.assertLogs(export.logger, "INFO") as logs:
            self.assertEqual(export._follow_reauth(session, "https://auth.openai.com/oauth/authorize"), self.url)
        self.assertEqual(session._registration_auth_page_state, state)
        self.assertFalse(session._registration_initial_otp_attempted)
        self.assertIsNone(session._registration_otp_ready_at)
        self.assertNotIn("private-fixture", "\n".join(logs.output))

    def test_no_pending_state_waits_from_ready_without_send_or_baseline(self):
        with patch.object(openai_auth, "initialize_passwordless_email_otp", return_value=False), \
             patch.object(openai_auth, "send_email_otp") as resend, \
             patch.object(export.time, "time", return_value=200):
            self.assertEqual(export._prepare_reauth_otp(object(), self.email, self.url, 100), (100, 200))
        resend.assert_not_called()

    def test_pending_state_uses_confirmed_initial_delivery_as_anchor(self):
        session = SimpleNamespace(_registration_otp_ready_at=230)
        with patch.object(openai_auth, "initialize_passwordless_email_otp", return_value=True) as initialize:
            self.assertEqual(export._prepare_reauth_otp(session, self.email, self.url, 100), (230, 230))
        initialize.assert_called_once_with(session, self.email, self.url)

    def test_non_verification_page_never_sends_or_waits(self):
        with patch.object(openai_auth, "initialize_passwordless_email_otp") as initialize:
            with self.assertRaisesRegex(RuntimeError, "未进入邮箱验证页"):
                export._prepare_reauth_otp(object(), self.email, "https://auth.openai.com/log-in/password", 100)
        initialize.assert_not_called()

    def run_setup(self, wait_result="012345", wait_error=None):
        from core import email_provider
        with ExitStack() as stack:
            p = lambda target, **kw: stack.enter_context(patch(target, **kw))
            session = SimpleNamespace()
            p("core.account_export._trigger_reauth_with_retry", return_value="https://auth.openai.com/oauth/authorize")
            p("core.account_export._follow_reauth_with_retry", return_value=self.url)
            p("core.account_export._prepare_reauth_otp", return_value=(100, 120))
            p("core.account_export.human_delay")
            p("config.email.USE_EMAIL_SERVICE", new=True)
            wait = p("core.email_provider.wait_for_otp", return_value=wait_result, side_effect=wait_error)
            resend = p("core.openai_auth.send_email_otp", side_effect=AssertionError("resend forbidden"))
            baseline = p("core.email_provider.prepare_otp_mail_baseline", side_effect=AssertionError("baseline forbidden"))
            validate = p("core.account_export._validate_reauth_otp_with_retry", return_value="https://chatgpt.com/callback")
            p("core.account_export._exchange_new_token", return_value="fixture")
            enroll = p("core.account_export._enroll_totp", return_value=("fixture-secret", "fixture"))
            p("core.account_export._activate_totp")
            p("core.account_export._refresh_activated_session")
            result = None
            try:
                result = export.setup_2fa(session, self.email)
            except Exception as exc:
                result = exc
        return result, wait, resend, baseline, validate, enroll

    def test_setup_forwards_ready_anchor_once_and_completes(self):
        result, wait, resend, baseline, validate, enroll = self.run_setup()
        self.assertEqual(result, "fixture-secret")
        wait.assert_called_once_with(self.email, after_ts=100, first_read_anchor_ts=120)
        resend.assert_not_called()
        baseline.assert_not_called()
        validate.assert_called_once()
        enroll.assert_called_once()

    def test_mail_timeout_stops_without_resend_or_another_poll_loop(self):
        from core.imap_mail_client import ImapOtpTimeout
        result, wait, resend, baseline, validate, enroll = self.run_setup(wait_error=ImapOtpTimeout("fixture"))
        self.assertIsInstance(result, ImapOtpTimeout)
        wait.assert_called_once()
        resend.assert_not_called()
        validate.assert_not_called()
        enroll.assert_not_called()

    def test_icapi_invalid_code_does_not_start_another_three_read_loop(self):
        from curl_cffi.requests.exceptions import HTTPError
        response = SimpleNamespace(status_code=401)
        error = HTTPError("invalid OTP", response=response)
        with patch.object(export, "_validate_reauth_otp", side_effect=error) as validate, \
             patch("config.email.USE_EMAIL_SERVICE", True), \
             patch("core.generic_api_mail_client.uses_direct_icapi_polling", return_value=True), \
             patch("core.email_provider.wait_for_otp") as wait:
            with self.assertRaises(HTTPError):
                export._validate_reauth_otp_with_retry(object(), self.email, "012345", 100)
        validate.assert_called_once()
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
