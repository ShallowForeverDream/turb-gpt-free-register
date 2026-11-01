import unittest
from unittest.mock import Mock, patch

from core import account_export, account_liveness, imap_mail_client as imap
from tests.test_imap_bounded_reads import Mailbox, message, TARGET, SHARED


class ImapQuotaTests(unittest.TestCase):
    def tearDown(self):
        imap.close_shared_imap_connections()

    def test_fetch_limit_is_terminal_and_contains_no_server_supplied_secrets(self):
        with self.assertRaises(imap.ImapFetchLimitError) as caught:
            imap._check_status("NO", [b"FETCH Fetch volume limit exceed private-password"], stage="fetch_headers")
        error = caught.exception
        self.assertFalse(error.retryable)
        self.assertEqual(error.stage, "fetch_headers")
        self.assertEqual(error.error_code, "imap_fetch_quota_exceeded")
        self.assertNotIn("private-password", str(error))

    def test_quota_stops_without_reconnecting_or_sleeping(self):
        account = imap.ImapEmailAccount(TARGET, "fixture", "imap.example.test")
        mail = Mock()
        with patch.object(imap, "get_account_context", return_value=account), \
             patch.object(imap, "_connect", return_value=mail) as connect, \
             patch.object(imap, "_search_messages", side_effect=imap.ImapFetchLimitError("fetch_headers")) as search, \
             patch.object(imap.time, "sleep") as sleep, \
             self.assertLogs(imap.logger, level="WARNING") as logs:
            with self.assertRaises(imap.ImapFetchLimitError):
                imap.fetch_latest_otp(TARGET, max_wait=300)
        connect.assert_called_once()
        search.assert_called_once()
        sleep.assert_not_called()
        mail.shutdown.assert_called_once()
        self.assertIn("imap_fetch_quota_exceeded", " ".join(logs.output))
        self.assertIn("fetch_headers", " ".join(logs.output))

    def test_text_fetch_limit_uses_same_terminal_error(self):
        from datetime import datetime, timedelta, timezone
        mail = Mailbox({b"1": message(to=SHARED)})
        original = mail.uid

        def uid(command, *args):
            if command == "FETCH" and "TEXT" in args[1]:
                return "NO", [b"FETCH Fetch volume limit exceed"]
            return original(command, *args)

        mail.uid = uid
        account = imap.ImapEmailAccount(TARGET, "fixture", "imap.example.test", username=SHARED, forwarded=True)
        with self.assertRaises(imap.ImapFetchLimitError) as caught:
            imap._search_messages(mail, datetime.now(timezone.utc) - timedelta(seconds=30),
                                  account=account, state=imap._SearchState())
        self.assertEqual(caught.exception.stage, "fetch_text")

    def test_other_server_errors_include_stage_without_echoing_response(self):
        with self.assertRaises(imap.ImapMailError) as caught:
            imap._check_status("NO", [b"private-password"], stage="uid_search")
        self.assertEqual(caught.exception.stage, "uid_search")
        self.assertNotIn("private-password", str(caught.exception))

    def test_twofa_does_not_resend_after_terminal_mail_refusal(self):
        quota = imap.ImapFetchLimitError("fetch_headers")
        with patch.object(account_export, "_trigger_reauth_with_retry", return_value="https://example.test/auth") as trigger, \
             patch.object(account_export, "_follow_reauth_with_retry", return_value="https://auth.openai.com/email-verification"), \
             patch.object(account_export, "human_delay"), \
             patch("config.email.USE_EMAIL_SERVICE", True), \
             patch("core.openai_auth.send_email_otp") as send, \
             patch("core.email_provider.wait_for_otp", side_effect=quota) as wait, \
             patch.object(account_export, "_enroll_totp") as enroll:
            with self.assertRaises(imap.ImapFetchLimitError):
                account_export.setup_2fa(Mock(), TARGET)
        trigger.assert_called_once()
        send.assert_not_called()  # Page delivery only; no resend on quota.
        wait.assert_called_once()
        enroll.assert_not_called()

    def test_live_check_does_not_treat_terminal_mail_refusal_as_network_retry(self):
        with patch.object(account_liveness, "wait_for_otp", side_effect=imap.ImapFetchLimitError("fetch_headers")) as wait, \
             patch.object(account_liveness, "send_email_otp") as send, \
             patch.object(account_liveness, "_is_retryable_network_error", return_value=True):
            with self.assertRaises(imap.ImapFetchLimitError):
                account_liveness._validate_with_retry(Mock(), TARGET, 100)
        wait.assert_called_once()
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
