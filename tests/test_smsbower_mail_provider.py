# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from config import email as email_config
from core import email_provider


class SmsBowerMailProviderTests(unittest.TestCase):
    def test_parse_sources_keeps_smsbower_mail(self):
        self.assertEqual(
            email_provider.parse_email_sources("outlook,smsbower_mail,remail,smsbower_mail"),
            ["outlook", "smsbower_mail", "remail"],
        )

    @patch("core.smsbower_mail_client.pick_account")
    def test_acquire_email_uses_smsbower_mail_client(self, pick_account):
        pick_account.return_value.email = "fresh@gmail.test"
        with patch("core.email_provider.parse_email_sources", return_value=["smsbower_mail"]):
            self.assertEqual(email_provider.acquire_email(), "fresh@gmail.test")

    @patch("core.smsbower_mail_client.fetch_latest_otp", return_value="123456")
    @patch("core.email_provider.resolve_email_source", return_value="smsbower_mail")
    def test_wait_for_otp_uses_smsbower_mail_client(self, resolve, fetch_latest_otp):
        with patch.object(email_config, "USE_EMAIL_SERVICE", True):
            self.assertEqual(email_provider.wait_for_otp("fresh@gmail.test", after_ts=123.0), "123456")
        fetch_latest_otp.assert_called_once_with("fresh@gmail.test", after_ts=123.0)

    @patch("core.smsbower_mail_client.release_account")
    @patch("core.email_provider.resolve_email_source", return_value="smsbower_mail")
    def test_release_email_uses_smsbower_mail_client(self, resolve, release_account):
        self.assertEqual(
            email_provider.release_email("fresh@gmail.test", status="failed"),
            "smsbower_mail",
        )
        release_account.assert_called_once_with("fresh@gmail.test", status="failed", note=None)


if __name__ == "__main__":
    unittest.main()
