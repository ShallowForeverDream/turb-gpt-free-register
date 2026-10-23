# -*- coding: utf-8 -*-
import unittest
from unittest.mock import Mock, call, patch

from core import outlook_client


class OutlookClientContextTests(unittest.TestCase):
    def setUp(self):
        outlook_client._CONTEXT_CACHE.clear()

    @patch("core.db.get_account_by_email")
    @patch("core.db.get_outlook_by_email", return_value=None)
    def test_restores_context_from_registered_account_after_pool_missing(
        self,
        get_outlook_by_email,
        get_account_by_email,
    ):
        get_account_by_email.return_value = {
            "email": "Registered@outlook.test",
            "email_source": "outlook",
            "password": "mail-password",
            "client_id": "client-id",
            "refresh_token": "refresh-token",
            "recovery_email": "recovery@example.test",
            "recovery_code": "recovery-code",
        }

        account = outlook_client.get_account_context("  registered@OUTLOOK.test ")

        self.assertIsNotNone(account)
        self.assertEqual(account.email, "Registered@outlook.test")
        self.assertEqual(account.password, "mail-password")
        self.assertEqual(account.client_id, "client-id")
        self.assertEqual(account.refresh_token, "refresh-token")
        self.assertEqual(account.recovery_email, "recovery@example.test")
        self.assertEqual(account.recovery_code, "recovery-code")
        get_outlook_by_email.assert_called_once_with("  registered@OUTLOOK.test ")
        get_account_by_email.assert_called_once_with("  registered@OUTLOOK.test ")

    @patch("core.db.get_account_by_email")
    @patch("core.db.get_outlook_by_email")
    def test_registered_account_fills_incomplete_pool_context(
        self,
        get_outlook_by_email,
        get_account_by_email,
    ):
        get_outlook_by_email.return_value = {
            "email": "registered@outlook.test",
            "password": "pool-password",
            "client_id": "",
            "refresh_token": "pool-refresh",
        }
        get_account_by_email.return_value = {
            "email": "registered@outlook.test",
            "email_source": "outlook",
            "password": "saved-password",
            "client_id": "saved-client",
            "refresh_token": "saved-refresh",
        }

        account = outlook_client.get_account_context("registered@outlook.test")

        self.assertIsNotNone(account)
        self.assertEqual(account.password, "pool-password")
        self.assertEqual(account.client_id, "saved-client")
        self.assertEqual(account.refresh_token, "pool-refresh")

    @patch("core.db.get_account_by_email", return_value={
        "email": "registered@outlook.test",
        "email_source": "remail",
        "password": "saved-password",
        "client_id": "saved-client",
        "refresh_token": "saved-refresh",
    })
    @patch("core.db.get_outlook_by_email", return_value={
        "email": "registered@outlook.test",
        "password": "pool-password",
        "client_id": "pool-client",
        "refresh_token": "pool-refresh",
    })
    def test_non_outlook_registered_source_is_not_read_from_outlook_pool(
        self,
        get_outlook_by_email,
        get_account_by_email,
    ):
        self.assertIsNone(outlook_client.get_account_context("registered@outlook.test"))

    @patch("core.db.get_account_by_email", return_value=None)
    @patch("core.db.get_outlook_by_email", return_value={
        "email": "Pool@outlook.test",
        "password": "pool-password",
        "client_id": "pool-client",
        "refresh_token": "pool-refresh",
    })
    def test_context_cache_is_case_insensitive(self, get_outlook_by_email, get_account_by_email):
        first = outlook_client.get_account_context("pool@outlook.test")
        second = outlook_client.get_account_context(" POOL@OUTLOOK.TEST ")

        self.assertIs(first, second)
        get_outlook_by_email.assert_called_once_with("pool@outlook.test")
        get_account_by_email.assert_called_once_with("pool@outlook.test")


class OutlookJunkOtpTests(unittest.TestCase):
    def test_finds_otp_in_junk_when_inbox_is_empty(self):
        account = outlook_client.OutlookAccount("sample@outlook.test", "password", "client", "refresh")
        mail, http = Mock(), Mock()
        mail.select.return_value = ("OK", [b"0"])
        mail.search.side_effect = [("OK", [b""]), ("OK", [b"1"])]
        mail.fetch.return_value = ("OK", [(b"1 (RFC822)", b"From: noreply@tm.openai.com\r\nSubject: Your ChatGPT code\r\n\r\nYour verification code is 123456")])
        with patch.object(outlook_client, "_ms_http", return_value=http), \
             patch.object(outlook_client, "_live_imap_access_token", return_value="token"), \
             patch.object(outlook_client.imaplib, "IMAP4_SSL", return_value=mail):
            messages = outlook_client._fetch_imap_direct_messages(account)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["_mail_folder"], "Junk")
        self.assertEqual(outlook_client.extract_otp(messages[0]), "123456")
        mail.select.assert_has_calls([call("INBOX", readonly=True), call("Junk", readonly=True)])
        mail.logout.assert_called_once()
        http.close.assert_called_once()

    def test_missing_junk_folder_preserves_inbox_messages(self):
        account = outlook_client.OutlookAccount("sample@outlook.test", "password", "client", "refresh")
        mail = Mock()
        mail.select.side_effect = [("OK", [b"1"]), ("NO", [b"missing folder"])]
        mail.search.return_value = ("OK", [b"1"])
        mail.fetch.return_value = ("OK", [(b"1 (RFC822)", b"From: noreply@tm.openai.com\r\nSubject: ChatGPT\r\n\r\n123456")])
        with patch.object(outlook_client, "_ms_http"), \
             patch.object(outlook_client, "_live_imap_access_token", return_value="token"), \
             patch.object(outlook_client.imaplib, "IMAP4_SSL", return_value=mail):
            messages = outlook_client._fetch_imap_direct_messages(account)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["_mail_folder"], "INBOX")


if __name__ == "__main__":
    unittest.main()
