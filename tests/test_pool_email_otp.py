import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class PoolEmailOtpTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)))
        state.start()
        self.addCleanup(state.stop)
        self.client = create_app(auth_code="fixture-auth").test_client()
        self.headers = {"X-Auth-Code": "fixture-auth", "Accept-Encoding": "identity"}
        self.email = "fixture@example.test"
        db.import_outlook_accounts([{"email": self.email, "password": "mail-password",
                                    "client_id": "fixture-client", "refresh_token": "fixture-refresh"}])
        db.import_imap_emails([{"email": self.email, "password": "imap-password", "server": "imap.example.test"}])
        db.import_generic_api_emails([{"email": self.email, "code_url": "https://mail.example.test/code"}])
        db.claim_next_domain_email(self.email)
        waiter = patch("core.email_provider.wait_for_otp", return_value="001234")
        self.wait = waiter.start()
        self.addCleanup(waiter.stop)

    def query(self, source="outlook", email=None, **kwargs):
        return self.client.get("/api/outlook/email-otp", query_string={
            "email": self.email if email is None else email, "source": source,
        }, headers=self.headers, **kwargs)

    def test_each_pool_source_is_passed_explicitly_without_creating_an_account(self):
        for source in ("outlook", "imap", "generic_api", "cloudflare_domain"):
            with self.subTest(source=source):
                self.wait.reset_mock()
                before = time.time()
                response = self.query(source)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), {"ok": True, "email": self.email, "source": source, "code": "001234"})
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.wait.assert_called_once()
                args, kwargs = self.wait.call_args
                self.assertEqual(args, (self.email,))
                self.assertEqual(kwargs["email_source"], source)
                self.assertTrue(kwargs["force_service"])
                self.assertEqual((kwargs["max_wait"], kwargs["poll_interval"], kwargs["settle_seconds"]), (2, 1, 0))
                self.assertGreaterEqual(kwargs["after_ts"], before - 900)
                self.assertLessEqual(kwargs["after_ts"], time.time() - 900)
                self.assertEqual(db.list_accounts_page()["total"], 0)

    def test_read_does_not_claim_or_change_mailbox_status(self):
        before = db.list_email_pool_page(source="all")["items"]
        self.assertEqual(self.query().status_code, 200)
        self.assertEqual(db.list_email_pool_page(source="all")["items"], before)

    def test_disabled_mailbox_can_still_read_its_mail(self):
        db.set_pool_registration_status(self.email, "outlook", "disabled")
        self.assertEqual(self.query().status_code, 200)
        self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")

    def test_lookup_does_not_fall_back_to_another_pool_source(self):
        db.delete_email_pool(self.email, source="imap")
        self.assertEqual(self.query("imap").status_code, 404)
        self.wait.assert_not_called()

    def test_invalid_source_empty_email_and_missing_mailbox_never_fetch_mail(self):
        for source in ("all", "", "unknown"):
            self.assertEqual(self.query(source).status_code, 400)
        self.assertEqual(self.query(email="").status_code, 400)
        self.assertEqual(self.query(email="missing@example.test").status_code, 404)
        self.wait.assert_not_called()

    def test_authentication_is_required(self):
        response = self.client.get("/api/outlook/email-otp", query_string={"email": self.email, "source": "outlook"})
        self.assertEqual(response.status_code, 401)
        self.wait.assert_not_called()

    def test_mail_client_errors_do_not_expose_credentials(self):
        self.wait.side_effect = RuntimeError("mail-password fixture-refresh shared-imap-authorization")
        with self.assertLogs("webui.app", level="WARNING"):
            response = self.query()
        self.assertEqual(response.status_code, 404)
        for secret in ("mail-password", "fixture-refresh", "shared-imap-authorization"):
            self.assertNotIn(secret, response.get_data(as_text=True))

    def test_imap_quota_is_reported_as_terminal_not_missing_mail(self):
        from core.imap_mail_client import ImapFetchLimitError
        self.wait.side_effect = ImapFetchLimitError("fetch_headers")
        with self.assertLogs("webui.app", level="WARNING"):
            response = self.query("imap")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error_code"], "imap_fetch_quota_exceeded")
        self.assertFalse(response.get_json()["retryable"])
        self.assertIn("取信流量额度", response.get_json()["error"])
        self.wait.assert_called_once()

    def test_unverified_freshness_has_an_explicit_terminal_reason(self):
        from core.otp_freshness import OtpFreshnessError
        self.wait.side_effect = OtpFreshnessError("missing_metadata")
        with self.assertLogs("webui.app", level="WARNING"):
            response = self.query("generic_api")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error_code"], "mail_otp_freshness_unverified")
        self.assertFalse(response.get_json()["retryable"])
        self.assertIn("缺少", response.get_json()["error"])
        self.assertNotIn("code", response.get_json())

    def test_account_imap_quota_is_reported_as_terminal(self):
        from core.imap_mail_client import ImapFetchLimitError
        aid = db.insert_account(email=self.email, email_source="imap", access_token="fixture")
        self.wait.side_effect = ImapFetchLimitError("fetch_headers")
        response = self.client.get(f"/api/accounts/{aid}/email-otp", headers=self.headers)
        self.assertEqual(response.status_code, 429)
        self.assertFalse(response.get_json()["retryable"])
        self.assertEqual(response.get_json()["error_code"], "imap_fetch_quota_exceeded")
        self.wait.assert_called_once()

    def test_missing_or_malformed_codes_are_not_returned_as_success(self):
        for code in (None, "", "12345", "1234567", "abcdef", "１２３４５６"):
            with self.subTest(code=code):
                self.wait.return_value = code
                self.assertEqual(self.query().status_code, 404)

    def test_pool_listing_keeps_mailbox_password_separate_from_gpt_account(self):
        db.insert_account(email=self.email, email_source="outlook", access_token="gpt-at")
        response = self.client.get("/api/outlook", query_string={"source": "outlook", "paged": 1}, headers=self.headers)
        self.assertEqual(response.get_json()["items"][0]["password"], "mail-password")
        self.assertEqual(self.query().status_code, 200)
        self.assertNotIn("mail-password", self.query().get_data(as_text=True))

    def test_forwarded_imap_queries_the_recipient_not_the_shared_inbox(self):
        recipient = "forwarded@icloud.com"
        db.import_forwarded_imap_emails([{"email": recipient}], inbox="receiver@example.test", server="imap.example.test")
        response = self.query("imap", recipient)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.wait.call_args.args, (recipient,))
        self.assertEqual(self.wait.call_args.kwargs["email_source"], "imap")
        self.assertNotIn("receiver@example.test", response.get_data(as_text=True))

    def test_both_templates_render_with_the_shared_mail_controls(self):
        for ui in ("modern", "legacy"):
            response = self.client.get("/", query_string={"ui": ui}, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            self.assertIn("function poolEmailPasswordCell(row)", html)
            self.assertIn("function poolEmailOtpCell(row)", html)
            self.assertIn("function queryPoolEmailOtp(email, source)", html)
            self.assertNotIn("{% include 'pool_mail_tools.html' %}", html)


if __name__ == "__main__":
    unittest.main()
