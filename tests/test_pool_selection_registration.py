import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app
from core import registration_service
import main


def _imap(email):
    return {
        "email": email, "imap_forwarded": True, "imap_username": "in@yeah.net",
        "imap_server": "imap.yeah.net", "imap_port": 993, "imap_ssl": True,
    }


class PoolSelectionRegistrationTests(unittest.TestCase):
    def test_blocked_registration_job_is_retryable(self):
        with patch.object(db, "get_successful_retry_for_job", return_value=None), \
             patch.object(db, "get_account", return_value=None), \
             patch.object(db, "get_account_by_email", return_value=None):
            info = registration_service.get_retry_info({"id": 99, "status": "blocked", "email": "x@icloud.com"})
        self.assertTrue(info["retryable"])
        self.assertEqual(info["retry_action"], "registration")

    def test_registration_workspace_response_is_reported_as_existing_account(self):
        session = SimpleNamespace(proxy="proxy", device_id="device", auth_session_logging_id="auth", sentinel_sid="sid", browser_profile={})
        validate = {
            "continue_url": "https://auth.openai.com/workspace",
            "page": {"type": "workspace"},
            "oai-client-auth-session": {"workspaces": []},
        }
        with patch.object(main, "BrowserSession", return_value=session), \
             patch.object(main, "network_preflight"), \
             patch.object(main, "get_providers", return_value={}), \
             patch.object(main, "get_csrf_token", return_value="csrf"), \
             patch.object(main, "signin_openai", return_value="authorize"), \
             patch.object(main, "follow_authorize", return_value="https://auth.openai.com/email-verification"), \
             patch.object(main, "wait_for_otp", return_value="123456"), \
             patch.object(main, "validate_email_otp", return_value=validate), \
             patch.object(main, "human_delay"), \
             patch.object(main, "save_account_data", return_value=7), \
             patch("core.account_liveness._select_workspace_and_fetch", return_value={"accessToken": "fresh-at", "user": {}, "account": {}}):
            with patch.object(main._email_cfg, "USE_EMAIL_SERVICE", True), \
                 patch.object(main._roxy_cfg, "REGISTRATION_DRIVER", "protocol"), \
                 patch.object(main._protocol_cfg, "CHATGPT_ANON_BOOTSTRAP_ENABLED", False), \
                 patch.object(main._protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False):
                result = main.run_registration("existing@icloud.com", "Test User", "1990-01-01")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "already_registered")
        self.assertTrue(result["existing_account"])

    def test_selected_pool_email_can_be_imported_as_registered_account(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            db.import_forwarded_imap_emails([_imap("chosen@icloud.com")], inbox="in@yeah.net", server="imap.yeah.net", port=993, use_ssl=True)
            imported, skipped = db.import_pool_emails_as_registered([{"email": "chosen@icloud.com", "source": "imap"}])
            self.assertEqual([x["email"] for x in imported], ["chosen@icloud.com"])
            self.assertEqual(skipped, [])
            self.assertEqual(db.get_account_by_email("chosen@icloud.com")["email_source"], "imap")
            self.assertIsNone(db.claim_next_imap_email())

    def test_auto_claim_skips_account_page_email(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            db.import_forwarded_imap_emails([_imap("chosen@icloud.com"), _imap("next@icloud.com")], inbox="in@yeah.net", server="imap.yeah.net", port=993, use_ssl=True)
            db.import_pool_emails_as_registered([{"email": "chosen@icloud.com", "source": "imap"}])
            claimed = db.claim_next_imap_email()
            self.assertEqual(claimed["email"], "next@icloud.com")

    def test_webui_pool_import_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            db.import_forwarded_imap_emails([_imap("chosen@icloud.com")], inbox="in@yeah.net", server="imap.yeah.net", port=993, use_ssl=True)
            client = create_app(local_no_auth=True).test_client()
            response = client.post("/api/accounts/import-pool", json={"items": [{"email": "chosen@icloud.com", "source": "imap"}]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["imported_count"], 1)


if __name__ == "__main__":
    unittest.main()
