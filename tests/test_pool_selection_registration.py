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
    def test_incomplete_postprocessing_does_not_offer_codex_retry(self):
        with patch.object(registration_service, "_account_for_job", return_value={"id": 7, "live_check_status": "action_required"}):
            info = registration_service.get_retry_info({"id": 99, "status": "success", "account_id": 7})
        self.assertEqual(info["display_status"], "partial_success")
        self.assertFalse(info["retryable"])
        self.assertIsNone(info["retry_action"])

    def test_known_deactivation_overrides_success_in_job_display(self):
        with patch.object(registration_service, "_account_for_job", return_value={"id": 7, "live_check_status": "deactivated"}):
            info = registration_service.get_retry_info({"id": 99, "status": "success", "account_id": 7})
        self.assertEqual(info["display_status"], "disabled")
        self.assertFalse(info["retryable"])

    def test_worker_persists_partial_success_and_keeps_registered_mailbox(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            email = "fixture@outlook.com"
            db.import_outlook_accounts([{"email": email, "password": "mail", "client_id": "client", "refresh_token": "refresh"}])
            aid = db.insert_account(email=email, access_token="fixture", email_source="outlook")
            job = db.create_job("outlook", email)
            with patch.object(registration_service, "_prepare_registration_args", return_value=(email, "Test", "1990-01-01")), \
                 patch.object(main, "run_registration", return_value={"success": True, "status": "partial_success", "account_id": aid,
                                                                     "email": email, "error": "后处理待核验"}):
                registration_service._run_one_job(job["id"], str(Path(tmp) / "job.log"))
            self.assertEqual(db.get_job(job["id"])["status"], "partial_success")
            self.assertEqual(db.get_job(job["id"])["error_message"], "后处理待核验")
            self.assertIsNotNone(db.get_account(aid))
            self.assertIsNone(db.claim_pool_email(email, "outlook"))

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
        events = []
        with patch("core.registration_completion.finish_account", side_effect=lambda *a, **kw: events.append("finish") or {"status": "success"}) as finish, \
             patch.object(main, "close_browser_session", side_effect=lambda *a: events.append("close")), \
             patch("core.protocol_traffic.current_traffic"), \
             patch("core.db.update_account_flow"), \
             patch.object(main, "BrowserSession", return_value=session), \
             patch.object(main, "network_preflight"), \
             patch.object(main, "get_providers", return_value={}), \
             patch.object(main, "get_csrf_token", return_value="csrf"), \
             patch.object(main, "signin_openai", return_value="authorize"), \
             patch.object(main, "follow_authorize", return_value="https://auth.openai.com/email-verification"), \
             patch.object(main, "send_email_otp") as send, \
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
        finish.assert_called_once()
        self.assertIs(finish.call_args.kwargs["session"], session)
        self.assertEqual(events, ["finish", "close"])
        send.assert_not_called()

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
