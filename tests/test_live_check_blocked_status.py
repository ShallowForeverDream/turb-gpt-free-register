import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import account_liveness as liveness, db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class LiveCheckBlockedStatusTests(unittest.TestCase):
    def test_preflight_denial_is_not_account_deactivation(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(liveness, "_LOG_DIR", Path(tmp)), \
             patch.object(liveness, "_stored_access_token", return_value=""), \
             patch.object(liveness, "_account_totp_secret", return_value=""), \
             patch.object(liveness, "_login_via_full_web_flow", side_effect=liveness.LoginPreflightBlockedError(403)), \
             patch.object(liveness, "wait_for_otp") as wait:
            result = liveness.check_account_liveness("test@example.test", proxy="")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["stage"], "login_preflight")
        self.assertEqual(result["error_code"], "http_403")
        self.assertIn("尚未发送邮箱验证码", result["error"])
        wait.assert_not_called()

    def test_status_poll_exposes_blocked_result_without_removing_saved_credentials(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))), \
             patch.object(db, "_now", return_value="2026-09-25T20:00:00"):
            db.import_registered_gpt_accounts([{
                "email": "test@example.test", "registration_password": "saved-password",
                "access_token": "saved-token", "totp_secret": "saved-secret",
            }])
            account_id = db.get_account_by_email("test@example.test")["id"]
            client = create_app(auth_code="test-auth").test_client()
            headers = {"X-Auth-Code": "test-auth", "Accept-Encoding": "identity"}
            before = client.get("/api/accounts/plan-check-status", headers=headers).get_json()
            result = {
                "ok": False, "status": "blocked", "stage": "login_preflight",
                "error_code": "http_403", "error": "登录入口拒绝访问，尚未发送邮箱验证码",
            }
            db.update_account_liveness(account_id, result)
            after = client.get("/api/accounts/plan-check-status", headers=headers).get_json()
            self.assertNotEqual(before["revision"], after["revision"])
            row = after["items"][0]
            self.assertEqual(row["live_check_status"], "blocked")
            self.assertEqual(row["live_check_stage"], "login_preflight")
            self.assertEqual(row["live_check_error_code"], "http_403")
            self.assertNotIn("access_token", row)
            saved = db.get_account(account_id)
            self.assertEqual(saved["access_token"], "saved-token")
            self.assertEqual(saved["totp_secret"], "saved-secret")
            self.assertTrue(db.claim_account_live_check(account_id))
            pending = db.get_account(account_id)
            self.assertIsNone(pending["live_check_error_code"])
            self.assertIsNone(pending["live_check_stage"])


if __name__ == "__main__":
    unittest.main()
