import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage


class DeactivatedAccountVisibilityTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)))
        state.start()
        self.addCleanup(state.stop)
        self.email = "fixture@outlook.com"
        db.import_outlook_accounts([{"email": self.email, "password": "mail-password",
                                    "client_id": "client", "refresh_token": "refresh"}])
        self.aid = db.insert_account(email=self.email, access_token="fixture-at", email_source="outlook")

    def test_deactivation_archives_account_and_disables_pool(self):
        db.update_account_liveness(self.aid, {"ok": False, "status": "deactivated", "error": "account_deactivated"})
        self.assertTrue(db.get_account(self.aid)["archived"])
        self.assertEqual(db.list_accounts_page()["total"], 0)
        self.assertEqual(db.list_accounts_page(archived="only")["total"], 1)
        self.assertEqual(db.list_account_plan_check_statuses()["total"], 0)
        disabled = db.list_email_pool_page(source="outlook", registration_status="disabled")
        self.assertEqual(disabled["total"], 1)
        self.assertEqual(disabled["items"][0]["registration_status"], "disabled")
        self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")
        self.assertEqual(db.list_email_pool_page(source="outlook", registration_status="registered")["total"], 0)
        self.assertIsNone(db.claim_pool_email(self.email, "outlook"))

    def test_network_failure_never_archives_or_disables(self):
        db.update_account_liveness(self.aid, {"ok": False, "status": "failed", "error": "HTTP 503"})
        self.assertFalse(db.get_account(self.aid).get("archived", False))
        self.assertNotEqual(db.get_outlook_by_email(self.email)["status"], "disabled")
        self.assertEqual(db.list_email_pool_page(source="outlook", registration_status="registered")["total"], 1)

    def test_revoked_token_or_network_failure_cannot_downgrade_deactivation(self):
        db.update_account_liveness(self.aid, {
            "ok": False, "status": "deactivated", "error": "account_deactivated",
            "error_code": "account_deactivated", "stage": "twofa_reauth",
        })
        for weaker in ({"status": "action_required", "error_code": "token_revoked"},
                       {"status": "failed", "error": "TLS timeout"}):
            db.update_account_liveness(self.aid, {"ok": False, **weaker})
            row = db.get_account(self.aid)
            self.assertEqual(row["live_check_status"], "deactivated")
            self.assertEqual(row["live_check_error_code"], "account_deactivated")
            self.assertEqual(row["live_check_stage"], "twofa_reauth")
            self.assertTrue(row["archived"])
            self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")

    def test_manual_disabled_filter_matches_display_with_existing_account(self):
        db.set_pool_registration_status(self.email, "outlook", "disabled")
        self.assertEqual(db.get_outlook_by_email(self.email)["registration_status"], "disabled")
        self.assertEqual(db.list_email_pool_page(source="outlook", registration_status="disabled")["total"], 1)

    def test_codex_deactivation_uses_same_terminal_state(self):
        db.update_account_codex_status(self.email, "deactivated", "account_deactivated")
        self.assertTrue(db.get_account(self.aid)["archived"])
        self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")

    def test_backfill_legacy_twofa_server_code_archives_and_disables(self):
        rows = db._load_accounts()
        rows[0]["totp_setup_status"] = "blocked"
        rows[0]["totp_setup_error"] = (
            "TwofaOtpBlockedError: 邮箱 OTP 提交被拒绝（HTTP 403，服务端代码 account_deactivated）；"
            "尚未进入 TOTP 注册阶段，账号 2FA 状态未改变。"
        )
        db._save_accounts(rows)

        self.assertEqual(db.sync_deactivated_accounts(), 1)
        account = db.get_account(self.aid)
        self.assertTrue(account["archived"])
        self.assertEqual(account["live_check_status"], "deactivated")
        self.assertEqual(account["live_check_error_code"], "account_deactivated")
        self.assertEqual(account["access_token"], "fixture-at")
        self.assertEqual(db.list_accounts_page()["total"], 0)
        self.assertEqual(db.list_account_plan_check_statuses()["total"], 0)
        self.assertEqual(db.list_accounts_page(archived="only")["total"], 1)
        self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")
        self.assertEqual(db.sync_deactivated_accounts(), 0)

    def test_backfill_structured_twofa_deactivation_codes(self):
        for code in ("account_deactivated", "account_deleted", "account_banned"):
            with self.subTest(code=code):
                rows = db._load_accounts()
                rows[0].update(archived=False, live_check_status="failed",
                               live_check_error_code=None, totp_setup_error_code=code)
                db._save_accounts(rows)
                self.assertEqual(db.sync_deactivated_accounts(), 1)
                self.assertEqual(db.get_account(self.aid)["live_check_error_code"], code)

    def test_backfill_never_uses_notes_or_generic_auth_errors(self):
        for error in ("HTTP Error 403", "token_revoked", "TLS timeout"):
            with self.subTest(error=error):
                rows = db._load_accounts()
                rows[0].update(totp_setup_status="blocked", totp_setup_error=error,
                               totp_setup_error_code="token_revoked",
                               note="服务端代码 account_deactivated）")
                db._save_accounts(rows)
                self.assertEqual(db.sync_deactivated_accounts(), 0)
                self.assertEqual(db.list_accounts_page()["total"], 1)
                self.assertNotEqual(db.get_outlook_by_email(self.email)["status"], "disabled")

    def test_confirmed_deactivation_cannot_reappear_after_unarchive(self):
        healthy_id = db.insert_account(email="healthy@example.test", access_token="healthy-at")
        rows = db._load_accounts()
        for row in rows:
            if row["id"] == self.aid:
                row["live_check_status"] = "deactivated"
        db._save_accounts(rows)
        db.archive_account(self.aid, archived=False)
        for read in (db.list_accounts_page, db.list_account_plan_check_statuses):
            result = read(limit=1)
            self.assertEqual(result["total"], 1)
            self.assertEqual([r["id"] for r in result["items"]], [healthy_id])
        self.assertEqual(len(db.list_accounts()), 1)
        self.assertEqual(db.list_accounts_page(archived="all")["total"], 2)

    def test_api_list_and_poll_both_exclude_stale_deactivated_rows(self):
        from webui.app import create_app

        client = create_app(auth_code="test-auth").test_client()
        rows = db._load_accounts()
        rows[0].update(codex_status="deactivated", archived=False)
        db._save_accounts(rows)
        headers = {"X-Auth-Code": "test-auth"}
        for path in ("/api/accounts?paged=1", "/api/accounts/plan-check-status"):
            response = client.get(path, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["total"], 0)
            self.assertEqual(response.get_json()["items"], [])


if __name__ == "__main__":
    unittest.main()
