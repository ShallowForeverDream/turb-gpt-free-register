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

    def test_manual_disabled_filter_matches_display_with_existing_account(self):
        db.set_pool_registration_status(self.email, "outlook", "disabled")
        self.assertEqual(db.get_outlook_by_email(self.email)["registration_status"], "disabled")
        self.assertEqual(db.list_email_pool_page(source="outlook", registration_status="disabled")["total"], 1)

    def test_codex_deactivation_uses_same_terminal_state(self):
        db.update_account_codex_status(self.email, "deactivated", "account_deactivated")
        self.assertTrue(db.get_account(self.aid)["archived"])
        self.assertEqual(db.get_outlook_by_email(self.email)["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
