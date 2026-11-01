import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from core import db
from core.chatgpt_plan import parse_accounts_check
from webui.app import _compact_account_for_list
from tests.test_forwarded_imap_and_account_import import storage


class PlanPromoDetailsTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(patch.multiple(db, **storage(root)))

    def parse(self, campaigns, plan="free"):
        return parse_accounts_check({"accounts": {"default": {
            "account": {"plan_type": plan},
            "eligible_promo_campaigns": campaigns,
        }}})

    def test_all_campaigns_preserved_without_changing_plus_logic(self):
        campaigns = {
            "plus": {"id": "plus-1-month-free", "metadata": {
                "discount": {"percentage": 100},
                "duration": {"num_periods": 1, "period": "month"},
                "no_auto_renewal_at_discount_end": False,
            }},
            "go": {"id": "go-discount", "metadata": {"custom_field": "保留未知字段"}},
        }
        result = self.parse(campaigns)
        self.assertTrue(result["plus_trial_eligible"])
        self.assertEqual(result["eligible_promo_campaigns"], campaigns)
        self.assertEqual(result["plus_trial_discount_percentage"], 100)
        other = self.parse({"go": campaigns["go"]})
        self.assertFalse(other["plus_trial_eligible"])
        self.assertIn("go", other["eligible_promo_campaigns"])
        self.assertEqual(self.parse(campaigns, "plus")["eligible_promo_campaigns"], {})
        self.assertEqual(self.parse({})["eligible_promo_campaigns"], {})

    def test_persistence_list_polling_and_failure_preservation(self):
        account_id = db.insert_account(email="test@example.test", access_token="fixture")
        result = self.parse({"go": {"id": "go-offer"}})
        self.assertTrue(db.update_account_plan_check(acc_id=account_id, result=result))
        row = db.get_account(account_id)
        self.assertEqual(row["eligible_promo_campaigns"], result["eligible_promo_campaigns"])
        self.assertEqual(_compact_account_for_list(row)["eligible_promo_campaigns"], result["eligible_promo_campaigns"])
        snapshot = db.list_account_plan_check_statuses()
        self.assertEqual(snapshot["items"][0]["eligible_promo_campaigns"], result["eligible_promo_campaigns"])
        changed = self.parse({"go": {"id": "changed"}})
        db.update_account_plan_check(acc_id=account_id, result=changed)
        self.assertNotEqual(snapshot["revision"], db.list_account_plan_check_statuses()["revision"])
        db.update_account_plan_check(acc_id=account_id, result={"ok": False, "error": "timeout"})
        self.assertEqual(db.get_account(account_id)["eligible_promo_campaigns"], changed["eligible_promo_campaigns"])
        db.update_account_plan_check(acc_id=account_id, result=self.parse({}))
        self.assertEqual(db.get_account(account_id)["eligible_promo_campaigns"], {})


if __name__ == "__main__":
    unittest.main()
