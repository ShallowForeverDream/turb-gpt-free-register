import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class AccountGroupFilterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state = patch.multiple(db, **storage(Path(tmp.name)))
        state.start()
        self.addCleanup(state.stop)
        self.ids = {}
        for email, group in (("sold1@icloud.com", "已卖"), ("sold2@outlook.com", "已卖"),
                             ("free@icloud.com", ""), ("other@icloud.com", "备用")):
            aid = db.insert_account(email=email, access_token="fixture")
            db.update_account_group(aid, group)
            self.ids[email] = aid
        self.client = create_app(auth_code="fixture").test_client()
        self.headers = {"X-Auth-Code": "fixture", "Accept-Encoding": "identity"}

    def query(self, **kwargs):
        return self.client.get("/api/accounts", query_string={"paged": 1, **kwargs}, headers=self.headers).get_json()

    def test_named_group_all_and_ungrouped(self):
        self.assertEqual(self.query()["total"], 4)
        self.assertEqual(self.query(group="已卖")["total"], 2)
        self.assertEqual(self.query(group="__ungrouped__")["items"][0]["id"], self.ids["free@icloud.com"])
        self.assertEqual(self.query(group="不存在")["total"], 0)

    def test_search_suffix_and_group_combine(self):
        rows = self.query(group="已卖", email_suffix="icloud.com", q="sold")
        self.assertEqual([row["id"] for row in rows["items"]], [self.ids["sold1@icloud.com"]])
        self.assertEqual(rows["total"], 1)

    def test_group_pagination_and_status_poll_use_same_scope(self):
        page = self.query(group="已卖", page=2, page_size=1)
        status = self.client.get("/api/accounts/plan-check-status", query_string={
            "group": "已卖", "page": 2, "page_size": 1}, headers=self.headers).get_json()
        self.assertEqual(page["total"], 2)
        self.assertEqual(status["total"], page["total"])
        self.assertEqual([r["id"] for r in page["items"]], [r["id"] for r in status["items"]])

    def test_group_does_not_make_archived_or_deactivated_accounts_visible(self):
        db.archive_accounts([self.ids["sold1@icloud.com"]])
        self.assertEqual(self.query(group="已卖")["total"], 1)
        db.update_account_liveness(self.ids["sold2@outlook.com"], {
            "ok": False, "status": "deactivated", "error_code": "account_deactivated"})
        self.assertEqual(self.query(group="已卖")["total"], 0)

    def test_both_templates_have_labelled_filter_and_shared_loader(self):
        for mode, element_id in (("modern", "accountGroupFilterV2"), ("legacy", "accountGroupFilter")):
            html = self.client.get("/", query_string={"ui": mode}, headers=self.headers).get_data(as_text=True)
            self.assertTrue('data-account-filter="group"' in html, mode)
            self.assertTrue('aria-label="分组筛选"' in html, mode)
            self.assertTrue("function getAccountColumnFiltersQuery()" in html, mode)

    def test_group_list_is_authenticated(self):
        self.assertEqual(self.client.get("/api/accounts/groups").status_code, 401)
        groups = self.client.get("/api/accounts/groups", headers=self.headers).get_json()["groups"]
        self.assertEqual(set(groups), {"已卖", "备用"})


if __name__ == "__main__":
    unittest.main()
