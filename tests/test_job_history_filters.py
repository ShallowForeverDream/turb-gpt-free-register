import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from core import db
from webui.app import create_app
from tests.test_forwarded_imap_and_account_import import storage


class JobHistoryFilterTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)))
        state.start()
        self.addCleanup(state.stop)
        db._ensure_sqlite()
        db._save_jobs([{"id": i, "email": f"fixture{i}@example.test", "status": "failed" if i%2 else "success",
                        "email_source": "generic_api", "created_at": "2026-10-01T10:00:00" if i<5 else "2026-10-30T10:00:00",
                        "started_at": "2026-10-30T10:00:00", "completed_at": "2026-10-30T10:01:00",
                        "error_message": "curl: (35) SSL_connect" if i%2 else None}
                       for i in range(1, 9)])
        self.client = create_app(auth_code="fixture").test_client()
        self.headers = {"X-Auth-Code": "fixture", "Accept-Encoding": "identity"}

    def test_status_and_dates_filter_before_count_and_pagination(self):
        with patch.object(db, "_load_jobs", side_effect=AssertionError("no full job scan")):
            result = self.client.get("/api/jobs?paged=1&page_size=1&status=failed&date_from=2026-10-30&date_to=2026-10-30", headers=self.headers).get_json()
            self.assertEqual(result["total"], 2)
            self.assertEqual(result["items"][0]["id"], 7)
            self.assertEqual(result["items"][0]["display_status"], "network_error")
            second = self.client.get("/api/jobs?paged=1&page_size=1&page=2&status=failed&date_from=2026-10-30", headers=self.headers).get_json()
            self.assertEqual(second["items"][0]["id"], 5)

    def test_query_matches_email_or_exact_id_and_percent_is_literal(self):
        self.assertEqual(db.list_jobs_page(filters={"q": "FIXTURE2@"})["total"], 1)
        self.assertEqual(db.list_jobs_page(filters={"q": "#3"})["items"][0]["id"], 3)
        self.assertEqual(db.list_jobs_page(filters={"q": "%"})["total"], 0)
        self.assertEqual(db.list_jobs_page(filters={"q": "' OR 1=1 --"})["total"], 0)
        self.assertEqual(db.list_jobs_page(filters={"source": "imap"})["total"], 0)

    def test_bad_filters_are_400_and_empty_filters_keep_old_contract(self):
        for query in ("status=network_fake", "date_from=not-a-date", "date_from=2026-10-31&date_to=2026-10-01"):
            self.assertEqual(self.client.get("/api/jobs?paged=1&"+query, headers=self.headers).status_code, 400)
        self.assertEqual(self.client.get("/api/jobs?paged=1", headers=self.headers).get_json()["total"], 8)

    def test_progress_only_statuses_and_old_failure_not_completed_by_later_account(self):
        db._save_accounts([{"id": 1, "email": "fixture1@example.test", "access_token": "private-token",
                            "totp_secret": "private-secret", "created_at": "2026-10-30T11:00:00",
                            "totp_setup_status": "success", "codex_status": "skipped"}])
        with patch("core.registration_service.read_job_log", return_value="fixture"):
            old = self.client.get("/api/jobs/1/log", headers=self.headers).get_json()
            self.assertEqual(old["progress"], {})
            db.update_job(2, account_id=1)
            current = self.client.get("/api/jobs/2/log", headers=self.headers).get_json()
        self.assertEqual(current["progress"], {"registration": "success", "twofa": "success", "codex": "skipped", "plan": "unknown"})
        self.assertNotIn("private-", json.dumps(current))


if __name__ == "__main__":
    unittest.main()
