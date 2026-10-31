import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class PoolFilterPerformanceTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)))
        state.start()
        self.addCleanup(state.stop)
        db.import_imap_emails([{"email": email, "password": "fixture", "server": "imap.example.test"}
                               for email in ("alpha@icloud.com", "beta@icloud.com", "other@example.test")])
        db.import_outlook_accounts([{"email": "alpha@outlook.com", "password": "fixture"}])
        db.insert_account(email="beta@icloud.com", email_source="imap", access_token="fixture")

    def test_icloud_query_and_registration_status_filters_combine(self):
        result = db.list_email_pool_page(source="icloud", registration_status="unregistered", q="alpha")
        self.assertEqual([row["email"] for row in result["items"]], ["alpha@icloud.com"])
        self.assertEqual(result["items"][0]["source"], "imap")
        self.assertEqual(db.list_email_pool_page(source="icloud", registration_status="registered")["total"], 1)
        db.set_pool_registration_status("alpha@icloud.com", "imap", "disabled")
        self.assertEqual(db.list_email_pool_page(source="icloud", registration_status="unregistered")["total"], 0)
        self.assertEqual(db.list_email_pool_page(source="icloud", registration_status="disabled")["total"], 1)

    def test_page_reads_do_not_wait_on_the_business_writer_lock(self):
        done = threading.Event()
        def read():
            try:
                db.list_email_pool_page(source="icloud", registration_status="unregistered")
            finally:
                done.set()
        with db._LOCK:
            thread = threading.Thread(target=read)
            thread.start()
            completed = done.wait(2)
        thread.join(3)
        self.assertTrue(completed)

    def test_api_accepts_virtual_icloud_source_and_returns_real_row_source(self):
        client = create_app(auth_code="fixture").test_client()
        response = client.get("/api/outlook", headers={"X-Auth-Code": "fixture"},
                              query_string={"source": "icloud", "status": "unregistered", "q": "alpha", "paged": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["total"], 1)
        self.assertEqual(response.get_json()["items"][0]["source"], "imap")
