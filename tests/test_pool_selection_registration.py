import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


def _imap(email):
    return {
        "email": email, "imap_forwarded": True, "imap_username": "in@yeah.net",
        "imap_server": "imap.yeah.net", "imap_port": 993, "imap_ssl": True,
    }


class PoolSelectionRegistrationTests(unittest.TestCase):
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
