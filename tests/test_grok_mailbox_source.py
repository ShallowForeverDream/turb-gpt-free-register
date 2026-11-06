import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db, grok_mail, grok_store
from tests.test_forwarded_imap_and_account_import import storage


class GrokMailboxSourceTests(unittest.TestCase):
    def test_pool_item_mailbox_is_readable_by_grok_api(self):
        with tempfile.TemporaryDirectory() as root, patch.multiple(db, **storage(Path(root))):
            email = "fixture@icloud.com"
            db.import_generic_api_emails([{"email": email, "code_url": "https://icapi.oaibx.com/api?token=fixture"}])
            # A list view model uses source=generic_api, while the mailbox record
            # must preserve its own source after loading from the pool.
            item = db.list_email_pool_page(source="generic_api", limit=5)["items"][0]
            box = grok_store.mailbox(item["email"], "generic_api")
            self.assertEqual(box["source"], "generic_api")
            with patch("core.icapi_mailbox.latest_code", return_value="A1B-C2D"):
                self.assertEqual(grok_mail.read_once(box), "A1B-C2D")

    def test_grok_mailbox_does_not_claim_gpt_mailbox(self):
        with tempfile.TemporaryDirectory() as root, patch.multiple(db, **storage(Path(root))):
            email = "fixture@icloud.com"
            db.import_generic_api_emails([{"email": email, "code_url": "https://icapi.oaibx.com/api?token=fixture"}])
            box = grok_store.mailbox(email, "generic_api")
            self.assertEqual(box["source"], "generic_api")
            self.assertEqual(db.get_generic_api_email_by_email(email)["status"], "available")


if __name__ == "__main__":
    unittest.main()
