import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from core import db, email_provider
from core import imap_mail_client as imap
from core.import_formats import parse_registered_accounts
from webui.app import create_app


def storage(root):
    return {
        "_ACCOUNTS_JSON": root / "accounts.json",
        "_OUTLOOK_JSON": root / "outlook.json",
        "_GENERIC_API_EMAIL_JSON": root / "generic.json",
        "_DOMAIN_EMAIL_JSON": root / "domain.json",
        "_JOBS_JSON": root / "jobs.json",
        "_LEGACY_ACCOUNTS_JSON": root / "legacy-accounts.json",
        "_LEGACY_OUTLOOK_JSON": root / "legacy-outlook.json",
        "_LEGACY_JOBS_JSON": root / "legacy-jobs.json",
        "_LEGACY_SQLITE": root / "legacy.db",
        "_CODEX_DIR": root / "codex",
        "_CODEX_AGENT_DIR": root / "codex-agent",
        "_LEGACY_CODEX_EXPORT_STATE": root / "state.json",
        "_SQLITE_READY": False,
        "_SQLITE_READY_PATH": None,
    }


class ImportedAccountTests(unittest.TestCase):
    def test_markdown_and_spreadsheet_formats(self):
        markdown = """| 邮箱 | 密码 | 2FA | access token |   |
| -- | -- | --- | ------------ | - |
| one@example.test | gpt-password | 2FA:JBSWY3DPEHPK3PXP | at-1 |   |
two@example.test\tgpt-password-2\tJBSWY3DPEHPK3PXP\tat-2
three@example.test,gpt-password-3,otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP,at-3
bad@example.test----pw----123456----at
"""
        rows, invalid = parse_registered_accounts(markdown)
        self.assertEqual(len(rows), 3)
        self.assertEqual(invalid, 1)
        self.assertEqual(rows[0]["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(rows[2]["totp_secret"], "JBSWY3DPEHPK3PXP")

    def test_account_api_stores_gpt_password_separately_and_skips_duplicates(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            text = "| 邮箱 | 密码 | 2FA | access token |\n| -- | -- | --- | --- |\n| one@example.test | gpt-pw | JBSWY3DPEHPK3PXP | at-value |"
            denied = client.post("/api/accounts/import", json={"text": text})
            self.assertEqual(denied.status_code, 401)
            response = client.post("/api/accounts/import", json={"text": text},
                                   headers={"X-Auth-Code": "test-auth"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["inserted"], 1)
            self.assertNotIn("gpt-pw", response.get_data(as_text=True))
            account = db.get_account_by_email("one@example.test")
            self.assertEqual(account["access_token"], "at-value")
            self.assertEqual(account["totp_secret"], "JBSWY3DPEHPK3PXP")
            self.assertEqual(json.loads(account["extra_json"])["registration_password"], "gpt-pw")
            self.assertFalse(account.get("password"))
            again = client.post("/api/accounts/import", json={"text": text},
                                headers={"X-Auth-Code": "test-auth"})
            self.assertEqual(again.get_json()["skipped"], 1)


class ForwardedImapTests(unittest.TestCase):
    def test_import_only_addresses_and_uses_shared_secret_at_runtime(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            body = {"source": "forwarded_imap", "text": "one@icloud.com\ntwo@icloud.com\nnot-an-email",
                    "forwarded_inbox": "shared@163.com", "imap_server": "imap.163.com",
                    "imap_port": 993, "imap_ssl": True}
            response = client.post("/api/outlook/import", json=body,
                                   headers={"X-Auth-Code": "test-auth"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["inserted"], 2)
            self.assertEqual(response.get_json()["invalid"], 1)
            row = db.get_imap_email_by_email("one@icloud.com")
            self.assertEqual(row["copy_line"], "one@icloud.com")
            self.assertEqual(row["imap_username"], "shared@163.com")
            self.assertTrue(row["imap_forwarded"])
            self.assertNotIn("imap_password", row)
            with patch.object(imap._email_cfg, "FORWARDED_IMAP_PASSWORD", "app-auth-code"):
                account = imap._account_from_row(row)
            self.assertEqual(account.email, "one@icloud.com")
            self.assertEqual(account.username, "shared@163.com")
            self.assertEqual(account.password, "app-auth-code")
            self.assertTrue(account.forwarded)
            self.assertEqual(db.imap_email_pool_summary()["available"], 2)
            mail = MagicMock()
            mail.select.return_value = ("OK", [])
            with patch.object(imap.imaplib, "IMAP4_SSL", return_value=mail):
                imap._connect(account)
            mail.login.assert_called_once_with("shared@163.com", "app-auth-code")
            with patch.object(imap._email_cfg, "FORWARDED_IMAP_PASSWORD", "app-auth-code"):
                self.assertEqual(email_provider.acquire_email_from_source("imap"), "one@icloud.com")
            self.assertEqual(db.imap_email_pool_summary()["available"], 1)

    def test_missing_shared_auth_code_does_not_consume_address(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            db.import_forwarded_imap_emails([{"email": "one@icloud.com"}], inbox="shared@163.com")
            with patch.object(imap._email_cfg, "FORWARDED_IMAP_PASSWORD", ""):
                with self.assertRaisesRegex(imap.ImapMailError, "FORWARDED_IMAP_PASSWORD"):
                    imap.pick_account()
            self.assertEqual(db.imap_email_pool_summary()["available"], 1)

    def test_forwarded_import_promotes_existing_pool_rows_to_registered_accounts(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            body = {
                "source": "forwarded_imap", "text": "one@icloud.com\ntwo@icloud.com",
                "forwarded_inbox": "shared@163.com", "imap_server": "imap.163.com",
                "as_registered": False,
            }
            headers = {"X-Auth-Code": "test-auth"}
            first = client.post("/api/outlook/import", json=body, headers=headers)
            self.assertEqual(first.status_code, 200)
            self.assertEqual(first.get_json()["inserted"], 2)

            body["as_registered"] = True
            promoted = client.post("/api/outlook/import", json=body, headers=headers)
            self.assertEqual(promoted.status_code, 200)
            self.assertEqual(promoted.get_json()["inserted"], 2)
            for address in ("one@icloud.com", "two@icloud.com"):
                row = db.get_imap_email_by_email(address)
                account = db.get_account_by_email(address)
                self.assertEqual(row["status"], "used")
                self.assertTrue(row["imap_forwarded"])
                self.assertEqual(row["registered_account_id"], account["id"])
                self.assertEqual(account["email_source"], "imap")
                self.assertFalse(account.get("access_token"))
                self.assertNotIn("imap_password", row)
            self.assertEqual(db.imap_email_pool_summary()["total"], 2)
            self.assertEqual(db.imap_email_pool_summary()["available"], 0)
            repeated = client.post("/api/outlook/import", json=body, headers=headers)
            self.assertEqual(repeated.get_json()["inserted"], 0)
            self.assertEqual(repeated.get_json()["skipped"], 2)

    def test_forwarded_import_can_create_pool_and_registered_account_together(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            response = client.post("/api/outlook/import", json={
                "source": "forwarded_imap", "text": "new@icloud.com",
                "forwarded_inbox": "shared@163.com", "imap_server": "imap.163.com",
                "imap_port": 993, "imap_ssl": True, "as_registered": True,
            }, headers={"X-Auth-Code": "test-auth"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["inserted"], 1)
            account = db.get_account_by_email("new@icloud.com")
            pool = db.get_imap_email_by_email("new@icloud.com")
            self.assertEqual(pool["registered_account_id"], account["id"])
            self.assertEqual(pool["copy_line"], "new@icloud.com")
            self.assertNotIn("imap_password", pool)

    def test_reimport_updates_shared_inbox_without_changing_registered_status(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            headers = {"X-Auth-Code": "test-auth"}
            body = {
                "source": "forwarded_imap", "text": "one@icloud.com",
                "forwarded_inbox": "shared@163.com", "imap_server": "imap.163.com",
                "imap_port": 993, "imap_ssl": True, "as_registered": True,
            }
            self.assertEqual(client.post("/api/outlook/import", json=body, headers=headers).get_json()["inserted"], 1)
            original = db.get_imap_email_by_email("one@icloud.com")
            with patch.object(imap._email_cfg, "FORWARDED_IMAP_PASSWORD", "app-auth-code"):
                self.assertEqual(imap.get_account_context("one@icloud.com").server, "imap.163.com")
            body.update(forwarded_inbox="shared@yeah.net", imap_server="imap.yeah.net", as_registered=False)
            corrected = client.post("/api/outlook/import", json=body, headers=headers)
            self.assertEqual(corrected.status_code, 200)
            self.assertEqual(corrected.get_json()["inserted"], 0)
            self.assertEqual(corrected.get_json()["updated"], 1)
            self.assertEqual(corrected.get_json()["skipped"], 0)
            row = db.get_imap_email_by_email("one@icloud.com")
            self.assertEqual(row["imap_username"], "shared@yeah.net")
            self.assertEqual(row["imap_server"], "imap.yeah.net")
            self.assertEqual(row["status"], "used")
            self.assertEqual(row["registered_account_id"], original["registered_account_id"])
            self.assertEqual(db.get_account_by_email("one@icloud.com")["email_source"], "imap")
            with patch.object(imap._email_cfg, "FORWARDED_IMAP_PASSWORD", "app-auth-code"):
                self.assertEqual(imap.get_account_context("one@icloud.com").server, "imap.yeah.net")
            same = client.post("/api/outlook/import", json=body, headers=headers).get_json()
            self.assertEqual((same["updated"], same["skipped"]), (0, 1))

    def test_recipient_matching_uses_original_address_not_shared_inbox(self):
        self.assertFalse(imap._matches_recipient({"to": "shared@163.com", "text": "To: other@icloud.com\nCode 111111"},
                                                 "one@icloud.com", forwarded=True))
        self.assertTrue(imap._matches_recipient({"to": "shared@163.com", "text": "From: OpenAI\nTo: One <one@icloud.com>\nCode 222222"},
                                                "one@icloud.com", forwarded=True))
        self.assertFalse(imap._matches_recipient({"to": "one@icloud.com.evil"},
                                                 "one@icloud.com", forwarded=True))

    def test_forwarded_otp_ignores_other_recipients_and_old_mail(self):
        account = imap.ImapEmailAccount("one@icloud.com", "auth", "imap.163.com", 993,
                                        username="shared@163.com", forwarded=True)
        now = time.time()
        current = datetime.fromtimestamp(now, timezone.utc).isoformat()
        old = datetime.fromtimestamp(now - 120, timezone.utc).isoformat()
        messages = [
            {"to": "shared@163.com", "from": "fwd@icloud.com", "subject": "Fwd: ChatGPT verification code",
             "text": "To: two@icloud.com\nYour code is 111111", "date": current},
            {"to": "shared@163.com", "from": "fwd@icloud.com", "subject": "Fwd: ChatGPT verification code",
             "text": "To: one@icloud.com\nYour code is 222222", "date": old},
            {"to": "shared@163.com", "from": "fwd@icloud.com", "subject": "Fwd: ChatGPT verification code",
             "text": "To: one@icloud.com\nYour code is 654321", "date": current},
        ]
        fake_mail = MagicMock()
        with patch.object(imap, "get_account_context", return_value=account), \
             patch.object(imap, "_connect", return_value=fake_mail), \
             patch.object(imap, "_search_messages", return_value=messages):
            self.assertEqual(imap.fetch_latest_otp("one@icloud.com", after_ts=now - 10,
                                                    max_wait=3, poll_interval=1, settle_seconds=0), "654321")


if __name__ == "__main__":
    unittest.main()
