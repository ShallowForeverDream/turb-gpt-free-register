import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import requests

from core import db, generic_api_mail_client as mail
from core.import_formats import normalize_generic_api_url
from tests.test_forwarded_imap_and_account_import import storage


class GenericApiUrlCompatibilityTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        state = patch.multiple(db, **storage(self.root))
        state.start()
        self.addCleanup(state.stop)
        cache = patch.dict(mail._CONTEXT_CACHE, clear=True)
        cache.start()
        self.addCleanup(cache.stop)
        self.email = "fixture@example.test"
        self.raw_url = "mail.example.test/api/mail/getCodeBySignature?s=a%2fb%2B+c==&x=1&x=2&empty="
        self.url = "https://" + self.raw_url

    def test_missing_scheme_defaults_to_https_without_rewriting_signature(self):
        self.assertEqual(normalize_generic_api_url(self.raw_url), self.url)
        self.assertEqual(normalize_generic_api_url("  " + self.raw_url + "  "), self.url)
        self.assertEqual(normalize_generic_api_url("//" + self.raw_url), self.url)

    def test_explicit_schemes_ports_and_legacy_dash_fix(self):
        for url in (self.url, "http://" + self.raw_url, "https://localhost:8443/code?s=fixture"):
            with self.subTest(url=url):
                self.assertEqual(normalize_generic_api_url(url), url)
        self.assertEqual(normalize_generic_api_url("---" + self.url), self.url)
        self.assertEqual(normalize_generic_api_url("localhost:8443/code"), "https://localhost:8443/code")
        self.assertEqual(normalize_generic_api_url("127.0.0.1:8443/code"), "https://127.0.0.1:8443/code")
        self.assertEqual(normalize_generic_api_url("[::1]:8443/code"), "https://[::1]:8443/code")

    def test_other_schemes_and_invalid_inputs_are_not_reinterpreted_as_hosts(self):
        for url in ("", "/relative/code", "?s=fixture", "#fragment", "not a url",
                    "mailto:user@example.test", "javascript:alert(1)", "file:///tmp/mail",
                    "ftp://mail.example.test/code", "https:/mail.example.test/code",
                    "mail.example.test:invalid/code", "mail.example.test:99999/code"):
            with self.subTest(url=url):
                self.assertEqual(normalize_generic_api_url(url), url)

    def test_new_import_stores_https_url_and_keeps_signature(self):
        self.assertEqual(db.import_generic_api_emails([
            {"email": self.email, "code_url": self.raw_url},
        ]), (1, 0))
        row = db.get_generic_api_email_by_email(self.email)
        self.assertEqual(row["code_url"], self.url)
        self.assertEqual(row["copy_line"], self.email + "----" + self.url)
        self.assertEqual(row["status"], "available")

    def test_file_import_accepts_exported_schemeless_url(self):
        path = self.root / "fixture.txt"
        path.write_text(self.email + "----" + self.raw_url + "\n", encoding="utf-8")
        self.assertEqual(mail.import_from_file(path), (1, 0))
        self.assertEqual(db.get_generic_api_email_by_email(self.email)["code_url"], self.url)

    def test_old_saved_row_works_without_reimport_or_status_change(self):
        original = {"id": 1, "email": self.email, "code_url": self.raw_url,
                    "status": "disabled", "note": "keep", "used_at": "2026-10-26T18:00:00"}
        db._save_collection("generic_api", [original])
        row = db.get_generic_api_email_by_email(self.email)
        self.assertEqual(row["code_url"], self.url)
        self.assertEqual((row["status"], row["note"], row["used_at"]),
                         (original["status"], original["note"], original["used_at"]))
        self.assertEqual(mail.get_account_context(self.email).code_url, self.url)
        self.assertEqual(db._read_record("generic_api", email=self.email), original)

    def test_runtime_context_normalizes_url(self):
        account = mail.GenericApiEmailAccount(self.email, self.raw_url)
        self.assertEqual(account.code_url, self.url)

    def test_poll_parameter_preserves_raw_signed_query_and_fragment(self):
        url = self.url + "#anchor"
        with patch.object(mail.time, "time", return_value=100):
            result = mail._cache_busted_url(url, 2)
        self.assertEqual(result, self.url + "&_otp_poll=100000-2#anchor")
        self.assertEqual(urlsplit(result).query.split("&_otp_poll=", 1)[0], urlsplit(url).query)

    def test_mock_fetch_uses_normalized_url_and_dedicated_mail_proxy(self):
        account = mail.GenericApiEmailAccount(self.email, self.raw_url)
        response = Mock(status_code=200, text=json.dumps({"code": "001234", "receivedAt": 100}))
        session = Mock(proxies={})
        session.get.return_value = response
        proxy = "http://127.0.0.1:21483"
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail.requests, "Session", return_value=session), \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", proxy), \
             patch("config.proxy.pick_proxy", side_effect=AssertionError("not a mail route")):
            code = mail.fetch_latest_otp(self.email, after_ts=100, max_wait=1, settle_seconds=0)
        self.assertEqual(code, "001234")
        self.assertTrue(session.get.call_args.args[0].startswith(self.url + "&_otp_poll="))
        self.assertEqual(session.proxies, {"http": proxy, "https": proxy})
        self.assertFalse(session.trust_env)

    def test_request_errors_do_not_log_signed_urls_or_credentials(self):
        account = mail.GenericApiEmailAccount(self.email, self.raw_url)
        clock = [100.0]

        def sleep(seconds):
            clock[0] += seconds

        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_fetch_poll_payload", side_effect=requests.exceptions.InvalidURL(
                 "bad https://user:private-password@mail.example.test/code?s=private-signature")), \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""), \
             patch.object(mail.time, "time", side_effect=lambda: clock[0]), \
             patch.object(mail.time, "sleep", side_effect=sleep), \
             self.assertLogs(mail.logger, level="INFO") as logs:
            with self.assertRaises(mail.GenericApiMailError) as error:
                mail.fetch_latest_otp(self.email, after_ts=100, max_wait=1, poll_interval=1, settle_seconds=0)
        output = "\n".join(logs.output) + str(error.exception)
        self.assertIn("InvalidURL", output)
        self.assertNotIn("private-signature", output)
        self.assertNotIn("private-password", output)


if __name__ == "__main__":
    unittest.main()
