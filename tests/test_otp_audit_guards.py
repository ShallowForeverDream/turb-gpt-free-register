"""Offline negative controls. No real mailbox, OTP send or registration calls."""
import ast
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import main
from core import generic_api_mail_client as mail
from core.otp_freshness import MailBaseline, OtpFreshnessError, endpoint_key, failure_message, new_mail_baseline, verify_mail_freshness


class FullOtpAuditTests(unittest.TestCase):
    email = "audit@example.test"
    url = "https://mail.example.test/code?s=private-fixture"

    def session(self, payload=None, error=None, status=200):
        session = Mock()
        response = Mock(status_code=status, text=json.dumps(payload))
        response.json.return_value = payload
        session.get.side_effect = error
        session.get.return_value = response
        return session

    def capture(self, session):
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_new_http_session", return_value=session):
            return mail.capture_mail_baseline(self.email)

    def test_timeout_remains_timeout_and_does_not_fabricate_baseline(self):
        session = self.session(error=requests.exceptions.ReadTimeout("private-fixture"))
        with self.assertRaises(OtpFreshnessError) as error:
            self.capture(session)
        self.assertEqual(error.exception.reason, "snapshot_timeout")
        self.assertNotIn("private-fixture", str(error.exception))
        session.close.assert_called_once()

    def test_failed_pre_send_capture_makes_zero_send_calls(self):
        session = self.session(error=requests.exceptions.ReadTimeout("private-fixture"))
        with patch.object(main, "send_email_otp") as send, patch.object(main, "follow_authorize") as follow:
            with self.assertRaises(OtpFreshnessError):
                main._follow_registration_authorize(object(), "https://auth.openai.com/authorize",
                    before_delivery=lambda: self.capture(session))
        follow.assert_not_called()
        send.assert_not_called()

    def test_cleanup_error_does_not_replace_the_original_timeout(self):
        session = self.session(error=requests.exceptions.ReadTimeout("private-fixture"))
        session.close.side_effect = OSError("private-cleanup-detail")
        with self.assertRaises(OtpFreshnessError) as error:
            self.capture(session)
        self.assertEqual(error.exception.reason, "snapshot_timeout")
        self.assertNotIn("private-cleanup-detail", str(error.exception))

    def test_tls_capture_failure_is_not_downgraded_to_missing_id(self):
        session = self.session(error=requests.exceptions.SSLError("private-fixture"))
        with self.assertRaises(OtpFreshnessError) as error:
            self.capture(session)
        self.assertEqual(error.exception.reason, "snapshot_tls_error")
        self.assertNotIn("private-fixture", str(error.exception))

    def test_capture_http_failure_is_terminal(self):
        session = self.session(status=503)
        with self.assertRaises(OtpFreshnessError) as error:
            self.capture(session)
        self.assertEqual(error.exception.reason, "snapshot_http_error")

    def test_both_capture_and_poll_verify_tls(self):
        session = self.session({"code": "001234", "messageId": "message-old"})
        self.capture(session)
        self.assertTrue(session.get.call_args.kwargs.get("verify", True))
        with patch.object(mail, "_new_http_session", return_value=session):
            mail._fetch_poll_payload(proxy_url="", poll_url=self.url, email=self.email,
                headers={}, after_ts=None, is_yangyang=False, public_inbox_api_url=None)
        self.assertTrue(session.get.call_args.kwargs.get("verify", True))

    def test_code_only_error_does_not_claim_that_a_mail_id_exists(self):
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
                                  now=101, candidate_code="001234")
        self.assertNotIn("返回了邮件 ID", str(error.exception))
        self.assertEqual(error.exception.reason, "missing_code_baseline")

    def test_legacy_error_label_no_longer_asserts_an_observed_mail_id(self):
        text = failure_message("mail_otp_freshness_unverified: 返回了邮件 ID，但没有有效的发码前基线，不能当作新邮件")
        self.assertIn("历史错误", text)
        self.assertNotIn("返回了邮件 ID", text)

    def test_new_observation_is_a_heuristic_not_delivery_proof(self):
        # The third code can have existed before sending but been omitted by
        # an incomplete/cached response. Set difference cannot date the mail.
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100, now=101,
                baseline=baseline, candidate_code="006789", code_history=("001234", "005555", "006789"))
        self.assertEqual(error.exception.reason, "snapshot_wait")
        self.assertEqual(verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
            now=160, baseline=baseline, candidate_code="006789",
            code_history=("001234", "005555", "006789")), "new_code_since_snapshot")

    def test_code_only_capture_is_a_snapshot_not_a_mail_id(self):
        baseline = self.capture(self.session({"status": 1, "code": "001234", "all_codes": ["001234"]}))
        self.assertIsNone(baseline.mail_ids)
        self.assertEqual(len(baseline.code_fingerprints), 1)

    def test_history_is_not_silently_truncated_into_a_complete_baseline(self):
        values = [f"{value:06d}" for value in range(101)]
        with self.assertRaises(OtpFreshnessError) as error:
            mail._mail_identity({"code": values[0], "all_codes": values})
        self.assertEqual(error.exception.reason, "code_history_invalid")

    def test_invalid_history_is_not_normalized_into_an_empty_success(self):
        with self.assertRaises(OtpFreshnessError):
            mail._mail_identity({"all_codes": [None, False, {"id": "fixture"}]})

    def test_fingerprint_secret_material_is_not_in_repr(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234",))
        self.assertFalse(repr(baseline.code_key) in repr(baseline), "key exposed by repr")
        self.assertFalse(repr(baseline.code_fingerprints) in repr(baseline), "fingerprints exposed by repr")

    def test_fresh_timestamp_path_remains_explicit(self):
        self.assertEqual(verify_mail_freshness({"received_at": 101}, email=self.email,
            url=self.url, after_ts=100, now=102), "received_at")

    def test_page_adapters_do_not_treat_html_as_a_json_id_snapshot(self):
        for url in ("https://mail.example.test/i/fixture",
                    "https://mail.example.test/messages/fixture/audit%40example.test"):
            with self.subTest(url=url), \
                 patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, url)), \
                 patch.object(mail, "_new_http_session") as factory:
                baseline = mail.capture_mail_baseline(self.email)
            factory.assert_not_called()
            self.assertIsNone(baseline.mail_ids)
            self.assertIsNone(baseline.code_fingerprints)
            with self.assertRaises(OtpFreshnessError):
                verify_mail_freshness({"mail_id": "unknown-new"}, email=self.email, url=url,
                    after_ts=baseline.observed_at + 1, now=baseline.observed_at + 2, baseline=baseline)

    def test_waiting_longer_does_not_expire_a_valid_presend_id_baseline(self):
        baseline = MailBaseline(self.email, endpoint_key(self.url), 99, frozenset({"old"}))
        self.assertEqual(verify_mail_freshness({"mail_id": "new"}, email=self.email,
            url=self.url, after_ts=100, now=150, baseline=baseline), "changed_mail_id")

    def test_no_verify_false_is_left_in_mail_module(self):
        tree = ast.parse(Path(mail.__file__).read_text(encoding="utf-8"))
        bad = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
               for kw in node.keywords if kw.arg == "verify" and isinstance(kw.value, ast.Constant)
               and kw.value.value is False]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
