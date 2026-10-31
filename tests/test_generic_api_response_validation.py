import json
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import generic_api_mail_client as mail
from core.otp_freshness import OtpFreshnessError, verify_mail_freshness


class GenericApiResponseValidationTests(unittest.TestCase):
    def parse(self, payload, after_ts=100):
        return mail._extract_structured_api_code(json.dumps(payload), after_ts=after_ts)

    def fetch(self, payload, **kwargs):
        text = payload if isinstance(payload, str) else json.dumps(payload)
        clock = [100.0]
        response = SimpleNamespace(status_code=kwargs.pop("status_code", 200))
        account = mail.GenericApiEmailAccount("fixture@example.test", "https://mail.example.test/code")
        with ExitStack() as stack:
            stack.enter_context(patch.object(mail, "get_account_context", return_value=account))
            stack.enter_context(patch.object(mail, "_fetch_poll_payload", return_value=(None, None, response, text)))
            stack.enter_context(patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""))
            stack.enter_context(patch.object(mail.time, "time", side_effect=lambda: clock[0]))
            stack.enter_context(patch.object(mail.time, "sleep", side_effect=lambda n: clock.__setitem__(0, clock[0] + n)))
            return mail.fetch_latest_otp(account.email, after_ts=100, max_wait=1,
                                         poll_interval=1, settle_seconds=0, **kwargs)

    def baseline(self, payload):
        response = Mock(status_code=200)
        response.json.return_value = payload
        session = Mock()
        session.get.return_value = response
        account = mail.GenericApiEmailAccount("fixture@example.test", "https://mail.example.test/code")
        with patch.object(mail, "get_account_context", return_value=account), \
             patch.object(mail, "_new_http_session", return_value=session):
            return mail.capture_mail_baseline(account.email)

    def test_explicit_fields_preserve_leading_zeros(self):
        for field in ("code", "otp", "verification_code", "verificationCode", "email_code", "emailCode"):
            with self.subTest(field=field):
                self.assertEqual(self.parse({field: "001234"})[0], "001234")

    def test_error_responses_cannot_be_interpreted_as_codes(self):
        for payload in (
            {"success": False, "code": "001234"},
            {"success": 0, "code": "001234"},
            {"success": "false", "code": "001234"},
            {"status": "error", "code": "001234"},
            {"status": False, "code": "001234"},
            {"error": "access denied", "code": "001234"},
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(self.parse(payload))

    def test_order_numbers_and_error_messages_are_not_mail(self):
        for payload in (
            {"id": 123456, "message": "no new mail"},
            {"status": 200, "order_id": 123456},
            {"code": None, "message": "Error code 123456"},
            {"data": {"order_id": 123456}},
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(self.parse(payload))

    def test_explicit_code_field_must_be_exactly_six_ascii_digits(self):
        for value in ("error: 123456", "1234567", "１２３４５６", {"id": 123456}, [123456]):
            with self.subTest(value=value):
                self.assertIsNone(self.parse({"code": value}))

    def test_known_mail_body_fields_remain_supported(self):
        self.assertEqual(self.parse({"text": "Your verification code is 001234", "receivedAt": 100})[0], "001234")

    def test_nested_data_code_fields_are_supported(self):
        payload = {
            "code": 0,
            "msg": "success",
            "data": {
                "code": "001234",
                "code_time": "2026-10-29T12:34:56+08:00",
                "expired_date": "2026-10-29T12:44:56+08:00",
            },
        }
        result = self.parse(payload, after_ts=None)
        self.assertEqual(result[0], "001234")
        self.assertEqual(result[1]["received_at"], "2026-10-29T12:34:56+08:00")
        self.assertTrue(result[1]["msg_ts"])

    def test_nested_no_code_state_is_not_a_code(self):
        payload = {
            "code": 0,
            "msg": "No verification code",
            "data": {"code": "", "code_time": "", "expired_date": ""},
        }
        self.assertIsNone(self.parse(payload, after_ts=None))

    def test_nested_order_id_is_not_a_mail_code(self):
        payload = {"code": 0, "data": {"order_id": 123456}}
        self.assertIsNone(self.parse(payload, after_ts=None))

    def test_nested_old_code_is_rejected_by_code_time(self):
        payload = {
            "code": 0,
            "data": {"code": "001234", "code_time": "1970-01-01T00:00:00Z"},
        }
        self.assertIsNone(self.parse(payload, after_ts=100))

    def test_nested_business_error_is_rejected(self):
        payload = {"code": 1, "msg": "error", "data": {"code": "001234"}}
        self.assertIsNone(self.parse(payload, after_ts=None))

    def test_nested_empty_code_creates_verified_empty_baseline(self):
        baseline = self.baseline({
            "code": 0,
            "msg": "No verification code",
            "data": {"code": "", "code_time": "", "expired_date": ""},
        })
        self.assertEqual(baseline.code_fingerprints, frozenset())
        self.assertEqual(verify_mail_freshness(
            {}, email="fixture@example.test", url="https://mail.example.test/code",
            after_ts=baseline.observed_at + 1, now=baseline.observed_at + 61,
            baseline=baseline, candidate_code="001234",
        ), "new_code_since_snapshot")

    def test_nested_presend_code_is_excluded_by_baseline(self):
        baseline = self.baseline({
            "code": 0,
            "data": {"code": "001234", "code_time": "", "expired_date": ""},
        })
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({
                "received_at": "2026-10-29T12:34:56+08:00",
            }, email="fixture@example.test", url="https://mail.example.test/code",
                after_ts=baseline.observed_at + 1, now=baseline.observed_at + 61,
                baseline=baseline, candidate_code="001234",
            )
        self.assertEqual(error.exception.reason, "unchanged_code_set")

    def test_old_or_invalid_message_time_is_rejected(self):
        for timestamp in (0, 90, "1970-01-01T00:00:00Z", "invalid-time"):
            with self.subTest(timestamp=timestamp):
                self.assertIsNone(self.parse({"code": "001234", "time": timestamp}))

    def test_valid_message_time_is_retained(self):
        result = self.parse({"code": "001234", "receivedAt": 100})
        self.assertEqual(result[0], "001234")
        self.assertEqual(result[1]["msg_ts"], 100)

    def test_stale_json_is_not_resurrected_by_raw_text_fallback(self):
        with self.assertRaises(OtpFreshnessError):
            self.fetch({"code": "001234", "time": 90})

    def test_business_error_json_is_not_resurrected_by_raw_text_fallback(self):
        with self.assertRaises(mail.GenericApiMailError):
            self.fetch({"success": False, "code": "001234"})

    def test_unknown_json_does_not_fall_back_to_arbitrary_numeric_values(self):
        for payload in ({"order_id": 123456}, [123456]):
            with self.subTest(payload=payload), self.assertRaises(mail.GenericApiMailError):
                self.fetch(payload)

    def test_malformed_json_is_not_scanned_as_plain_text(self):
        with self.assertRaises(mail.GenericApiMailError):
            self.fetch('{"error": "Error code 123456",')

    def test_recipient_mismatch_is_rejected(self):
        for mailbox in ("other@example.test", {"address": "other@example.test"}):
            with self.subTest(mailbox=mailbox), self.assertRaises(OtpFreshnessError):
                self.fetch({"code": "001234", "mailbox": mailbox})

    def test_matching_recipient_is_accepted(self):
        self.assertEqual(self.fetch({"code": "001234", "receivedAt": 100, "mailbox": {"address": "fixture@example.test"}}), "001234")

    def test_plain_text_code_without_mail_metadata_is_not_submitted(self):
        with self.assertRaises(OtpFreshnessError) as error:
            self.fetch("Your verification code is 001234")
        self.assertEqual(error.exception.reason, "missing_code_baseline")

    def test_response_bodies_are_not_echoed_into_errors(self):
        for status_code in (200, 500):
            with self.subTest(status_code=status_code):
                with self.assertRaises(mail.GenericApiMailError) as error:
                    self.fetch({"message": "private-signature private-password"}, status_code=status_code)
                self.assertNotIn("private-signature", str(error.exception))
                self.assertNotIn("private-password", str(error.exception))


if __name__ == "__main__":
    unittest.main()
