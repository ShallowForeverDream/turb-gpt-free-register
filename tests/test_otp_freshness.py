import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main
from core import email_provider, generic_api_mail_client as mail, registration_service as svc
from core.otp_freshness import (MailBaseline, OtpFreshnessError, endpoint_key,
                                new_mail_baseline, verify_mail_freshness)


class OtpFreshnessPolicyTests(unittest.TestCase):
    email = "fixture@example.test"
    url = "https://mail.example.test/code?s=private-fixture"

    def baseline(self, ids=frozenset({"old"}), *, email=None, url=None, observed_at=99):
        return MailBaseline(email or self.email, endpoint_key(url or self.url), observed_at, ids)

    def verify(self, meta, baseline=None, after_ts=100, now=102):
        return verify_mail_freshness(meta, email=self.email, url=self.url, after_ts=after_ts,
                                     now=now, baseline=baseline)

    def reason(self, reason, meta, **kwargs):
        with self.assertRaises(OtpFreshnessError) as error:
            self.verify(meta, **kwargs)
        self.assertEqual(error.exception.reason, reason)

    def test_message_after_send_passes_by_time(self):
        self.assertEqual(self.verify({"received_at": 101}), "received_at")

    def test_older_timestamp_is_never_allowed_even_with_changed_id(self):
        self.reason("old_mail", {"received_at": 99.9, "mail_id": "new"}, baseline=self.baseline())

    def test_timestamp_with_timezone_or_epoch_is_required(self):
        self.reason("timezone_missing", {"received_at": "1970-01-01T00:01:41"})
        self.reason("invalid_time", {"received_at": "not-a-time"})
        self.reason("future_time", {"received_at": 120})
        self.assertEqual(self.verify({"received_at": "1970-01-01T00:01:41Z"}), "received_at")
        self.assertEqual(self.verify({"received_at": "Thu, 01 Jan 1970 00:01:41 +0000"}), "received_at")

    def test_missing_send_time_or_metadata_fails_closed(self):
        self.reason("missing_send_time", {"received_at": 101}, after_ts=None)
        self.reason("missing_metadata", {})

    def test_changed_mail_id_requires_pre_send_baseline(self):
        self.assertEqual(self.verify({"mail_id": "new"}, baseline=self.baseline()), "changed_mail_id")
        self.reason("missing_baseline", {"mail_id": "new"})

    def test_changed_code_set_is_a_candidate_after_the_60_second_wait(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
                                  now=101, baseline=baseline, candidate_code="006789",
                                  code_history=("001234", "005555", "006789"))
        self.assertEqual(error.exception.reason, "snapshot_wait")
        self.assertEqual(verify_mail_freshness({}, email=self.email, url=self.url,
            after_ts=100, now=160, baseline=baseline, candidate_code="006789",
            code_history=("001234", "005555", "006789")), "new_code_since_snapshot")

    def test_unchanged_code_set_is_waited_not_submitted(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
                                  now=101, baseline=baseline,
                                  candidate_code="001234", code_history=("001234", "005555"))
        self.assertEqual(error.exception.reason, "unchanged_code_set")
        self.assertTrue(error.exception.waitable)

    def test_code_must_be_present_in_current_history(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234",))
        with self.assertRaises(OtpFreshnessError) as error:
            verify_mail_freshness({}, email=self.email, url=self.url, after_ts=100,
                                  now=101, baseline=baseline,
                                  candidate_code="006789", code_history=("001234",))
        self.assertEqual(error.exception.reason, "code_history_mismatch")

    def test_code_baseline_contains_only_keyed_fingerprints(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        rendered = repr(baseline)
        self.assertNotIn("001234", rendered)
        self.assertNotIn("005555", rendered)

    def test_same_id_is_old_even_if_numeric_code_or_response_time_changed(self):
        self.reason("unchanged_id", {"mail_id": "old", "received_at": 101}, baseline=self.baseline())

    def test_baseline_from_after_send_or_too_old_is_invalid(self):
        for observed in (101, 69):
            with self.subTest(observed=observed):
                self.reason("missing_baseline", {"mail_id": "new"}, baseline=self.baseline(observed_at=observed))

    def test_unknown_snapshot_is_not_the_same_as_verified_empty_inbox(self):
        self.reason("missing_baseline", {"mail_id": "new"}, baseline=self.baseline(ids=None))
        self.assertEqual(self.verify({"mail_id": "new"}, baseline=self.baseline(ids=frozenset())), "changed_mail_id")

    def test_baseline_is_bound_to_mailbox_and_endpoint(self):
        for baseline in (self.baseline(email="other@example.test"), self.baseline(url=self.url + "-other")):
            self.reason("missing_baseline", {"mail_id": "new"}, baseline=baseline)
        self.reason("recipient_mismatch", {"recipient": "other@example.test", "received_at": 101})

    def test_concurrent_mailboxes_do_not_share_baselines(self):
        barrier = threading.Barrier(2)

        def check(index):
            email = f"mail{index}@example.test"
            url = f"https://mail.example.test/{index}"
            baseline = MailBaseline(email, endpoint_key(url), 99, frozenset({f"old-{index}"}))
            barrier.wait(2)
            return verify_mail_freshness({"mail_id": f"new-{index}"}, email=email, url=url,
                                         after_ts=100, now=101, baseline=baseline)

        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(list(pool.map(check, (1, 2))), ["changed_mail_id", "changed_mail_id"])

    def test_failure_reason_never_discloses_otp_or_endpoint(self):
        with self.assertRaises(OtpFreshnessError) as error:
            self.verify({})
        self.assertNotIn("private-fixture", str(error.exception))
        info = svc.failure_info(error.exception)
        self.assertTrue(info["needs_manual_review"])
        self.assertIn("未提交", info["status_message"])


class GenericApiFreshnessTests(unittest.TestCase):
    email = OtpFreshnessPolicyTests.email
    url = OtpFreshnessPolicyTests.url
    baseline = OtpFreshnessPolicyTests.baseline

    def fetch(self, payloads, baseline=None, excluded=None, first_delay=0):
        clock = [100.0]
        sequence = iter(payloads)
        last = [None]

        def payload(**kwargs):
            self.assertIsNone(kwargs["after_ts"])
            last[0] = next(sequence, last[0])
            text = json.dumps(last[0])
            return None, None, SimpleNamespace(status_code=200), text

        with ExitStack() as stack:
            stack.enter_context(patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)))
            call = stack.enter_context(patch.object(mail, "_fetch_poll_payload", side_effect=payload))
            stack.enter_context(patch.object(mail._email_cfg, "GENERIC_API_PROXY", ""))
            stack.enter_context(patch.object(mail.time, "time", side_effect=lambda: clock[0]))
            stack.enter_context(patch.object(mail.time, "sleep", side_effect=lambda n: clock.__setitem__(0, clock[0] + n)))
            result = mail.fetch_latest_otp(self.email, after_ts=100,
                max_wait=70 if first_delay else 3, poll_interval=1,
                settle_seconds=0, mail_baseline=baseline, exclude_codes=excluded,
                first_read_delay_seconds=first_delay)
            return result, call.call_count, clock[0]

    def test_old_then_new_mail_uses_only_the_new_message(self):
        result, count, _ = self.fetch([
            {"code": "001234", "receivedAt": 99, "messageId": "old"},
            {"code": "006789", "receivedAt": 101, "messageId": "new"},
        ], self.baseline())
        self.assertEqual((result, count), ("006789", 2))

    def test_code_history_delta_returns_candidate_only_after_60_seconds(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        result, count, now = self.fetch([
            {"status": 1, "code": "001234", "all_codes": ["001234", "005555"]},
            {"status": 1, "code": "006789", "all_codes": ["006789", "001234", "005555"]},
        ], baseline, first_delay=60)
        self.assertEqual((result, count, now), ("006789", 2, 161))

    def test_real_shape_unchanged_until_timeout_never_returns_old_code(self):
        baseline = new_mail_baseline(email=self.email, url=self.url, observed_at=99,
                                     mail_ids=None, codes=("001234", "005555"))
        with self.assertRaises(OtpFreshnessError) as error:
            self.fetch([{"status": 1, "code": "001234", "all_codes": ["001234", "005555"]}], baseline)
        self.assertEqual(error.exception.reason, "unchanged_code_set")

    def test_missing_metadata_stops_immediately_without_validation(self):
        with self.assertRaises(OtpFreshnessError) as error:
            self.fetch([{"code": "001234"}])
        self.assertEqual(error.exception.reason, "missing_code_baseline")

    def test_changed_id_without_time_is_usable_only_with_baseline(self):
        self.assertEqual(self.fetch([{"code": "001234", "messageId": "new"}], self.baseline())[0], "001234")
        with self.assertRaises(OtpFreshnessError) as error:
            self.fetch([{"code": "001234", "messageId": "new"}])
        self.assertEqual(error.exception.reason, "missing_baseline")

    def test_unchanged_id_and_excluded_code_never_return(self):
        for payload, excluded, reason in [
            ({"code": "006789", "messageId": "old"}, None, "unchanged_id"),
            ({"code": "001234", "receivedAt": 100, "messageId": "new"}, {"001234"}, "excluded_code"),
        ]:
            with self.subTest(reason=reason), self.assertRaises(OtpFreshnessError) as error:
                self.fetch([payload], self.baseline(), excluded)
            self.assertEqual(error.exception.reason, reason)

    def test_capture_reads_only_metadata_through_the_mail_route(self):
        response = Mock(status_code=200)
        response.json.return_value = {"code": "001234", "messageId": "old"}
        session = Mock()
        session.get.return_value = response
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_new_http_session", return_value=session) as factory, \
             patch.object(mail._email_cfg, "GENERIC_API_PROXY", "http://127.0.0.1:21483"):
            baseline = mail.capture_mail_baseline(self.email)
        factory.assert_called_once_with("http://127.0.0.1:21483")
        self.assertEqual(baseline.mail_ids, frozenset({"old"}))
        session.get.assert_called_once()
        session.close.assert_called_once()

    def test_capture_code_history_without_metadata_keeps_a_complete_snapshot(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 1, "code": "001234",
                                      "all_codes": ["001234", "005555", "009999"]}
        session = Mock(); session.get.return_value = response
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_new_http_session", return_value=session):
            baseline = mail.capture_mail_baseline(self.email)
        self.assertIsNone(baseline.mail_ids)
        self.assertEqual(len(baseline.code_fingerprints), 3)
        self.assertNotIn("001234", repr(baseline))

    def test_arbitrary_json_id_is_not_a_mail_id_baseline(self):
        response = Mock(status_code=200)
        response.json.return_value = {"code": "001234", "id": "order-id"}
        session = Mock()
        session.get.return_value = response
        with patch.object(mail, "get_account_context", return_value=mail.GenericApiEmailAccount(self.email, self.url)), \
             patch.object(mail, "_new_http_session", return_value=session):
            baseline = mail.capture_mail_baseline(self.email)
        self.assertIsNone(baseline.mail_ids)
        self.assertEqual(len(baseline.code_fingerprints), 1)

    def test_dispatcher_preserves_baseline_and_rejected_codes(self):
        baseline = self.baseline()
        with patch.object(email_provider, "_registered_email_source", return_value="generic_api"), \
             patch.object(email_provider, "resolve_email_source", return_value="generic_api"), \
             patch.object(mail, "fetch_latest_otp", return_value="006789") as fetch:
            email_provider.wait_for_otp(self.email, after_ts=100, force_service=True,
                                        mail_baseline=baseline, exclude_codes={"001234"})
        self.assertEqual(fetch.call_args.kwargs["mail_baseline"], baseline)
        self.assertEqual(fetch.call_args.kwargs["exclude_codes"], {"001234"})

    def test_baseline_callback_precedes_send_and_cutoff(self):
        events = []
        clock = [99.0]

        def baseline():
            events.append("baseline")
            clock[0] = 100

        with patch.object(main, "follow_authorize", side_effect=lambda *_: events.append("authorize") or "https://auth.openai.com/email-verification"), \
             patch.object(main, "send_email_otp") as send, \
             patch.object(main.time, "time", side_effect=lambda: clock[0]):
            _, cutoff = main._follow_registration_authorize(object(), "https://auth.openai.com/authorize",
                before_delivery=baseline)
        self.assertEqual(events, ["baseline", "authorize"])
        send.assert_not_called()
        self.assertEqual(cutoff, 100)


if __name__ == "__main__":
    unittest.main()
