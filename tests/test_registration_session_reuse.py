import tempfile
import threading
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import chatgpt_plan as plan, db, plan_check_service as service
from core import protocol_traffic, registration_completion
from tests.test_forwarded_imap_and_account_import import storage


class PlanSession:
    def __init__(self, *, low_traffic=False):
        self._owner_thread_id = threading.get_ident()
        self._closed = False
        self.proxy_target = "socks5://user:private@proxy.test:1080"
        self.device_id = "registration-device"
        self.oai_session_id = "registration-session"
        self.cookies = {"fixture": "registration-cookie"}
        self.protocol_low_traffic = low_traffic
        self.protocol_traffic = protocol_traffic.ProtocolTraffic(
            low_traffic=low_traffic, budget_bytes=1000000,
        )
        self.requests = []
        self.responses = []
        self.reset_circuit_breaker = Mock()

    def get_chatgpt_headers(self, **kwargs):
        return {"oai-device-id": self.device_id, "oai-session-id": self.oai_session_id}

    def get(self, url, *, headers, **kwargs):
        assert threading.get_ident() == self._owner_thread_id
        self.requests.append((url, dict(headers), dict(self.cookies)))
        data = {"accounts": {"fixture-account": {
            "account": {"account_id": "fixture-account", "plan_type": "free"},
        }}}
        response = self.responses.pop(0) if self.responses else SimpleNamespace(
            status_code=200, text="{}", headers={}, json=lambda: data,
            upload_size=10, request_size=0, download_size=20, header_size=0,
            content=b"fixture", redirect_count=0,
        )
        self.protocol_traffic.record(url, response, tunneled=False)
        return response

    def js_timezone_offset_min(self):
        return -480

    def fingerprint_summary_text(self):
        return "fixture"


class RegistrationSessionReuseTests(unittest.TestCase):
    def setUp(self):
        self.driver = patch("core.workflow_driver.resolve_driver", return_value="protocol")
        self.driver.start()
        self.addCleanup(self.driver.stop)

    def test_all_plan_reads_reuse_cookie_device_route_and_skip_only_home(self):
        for low_traffic in (False, True):
            with self.subTest(low_traffic=low_traffic):
                session = PlanSession(low_traffic=low_traffic)
                with patch("core.workflow_driver.create_account_session") as factory, \
                     patch.object(plan, "open_plan_check_proxy") as relay, \
                     patch.object(plan, "resolve_plan_check_route") as route, \
                     patch.object(plan, "_warm_plan_session") as home, \
                     patch.object(plan, "close_browser_session") as close:
                    results = [plan.check_account_plan(token, existing_session=session)
                               for token in ("initial-at", "initial-at", "latest-at")]
                self.assertTrue(all(r["ok"] for r in results))
                self.assertTrue(all(r["proxy_mode"] == "registration_session" for r in results))
                self.assertNotIn("private", str(results))
                factory.assert_not_called()
                relay.assert_not_called()
                route.assert_not_called()
                home.assert_not_called()
                close.assert_not_called()
                self.assertEqual(len(session.requests), 3)
                self.assertTrue(all(plan.ACCOUNTS_CHECK_PATH in r[0] for r in session.requests))
                self.assertEqual([r[1]["authorization"] for r in session.requests],
                                 ["Bearer initial-at", "Bearer initial-at", "Bearer latest-at"])
                self.assertTrue(all(r[1]["oai-device-id"] == session.device_id for r in session.requests))
                self.assertTrue(all(r[2] == session.cookies for r in session.requests))
                self.assertEqual(session.protocol_traffic.skipped["plan_home_document_reused_session"], 3)
                self.assertEqual(session.protocol_traffic.snapshot()["total_bytes"], 90)

    def test_borrowed_error_never_closes_session_or_mistakes_401_for_success(self):
        session = PlanSession()
        session.responses = [SimpleNamespace(status_code=401, text="revoked", headers={})]
        with patch.object(plan, "close_browser_session") as close:
            result = plan.check_account_plan("fixture-at", existing_session=session)
        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_live_check"])
        self.assertEqual(result["http_status"], 401)
        self.assertEqual(len(session.requests), 1)
        close.assert_not_called()
        self.assertFalse(session._closed)

    def test_borrowed_transport_retry_uses_same_session(self):
        session = PlanSession()
        session.responses = [SimpleNamespace(status_code=503, text="unavailable", headers={})]
        result = plan.check_account_plan("fixture-at", existing_session=session,
                                         max_attempts=2, retry_delay=0)
        self.assertTrue(result["ok"])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(session.requests[0][1:], session.requests[1][1:])

    def test_closed_or_foreign_thread_session_never_issues_request(self):
        session = PlanSession()
        session._closed = True
        result = plan.check_account_plan("fixture-at", existing_session=session)
        self.assertIn("已关闭", result["error"])
        session._closed = False
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(plan.check_account_plan, "fixture-at", existing_session=session).result()
        self.assertIn("跨线程", result["error"])
        self.assertEqual(session.requests, [])

    def test_expired_token_still_rejected_without_network(self):
        session = PlanSession()
        with patch.object(plan, "token_claims", return_value={"token_expired": True}):
            result = plan.check_account_plan("fixture-at", existing_session=session)
        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_live_check"])
        self.assertEqual(session.requests, [])

    def test_joined_query_recheck_and_final_validation_use_owner_thread_latest_at(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            aid = db.insert_account(email="fixture@example.test", access_token="initial-at",
                                    extra={"registration_password": "fixture-existing-password"})
            session = PlanSession()

            def twofa(**kwargs):
                self.assertIs(kwargs["existing_session"], session)
                db.update_account_liveness(aid, {"ok": True, "access_token": "latest-at"})
                db.update_account_totp_secret(aid, {"ok": True, "totp_secret": "fixture-secret"})
                future = Future()
                future.set_result({"ok": True})
                return {"accepted": True, "future": future}

            with patch("config.register.AUTO_PLAN_CHECK_AFTER_REGISTER", True), \
                 patch("config.twofa.ENABLE_2FA", True), \
                 patch.object(service, "_wait_for_rate_slot"), \
                 patch.object(service, "_registration_recheck_delay", return_value=0.001), \
                 patch.object(service.time, "sleep"), \
                 patch("core.workflow_driver.submit_with_driver") as submit, \
                 patch("core.workflow_driver.create_account_session") as factory, \
                 patch("core.proxy_chain.open_proxy_pool_proxy") as relay, \
                 patch("core.twofa_service.enqueue_account_totp_setup", side_effect=twofa):
                result = registration_completion.finish_account(aid, session=session)
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["credential_validation"], "valid")
            self.assertEqual([r[1]["authorization"] for r in session.requests],
                             ["Bearer initial-at", "Bearer initial-at", "Bearer latest-at"])
            self.assertEqual(db.get_account(aid)["plan_check_status"], "success")
            self.assertEqual(db.get_account(aid)["access_token"], "latest-at")
            submit.assert_not_called()
            factory.assert_not_called()
            relay.assert_not_called()
            self.assertFalse(session._closed)

    def test_cancelled_inline_query_releases_slots_without_request(self):
        slots = threading.BoundedSemaphore(1)
        execution = threading.BoundedSemaphore(1)
        with patch.object(service, "_QUEUE_SLOTS", slots), \
             patch.object(service, "_EXECUTION_SLOTS", execution), \
             patch.object(db, "claim_account_plan_check", return_value=True), \
             patch.object(db, "mark_account_plan_check_running", return_value=False), \
             patch.object(service, "check_account_plan") as check:
            queued = service.enqueue_account_plan_check(account_id=99999, email="fixture@example.test",
                        access_token="fixture", trigger="registration_auto", existing_session=PlanSession(), return_future=True)
        self.assertFalse(queued["future"].result()["ok"])
        check.assert_not_called()
        self.assertTrue(slots.acquire(blocking=False))
        self.assertTrue(execution.acquire(blocking=False))

    def test_queue_busy_and_full_do_not_use_borrowed_session(self):
        session = PlanSession()
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch.object(service, "_QUEUE_SLOTS", slots):
            result = service.enqueue_account_plan_check(account_id=99999, email="fixture@example.test",
                        access_token="fixture", trigger="registration_auto", existing_session=session)
        self.assertTrue(result["queue_full"])
        slots.release()
        with patch.object(service, "_QUEUE_SLOTS", slots), \
             patch.object(db, "claim_account_plan_check", return_value=False):
            result = service.enqueue_account_plan_check(account_id=99999, email="fixture@example.test",
                        access_token="fixture", trigger="registration_auto", existing_session=session)
        self.assertTrue(result["busy"])
        self.assertEqual(session.requests, [])
        self.assertTrue(slots.acquire(blocking=False))

    def test_borrowed_query_exception_persists_failure_and_releases_capacity(self):
        slots = threading.BoundedSemaphore(1)
        execution = threading.BoundedSemaphore(1)
        with patch.object(service, "_QUEUE_SLOTS", slots), \
             patch.object(service, "_EXECUTION_SLOTS", execution), \
             patch.object(db, "claim_account_plan_check", return_value=True), \
             patch.object(db, "mark_account_plan_check_running", return_value=True), \
             patch.object(db, "update_account_plan_check") as save, \
             patch.object(service, "_wait_for_rate_slot"), \
             patch.object(service, "check_account_plan", side_effect=RuntimeError("fixture")):
            queued = service.enqueue_account_plan_check(account_id=99999, email="fixture@example.test",
                        access_token="fixture", trigger="registration_auto", existing_session=PlanSession(), return_future=True)
        self.assertFalse(queued["future"].result()["ok"])
        save.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))
        self.assertTrue(execution.acquire(blocking=False))

    def test_independent_query_still_uses_background_executor(self):
        future = Future()
        future.set_result({"ok": True})
        slots = threading.BoundedSemaphore(1)
        with patch.object(service, "_QUEUE_SLOTS", slots), \
             patch.object(db, "claim_account_plan_check", return_value=True), \
             patch("core.workflow_driver.submit_with_driver", return_value=future) as submit:
            queued = service.enqueue_account_plan_check(account_id=99999, email="fixture@example.test",
                        access_token="fixture", trigger="manual", return_future=True)
        self.assertIs(queued["future"], future)
        submit.assert_called_once()
        self.assertNotIn("existing_session", submit.call_args.kwargs)

    def test_independent_query_owns_and_closes_its_new_session(self):
        session = PlanSession()
        with patch("core.workflow_driver.create_account_session", return_value=session) as factory, \
             patch.object(plan, "open_plan_check_proxy", return_value=("", None)), \
             patch.object(plan, "_warm_plan_session") as home, \
             patch.object(plan, "close_browser_session") as close:
            result = plan.check_account_plan("fixture", proxy="")
        self.assertTrue(result["ok"])
        factory.assert_called_once()
        home.assert_called_once_with(session)
        close.assert_called_once_with(session)

    def test_inline_calls_obey_shared_execution_limit(self):
        first_pair = threading.Barrier(2)
        guard = threading.Lock()
        active = peak = started = 0
        execution = threading.BoundedSemaphore(2)
        slots = threading.BoundedSemaphore(10)

        def check(token, **kwargs):
            nonlocal active, peak, started
            self.assertEqual(kwargs["existing_session"]._owner_thread_id, threading.get_ident())
            with guard:
                active += 1
                peak = max(peak, active)
                started += 1
                index = started
            try:
                if index <= 2:
                    first_pair.wait(timeout=5)
                return {"ok": True}
            finally:
                with guard:
                    active -= 1

        def run(index):
            queued = service.enqueue_account_plan_check(account_id=99990 + index, email="fixture@example.test",
                        access_token="fixture", trigger="registration_final", existing_session=PlanSession(), return_future=True)
            return queued["future"].result()

        with patch.object(service, "_QUEUE_SLOTS", slots), \
             patch.object(service, "_EXECUTION_SLOTS", execution), \
             patch.object(db, "claim_account_plan_check", return_value=True), \
             patch.object(db, "mark_account_plan_check_running", return_value=True), \
             patch.object(db, "update_account_plan_check"), \
             patch.object(service, "_wait_for_rate_slot"), \
             patch.object(service, "check_account_plan", side_effect=check), \
             ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(run, range(3)))
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual(peak, 2)
        self.assertEqual(started, 3)
        self.assertEqual(active, 0)
        self.assertTrue(execution.acquire(blocking=False))
        self.assertTrue(execution.acquire(blocking=False))
        self.assertFalse(execution.acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
