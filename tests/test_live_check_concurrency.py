import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from core import db, live_check_service as service, account_concurrency
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class LiveCheckConcurrencyTests(unittest.TestCase):
    def setUp(self):
        previous = account_concurrency.queue_settings()['workers']
        self.addCleanup(account_concurrency.configure_workers, previous)
        account_concurrency.configure_workers(1)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.multiple(db, **storage(Path(root))))
        self.executor = ThreadPoolExecutor(max_workers=16)
        self.gate = threading.Event()
        self.entered = []
        self.changed = threading.Condition()
        self.stack.enter_context(patch.multiple(
            service, _EXECUTOR=self.executor, _WORKERS=1,
            _RUNNING=set(), _QUEUE_SLOTS=threading.BoundedSemaphore(500),
        ))
        self.stack.enter_context(patch("core.workflow_driver.require_driver_ready", return_value="protocol"))
        self.stack.enter_context(patch.object(service, "_append_log"))
        self.stack.enter_context(patch.object(service, "resolve_plan_check_route", return_value={}))
        self.stack.enter_context(patch.object(service, "open_plan_check_proxy", return_value=(None, None)))
        self.check = self.stack.enter_context(patch.object(service, "check_account_liveness", side_effect=self._check))
        self.ids = [db.insert_account(email=f"fixture{i}@example.test", access_token="fixture-at") for i in range(6)]
        self.addCleanup(self._drain)

    def _drain(self):
        self.gate.set()
        self.executor.shutdown(wait=True)

    def _check(self, email, **kwargs):
        with self.changed:
            self.entered.append(email)
            self.changed.notify_all()
        if not self.gate.wait(5):
            raise RuntimeError("fixture release timed out")
        return {"ok": True, "status": "live"}

    def _enqueue(self, ids=None):
        for account_id in ids or self.ids:
            account = db.get_account(account_id)
            result = service.enqueue_account_live_check(account_id=account_id, email=account["email"])
            self.assertTrue(result["accepted"])

    def _wait_entered(self, count):
        with self.changed:
            self.assertTrue(self.changed.wait_for(lambda: len(self.entered) >= count, timeout=3))

    def test_three_workers_really_overlap_and_leave_remaining_jobs_queued(self):
        service.configure_workers(3)
        self._enqueue()
        self._wait_entered(3)
        self.assertEqual(service.queue_settings()["running"], 3)
        statuses = [db.get_account(i)["live_check_status"] for i in self.ids]
        self.assertEqual(statuses.count("running"), 3)
        self.assertEqual(statuses.count("queued"), 3)
        self.assertEqual(len(self.entered), 3)
        self._drain()
        self.assertEqual(len(self.entered), 6)
        self.assertEqual(service.queue_settings()["running"], 0)

    def test_increasing_limit_releases_already_queued_jobs(self):
        self._enqueue()
        self._wait_entered(1)
        self.assertEqual(len(self.entered), 1)
        service.configure_workers(3)
        self._wait_entered(3)
        self.assertEqual(service.queue_settings()["running"], 3)

    def test_cancelled_queued_task_never_logs_in(self):
        self._enqueue(self.ids[:2])
        self._wait_entered(1)
        waiting = next(i for i in self.ids[:2] if db.get_account(i)["live_check_status"] == "queued")
        cancelled_email = db.get_account(waiting)["email"]
        self.assertTrue(db.cancel_account_queued_task(waiting, "live"))
        self._drain()
        self.assertNotIn(cancelled_email, self.entered)

    def test_decreasing_limit_waits_for_existing_tasks_to_finish(self):
        releases = {db.get_account(i)["email"]: threading.Event() for i in self.ids[:4]}
        self.addCleanup(lambda: [event.set() for event in releases.values()])

        def check(email, **kwargs):
            with self.changed:
                self.entered.append(email)
                self.changed.notify_all()
            if not releases[email].wait(5):
                raise RuntimeError("fixture release timed out")
            return {"ok": True, "status": "live"}

        self.check.side_effect = check
        service.configure_workers(3)
        self._enqueue(self.ids[:4])
        self._wait_entered(3)
        service.configure_workers(1)
        for email in self.entered[:2]:
            releases[email].set()
        with service._CAPACITY:
            self.assertTrue(service._CAPACITY.wait_for(lambda: len(service._RUNNING) == 1, timeout=3))
        self.assertEqual(len(self.entered), 3)
        releases[self.entered[2]].set()
        self._wait_entered(4)
        self.assertEqual(service.queue_settings()["running"], 1)

    def test_failed_task_releases_capacity_for_next_task(self):
        self.check.side_effect = RuntimeError("fixture network failure")
        with self.assertLogs(service.logger, level="ERROR"):
            self._enqueue(self.ids[:2])
            self._drain()
        self.assertEqual(self.check.call_count, 2)
        self.assertEqual(service.queue_settings()["running"], 0)
        self.assertTrue(all(db.get_account(i)["live_check_status"] == "failed" for i in self.ids[:2]))

    def test_stale_task_request_cannot_override_saved_page_workers(self):
        service.configure_workers(3)
        client = create_app(auth_code="test-auth").test_client()
        with patch.object(service, "enqueue_account_live_check", return_value={"accepted": True}) as enqueue:
            response = client.post("/api/accounts/check-live-bulk", headers={"X-Auth-Code": "test-auth"},
                                   json={"account_ids": self.ids[:3], "workers": 1})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["workers"], 3)
        self.assertEqual(response.get_json()["queue"]["workers"], 3)
        self.assertEqual(enqueue.call_count, 3)

    def test_api_rejects_invalid_workers_without_enqueuing(self):
        client = create_app(auth_code="test-auth").test_client()
        with patch.object(service, "enqueue_account_live_check") as enqueue:
            response = client.post("/api/accounts/check-live-bulk", headers={"X-Auth-Code": "test-auth"},
                                   json={"account_ids": self.ids[:3], "workers": "bad"})
        self.assertEqual(response.status_code, 400)
        enqueue.assert_not_called()
        self.assertEqual(service.queue_settings()["workers"], 1)

    def test_worker_limits_are_bounded(self):
        service.configure_workers(999)
        self.assertEqual(service.queue_settings()["workers"], 16)
        service.configure_workers(0)
        self.assertEqual(service.queue_settings()["workers"], 1)


if __name__ == "__main__":
    unittest.main()
