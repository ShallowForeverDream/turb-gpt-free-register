import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db, registration_service as svc
from tests.test_forwarded_imap_and_account_import import storage


class RegistrationQueueRaceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        state = patch.multiple(db, **storage(self.root), _LOG_DIR=self.root / "logs")
        state.start()
        self.addCleanup(state.stop)
        self.job = db.create_job("outlook", "fixture@example.test")
        self.jid = self.job["id"]
        self.addCleanup(svc._deactivate_job, self.jid)

    def stale_first_read(self, status, new_status):
        original = db.get_job
        calls = 0

        def get(jid):
            nonlocal calls
            snapshot = original(jid)
            calls += 1
            if calls == 1:
                self.assertEqual(snapshot["status"], status)
                db.update_job(jid, status=new_status)
            return snapshot
        return patch.object(db, "get_job", side_effect=get)

    def test_cancel_that_loses_to_worker_start_sends_stop_instead(self):
        svc._activate_job(self.jid)
        with self.stale_first_read("pending", "running"):
            result = svc.request_stop_job(self.jid)
        self.assertEqual(result["state"], "stopping")
        self.assertEqual(db.get_job(self.jid)["status"], "stopping")
        self.assertTrue(svc.is_stop_requested(self.jid))

    def test_stop_that_loses_to_completion_cannot_overwrite_success(self):
        svc._activate_job(self.jid)
        db.update_job(self.jid, status="running")
        with self.stale_first_read("running", "success"):
            result = svc.request_stop_job(self.jid)
        self.assertEqual(result["state"], "success")
        self.assertEqual(db.get_job(self.jid)["status"], "success")

    def test_all_terminal_states_are_already_finished(self):
        for status in ("partial_success", "disabled", "blocked", "already_registered"):
            db.update_job(self.jid, status=status)
            result = svc.request_stop_job(self.jid)
            self.assertTrue(result["ok"])
            self.assertEqual(result["state"], status)

    def test_cancel_between_worker_read_and_start_never_executes(self):
        with self.stale_first_read("pending", "cancelled"), \
             patch("main.run_registration") as run:
            svc._run_one_job(self.jid, self.job["log_file"])
        run.assert_not_called()
        self.assertEqual(db.get_job(self.jid)["status"], "cancelled")
        self.assertNotIn(self.jid, svc._ACTIVE_JOBS)

    def test_batch_cancel_cannot_overwrite_a_started_job(self):
        snapshot = db.list_jobs()
        db.update_job(self.jid, status="running")
        with patch.object(db, "list_jobs", return_value=snapshot):
            self.assertEqual(svc.cancel_pending_jobs(), 0)
        self.assertEqual(db.get_job(self.jid)["status"], "running")

    def test_only_one_of_five_workers_can_claim_the_same_row(self):
        with ThreadPoolExecutor(max_workers=5) as executor:
            claims = list(executor.map(lambda _: db.update_job_if_status(
                self.jid, ("pending",), status="running"), range(5)))
        self.assertEqual(sum(claims), 1)


if __name__ == "__main__":
    unittest.main()
