import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from config import email as email_cfg, register as register_cfg
from core import db, email_provider, registration_service as service
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class RegistrationEmailSourceChoiceTests(unittest.TestCase):
    def setUp(self):
        from core import registration_service
        self.addCleanup(registration_service.configure_workers, registration_service.get_executor_workers())
        registration_service.configure_workers(3)
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        state = patch.multiple(db, **{**storage(self.root), "_LOG_DIR": self.root / "logs"})
        state.start()
        self.addCleanup(state.stop)
        self.client = create_app(auth_code="fixture-auth").test_client()
        self.headers = {"X-Auth-Code": "fixture-auth", "Accept-Encoding": "identity"}

    def test_request_uses_chosen_source_instead_of_global_fallbacks(self):
        with patch.object(email_cfg, "EMAIL_SOURCE", "remail"), patch.object(email_cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(service, "submit_registration", return_value=[]) as submit:
            response = self.client.post("/api/jobs", headers=self.headers,
                                        json={"count": 3, "workers": 3, "email_source": "imap"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["email_sources"], ["imap"])
            submit.assert_called_once_with(count=3, workers=3, email_source="imap")
            self.assertEqual(email_cfg.EMAIL_SOURCE, "remail")

    def test_invalid_type_never_submits_a_job(self):
        with patch.object(service, "submit_registration") as submit:
            response = self.client.post("/api/jobs", headers=self.headers,
                                        json={"count": 1, "email_source": "not-a-source"})
            self.assertEqual(response.status_code, 400)
            submit.assert_not_called()

    def test_selected_addresses_cannot_conflict_with_chosen_type(self):
        with patch.object(service, "submit_registration") as submit, patch.object(db, "claim_pool_emails") as claim:
            response = self.client.post("/api/jobs", headers=self.headers, json={"email_source": "outlook",
                "selected_emails": [{"email": "fixture@example.test", "source": "imap"}]})
            self.assertEqual(response.status_code, 400)
            claim.assert_not_called()
            submit.assert_not_called()

    def test_manual_otp_mode_does_not_silently_ignore_type_selection(self):
        with patch.object(email_cfg, "USE_EMAIL_SERVICE", False), patch.object(service, "submit_registration") as submit:
            response = self.client.post("/api/jobs", headers=self.headers, json={"count": 1, "email_source": "imap"})
            self.assertEqual(response.status_code, 400)
            submit.assert_not_called()

    def test_empty_choice_preserves_existing_configuration(self):
        with patch.object(email_cfg, "EMAIL_SOURCE", "outlook"), patch.object(email_cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(service, "submit_registration", return_value=[]) as submit:
            response = self.client.post("/api/jobs", headers=self.headers, json={"count": 1, "workers": 3})
            self.assertEqual(response.status_code, 200)
            submit.assert_called_once_with(count=1, workers=3)

    def test_worker_honors_saved_job_source_without_mutating_config(self):
        job = db.create_job(email_source="imap")
        observed = []

        def register(**kwargs):
            observed.append(email_provider.parse_email_sources())
            return {"success": False, "error": "fixture, no remote registration"}

        with patch.object(email_cfg, "EMAIL_SOURCE", "outlook"), patch.object(email_cfg, "USE_EMAIL_SERVICE", True), \
             patch("main.run_registration", side_effect=register), \
             patch.object(service, "_prepare_registration_args", return_value=(None, "Fixture User", "1990-01-01")):
            service._run_one_job(job["id"], job["log_file"])
            self.assertEqual(observed, [["imap"]])
            self.assertEqual(email_provider.parse_email_sources(), ["outlook"])

    def test_two_parallel_jobs_keep_their_source_choices_separate(self):
        barrier = threading.Barrier(2)

        def run(source):
            with email_provider.use_email_sources(source):
                barrier.wait(timeout=3)
                return email_provider.acquire_email()

        with patch.object(email_cfg, "EMAIL_SOURCE", "generic_api"), \
             patch.object(email_provider, "_pick_from_source", side_effect=lambda source: source + "@example.test"), \
             ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(run, ["outlook", "imap"]))
            self.assertEqual(results, ["outlook@example.test", "imap@example.test"])
            self.assertEqual(email_provider.parse_email_sources(), ["generic_api"])

    def test_chosen_source_never_falls_back_to_other_types(self):
        with patch.object(email_cfg, "EMAIL_SOURCE", "imap,outlook"), \
             patch.object(email_provider, "_pick_from_source", side_effect=RuntimeError("fixture empty pool")) as pick, \
             email_provider.use_email_sources("outlook"):
            with self.assertRaises(RuntimeError):
                email_provider.acquire_email()
            pick.assert_called_once_with("outlook")

    def test_automatic_pool_mode_ignores_stale_manual_email(self):
        with patch.object(email_cfg, "USE_EMAIL_SERVICE", True), \
             patch.object(register_cfg, "REGISTER_EMAIL", "stale@example.test"):
            self.assertIsNone(service._prepare_registration_args()[0] or None)
            self.assertEqual(service._prepare_registration_args("chosen@example.test")[0], "chosen@example.test")


if __name__ == "__main__":
    unittest.main()
