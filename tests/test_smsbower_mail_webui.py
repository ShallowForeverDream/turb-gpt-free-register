# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from core import db, registration_service
from tests.test_forwarded_imap_and_account_import import storage

from config import email as email_config
from webui.app import create_app


class SmsBowerMailWebUiTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)), _DATA_DIR=Path(root.name), _LOG_DIR=Path(root.name)/"logs")
        state.start()
        self.addCleanup(state.stop)
        workers = patch.object(registration_service, "get_executor_workers", return_value=2)
        workers.start()
        self.addCleanup(workers.stop)
        ready = patch("core.workflow_driver.require_driver_ready", return_value="protocol")
        ready.start()
        self.addCleanup(ready.stop)
        self.client = create_app(auth_code="test-auth").test_client()
        self.client.environ_base["HTTP_X_AUTH_CODE"] = "test-auth"

    @patch("webui.app.svc.submit_registration")
    def test_jobs_rejects_smsbower_mail_without_key(self, submit_registration):
        submit_registration.return_value = []
        with patch.object(email_config, "USE_EMAIL_SERVICE", True), patch.object(
            email_config, "EMAIL_SOURCE", "smsbower_mail"
        ), patch.object(email_config, "SMSBOWER_MAIL_API_BASE", "https://smsbower.page/api/mail"), patch.object(
            email_config, "SMSBOWER_MAIL_API_KEY", ""
        ), patch(
            "config.codex.SMSBOWER_API_KEY", ""
        ):
            response = self.client.post("/api/jobs", json={"count": 1, "workers": 1})

        self.assertEqual(response.status_code, 400)
        self.assertIn("SMSBower API Key", response.get_json()["error"])
        submit_registration.assert_not_called()

    @patch("webui.app.svc.submit_registration", return_value=[{"id": 1}])
    @patch("webui.app.db.outlook_pool_summary")
    def test_jobs_with_smsbower_mail_config_skips_local_pool(self, outlook_pool_summary, submit_registration):
        outlook_pool_summary.return_value = {"total": 0, "available": 0, "used": 0, "failed": 0}
        with patch.object(email_config, "USE_EMAIL_SERVICE", True), patch.object(
            email_config, "EMAIL_SOURCE", "smsbower_mail"
        ), patch.object(email_config, "SMSBOWER_MAIL_API_BASE", "https://smsbower.page/api/mail"), patch.object(
            email_config, "SMSBOWER_MAIL_API_KEY", "mail-key"
        ):
            response = self.client.post("/api/jobs", json={"count": 1, "workers": 1})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["warning"], "")
        outlook_pool_summary.assert_not_called()
        submit_registration.assert_called_once_with(count=1, workers=2)


if __name__ == "__main__":
    unittest.main()
