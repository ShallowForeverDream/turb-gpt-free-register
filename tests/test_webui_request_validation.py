import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class ApiRequestValidationTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(patch.multiple(db, **storage(root)))
        self.client = create_app(auth_code="fixture").test_client()
        self.headers = {"X-Auth-Code": "fixture"}

    def test_non_object_json_is_rejected_before_dispatch_or_driver_check(self):
        with patch("core.workflow_driver.require_driver_ready") as driver, \
             patch("webui.app.svc.submit_registration") as submit:
            for path in ("/api/jobs", "/api/accounts/1/note", "/api/jobs/concurrency"):
                for body in ('[1]', '"private-fixture"', '123', 'true', 'null', '{bad'):
                    with self.subTest(path=path, body=body):
                        response = self.client.post(path, headers=self.headers,
                            data=body, content_type="application/json")
                        self.assertEqual(response.status_code, 400)
                        self.assertNotIn("private-fixture", response.get_data(as_text=True))
            driver.assert_not_called()
            submit.assert_not_called()

    def test_invalid_json_does_not_bypass_authentication(self):
        self.assertEqual(self.client.post("/api/jobs", json=[1]).status_code, 401)


if __name__ == "__main__":
    unittest.main()
