import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import account_liveness as liveness, db
from tests.test_forwarded_imap_and_account_import import storage


class _Response:
    status_code = 302
    headers = {"location": "https://auth.openai.com/authorize/continue?state=x"}
    text = ""

    def raise_for_status(self):
        return None

    def json(self):
        return {}


class _Session:
    def __init__(self):
        self.posts = []

    def get_auth_headers(self, referer=""):
        return {"referer": referer, "content-type": "application/json"}

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return _Response()


class WorkspaceSelectionTests(unittest.TestCase):
    def test_default_organization_and_personal_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))), \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "at"}):
            db.import_registered_gpt_accounts([{"email": "a@example.test", "access_token": ""}])
            session = _Session()
            result = {"oai-client-auth-session": {"workspaces": [
                {"id": "org-1", "name": "团队", "kind": "organization"},
                {"id": "personal-1", "name": None, "kind": "personal"},
            ]}}
            self.assertEqual(liveness._select_workspace_and_fetch(session, "a@example.test", result)["accessToken"], "at")
            self.assertIn('"workspace_id": "org-1"', session.posts[0][1]["data"])
            db.update_account_workspace_preference(1, "personal")
            session = _Session()
            liveness._select_workspace_and_fetch(session, "a@example.test", result)
            self.assertIn('"workspace_id": "personal-1"', session.posts[0][1]["data"])

    def test_multiple_organizations_require_explicit_id(self):
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))):
            db.import_registered_gpt_accounts([{"email": "a@example.test", "access_token": ""}])
            result = {"oai-client-auth-session": {"workspaces": [
                {"id": "org-1", "name": "团队一", "kind": "organization"},
                {"id": "org-2", "name": "团队二", "kind": "organization"},
            ]}}
            with self.assertRaisesRegex(liveness.WorkspaceSelectionRequiredError, "多个同类"):
                liveness._select_workspace_and_fetch(_Session(), "a@example.test", result)
            self.assertEqual(len(db.get_account(1)["workspace_options"]), 2)


if __name__ == "__main__":
    unittest.main()
