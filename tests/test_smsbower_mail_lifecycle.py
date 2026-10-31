"""Offline integration checks: real dispatcher/journal, fake upstream only."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from core import db, email_provider, registration_completion as completion
from core import smsbower_mail_client as mail
from tests.test_forwarded_imap_and_account_import import storage


class SmsBowerLifecycleTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        state = patch.multiple(db, **storage(Path(root.name)), _DATA_DIR=Path(root.name), _LOG_DIR=Path(root.name)/"logs")
        state.start()
        self.addCleanup(state.stop)
        mail._CONTEXT_CACHE.clear()
        self.addCleanup(mail._CONTEXT_CACHE.clear)

    def test_completion_only_closes_after_all_steps_and_only_once(self):
        row = {"email": "fixture@gmail.com", "email_source": "smsbower_mail"}
        with patch.object(db, "get_account", return_value=row), \
             patch.object(mail, "mark_success_closed", return_value="closed") as close:
            result = {"success": True, "account_id": 1, "completion": {"status": "success"}}
            completion.complete_registration_result(result)
            completion.complete_registration_result(result)
            close.assert_called_once_with(row["email"])

    def test_codex_failure_or_partial_completion_keeps_mail_open(self):
        row = {"email": "fixture@gmail.com", "email_source": "smsbower_mail"}
        with patch.object(db, "get_account", return_value=row), \
             patch.object(mail, "mark_success_closed") as close:
            for success, state in [(False, "success"), (True, "partial"), (True, "login_required")]:
                completion.complete_registration_result({"success": success, "account_id": 1,
                                                        "completion": {"status": state}})
            close.assert_not_called()

    def test_uncertain_close_is_visible_as_partial_success_without_replay(self):
        row = {"email": "fixture@gmail.com", "email_source": "smsbower_mail"}
        with patch.object(db, "get_account", return_value=row), \
             patch.object(mail, "mark_success_closed", return_value="pending") as close:
            result = {"success": True, "account_id": 1, "completion": {"status": "success"}}
            completion.complete_registration_result(result)
            completion.complete_registration_result(result)
        close.assert_called_once()
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "partial_success")

    def test_non_sms_pools_keep_existing_failure_state(self):
        with patch.object(email_provider, "resolve_email_source", return_value="imap"), \
             patch("core.imap_mail_client.release_account") as release:
            email_provider.release_email("fixture@example.test", status="failed_created")
            release.assert_called_once_with("fixture@example.test", status="failed", note=None)

    def test_source_and_creation_state_survive_restart_before_local_account(self):
        account = mail.SmsBowerMailAccount("fixture@gmail.com", "4")
        mail._CONTEXT_CACHE[account.email] = account
        mail.release_account(account.email, status="failed_created")
        mail._CONTEXT_CACHE.clear()
        with patch.object(db, "get_account_by_email", return_value=None):
            self.assertEqual(email_provider.resolve_email_source(account.email), "smsbower_mail")
            with patch.object(mail, "_request") as request:
                self.assertFalse(email_provider.release_email_if_unconsumed(""))
                email_provider.release_email_if_unconsumed(account.email)
                request.assert_not_called()

    def test_unresolved_paid_allocation_does_not_fall_back_to_another_supplier(self):
        with patch.object(email_provider, "parse_email_sources", return_value=["smsbower_mail", "remail"]), \
             patch.object(email_provider, "_pick_from_source", side_effect=mail.SmsBowerMailError("unresolved")) as pick:
            with self.assertRaises(mail.SmsBowerMailError):
                email_provider.acquire_email()
            pick.assert_called_once_with("smsbower_mail")

    def test_protocol_preflight_refusal_never_purchases_mail(self):
        import main
        from config import email, openai_protocol
        session = Mock(proxy=None, device_id="fixture", auth_session_logging_id="fixture")
        with patch("core.workflow_driver.require_driver_ready", return_value="protocol"), \
             patch.object(email, "USE_EMAIL_SERVICE", True), \
             patch.object(main, "BrowserSession", return_value=session), \
             patch.object(main, "network_preflight", side_effect=RuntimeError("HTTP 429")), \
             patch.object(main, "acquire_email") as acquire, \
             patch.object(main, "close_browser_session"), patch.object(db, "update_account_flow"):
            result = main.run_registration(email=None, name="Fixture User", birthday="1990-01-01")
        self.assertFalse(result["success"])
        acquire.assert_not_called()
