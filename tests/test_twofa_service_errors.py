import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from curl_cffi.requests.exceptions import HTTPError
from core import db, twofa_service
from tests.test_forwarded_imap_and_account_import import storage


class TwofaServiceErrorTests(unittest.TestCase):
    def test_inline_and_queued_setups_share_concurrency_limit(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.multiple(db, **storage(Path(tmp)), _LOG_DIR=Path(tmp) / "jobs"), \
             patch.object(twofa_service, "_LOG_DIR", Path(tmp) / "twofa"), \
             patch.object(twofa_service, "_EXECUTION_SLOTS", threading.BoundedSemaphore(1)):
            aids = [db.insert_account(email=f"fixture-{n}@example.test", access_token="fixture") for n in range(3)]
            active = peak = 0
            lock = threading.Lock()
            def make_session(**kwargs):
                return SimpleNamespace(proxy="", device_id="fixture", kind="protocol", is_browser_workflow=False,
                                       fingerprint_summary_text=lambda: "fixture", owner=threading.get_ident())
            def setup(session, *args, **kwargs):
                nonlocal active, peak
                self.assertEqual(session.owner, threading.get_ident())
                with lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.05)
                with lock:
                    active -= 1
                return "JBSWY3DPEHPK3PXP"
            def inline(n):
                return twofa_service.enqueue_account_totp_setup(account_id=aids[n], email=f"fixture-{n}@example.test",
                                                               access_token="fixture", existing_session=make_session())["future"].result()
            with patch("config.roxybrowser.REGISTRATION_DRIVER", "protocol"), \
                 patch("config.email.USE_EMAIL_SERVICE", True), \
                 patch.object(twofa_service, "_resolve_twofa_proxy", return_value=(None, None, "fixture")), \
                 patch("core.workflow_driver.create_account_session", side_effect=make_session), \
                 patch.object(twofa_service, "close_browser_session"), \
                 patch.object(twofa_service, "setup_2fa", side_effect=setup), \
                 ThreadPoolExecutor(max_workers=2) as executor:
                pending = [executor.submit(inline, n) for n in range(2)]
                queued = twofa_service.enqueue_account_totp_setup(account_id=aids[2], email="fixture-2@example.test", access_token="fixture")
                self.assertTrue(queued["future"].result(timeout=10)["ok"])
                self.assertTrue(all(f.result(timeout=10)["ok"] for f in pending))
            self.assertEqual(peak, 1)

    def test_borrowed_registration_session_stays_on_owner_thread_and_is_not_closed(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.multiple(db, **storage(Path(tmp)), _LOG_DIR=Path(tmp) / "jobs"), \
             patch.object(twofa_service, "_LOG_DIR", Path(tmp) / "twofa"):
            aid = db.insert_account(email="fixture@outlook.com", access_token="old")
            owner = threading.get_ident()
            session = SimpleNamespace(proxy="", device_id="original", kind="protocol", is_browser_workflow=False,
                                      fingerprint_summary_text=lambda: "fixture")
            def setup(env, email, access_token):
                self.assertIs(env, session)
                self.assertEqual(threading.get_ident(), owner)
                env._twofa_session_info = {"accessToken": "after-activation", "user": {"mfa": True}}
                return "JBSWY3DPEHPK3PXP"
            with patch("config.roxybrowser.REGISTRATION_DRIVER", "protocol"), \
                 patch("config.email.USE_EMAIL_SERVICE", True), \
                 patch.object(twofa_service, "_resolve_twofa_proxy") as route, \
                 patch("core.workflow_driver.create_account_session") as factory, \
                 patch.object(twofa_service, "close_browser_session") as close, \
                 patch.object(twofa_service, "setup_2fa", side_effect=setup):
                queued = twofa_service.enqueue_account_totp_setup(account_id=aid, email="fixture@outlook.com",
                                                                  access_token="old", existing_session=session)
                self.assertTrue(queued["future"].done())
                self.assertTrue(queued["future"].result()["ok"])
            factory.assert_not_called()
            route.assert_not_called()
            close.assert_not_called()
            self.assertEqual(db.get_account(aid)["access_token"], "after-activation")
            self.assertTrue(db.get_account(aid)["totp_secret"])
            self.assertFalse(twofa_service.is_running(aid))

    def run_failure(self, code, status=401, path="activate_enrollment"):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.multiple(db, **storage(Path(tmp)), _LOG_DIR=Path(tmp) / "jobs"), \
             patch.object(twofa_service, "_LOG_DIR", Path(tmp) / "twofa"):
            email = "fixture@outlook.com"
            db.import_outlook_accounts([{"email": email, "password": "fixture", "client_id": "fixture", "refresh_token": "fixture"}])
            aid = db.insert_account(email=email, access_token="fixture", email_source="outlook")
            response = SimpleNamespace(status_code=status, url="https://example.test/mfa/" + path,
                                       json=lambda: {"error": {"code": code}})
            error = HTTPError("HTTP Error " + str(status), 0, response)
            session = SimpleNamespace(proxy="", proxy_target="", device_id="fixture", kind="protocol",
                                      is_browser_workflow=False, fingerprint_summary_text=lambda: "fixture")
            with patch("config.roxybrowser.REGISTRATION_DRIVER", "protocol"), \
                 patch("config.email.USE_EMAIL_SERVICE", True), \
                 patch.object(twofa_service, "_resolve_twofa_proxy", return_value=(None, None, "fixture")), \
                 patch("core.workflow_driver.create_account_session", return_value=session), \
                 patch.object(twofa_service, "close_browser_session"), \
                 patch.object(twofa_service, "setup_2fa", side_effect=error):
                queued = twofa_service.enqueue_account_totp_setup(account_id=aid, email=email, access_token="fixture")
                self.assertTrue(queued["accepted"])
                result = queued["future"].result(timeout=10)
            return result, db.get_account(aid), db.get_outlook_by_email(email)

    def test_activate_revoked_token_is_action_required_not_deactivated(self):
        result, account, mailbox = self.run_failure("token_revoked")
        self.assertFalse(result["ok"])
        self.assertEqual(account.get("live_check_status"), "action_required")
        self.assertEqual(account.get("live_check_error_code"), "token_revoked")
        self.assertEqual(account.get("live_check_stage"), "twofa_activate")
        self.assertEqual(account.get("totp_setup_error_code"), "token_revoked")
        self.assertEqual(account.get("totp_setup_http_status"), 401)
        self.assertEqual(account.get("totp_setup_stage"), "twofa_activate")
        self.assertFalse(account.get("totp_secret"))
        self.assertFalse(account.get("archived", False))
        self.assertNotEqual(mailbox.get("status"), "disabled")

    def test_explicit_deactivation_in_error_body_disables_mailbox(self):
        _, account, mailbox = self.run_failure("account_deactivated", 403)
        self.assertEqual(account.get("live_check_status"), "deactivated")
        self.assertTrue(account.get("archived"))
        self.assertEqual(mailbox.get("status"), "disabled")

    def test_wrong_otp_401_is_not_a_revoked_access_token(self):
        _, account, mailbox = self.run_failure("invalid_otp", path="email-otp/validate")
        self.assertNotIn(account.get("live_check_status"), {"action_required", "deactivated"})
        self.assertNotEqual(mailbox.get("status"), "disabled")

    def test_malformed_response_url_does_not_hide_original_error(self):
        response = SimpleNamespace(status_code=401, url="http://[invalid", json=lambda: {"error": {"code": "token_revoked"}})
        error = HTTPError("HTTP Error 401", 0, response)
        self.assertEqual(twofa_service._error_context(error), ("token_revoked", 401, "twofa_reauth"))


if __name__ == "__main__":
    unittest.main()
