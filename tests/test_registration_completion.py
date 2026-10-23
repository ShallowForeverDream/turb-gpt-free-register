import json
from concurrent.futures import ThreadPoolExecutor
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core import protocol_traffic, registration_completion
from core.workflow_driver import submit_with_driver
from webui.app import _account_secret_value, _compact_account_for_list, create_app
from tests.test_forwarded_imap_and_account_import import storage


class RegistrationCompletionTests(unittest.TestCase):
    def test_separate_passwords_are_on_demand_and_not_bulk_disclosed(self):
        row = {"id": 99999, "email": "fixture@outlook.com", "email_source": "outlook",
               "password": "mail-password", "extra_json": json.dumps({"registration_password": "gpt-password"})}
        with patch("webui.app.db.get_outlook_by_email", return_value={"password": "mail-password"}):
            compact = _compact_account_for_list(row)
            self.assertTrue(compact["has_gpt_password"])
            self.assertTrue(compact["has_mail_password"])
            self.assertNotIn("password", compact)
            self.assertNotIn("mail-password", json.dumps(compact))
            self.assertEqual(_account_secret_value(row, "password"), "gpt-password")
            self.assertEqual(_account_secret_value(row, "mail_password"), "mail-password")
            row["extra_json"] = "{}"
            self.assertEqual(_account_secret_value(row, "password"), "未设置")

    def test_forwarded_imap_does_not_expose_receiver_authorization(self):
        row = {"email_source": "imap", "password": "shared-imap-authorization"}
        self.assertEqual(_account_secret_value(row, "mail_password"), "")

    def test_outlook_otp_query_uses_saved_source_without_sending_mail(self):
        from core import db
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))), \
             patch("webui.app.db.get_account", return_value={"email": "fixture@outlook.com", "email_source": "outlook"}), \
             patch("core.email_provider.wait_for_otp", return_value="123456") as wait:
            client = create_app(auth_code="fixture").test_client()
            response = client.get("/api/accounts/99999/email-otp", headers={"X-Auth-Code": "fixture"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(wait.call_args.kwargs["email_source"], "outlook")
        self.assertTrue(wait.call_args.kwargs["force_service"])

    def test_joined_queues_are_ordered_and_counted_before_meter_closes(self):
        events = []
        response = SimpleNamespace(upload_size=10, request_size=0, download_size=20, header_size=0, content=b"x", redirect_count=0)
        with ThreadPoolExecutor(max_workers=1) as executor:
            def enqueue(stage):
                def run(**kwargs):
                    def task():
                        events.append(stage)
                        protocol_traffic.current_traffic().record("https://example.test/" + stage, response)
                        return {"ok": True}
                    return {"accepted": True, "future": submit_with_driver(executor, task)}
                return run

            @protocol_traffic.capture_protocol_registration
            @registration_completion.complete_registration_flow
            def register():
                self.assertTrue(registration_completion.completion_managed())
                protocol_traffic.current_traffic().record("https://example.test/register", response)
                return {"success": True, "account_id": 99999}

            with patch("core.workflow_driver.resolve_driver", return_value="protocol"), \
                 patch("core.registration_completion.db.get_account", return_value={"id": 99999, "email": "fixture@example.test", "access_token": "fixture"}), \
                 patch("core.registration_completion.db.update_account_flow") as save, \
                 patch("config.register.AUTO_PLAN_CHECK_AFTER_REGISTER", True), \
                 patch("config.twofa.ENABLE_2FA", True), \
                 patch("core.plan_check_service.enqueue_account_plan_check", side_effect=enqueue("plan")), \
                 patch("core.twofa_service.enqueue_account_totp_setup", side_effect=enqueue("twofa")):
                result = register()
        self.assertEqual(events, ["plan", "twofa"])
        self.assertEqual(result["network_traffic"]["total_bytes"], 90)
        self.assertEqual(result["completion"]["status"], "success")
        self.assertIsNone(protocol_traffic.current_traffic())
        self.assertFalse(registration_completion.completion_managed())
        self.assertEqual(save.call_args.kwargs["traffic"]["total_bytes"], 90)

    def test_disabled_post_steps_do_not_enqueue(self):
        with patch("core.registration_completion.db.get_account", return_value={"email": "fixture@example.test", "access_token": "fixture"}), \
             patch("core.registration_completion.db.update_account_flow"), \
             patch("config.register.AUTO_PLAN_CHECK_AFTER_REGISTER", False), \
             patch("config.twofa.ENABLE_2FA", False), \
             patch("core.plan_check_service.enqueue_account_plan_check") as plan, \
             patch("core.twofa_service.enqueue_account_totp_setup") as twofa:
            result = registration_completion.finish_account(99999)
        plan.assert_not_called()
        twofa.assert_not_called()
        self.assertEqual(result, {"plan": "skipped", "twofa": "skipped", "status": "success"})

    def test_unknown_registration_time_never_uses_local_insert_time(self):
        from core.db import _account_registered_at
        self.assertEqual(_account_registered_at({"created_at": "2026-10-23T12:00:00", "extra_json": "{}"}), "")
        self.assertEqual(_account_registered_at({"created_at": "2026-10-23T12:00:00", "extra_json": '{"account":{"createdTime":"invalid"}}'}), "")

    def test_no_session_skips_post_processing(self):
        with patch("core.registration_completion.db.get_account", return_value={"email": "fixture@example.test"}), \
             patch("core.registration_completion.db.update_account_flow"), \
             patch("core.twofa_service.enqueue_account_totp_setup") as twofa:
            result = registration_completion.finish_account(99999)
        self.assertEqual(result["status"], "login_required")
        twofa.assert_not_called()

    def test_post_failure_does_not_erase_registration_success(self):
        @registration_completion.complete_registration_flow
        def register():
            return {"success": True, "account_id": 99999}
        with patch("core.registration_completion.finish_account", return_value={"status": "partial"}):
            self.assertTrue(register()["success"])

    def test_invalid_callback_is_not_replayed_and_uses_one_normal_login(self):
        import main
        session = SimpleNamespace(proxy="fixture-proxy", proxy_target="fixture-proxy")
        info = {"accessToken": "fixture-token"}
        relay = SimpleNamespace(close=lambda: None)
        with patch.object(main, "follow_oauth_callback", side_effect=RuntimeError("OAuth 回调返回认证错误页（error=OAuthCallback）")) as follow, \
             patch.object(main, "close_browser_session"), \
             patch("core.proxy_chain.open_proxy_pool_proxy", return_value=("fixture-transport", relay)), \
             patch("core.email_provider.resolve_email_source", return_value="outlook"), \
             patch("core.account_liveness.check_account_liveness", return_value={"ok": True, "session": info, "access_token": "fixture-token"}) as login:
            result = main._finalize_registration_session(session, "https://chatgpt.com/api/auth/callback/openai", "fixture@outlook.com")
        self.assertEqual(result, (info, "fixture-token"))
        follow.assert_called_once()
        login.assert_called_once()
        self.assertEqual(login.call_args.kwargs["proxy"], "fixture-transport")
        self.assertEqual(login.call_args.kwargs["email_source"], "outlook")

    def test_refusal_does_not_trigger_callback_recovery(self):
        import main
        with patch.object(main, "follow_oauth_callback", side_effect=RuntimeError("HTTP 403")), \
             patch("core.account_liveness.check_account_liveness") as login:
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                main._finalize_registration_session(object(), "https://chatgpt.com/callback", "fixture@example.test")
        login.assert_not_called()


if __name__ == "__main__":
    unittest.main()
