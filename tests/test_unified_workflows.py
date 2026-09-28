import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from config import roxybrowser as cfg
from core import workflow_driver as router
from core import account_liveness, db, email_change_service
from core.browser_workflows import BrowserAccountSession, BrowserActionRequired, BrowserHTTPError
from tests.test_forwarded_imap_and_account_import import storage


class RoutingTests(unittest.TestCase):
    def test_one_setting_overrides_old_codex_choice(self):
        from core import codex_oauth
        with patch.object(cfg, "REGISTRATION_DRIVER", "roxy"),              patch("config.codex.CODEX_OAUTH_DRIVER", "protocol"),              patch.object(router, "require_driver_ready", return_value="roxy"),              patch("core.roxy_codex_oauth.run_roxy_codex_oauth", return_value={"ok": True}) as browser,              patch.object(codex_oauth, "BrowserSession") as protocol:
            self.assertTrue(codex_oauth.run_codex_oauth("a@example.test", force=True)["ok"])
        browser.assert_called_once()
        protocol.assert_not_called()

    def test_driver_pinned_during_operation(self):
        @router.unified_workflow("test")
        def task():
            with patch.object(cfg, "REGISTRATION_DRIVER", "roxy"):
                return router.resolve_driver()
        with patch.object(cfg, "REGISTRATION_DRIVER", "protocol"):
            self.assertEqual(task(), "protocol")
        self.assertIsNone(router._ACTIVE.get())

    def test_unknown_driver_not_silently_protocol(self):
        with patch.object(cfg, "REGISTRATION_DRIVER", "missing"):
            with self.assertRaises(ValueError):
                router.create_account_session()

    def test_browser_factory_never_creates_protocol_session(self):
        factory = Mock()
        with patch.object(cfg, "REGISTRATION_DRIVER", "roxy"),              patch.object(router, "require_driver_ready", return_value="roxy"),              patch("core.browser_workflows.BrowserAccountSession", return_value="browser") as ctor:
            self.assertEqual(router.create_account_session(proxy="http://127.0.0.1:1", protocol_factory=factory), "browser")
        factory.assert_not_called()
        ctor.assert_called_once_with("roxy", proxy="http://127.0.0.1:1")

    def test_live_check_uses_browser_and_does_not_enter_protocol_login(self):
        browser = Mock()
        browser.login.return_value = {"accessToken": "at", "user": {"email": "a@example.test"}}
        browser.fingerprint_summary.return_value = {"driver": "roxy"}
        browser.fingerprint_summary_text.return_value = "driver=roxy"
        browser.proxy = ""
        browser._live_workspace_selected = None
        manager = Mock(__enter__=Mock(return_value=browser), __exit__=Mock(return_value=False))
        with tempfile.TemporaryDirectory() as tmp, patch.object(account_liveness, "_LOG_DIR", Path(tmp)),              patch.object(cfg, "REGISTRATION_DRIVER", "roxy"),              patch.object(router, "require_driver_ready", return_value="roxy"),              patch("core.browser_workflows.BrowserAccountSession", return_value=manager),              patch.object(account_liveness, "BrowserSession") as protocol:
            result = account_liveness.check_account_liveness("a@example.test", email_source="imap")
        self.assertEqual(result["driver"], "roxy")
        self.assertTrue(result["ok"])
        browser.login.assert_called_once_with("a@example.test", email_source="imap")
        protocol.assert_not_called()
        manager.__exit__.assert_called_once()

    def test_browser_email_change_never_replaces_session_on_error(self):
        browser = Mock(is_browser_workflow=True)
        with patch.object(email_change_service, "_post", side_effect=RuntimeError("HTTP 403")),              patch.object(email_change_service, "_new_session") as fallback:
            with self.assertRaises(RuntimeError):
                email_change_service._post_with_network_retry(
                    browser, account_id=1, path="/x", token="at", payload={}
                )
        fallback.assert_not_called()

    def test_missing_roxy_config_stops_before_job_creation(self):
        from webui.app import create_app
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(db, **storage(Path(tmp))),              patch.object(cfg, "REGISTRATION_DRIVER", "roxy"),              patch.object(cfg, "ROXY_API_TOKEN", ""),              patch("webui.app.svc.submit_registration") as submit:
            client = create_app(auth_code="test").test_client()
            with patch.object(router, "require_driver_ready", side_effect=RuntimeError("Roxy API Token 未配置")):
                result = client.post("/api/jobs", json={"count": 1}, headers={"X-Auth-Code":"test"})
            self.assertEqual(result.status_code, 409)
            self.assertEqual(db.list_jobs(), [])
            with patch.object(router, "require_driver_ready", side_effect=RuntimeError("Roxy API Token 未配置")):
                self.assertEqual(client.get("/api/workflow-driver", headers={"X-Auth-Code":"test"}).get_json()["ready"], False)
        submit.assert_not_called()


class BrowserTransportTests(unittest.TestCase):
    def browser(self):
        driver = Mock(current_url="https://chatgpt.com/")
        driver.execute_script.return_value = {}
        session = BrowserAccountSession("roxy", driver=driver)
        driver.execute_async_script.return_value = {
            "status":200, "url":"https://chatgpt.com/backend-api/test", "text":"{}", "headers":{}
        }
        return session, driver

    def test_fetch_uses_browser_and_strips_forged_transport_headers(self):
        browser, driver = self.browser()
        response = browser.post("https://chatgpt.com/backend-api/test",
                                headers={"User-Agent":"fake", "Cookie":"secret", "Origin":"fake",
                                         "authorization":"Bearer own-token", "Sec-Fetch-Site":"none"},
                                json={"test":True})
        self.assertEqual(response.status_code, 200)
        args = driver.execute_async_script.call_args.args
        self.assertEqual(args[3], {"authorization":"Bearer own-token","content-type":"application/json"})
        self.assertEqual(json.loads(args[4]), {"test":True})
        self.assertIn("redirect:'error'", args[0])
        browser.close()
        driver.quit.assert_not_called()  # borrowed context

    def test_disallows_token_transmission_to_other_hosts(self):
        browser, driver = self.browser()
        for target in ("https://other.test/api", "http://chatgpt.com/api", "https://chatgpt.com.evil.test/api"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                browser.post(target, headers={"authorization":"Bearer secret"})
        driver.execute_async_script.assert_not_called()

    def test_forbidden_response_and_fetch_errors_do_not_fallback(self):
        browser, driver = self.browser()
        driver.execute_async_script.return_value = {"status":403,"url":"https://chatgpt.com/auth/login"}
        with self.assertRaises(BrowserHTTPError):
            browser.get("https://chatgpt.com/api/auth/session")
        driver.execute_async_script.return_value = {"error":True}
        with self.assertRaisesRegex(RuntimeError, "不会切换"):
            browser.get("https://chatgpt.com/api/auth/session")

    def test_init_failure_closes_created_browser(self):
        driver = Mock()
        driver.execute_script.side_effect = RuntimeError("browser disconnected")
        def open_browser(stack, *_):
            stack.callback(driver.quit)
            return driver, SimpleNamespace(raw={})
        with patch("core.browser_workflows._open_browser", side_effect=open_browser):
            with self.assertRaises(RuntimeError):
                BrowserAccountSession("roxy")
        driver.quit.assert_called_once()

    def test_login_rejects_wrong_account(self):
        browser, driver = self.browser()
        driver.execute_async_script.return_value = {
            "status":200, "url":"https://chatgpt.com/api/auth/session",
            "text":json.dumps({"accessToken":"at","user":{"email":"other@example.test"}})
        }
        with self.assertRaisesRegex(BrowserActionRequired, "不一致"):
            browser.login("a@example.test")

    def test_existing_mfa_does_not_enroll_again(self):
        browser, driver = self.browser()
        with patch.object(browser, "login", return_value={"accessToken":"at","user":{"mfa":True}}),              patch("core.account_export._enroll_totp") as enroll:
            with self.assertRaisesRegex(BrowserActionRequired, "已开启 MFA"):
                browser.setup_twofa("a@example.test")
        enroll.assert_not_called()

    def test_workspace_ambiguity_requires_choice(self):
        browser, driver = self.browser()
        driver.execute_script.return_value = [
            {"id":"one","kind":"organization","name":"One"},
            {"id":"two","kind":"organization","name":"Two"},
        ]
        with patch.object(db, "update_account_workspace_options"),              patch.object(db, "get_account_by_email", return_value={"workspace_preference":"organization"}),              patch("core.roxy_registration._human_click") as click:
            with self.assertRaisesRegex(BrowserActionRequired, "指定"):
                browser._choose_workspace("a@example.test")
        click.assert_not_called()


if __name__ == "__main__":
    unittest.main()
