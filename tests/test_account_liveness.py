# -*- coding: utf-8 -*-
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import core.account_liveness as liveness
import core.live_check_service as live_service


class _DummyHttpSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _DummyBrowserSession:
    created = []

    def __init__(self, proxy=None, **kwargs):
        self.proxy = proxy
        self.received_proxy = proxy
        self.device_id = "device-test"
        self.session = _DummyHttpSession()
        self.blocked_until = 0.0
        self.blocked_reason = ""
        self.created.append(self)
        self.kwargs = kwargs

    def fingerprint_summary(self):
        return {
            "proxy": self.proxy or "",
            "user_agent": "test-agent",
            "accept_language": "en-US",
            "timezone_iana": "UTC",
            "timezone_offset_minutes": 0,
            "screen_width": 1440,
            "screen_height": 900,
            "device_pixel_ratio": 2,
            "hardware_concurrency": 8,
            "device_memory": 8,
            "geo_country": "US",
            "geo_city": "Test",
        }

    def fingerprint_summary_text(self):
        return "test-fingerprint"

    def reset_circuit_breaker(self):
        self.blocked_until = 0.0
        self.blocked_reason = ""


class _DummyQueueSlot:
    def __init__(self):
        self.released = False

    def release(self):
        self.released = True


class AccountLivenessTests(unittest.TestCase):
    def setUp(self):
        _DummyBrowserSession.created = []

    def test_reauth_sends_otp_before_polling_verification_page(self):
        session = _DummyBrowserSession(proxy="")
        events = []
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="auth"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value="https://auth.openai.com/email-verification"), \
             patch.object(liveness, "human_delay"), \
             patch.object(liveness, "initialize_passwordless_login_otp", side_effect=lambda *_args, **_kwargs: events.append("send") or False), \
             patch.object(liveness, "_validate_reauth_with_retry", side_effect=lambda *a, **kw: events.append("wait") or "continue") as validate, \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "fixture"}):
            result = liveness._login_via_reauth(session, "fixture@example.test", 1.0, email_source="outlook")
        self.assertEqual(events, ["send", "wait"])
        self.assertGreater(validate.call_args.args[2], 1.0)
        # ICAPI/签名 API 的 30 秒首读延迟必须以验证码页面就绪为锚点，
        # 不能把调用方传入的较早时间当作“页面已等待很久”。
        self.assertGreaterEqual(validate.call_args.kwargs["first_read_anchor_ts"], time.time() - 5)
        self.assertEqual(result["accessToken"], "fixture")

    def test_refused_reauth_otp_send_does_not_start_mail_polling(self):
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="auth"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value="https://auth.openai.com/email-verification"), \
             patch.object(liveness, "human_delay"), \
             patch.object(liveness, "initialize_passwordless_login_otp", side_effect=RuntimeError("HTTP 403")) as send, \
             patch.object(liveness, "_validate_reauth_with_retry") as validate:
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                liveness._login_via_reauth(_DummyBrowserSession(), "fixture@example.test", 1.0)
        send.assert_called_once()
        validate.assert_not_called()

    def test_normal_login_preserves_explicit_deactivation_error_code(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(liveness, "_LOG_DIR", Path(tmp)), \
             patch("core.workflow_driver.resolve_driver", return_value="protocol"), \
             patch.object(liveness, "_stored_access_token", return_value=""), \
             patch.object(liveness, "_account_totp_secret", return_value=""), \
             patch.object(liveness, "_login_via_full_web_flow", side_effect=liveness.AccountUnusableError(
                 "account_deactivated", error_code="account_deactivated")):
            result = liveness.check_account_liveness("fixture@example.test", proxy="")
        self.assertEqual(result["status"], "deactivated")
        self.assertEqual(result["error_code"], "account_deactivated")
        self.assertEqual(result["stage"], "authentication")

    def test_passwordless_login_sends_email_otp_before_waiting(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_network_preflight_with_retry", return_value=(session, "authorize")), \
             patch.object(liveness, "follow_authorize", return_value="https://auth.openai.com/email-verification"), \
             patch.object(liveness, "_account_registration_password", return_value=""), \
             patch.object(liveness, "initialize_passwordless_login_otp", return_value=True) as send, \
             patch.object(liveness, "_login_via_password_or_otp", return_value={"accessToken": "test"}) as login:
            _, info = liveness._login_via_full_web_flow(
                "user@outlook.test", "", email_source="outlook", fingerprint_state={},
            )
        self.assertEqual(info["accessToken"], "test")
        send.assert_called_once_with(
            session, "user@outlook.test", "https://auth.openai.com/email-verification")
        login.assert_called_once()

    def test_reauth_never_calls_direct_resend_for_login_password_page(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="auth"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value="https://auth.openai.com/log-in/password"), \
             patch.object(liveness, "human_delay"), \
             patch.object(liveness, "initialize_passwordless_login_otp", return_value=False), \
             patch.object(liveness, "send_email_otp", side_effect=AssertionError("resend forbidden")), \
             patch.object(liveness, "_validate_reauth_with_retry", return_value="continue") as validate, \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "fixture"}):
            liveness._login_via_reauth(session, "fixture@example.test", 1.0)
        validate.assert_called_once()
        self.assertIsNotNone(validate.call_args.kwargs["first_read_anchor_ts"])

    def test_reauth_error_page_stops_before_wait_or_resend(self):
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="auth"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value="https://auth.openai.com/log-in/password"), \
             patch.object(liveness, "human_delay"), \
             patch.object(liveness, "initialize_passwordless_login_otp",
                          side_effect=liveness.LoginPageUnavailableError("邮箱登录页没有可读取的会话状态，尚未发码")), \
             patch.object(liveness, "send_email_otp", side_effect=AssertionError("resend forbidden")), \
             patch.object(liveness, "wait_for_otp", side_effect=AssertionError("mail read forbidden")):
            with self.assertRaisesRegex(RuntimeError, "重认证登录页不可用"):
                liveness._login_via_reauth(_DummyBrowserSession(), "fixture@example.test", 1.0)

    def test_preflight_preserves_explicit_direct_route_and_skips_providers(self):
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context"), \
             patch.object(liveness, "probe_auth_session"), \
             patch.object(liveness, "get_csrf_token", return_value="csrf"), \
             patch.object(liveness, "signin_openai", return_value="https://auth.example/authorize"):
            session, authorize_url = liveness._network_preflight_with_retry(
                "user@example.com", "", max_attempts=1
            )

        self.assertEqual(session.proxy, "")
        self.assertEqual(authorize_url, "https://auth.example/authorize")
        self.assertTrue(
            session.kwargs["fingerprint_seed"].startswith("live-check:user@example.com:")
        )

    def test_preflight_retries_with_same_session_on_transport_timeout(self):
        csrf_errors = [TimeoutError("connection timeout"), "csrf"]
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context"), \
             patch.object(liveness, "probe_auth_session"), \
             patch.object(liveness, "get_csrf_token", side_effect=csrf_errors), \
             patch.object(liveness, "signin_openai", return_value="authorize"), \
             patch.object(liveness.time, "sleep"):
            session, _ = liveness._network_preflight_with_retry(
                "user@example.com", None, max_attempts=2
            )

        self.assertIs(_DummyBrowserSession.created[-1], session)
        self.assertEqual(len(_DummyBrowserSession.created), 1)
        self.assertFalse(_DummyBrowserSession.created[0].session.closed)
        self.assertIsNone(_DummyBrowserSession.created[0].received_proxy)

    def test_preflight_rebuilds_transport_on_boringssl_reset(self):
        state = {}
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context", side_effect=[
                 RuntimeError("curl: (35) BoringSSL SSL_connect: Connection closed abruptly"),
                 None,
             ]), \
             patch.object(liveness, "probe_auth_session"), \
             patch.object(liveness, "get_csrf_token", return_value="csrf"), \
             patch.object(liveness, "signin_openai", return_value="authorize"), \
             patch.object(liveness.time, "sleep"):
            session, _ = liveness._network_preflight_with_retry(
                "user@example.com", "proxy", max_attempts=2, fingerprint_state=state
            )

        self.assertIs(_DummyBrowserSession.created[-1], session)
        self.assertEqual(len(_DummyBrowserSession.created), 2)
        self.assertTrue(_DummyBrowserSession.created[0].session.closed)
        self.assertFalse(_DummyBrowserSession.created[1].session.closed)
        self.assertEqual(
            _DummyBrowserSession.created[0].kwargs["fingerprint_seed"],
            _DummyBrowserSession.created[1].kwargs["fingerprint_seed"],
        )

    def test_callback_403_stops_before_fetching_token(self):
        session = _DummyBrowserSession(proxy="proxy")
        with patch.object(
            liveness,
            "follow_oauth_callback",
            side_effect=[RuntimeError("HTTP 403 from callback/openai"), "https://chatgpt.com/"],
        ) as callback, patch.object(
            liveness,
            "fetch_session",
            return_value={"accessToken": "token"},
        ) as fetch, patch.object(liveness.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                liveness._follow_continue_and_fetch(
                    session,
                    "https://auth.openai.com/authorize/continue?state=test",
                    referer="https://auth.openai.com/email-verification",
                )

        self.assertEqual(callback.call_count, 1)
        fetch.assert_not_called()

    def test_preflight_refusal_stops_before_signin_or_otp(self):
        for status in (403, 429):
            with self.subTest(status=status):
                error = RuntimeError("request rejected")
                error.response = SimpleNamespace(status_code=status)
                with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
                     patch.object(liveness, "_warm_login_fingerprint_context", side_effect=error) as warm, \
                     patch.object(liveness, "signin_openai") as signin, \
                     patch.object(liveness, "wait_for_otp") as otp, \
                     patch.object(liveness, "_clear_optional_bootstrap_circuit") as reset, \
                     patch.object(liveness.time, "sleep") as sleep:
                    with self.assertRaises(liveness.LoginPreflightBlockedError) as caught:
                        liveness._network_preflight_with_retry("user@example.com", "proxy", max_attempts=4)
                self.assertEqual(caught.exception.status_code, status)
                self.assertIn("尚未发送邮箱验证码", str(caught.exception))
                warm.assert_called_once()
                signin.assert_not_called()
                otp.assert_not_called()
                reset.assert_not_called()
                sleep.assert_not_called()
                self.assertTrue(_DummyBrowserSession.created[-1].session.closed)

    def test_fingerprint_identity_is_pinned_when_session_is_recreated_in_one_attempt(self):
        state = {}
        first = MagicMock()
        first.browser_profile = {
            "navigator_language": "ja-JP",
            "timezone_iana": "Asia/Tokyo",
            "screen_width": 1512,
        }
        second = MagicMock()
        second.browser_profile = dict(first.browser_profile)
        with patch.object(liveness, "BrowserSession", side_effect=[first, second]) as factory:
            self.assertIs(
                liveness._new_fingerprint_pinned_session(
                    "user@example.com", "socks5://proxy:1080", state,
                ),
                first,
            )
            self.assertIs(
                liveness._new_fingerprint_pinned_session(
                    "user@example.com", "", state,
                ),
                second,
            )

        first_kwargs = factory.call_args_list[0].kwargs
        second_kwargs = factory.call_args_list[1].kwargs
        self.assertTrue(first_kwargs["detect_exit_geo"])
        self.assertIsNone(first_kwargs["browser_profile"])
        self.assertFalse(second_kwargs["detect_exit_geo"])
        self.assertEqual(second_kwargs["browser_profile"]["navigator_language"], "ja-JP")
        self.assertEqual(second_kwargs["browser_profile"]["timezone_iana"], "Asia/Tokyo")
        self.assertEqual(first_kwargs["fingerprint_seed"], second_kwargs["fingerprint_seed"])
        self.assertTrue(str(first_kwargs["fingerprint_seed"]).startswith("live-check:user@example.com:"))

    def test_reauth_otp_dead_account_error_is_not_retried(self):
        response = SimpleNamespace(
            status_code=403,
            text='{"error":{"code":"account_deactivated"}}',
        )
        error = RuntimeError("HTTP Error 403")
        error.response = response
        session = _DummyBrowserSession(proxy="proxy")

        with patch.object(liveness, "_validate_reauth_otp", side_effect=error), \
             patch.object(liveness, "wait_for_otp", return_value="123456"):
            with self.assertRaises(liveness.AccountUnusableError) as ctx:
                liveness._validate_reauth_with_retry(session, "user@example.com", 1.0)

        self.assertEqual(ctx.exception.error_code, "account_deactivated")

    def test_existing_access_token_uses_reauth_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "_warm_authenticated_session") as warm, \
                 patch.object(liveness, "human_delay"), \
                 patch.object(liveness, "_login_via_reauth", return_value={
                     "accessToken": "new-token",
                     "user": {"id": "user-1"},
                     "account": {"planType": "free"},
                 }) as reauth:
                result = liveness.check_account_liveness("user@example.com", proxy="")

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        warm.assert_called_once_with(session, "old-token")
        reauth.assert_called_once()
        self.assertTrue(session.session.closed)

    def test_reauth_403_reports_blocked_without_fallback_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            reauth_session = _DummyBrowserSession(proxy="socks5://proxy.example:1080")
            full_session = _DummyBrowserSession(proxy="socks5://proxy.example:1080")
            fresh_info = {
                "accessToken": "new-token",
                "user": {"id": "user-1"},
                "account": {"planType": "free"},
            }
            state = {}
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "_account_totp_secret", return_value=""), \
                 patch.object(liveness, "_new_fingerprint_pinned_session", return_value=reauth_session), \
                 patch.object(liveness, "_warm_authenticated_session"), \
                 patch.object(liveness, "human_delay"), \
                 patch.object(liveness, "_login_via_reauth", side_effect=RuntimeError("HTTP 403 callback")), \
                 patch.object(liveness, "_login_via_full_web_flow", return_value=(
                     full_session, fresh_info,
                 )) as full_login:
                result = liveness.check_account_liveness(
                    "user@example.com",
                    proxy=None,
                    fingerprint_state=state,
                )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["error_code"], "http_403")
        self.assertNotIn("access_token", result)
        full_login.assert_not_called()
        self.assertTrue(reauth_session.session.closed)

    def test_live_check_rotates_exit_only_for_transport_failure(self):
        slot = _DummyQueueSlot()
        failed = {"ok": False, "status": "failed", "error": "Timeout: curl: (28) Connection timed out after 12001 milliseconds"}
        ok = {"ok": True, "status": "live", "access_token": "fresh"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "generic_api"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", side_effect=[
                 {"proxy": "socks5://proxy1", "network_route": "proxy_chain", "proxy_mode": "auto"},
                 {"proxy": "socks5://proxy2", "network_route": "proxy_chain", "proxy_mode": "auto"},
             ]), \
             patch.object(live_service, "open_plan_check_proxy", side_effect=[("http://127.0.0.1:1", None), ("http://127.0.0.1:2", None)]), \
             patch.object(live_service, "check_account_liveness", side_effect=[failed, ok]) as check:
            result = live_service._run_live_check(account_id=1, email="user@example.com", proxy=None, trigger="manual")
        self.assertTrue(result["ok"])
        self.assertEqual(check.call_count, 2)
        self.assertEqual([c.kwargs["proxy"] for c in check.call_args_list], ["http://127.0.0.1:1", "http://127.0.0.1:2"])
        self.assertFalse(slot.released)

    def test_live_check_rebuilds_stale_local_relay_before_rotating_exit(self):
        slot = _DummyQueueSlot()
        stale = SimpleNamespace(last_error="ProxyChainError: upstream returned HTTP 502", close=MagicMock())
        fresh = SimpleNamespace(last_error="", close=MagicMock())
        failed = {"ok": False, "status": "failed",
                  "error": "ProxyError: curl: (97) Received invalid version in initial SOCKS5 response"}
        ok = {"ok": True, "status": "live", "access_token": "fresh"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "generic_api"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={
                 "proxy": "socks5://proxy.example:1080",
                 "network_route": "proxy_chain",
                 "proxy_mode": "auto",
                 "upstream_proxy": "http://127.0.0.1:21483",
             }) as route, \
             patch.object(live_service, "open_plan_check_proxy", side_effect=[
                 ("http://127.0.0.1:1", stale),
                 ("http://127.0.0.1:2", fresh),
             ]) as proxy_open, \
             patch.object(live_service, "check_account_liveness", side_effect=[failed, ok]) as check:
            result = live_service._run_live_check(
                account_id=1, email="user@example.com", proxy=None, trigger="manual",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(route.call_count, 1)
        self.assertEqual(proxy_open.call_count, 2)
        self.assertEqual([c.kwargs["proxy"] for c in check.call_args_list],
                         ["http://127.0.0.1:1", "http://127.0.0.1:2"])
        self.assertEqual(slot.released, False)

    def test_live_check_does_not_rotate_after_deactivation(self):
        slot = _DummyQueueSlot()
        dead = {"ok": False, "status": "deactivated", "error": "account_deactivated"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "generic_api"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={"proxy": "socks5://proxy1", "network_route": "proxy", "proxy_mode": "auto"}), \
             patch.object(live_service, "open_plan_check_proxy", return_value=("http://127.0.0.1:1", None)), \
             patch.object(live_service, "check_account_liveness", return_value=dead) as check:
            result = live_service._run_live_check(account_id=1, email="user@example.com", proxy=None, trigger="manual")
        self.assertEqual(result["status"], "deactivated")
        self.assertEqual(check.call_count, 1)

    def test_service_refusal_does_not_switch_to_direct_connection(self):
        slot = _DummyQueueSlot()
        failed = {"ok": False, "status": "blocked", "error": "HTTP Error 403: blocked"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "remail"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={
                 "proxy": "socks5://proxy.example:1080",
                 "network_route": "proxy",
                 "proxy_mode": "auto",
             }), \
             patch.object(live_service, "check_account_liveness", return_value=failed) as check:
            result = live_service._run_live_check(
                account_id=1,
                email="user@example.com",
                proxy=None,
                trigger="manual",
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "blocked")
        check.assert_called_once()
        self.assertEqual(check.call_args_list[0].kwargs["proxy"], "socks5://proxy.example:1080")
        self.assertEqual(check.call_args_list[0].kwargs["email_source"], "remail")
        self.assertFalse(slot.released)


if __name__ == "__main__":
    unittest.main()
