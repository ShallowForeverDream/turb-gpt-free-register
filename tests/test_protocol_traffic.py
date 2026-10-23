import gzip
import json
from contextvars import copy_context
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from curl_cffi import CurlOpt

from core import account_export, chatgpt_bootstrap, protocol_traffic
from core.session import BrowserSession


class ProtocolTrafficTests(unittest.TestCase):
    def test_only_registration_context_skips_optional_bootstrap(self):
        session = Mock(protocol_low_traffic=True)
        session.protocol_traffic = protocol_traffic.ProtocolTraffic(low_traffic=True, budget_bytes=1000000)
        chatgpt_bootstrap.anonymous_bootstrap(session)
        chatgpt_bootstrap.authenticated_bootstrap(session, "test-token")
        session.get.assert_not_called()
        session.post.assert_not_called()
        self.assertEqual(session.protocol_traffic.skipped, {
            "anonymous_bootstrap": 1, "authenticated_bootstrap": 1,
        })

        # Standalone live checks have no registration flag and retain their flow.
        ordinary = Mock(protocol_low_traffic=False)
        ordinary.js_timezone_offset_min.return_value = 0
        ordinary.browser_profile = {"navigator_language": "en-US"}
        ordinary.get_chatgpt_headers.side_effect = lambda **kwargs: {}
        ordinary.get.return_value.status_code = 200
        ordinary.post.return_value.status_code = 200
        ordinary.post.return_value.json.return_value = {"prepare_token": "test"}
        with patch.object(chatgpt_bootstrap, "generate_requirements_token", return_value="fixture"):
            chatgpt_bootstrap.anonymous_bootstrap(ordinary)
            chatgpt_bootstrap.authenticated_bootstrap(ordinary, "test-token")
        self.assertEqual(ordinary.get.call_count, 18)
        self.assertEqual(ordinary.post.call_count, 2)

    def test_callback_executes_oauth_hops_and_skips_only_home_with_cookie(self):
        session = Mock(protocol_low_traffic=True)
        cookies = []
        session.session.cookies.jar = cookies
        start = "https://auth.openai.com/authorize/continue?code=private-code"
        callback = "https://chatgpt.com/api/auth/callback/openai?code=private-code"

        def get(url, **kwargs):
            self.assertFalse(kwargs["allow_redirects"])
            if url == callback:
                cookies.append(SimpleNamespace(domain=".chatgpt.com", name="__Secure-next-auth.session-token.0", value="private"))
            return SimpleNamespace(
                status_code=302, url=url, raise_for_status=lambda: None,
                headers={"location": callback if url == start else "/"},
            )

        session.get.side_effect = get
        final = account_export.follow_oauth_callback(session, start)
        self.assertEqual(final, "https://chatgpt.com/")
        self.assertEqual([call.args[0] for call in session.get.call_args_list], [start, callback])
        session.protocol_traffic.skip.assert_called_once_with("post_callback_home_document")
        # AT remains a required, independent check; a cookie is not success.
        session.get.side_effect = None
        session.get.return_value.json.return_value = {"WARNING_BANNER": "test"}
        with self.assertRaisesRegex(RuntimeError, "accessToken"):
            account_export.fetch_session(session)

    def test_callback_without_cookie_downloads_home_and_workspace_is_preserved(self):
        for target in ("https://chatgpt.com/", "https://auth.openai.com/workspace"):
            with self.subTest(target=target):
                session = Mock(protocol_low_traffic=True)
                session.session.cookies.jar = []
                session.get.side_effect = [
                    SimpleNamespace(status_code=302, headers={"location": target}, raise_for_status=lambda: None),
                    SimpleNamespace(status_code=200, headers={}, url=target, raise_for_status=lambda: None),
                ]
                self.assertEqual(account_export.follow_oauth_callback(
                    session, "https://chatgpt.com/api/auth/callback/openai?state=private"
                ), target)
                self.assertEqual(session.get.call_count, 2)

    def test_callback_does_not_download_error_page_or_retry_denial(self):
        session = Mock(protocol_low_traffic=True)
        session.get.return_value = SimpleNamespace(
            status_code=302, headers={"location": "/api/auth/error?error=private"}, raise_for_status=lambda: None,
        )
        with self.assertRaisesRegex(RuntimeError, "认证错误页"):
            account_export.follow_oauth_callback(session, "https://chatgpt.com/api/auth/callback/openai")
        session.get.assert_called_once()
        session.get.reset_mock()
        session.get.return_value.raise_for_status = Mock(side_effect=RuntimeError("HTTP 403"))
        with self.assertRaisesRegex(RuntimeError, "403"):
            account_export.follow_oauth_callback(session, "https://auth.openai.com/continue")
        session.get.assert_called_once()

    def test_incomplete_transfer_cannot_certify_budget_and_urls_are_redacted(self):
        meter = protocol_traffic.ProtocolTraffic(low_traffic=True, budget_bytes=1000000)
        meter.record("https://user:password@auth.openai.com/mfa-challenge/abcdef1234567890abcdef1234567890?email=private@example.test", SimpleNamespace(
            upload_size=10, request_size=100, download_size=50, header_size=70,
            content=b"x" * 10000, redirect_count=1,
        ))
        meter.record("https://auth.openai.com/validate", failed=True)
        data = meter.snapshot()
        self.assertEqual(data["total_bytes"], 230)
        self.assertEqual(data["decoded_download_bytes"], 10000)
        self.assertIsNone(data["within_budget"])
        self.assertEqual(data["failed_request_count"], 1)
        encoded = json.dumps(data)
        for secret in ("password", "private@example.test", "abcdef1234567890abcdef1234567890"):
            self.assertNotIn(secret, encoded)

    def test_capture_includes_failure_result_and_does_not_leak_to_background(self):
        seen = []

        @protocol_traffic.capture_protocol_registration
        def run():
            meter = protocol_traffic.current_traffic()
            self.assertIsNotNone(meter)
            context = copy_context()
            thread = threading.Thread(target=context.run, args=(lambda: seen.append(protocol_traffic.current_traffic()),))
            thread.start()
            thread.join(timeout=3)
            meter.record("https://auth.openai.com/validate", failed=True)
            return {"success": False}

        with patch("core.workflow_driver.resolve_driver", return_value="protocol"):
            result = run()
        self.assertEqual(seen, [None])
        self.assertFalse(result["success"])
        self.assertEqual(result["network_traffic"]["failed_request_count"], 1)
        self.assertIsNone(protocol_traffic.current_traffic())

    def test_concurrent_registrations_keep_separate_counters(self):
        barrier = threading.Barrier(2)
        results = []

        @protocol_traffic.capture_protocol_registration
        def run(size):
            barrier.wait(timeout=3)
            protocol_traffic.current_traffic().record("https://chatgpt.com/api/auth/session", SimpleNamespace(
                upload_size=0, request_size=10, download_size=size, header_size=10,
                content=b"x", redirect_count=0,
            ))
            return {"success": True}

        with patch("core.workflow_driver.resolve_driver", return_value="protocol"):
            threads = [threading.Thread(target=lambda size=size: results.append(run(size))) for size in (100, 200)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        self.assertEqual(sorted(result["network_traffic"]["total_bytes"] for result in results), [120, 220])

    def test_complete_mode_and_browser_driver_remain_available(self):
        @protocol_traffic.capture_protocol_registration
        def run():
            meter = protocol_traffic.current_traffic()
            return {"meter_low": meter.low_traffic if meter is not None else None}

        with patch("core.workflow_driver.resolve_driver", return_value="protocol"), \
             patch("config.openai_protocol.PROTOCOL_LOW_TRAFFIC", False):
            result = run()
            self.assertFalse(result["meter_low"])
            self.assertIn("network_traffic", result)
        with patch("core.workflow_driver.resolve_driver", return_value="roxy"):
            result = run()
            self.assertIsNone(result["meter_low"])
            self.assertNotIn("network_traffic", result)

    def test_real_gzip_http_transfer_uses_compressed_size_not_decoded_length(self):
        content = b"local-http-fixture-" * 10000
        wire = gzip.compress(content)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(wire)))
                self.end_headers()
                self.wfile.write(wire)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            meter = protocol_traffic.ProtocolTraffic(low_traffic=True, budget_bytes=1000000)
            token = protocol_traffic._ACTIVE.set(meter)
            try:
                with BrowserSession(proxy="", detect_exit_geo=False) as session:
                    session.session.trust_env = False
                    session.session.curl_options[CurlOpt.PROXY] = ""
                    response = session.get(f"http://127.0.0.1:{server.server_port}/fixture", allow_redirects=False)
                    self.assertEqual(response.content, content)
                    self.assertEqual(response.download_size, len(wire))
            finally:
                protocol_traffic._ACTIVE.reset(token)
            data = meter.snapshot()
            self.assertEqual(data["decoded_download_bytes"], len(content))
            self.assertLess(data["download_bytes"], len(content) // 10)
            self.assertEqual(data["total_bytes"], response.upload_size + response.request_size + response.download_size + response.header_size)
            self.assertTrue(data["measurement_complete"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
