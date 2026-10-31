"""Offline fixtures for the client-loader initial send seen in the manual trace."""
import json
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main
from core import openai_auth
from core.auth_page_state import read_auth_page_session


def document(state):
    entries = []

    def pack(value):
        ref = len(entries)
        entries.append(None)
        if isinstance(value, dict):
            entries[ref] = {"_" + str(pack(k)): pack(v) for k, v in value.items()}
        else:
            entries[ref] = value
        return ref

    pack({"loaderData": {"routes/layouts/client-auth-session-layout/layout": {"session": state}}})
    return "<script>window.__reactRouterContext.streamController.enqueue(" + json.dumps(json.dumps(entries)) + ");</script>"


class InitialDeliveryTests(unittest.TestCase):
    email = "fixture@example.test"
    url = "https://auth.openai.com/email-verification?auth_page=private-fixture"

    def setUp(self):
        challenge = patch.object(openai_auth, "request_sentinel_token", return_value={})
        header = patch.object(openai_auth, "build_sentinel_header", return_value=("fixture-token", "fixture-observer"))
        self.challenge = challenge.start()
        self.addCleanup(challenge.stop)
        self.header = header.start()
        self.addCleanup(header.stop)

    def state(self):
        return {"session_id": "session-fixture", "email": self.email,
                "email_verification_mode": "passwordless_login",
                "passwordless_email_otp_send_pending": True, "is_missing_session": False}

    def session(self, state=None):
        response = Mock(status_code=200)
        response.json.return_value = {"page": {"type": "email_otp_verification"}}
        return SimpleNamespace(_registration_auth_page_state=state or self.state(),
                               _registration_auth_page_url=self.url,
                               _registration_initial_otp_attempted=False,
                               get_auth_headers=Mock(return_value={"content-type": "application/json"}),
                               post=Mock(return_value=response))

    def test_decodes_only_the_server_session_not_arbitrary_script_text(self):
        self.assertEqual(read_auth_page_session(document(self.state())), self.state())
        for html in ("passwordless_email_otp_send_pending:true", "<script>alert('x')</script>",
                     "window.__reactRouterContext.streamController.enqueue(not_json)"):
            self.assertIsNone(read_auth_page_session(html))

    def test_pending_send_is_one_empty_post_not_resend_or_get(self):
        session = self.session()
        with patch.object(openai_auth.time, "time", return_value=150):
            self.assertTrue(openai_auth.initialize_passwordless_email_otp(session, self.email, self.url))
        args, options = session.post.call_args
        self.assertEqual(args, ("https://auth.openai.com/api/accounts/passwordless/send-otp",))
        self.assertEqual(options["data"], "")
        self.assertFalse(options["allow_redirects"])
        self.assertEqual(options["headers"]["content-type"], "application/json")
        self.assertEqual(options["headers"]["openai-sentinel-token"], "fixture-token")
        self.challenge.assert_called_once_with(session, "authorize_continue")
        self.header.assert_called_once_with(session, {}, "authorize_continue")
        self.assertEqual(session._registration_otp_ready_at, 150)
        self.assertFalse(openai_auth.initialize_passwordless_email_otp(session, self.email, self.url))
        self.assertEqual(session.post.call_count, 1)

    def test_no_pending_flag_never_sends(self):
        for state in ({}, {"passwordless_email_otp_send_pending": False},
                      {"passwordless_email_otp_send_pending": "true"}):
            session = self.session()
            session._registration_auth_page_state = state
            self.assertFalse(openai_auth.initialize_passwordless_email_otp(session, self.email, self.url))
            session.post.assert_not_called()

    def test_real_curl_transport_keeps_json_type_for_empty_initial_post(self):
        from curl_cffi.requests import Session
        visits = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                visits.append((self.headers.get("Content-Type"), self.rfile.read(length)))
                body = b'{"page":{"type":"email_otp_verification"}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with Session(trust_env=False) as http:
            session = self.session()
            session.post.side_effect = lambda url, **kwargs: http.post(
                f"http://127.0.0.1:{server.server_port}/initial-send", **kwargs)
            self.assertTrue(openai_auth.initialize_passwordless_email_otp(session, self.email, self.url))
        self.assertEqual(visits, [("application/json", b"")])

    def test_session_mismatch_and_foreign_origin_never_send(self):
        for key, value in (("email", "other@example.test"), ("session_id", ""),
                           ("is_missing_session", True), ("email_verification_mode", "unexpected")):
            session = self.session()
            session._registration_auth_page_state[key] = value
            with self.assertRaisesRegex(RuntimeError, "会话不匹配"):
                openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
            session.post.assert_not_called()
        session = self.session()
        with self.assertRaises(RuntimeError):
            openai_auth.initialize_passwordless_email_otp(session, self.email, self.url.replace("auth.openai.com", "foreign.test"))
        session.post.assert_not_called()

    def test_access_refusal_is_terminal_without_challenge_or_replay(self):
        for status in (401, 403, 429, 500):
            session = self.session()
            session.post.return_value.status_code = status
            with self.assertRaisesRegex(RuntimeError, "HTTP " + str(status)):
                openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
            with self.assertRaisesRegex(RuntimeError, "未重复发送"):
                openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
            self.assertEqual(session.post.call_count, 1)

    def test_uncertain_network_send_never_repeats_or_leaks_exception(self):
        session = self.session()
        session.post.side_effect = RuntimeError("private-token")
        with self.assertRaisesRegex(RuntimeError, "未自动重发") as error:
            openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
        self.assertNotIn("private-token", str(error.exception))
        with self.assertRaisesRegex(RuntimeError, "未重复发送"):
            openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
        self.assertEqual(session.post.call_count, 1)

    def test_unexpected_response_is_not_delivery_confirmation(self):
        session = self.session()
        session.post.return_value.json.return_value = {"page": {"type": "login"}}
        with self.assertRaisesRegex(RuntimeError, "未确认邮箱验证状态"):
            openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)

    def test_error_category_is_useful_without_exposing_response_details(self):
        session = self.session()
        response = session.post.return_value
        response.status_code = 400
        response.json.return_value = {"error": {"code": "unsupported_content_type", "message": "private-value"}}
        response.text = "private-value"
        with self.assertRaisesRegex(RuntimeError, "unsupported_content_type") as error:
            openai_auth.initialize_passwordless_email_otp(session, self.email, self.url)
        self.assertNotIn("private-value", str(error.exception))

    def test_prepare_uses_initial_delivery_completion_as_wait_anchor(self):
        session = self.session()
        with patch.object(openai_auth.time, "time", return_value=150), \
             patch.object(main, "send_email_otp") as resend:
            self.assertEqual(main._prepare_registration_otp(session, self.email, self.url, issued_after=100),
                             (None, 150))
        resend.assert_not_called()

    def test_authorize_retains_query_for_state_but_does_not_log_values(self):
        response = Mock(url=self.url, status_code=200, text=document(self.state()))
        session = SimpleNamespace(get_auth_navigate_headers=Mock(return_value={}), get=Mock(return_value=response))
        with self.assertLogs(openai_auth.logger, "INFO") as logs:
            self.assertEqual(openai_auth.follow_authorize(session, "https://auth.openai.com/oauth/authorize"), self.url)
        self.assertEqual(session._registration_auth_page_state, self.state())
        self.assertNotIn("private-fixture", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
