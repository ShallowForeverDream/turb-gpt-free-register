import json
import os
import tempfile
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from core import (cf_temp_mail_client, cloudmail_client, email_provider,
                  generic_api_mail_client, gptmail_client, mailnest_client, smsbower_mail_client,
                  outlook_client, remail_client)


class _MailFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        # Consume POST data before closing HTTP/1.0: unread input can cause
        # Windows to reset the socket while the client reads our response.
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        payload = {"success": True, "code": "00000" if self.path == "/mailnest" else 200,
                   "data": {"token": "fixture-token"}}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *_args):
        pass


class MailNetworkRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MailFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(3)

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = self.stack.enter_context(tempfile.TemporaryDirectory())
        # Empty NO_PROXY ensures localhost does not accidentally bypass this
        # deliberately broken proxy. Success must come from the mail route.
        poison = {key: "http://127.0.0.1:9" for key in
                  ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
        poison.update(no_proxy="", NO_PROXY="", NETRC=str(Path(root) / "missing-netrc"))
        self.stack.enter_context(patch.dict(os.environ, poison))
        self.pick_proxy = self.stack.enter_context(patch("config.proxy.pick_proxy", side_effect=AssertionError("mail used registration pool")))

    def test_outlook_http_and_microsoft_oauth_bypass_environment_proxy_on_the_wire(self):
        for factory in (outlook_client._http_session, outlook_client._ms_http):
            with self.subTest(factory=factory.__name__):
                session = factory()
                try:
                    self.assertFalse(session.trust_env)
                    self.assertEqual(session.proxies, {"all": ""})
                    self.assertEqual(session.get(self.base + "/outlook", timeout=3).status_code, 200)
                finally:
                    session.close()
        self.pick_proxy.assert_not_called()

    def test_generic_api_direct_session_bypasses_environment_proxy_on_the_wire(self):
        session = generic_api_mail_client._new_http_session()
        try:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies, {})
            self.assertEqual(session.get(self.base + "/generic", timeout=3).status_code, 200)
        finally:
            session.close()
        self.pick_proxy.assert_not_called()

    def test_other_mail_http_clients_bypass_environment_proxy_on_the_wire(self):
        self.stack.enter_context(patch.object(gptmail_client, "BASE_URL", self.base))
        self.stack.enter_context(patch.object(gptmail_client, "_headers", return_value={}))
        self.stack.enter_context(patch.object(mailnest_client, "BASE_URL", self.base))
        self.stack.enter_context(patch.object(mailnest_client, "_api_key", return_value="fixture"))
        for module in (cf_temp_mail_client, remail_client, cloudmail_client):
            self.stack.enter_context(patch.object(module, "_base_url", return_value=self.base))
        self.stack.enter_context(patch.object(cf_temp_mail_client, "_build_headers", return_value={}))
        self.stack.enter_context(patch.object(cf_temp_mail_client, "_auth_params", return_value={}))
        self.stack.enter_context(patch.object(cloudmail_client, "_token", return_value="fixture"))
        self.stack.enter_context(patch.object(cloudmail_client, "_token_path_candidates", return_value=["/cloudmail/token"]))

        self.assertIsInstance(gptmail_client._get("/gptmail"), dict)
        self.assertIsInstance(mailnest_client._request("GET", "/mailnest"), dict)
        self.assertIsInstance(cf_temp_mail_client._request("GET", "/cf"), dict)
        self.assertIsInstance(remail_client._request("GET", "/remail", authenticated=False), dict)
        self.assertIsInstance(cloudmail_client._request("/cloudmail"), dict)
        self.assertIsInstance(cloudmail_client._request_raw("GET", "/cloudmail"), dict)
        self.assertIsInstance(cloudmail_client._request_raw("POST", "/cloudmail"), dict)
        self.assertEqual(cloudmail_client.gen_token(email="fixture@example.test", password="fixture-password"), "fixture-token")
        self.pick_proxy.assert_not_called()

    def test_all_otp_dispatchers_are_independent_of_the_login_proxy(self):
        sources = {
            "outlook": "outlook_client", "imap": "imap_mail_client", "generic_api": "generic_api_mail_client",
            "cloudflare_domain": "qqmail_client", "gptmail": "gptmail_client", "cloudflare": "cf_temp_mail_client",
            "mailnest": "mailnest_client", "cloudmail": "cloudmail_client", "remail": "remail_client",
            "smsbower_mail": "smsbower_mail_client",
        }
        for source, module in sources.items():
            with self.subTest(source=source), patch(f"core.{module}.fetch_latest_otp", return_value="001234") as fetch:
                code = email_provider.wait_for_otp("fixture@example.test", after_ts=123, max_wait=2,
                                                  poll_interval=1, settle_seconds=0, email_source=source, force_service=True)
                self.assertEqual(code, "001234")
                fetch.assert_called_once_with("fixture@example.test", after_ts=123, max_wait=2,
                                              poll_interval=1, settle_seconds=0)
        self.pick_proxy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
