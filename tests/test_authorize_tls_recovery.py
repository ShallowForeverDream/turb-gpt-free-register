import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch, call
from core import openai_auth


class AuthorizeTlsRecoveryTests(unittest.TestCase):
    def test_tls_rebuilds_only_transport_preserving_session_and_url(self):
        response = Mock(url="https://auth.openai.com/email-verification", text="")
        failure = RuntimeError("curl: (35) BoringSSL SSL_connect: Connection closed abruptly")
        session = SimpleNamespace(get_auth_navigate_headers=Mock(return_value={}),
                                  get=Mock(side_effect=[failure, failure, response]),
                                  reopen_transport=Mock(), reset_circuit_breaker=Mock(),
                                  device_id="same-device", proxy="same-route")
        url = "https://auth.openai.com/oauth/authorize?state=fixture"
        with patch.object(openai_auth, "_proxy_retry_config", return_value=(3, 1.5)), \
             patch.object(openai_auth, "_interruptible_sleep") as sleep:
            self.assertEqual(openai_auth.follow_authorize(session, url), response.url)
        self.assertEqual(session.reopen_transport.call_count, 2)
        self.assertEqual([args[0][0] for args in session.get.call_args_list], [url]*3)
        self.assertEqual(sleep.call_args_list, [call(1.5), call(3)])
        self.assertEqual((session.device_id, session.proxy), ("same-device", "same-route"))

    def test_tls_exhaustion_is_bounded_and_business_400_does_not_retry(self):
        for error, count in ((RuntimeError("curl: (35) SSL_connect"), 3), (RuntimeError("HTTP 400"), 1)):
            session = SimpleNamespace(get_auth_navigate_headers=Mock(return_value={}), get=Mock(side_effect=error),
                                      reopen_transport=Mock(), reset_circuit_breaker=Mock())
            with patch.object(openai_auth, "_proxy_retry_config", return_value=(3, 1)), \
                 patch.object(openai_auth, "_interruptible_sleep"):
                with self.assertRaises(RuntimeError):
                    openai_auth.follow_authorize(session, "https://auth.openai.com/oauth/authorize")
            self.assertEqual(session.get.call_count, count)
            self.assertEqual(session.reopen_transport.call_count, count-1)

    def test_stop_during_backoff_does_not_issue_another_request(self):
        session = SimpleNamespace(get_auth_navigate_headers=Mock(return_value={}),
                                  get=Mock(side_effect=RuntimeError("curl: (35) SSL_connect")),
                                  reopen_transport=Mock(), reset_circuit_breaker=Mock())
        with patch.object(openai_auth, "_proxy_retry_config", return_value=(3, 1)), \
             patch.object(openai_auth, "_interruptible_sleep", side_effect=RuntimeError("stopped")):
            with self.assertRaisesRegex(RuntimeError, "stopped"):
                openai_auth.follow_authorize(session, "https://auth.openai.com/oauth/authorize")
        self.assertEqual(session.get.call_count, 1)
