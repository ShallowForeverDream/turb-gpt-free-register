import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import account_export, sms_provider


class CredentialLogTests(unittest.TestCase):
    def session(self, data, status=200):
        response = Mock(status_code=status, text="private-response-body")
        response.json.return_value = data
        response.raise_for_status.side_effect = RuntimeError("HTTP failure")
        return SimpleNamespace(device_id="fixture", navigator_language=lambda: "en-US",
            get_chatgpt_headers=lambda **kwargs: {}, post=Mock(return_value=response))

    def test_partial_enrollment_never_includes_secret_in_exception(self):
        session = self.session({"secret": "private-response-secret"})
        with self.assertRaises(RuntimeError) as error:
            account_export._enroll_totp(session, "fixture-token")
        self.assertNotIn("private-response-secret", str(error.exception))

    def test_mfa_http_errors_never_include_response_body_in_logs(self):
        for operation in ("enroll", "activate"):
            with self.subTest(operation=operation):
                session = self.session({}, status=400)
                with self.assertLogs(account_export.logger, "ERROR") as logs, self.assertRaises(RuntimeError):
                    if operation == "enroll":
                        account_export._enroll_totp(session, "fixture-token")
                    else:
                        account_export._activate_totp(session, "fixture-token", "JBSWY3DPEHPK3PXP", "fixture-id")
                self.assertNotIn("private-response-body", "\n".join(logs.output))

    def test_other_sms_providers_never_log_received_codes(self):
        for provider in ("l", "h", "grizzly"):
            with self.subTest(provider=provider), \
                 patch.object(sms_provider, "_provider", return_value=provider), \
                 patch.object(sms_provider, "_post_l_json", return_value={"code": "001234"}), \
                 patch.object(sms_provider, "_post_h_json", return_value={"code": "001234"}), \
                 patch.object(sms_provider, "_request_grizzly", return_value="STATUS_OK:001234"), \
                 self.assertLogs(sms_provider.logger, "INFO") as logs:
                self.assertEqual(sms_provider.wait_for_sms_code("fixture-id", Mock(), max_wait=1), "001234")
            self.assertNotIn("001234", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
