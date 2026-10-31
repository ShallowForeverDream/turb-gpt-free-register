# -*- coding: utf-8 -*-
import unittest
from pathlib import Path

from config import email
from webui.config_editor import EDITABLE_FIELDS


class SmsBowerMailConfigTests(unittest.TestCase):
    def test_email_config_declares_smsbower_mail_defaults(self):
        source = Path(email.__file__).read_text(encoding="utf-8")
        self.assertIn('SMSBOWER_MAIL_API_BASE = "https://smsbower.page/api/mail"', source)
        self.assertIn('SMSBOWER_MAIL_SERVICE = "dr"', source)
        self.assertIn('SMSBOWER_MAIL_DOMAIN = "gmail.com"', source)
        self.assertIn('SMSBOWER_MAIL_ALIAS_LENGTH = 0', source)
        self.assertIn('"smsbower_mail"', source)

    def test_webui_exposes_smsbower_mail_fields(self):
        fields = {item["key"]: item for item in EDITABLE_FIELDS}
        for key in (
            "SMSBOWER_MAIL_API_BASE",
            "SMSBOWER_MAIL_SERVICE",
            "SMSBOWER_MAIL_DOMAIN",
            "SMSBOWER_MAIL_ALIAS_LENGTH",
            "SMSBOWER_MAIL_ACTIVATION_WAIT",
            "SMSBOWER_MAIL_ACTIVATION_RETRY_INTERVAL",
            "SMSBOWER_MAIL_REQUEST_TIMEOUT",
        ):
            self.assertEqual(fields[key]["group"], "邮箱 / OTP")
        self.assertEqual(fields["SMSBOWER_MAIL_ALIAS_LENGTH"]["type"], "int")


if __name__ == "__main__":
    unittest.main()
