"""Exercise the real XLSX upload path with synthetic, disposable credentials."""
from io import BytesIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from xml.sax.saxutils import escape
from zipfile import ZipFile

from core import db
from core.import_formats import parse_registered_accounts_xlsx
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


def workbook_bytes(rows):
    """Make a small OOXML fixture using standard-library ZIP/XML."""
    sheet_rows = []
    for row_number, values in enumerate(rows, 1):
        cells = []
        for column, value in enumerate(values):
            letter = chr(ord("A") + column)
            if value is None:
                continue
            if isinstance(value, tuple) and value[0] == "formula":
                cells.append(f'<c r="{letter}{row_number}"><f>{escape(value[1])}</f></c>')
            else:
                cells.append(f'<c r="{letter}{row_number}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>')
        sheet_rows.append(f'<row r="{row_number}">{"".join(cells)}</row>')
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:D{len(rows)}"/><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="账号" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/worksheets/sheet1.xml", xml)
    return output.getvalue()


class XlsxAccountImportTests(unittest.TestCase):
    def test_parser_maps_header_and_rejects_formula_and_current_otp(self):
        data = workbook_bytes([
            ("AT", "2FA", "密码", "邮箱"),
            ("token-one", "JBSWY3DPEHPK3PXP", "gpt-password", "one@example.test"),
            ("token-two", "123456", "gpt-password", "two@example.test"),
            (("formula", "1+1"), "JBSWY3DPEHPK3PXP", "gpt-password", "three@example.test"),
        ])
        records, invalid = parse_registered_accounts_xlsx(data)
        self.assertEqual(len(records), 1)
        self.assertEqual(invalid, 2)
        self.assertEqual(records[0], {
            "email": "one@example.test", "registration_password": "gpt-password",
            "totp_secret": "JBSWY3DPEHPK3PXP", "access_token": "token-one",
        })

    def test_upload_imports_once_without_returning_secrets(self):
        data = workbook_bytes([
            ("邮箱", "密码", "2FA", "AT"),
            ("one@example.test", "secret-password", "JBSWY3DPEHPK3PXP", "secret-token"),
        ])
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()

            def upload():
                return client.post("/api/accounts/import",
                                   data={"file": (BytesIO(data), "accounts.xlsx")},
                                   content_type="multipart/form-data",
                                   headers={"X-Auth-Code": "test-auth"})

            denied = client.post("/api/accounts/import",
                                 data={"file": (BytesIO(data), "accounts.xlsx")},
                                 content_type="multipart/form-data")
            self.assertEqual(denied.status_code, 401)
            first = upload()
            self.assertEqual(first.status_code, 200)
            self.assertEqual(first.get_json()["inserted"], 1)
            self.assertNotIn("secret-token", first.get_data(as_text=True))
            self.assertNotIn("secret-password", first.get_data(as_text=True))
            account = db.get_account_by_email("one@example.test")
            self.assertEqual(account["access_token"], "secret-token")
            self.assertEqual(upload().get_json()["skipped"], 1)

    def test_invalid_file_and_missing_headers_have_clear_errors(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **storage(Path(td))):
            client = create_app(auth_code="test-auth").test_client()
            headers = {"X-Auth-Code": "test-auth"}
            invalid = client.post("/api/accounts/import", data={"file": (BytesIO(b"not-xlsx"), "bad.xlsx")},
                                  content_type="multipart/form-data", headers=headers)
            self.assertEqual(invalid.status_code, 400)
            self.assertIn(".xlsx", invalid.get_json()["error"])
            missing = client.post("/api/accounts/import", data={"file": (BytesIO(workbook_bytes([
                ("A", "B", "C", "D"), ("one@example.test", "pw", "totp", "token"),
            ])), "bad.xlsx")}, content_type="multipart/form-data", headers=headers)
            self.assertEqual(missing.status_code, 400)
            self.assertIn("表头", missing.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
