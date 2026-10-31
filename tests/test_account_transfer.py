import csv
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openpyxl import Workbook
from core import db
from core.account_transfer import parse_selected_text, parse_selected_xlsx, validate_fields
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class SelectedFieldParsingTests(unittest.TestCase):
    def test_email_only_and_headerless_order(self):
        rows, invalid = parse_selected_text('one@example.test\ntwo@example.test', ['email'])
        self.assertEqual(invalid, 0)
        self.assertEqual(len(rows), 2)
        rows, _ = parse_selected_text('mail-pw----one@example.test----gpt-pw',
                                      ['mail_password', 'email', 'registration_password'])
        self.assertEqual(rows[0]['mail_password'], 'mail-pw')
        self.assertEqual(rows[0]['registration_password'], 'gpt-pw')

    def test_header_mapping_and_multiline_notes(self):
        text = '备注\t邮箱\t邮箱密码\n"first\nsecond\tline"\tone@example.test\tmail-pw\n'
        rows, invalid = parse_selected_text(text, ['email', 'note'])
        self.assertEqual(invalid, 0)
        self.assertEqual(rows[0], {'email': 'one@example.test', 'note': 'first\nsecond\tline'})

    def test_csv_and_markdown(self):
        for text in ['邮箱,分组\none@example.test,已卖',
                     '| 邮箱 | 分组 |\n| -- | -- |\n| one@example.test | 已卖 |']:
            rows, invalid = parse_selected_text(text, ['email', 'account_group'])
            self.assertEqual(invalid, 0)
            self.assertEqual(rows[0]['account_group'], '已卖')

    def test_unknown_readonly_missing_and_duplicate_fields(self):
        for fields in [[], ['note'], ['email', 'unknown'], ['email', 'registered_at'], ['email', 'email']]:
            with self.assertRaises(ValueError):
                validate_fields(fields, importing=True)
        with self.assertRaises(ValueError):
            parse_selected_text('邮箱,分组\none@example.test,test', ['email', 'mail_password'])

    def test_invalid_rows_are_counted_without_echoing(self):
        rows, invalid = parse_selected_text('bad----secret\none@example.test----123456', ['email', 'totp_secret'])
        self.assertEqual(rows, [])
        self.assertEqual(invalid, 2)

    def test_ambiguous_headers_and_unclosed_quotes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, '重复'):
            parse_selected_text('邮箱,邮箱\none@example.test,two@example.test', ['email'])
        with self.assertRaisesRegex(ValueError, '引号'):
            parse_selected_text('"one@example.test', ['email'])

    def test_xlsx_reorders_headers_and_rejects_formula_and_numeric_secrets(self):
        book = Workbook(); sheet = book.active
        sheet.append(['邮箱密码', '邮箱', '备注'])
        sheet.append(['mail-pw', 'one@example.test', 'ok'])
        sheet.append(['=1+2', 'two@example.test', 'formula'])
        sheet.append([123456, 'three@example.test', 'number'])
        stream = io.BytesIO(); book.save(stream); book.close()
        rows, invalid = parse_selected_xlsx(stream.getvalue(), ['email', 'mail_password'])
        self.assertEqual(rows, [{'email': 'one@example.test', 'mail_password': 'mail-pw'}])
        self.assertEqual(invalid, 2)


class AccountTransferAPITests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        context = patch.multiple(db, **storage(Path(folder.name))); context.start(); self.addCleanup(context.stop)
        guard = patch.object(socket.socket, 'connect', side_effect=AssertionError('No network in local data transfer'))
        guard.start(); self.addCleanup(guard.stop)
        self.client = create_app(auth_code='fixture').test_client()
        self.headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}

    def post(self, path, data):
        return self.client.post(path, json=data, headers=self.headers)

    def seed(self):
        response = self.post('/api/accounts/import', {
            'fields': ['email', 'registration_password', 'mail_password', 'account_group', 'note'],
            'text': 'one@example.test\tgpt-pw\tmail-pw\tgroup-one\t"line one\nline two"'})
        self.assertEqual(response.status_code, 200)
        return db.get_account_by_email('one@example.test')

    def test_auth_is_required(self):
        for url in ['/api/accounts/import', '/api/accounts/export-fields']:
            self.assertEqual(self.client.post(url, json={}).status_code, 401)
        self.assertEqual(self.client.get('/api/accounts/transfer-schema').status_code, 401)

    def test_schema_has_no_credentials(self):
        r = self.client.get('/api/accounts/transfer-schema', headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json), {'fields', 'default_import_fields'})

    def test_email_only_does_not_create_token_or_registration_date(self):
        r = self.post('/api/accounts/import', {'fields': ['email'], 'text': 'one@example.test'})
        self.assertEqual(r.json['inserted'], 1)
        row = db.get_account_by_email('one@example.test')
        self.assertFalse(row.get('access_token'))
        self.assertFalse(row.get('totp_secret'))
        self.assertFalse(row.get('registered_at'))

    def test_stores_separate_passwords_group_note_and_duplicate_skips(self):
        row = self.seed()
        self.assertEqual(row['mail_password'], 'mail-pw')
        self.assertEqual(json.loads(row['extra_json'])['registration_password'], 'gpt-pw')
        self.assertEqual(row['account_group'], 'group-one')
        r = self.post('/api/accounts/import', {'fields': ['email','mail_password'], 'text': 'one@example.test----replacement'})
        self.assertEqual(r.json['skipped'], 1)
        self.assertEqual(db.get_account(row['id'])['mail_password'], 'mail-pw')

    def test_export_only_selected_fields_and_preserves_multiline(self):
        row = self.seed()
        response = self.post('/api/accounts/export-fields', {'ids': [row['id']], 'fields': ['email','note','registered_at']})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        text = response.get_data(as_text=True).lstrip('\ufeff')
        self.assertNotIn('gpt-pw', text); self.assertNotIn('mail-pw', text)
        records = list(csv.reader(io.StringIO(text), delimiter='\t'))
        self.assertEqual(records[1], ['one@example.test','line one\nline two',''])

    def test_export_passwords_are_distinct_and_id_deduplicated(self):
        row = self.seed()
        response = self.post('/api/accounts/export-fields', {'ids': [row['id'],row['id']], 'fields': ['registration_password','mail_password']})
        records = list(csv.reader(io.StringIO(response.get_data(as_text=True).lstrip('\ufeff')), delimiter='\t'))
        self.assertEqual(records[1:], [['gpt-pw','mail-pw']])

    def test_export_invalid_requests_do_not_return_credentials(self):
        self.seed()
        for data, expected in [({'ids':[True],'fields':['email']},400), ({'ids':[-1],'fields':['email']},400),
                               ({'ids':[999],'fields':['email']},404), ({'ids':[1],'fields':['no-such-field']},400)]:
            response = self.post('/api/accounts/export-fields', data)
            self.assertEqual(response.status_code, expected)
            self.assertNotIn('gpt-pw', response.get_data(as_text=True))

    def test_text_file_with_selected_fields(self):
        response = self.client.post('/api/accounts/import', headers=self.headers, data={
            'fields': json.dumps(['email','mail_password']),
            'file': (io.BytesIO('邮箱密码\t邮箱\nmail-pw\tone@example.test'.encode()), 'fixture.tsv')})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['inserted'], 1)

    def test_invalid_field_choices_rejected_before_write(self):
        response = self.post('/api/accounts/import', {'fields':['email','registered_at'],'text':'one@example.test,2020-01-01'})
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(db.get_account_by_email('one@example.test'))

    def test_non_object_json_returns_400_not_server_error(self):
        for path in ['/api/accounts/import', '/api/accounts/export-fields']:
            self.assertEqual(self.post(path, ['invalid']).status_code, 400)


if __name__ == '__main__':
    unittest.main()
