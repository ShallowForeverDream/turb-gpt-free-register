"""Synthetic Burp envelopes only; no user capture or real credentials."""
import base64
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import ExitStack, closing
from email.utils import formatdate
from pathlib import Path
from unittest.mock import patch

from core import db, grok_capture as capture, grok_store
from tests.test_forwarded_imap_and_account_import import storage

EMAIL = 'fixture@icloud.com'
NOW = 1804200000


def fixture(path, *, target=EMAIL, response_email=None, final_email=None, final_confirmed=True,
            request_sso='fake-fixture-sso', max_age=86400, domain='.grok.com', verified=True):
    root = ET.Element('items')
    def add(method, endpoint, request, response, cookies=(), cookie_header=''):
        item = ET.SubElement(root, 'item')
        ET.SubElement(item, 'url').text = 'https://grok.com'+endpoint
        ET.SubElement(item, 'method').text = method
        ET.SubElement(item, 'status').text = '200'
        body = json.dumps(request).encode() if request is not None else b''
        raw = (f'{method} {endpoint} HTTP/2\r\nHost: grok.com\r\nContent-Type: application/json\r\n'+
               (f'Cookie: {cookie_header}\r\n' if cookie_header else '')+'\r\n').encode()+body
        ET.SubElement(item, 'request', base64='true').text = base64.b64encode(raw).decode()
        raw = ('HTTP/2 200 OK\r\nContent-Type: application/json\r\nDate: '+formatdate(NOW, usegmt=True)+'\r\n'+
               ''.join('Set-Cookie: '+c+'\r\n' for c in cookies)+'\r\n').encode()+json.dumps(response).encode()
        ET.SubElement(item, 'response', base64='true').text = base64.b64encode(raw).decode()
    add('POST', '/api/auth/sign-up/create-account',
        {'email': target, 'password': 'private-password-never-import', 'emailValidationCode': '123456', 'turnstileToken': 'private-challenge'},
        {'session': {'email': response_email or target, 'userId': 'fixture-user', 'emailConfirmed': False, 'hasPassword': False}},
        [f'sso=fake-fixture-sso; Domain={domain}; Path=/; Max-Age={max_age}; Secure; HttpOnly',
         f'sso-rw=fake-fixture-rw; Domain={domain}; Path=/; Max-Age={max_age}; Secure; HttpOnly'])
    if verified:
        add('GET', '/api/auth/session', None,
            {'session': {'email': final_email or target, 'userId': 'fixture-user', 'emailConfirmed': final_confirmed, 'hasPassword': True}},
            cookie_header='sso='+request_sso+'; sso-rw=fake-fixture-rw')
    ET.ElementTree(root).write(path, encoding='utf-8')


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(self.root)))
        self.stack.enter_context(patch.object(capture.time, 'time', return_value=NOW+100))
        self.path = self.root/'capture.xml'; fixture(self.path)
        db.import_generic_api_emails([{'email': EMAIL, 'code_url': 'https://fixture.test/api'}])

    def test_only_ssos_are_imported_and_public_lists_show_manual_origin(self):
        aid = db.insert_account(email=EMAIL, access_token='private-gpt-token')
        before = db.get_account(aid)
        record = capture.inspect_capture(self.path, EMAIL)
        self.assertTrue(record.capture_session_verified)
        self.assertNotIn('fake-fixture-sso', repr(record))
        result = capture.import_capture(self.path, EMAIL)
        self.assertTrue(result['imported']); self.assertFalse(result['password_imported'])
        public = grok_store.accounts()['items'][0]
        self.assertEqual(public['registration_origin'], 'manual_capture')
        self.assertEqual(public['session_validation_status'], 'capture_only')
        self.assertFalse(public['has_password'])
        self.assertEqual(grok_store.secret(public['id'], 'sso'), 'fake-fixture-sso')
        self.assertEqual(grok_store.secret(public['id'], 'sso_rw'), 'fake-fixture-rw')
        self.assertEqual(db.get_account(aid), before)
        with closing(grok_store.connect()) as c:
            payload = c.execute('SELECT payload FROM grok_accounts').fetchone()[0]
            self.assertNotIn('private-password', payload)
            self.assertNotIn('123456', payload)
            self.assertNotIn('private-challenge', payload)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM grok_jobs').fetchone()[0], 0)
        self.assertEqual(db.get_generic_api_email_by_email(EMAIL)['status'], 'available')

    def test_idempotent_import_and_no_network_or_auto_registration(self):
        with patch('requests.sessions.Session.request', side_effect=AssertionError('No HTTP')), \
             patch('core.grok_service.submit', side_effect=AssertionError('No signup')):
            first = capture.import_capture(self.path, EMAIL)
            second = capture.import_capture(self.path, EMAIL)
        self.assertEqual(first['account_id'], second['account_id'])
        self.assertTrue(second['already_present']); self.assertFalse(second['imported'])

    def test_target_final_identity_cookie_and_confirmation_must_all_match(self):
        for kwargs in ({'target': 'other@icloud.com'}, {'response_email': 'other@icloud.com'},
                       {'final_email': 'other@icloud.com'}, {'request_sso': 'other-session'},
                       {'verified': False}, {'final_confirmed': False}, {'domain': '.evil.test'}, {'max_age': -1}):
            with self.subTest(kwargs=kwargs):
                fixture(self.path, **kwargs)
                with self.assertRaises(capture.CaptureError): capture.import_capture(self.path, EMAIL)
                self.assertEqual(grok_store.accounts()['total'], 0)

    def test_cannot_overwrite_different_existing_session_or_active_job(self):
        jid = grok_store.create_jobs([{'email': EMAIL, 'source': 'generic_api'}])[0]
        with self.assertRaises(capture.CaptureError): capture.import_capture(self.path, EMAIL)
        grok_store.update_job(jid, 'failed', 'fixture', 'fixture')
        capture.import_capture(self.path, EMAIL)
        with closing(grok_store.connect()) as c, c:
            c.execute("UPDATE grok_accounts SET sso_digest='different-existing-session'")
        with self.assertRaises(capture.CaptureError): capture.import_capture(self.path, EMAIL)

    def test_malformed_and_entity_files_do_not_leak_contents(self):
        for text in ('private-token-not-xml', '<!ENTITY private "secret"><items/>'):
            self.path.write_text(text, encoding='utf-8')
            with self.assertRaises(capture.CaptureError) as caught: capture.inspect_capture(self.path, EMAIL)
            self.assertNotIn('private-token', str(caught.exception))


if __name__ == '__main__': unittest.main()
