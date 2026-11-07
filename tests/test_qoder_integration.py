import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core import db, qoder_mail, qoder_service, qoder_store
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class QoderStorageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        self.stack.enter_context(patch.multiple(qoder_service, _PENDING=[], _RUNNING={}, _EXECUTOR=None,
                                               _WORKERS=1, _PAUSED=False, _INITIALIZED=False))
        self.email = 'qoder-fixture@icloud.com'
        self.item = {'email': self.email, 'source': 'generic_api'}
        db.import_generic_api_emails([{'email': self.email, 'code_url': 'https://icapi.oaibx.com/api?token=fixture'}])

    def test_create_job_and_save_pat_requires_confirmed_profile(self):
        jid = qoder_store.create_jobs([self.item], driver='browser')[0]
        with self.assertRaisesRegex(ValueError, '尚未确认提交资料'):
            qoder_store.save_account(jid, {'pat': 'pt-' + 'x' * 70})
        qoder_store.update_job(jid, 'running', 'code_submitted', 'fixture',
                               private={'profile_submitted': True, 'password_confirmed': True})
        saved = qoder_store.save_account(jid, {'pat': 'pt-' + 'x' * 70, 'pat_rw': ''})
        self.assertEqual(saved['account_id'], qoder_store.account_id_for_email(self.email))
        self.assertTrue(qoder_store.accounts()['items'][0]['has_pat'])

    def test_duplicate_and_uncertain_are_reported_with_email(self):
        jid = qoder_store.create_jobs([self.item], driver='browser')[0]
        with self.assertRaisesRegex(ValueError, self.email):
            qoder_store.create_jobs([self.item], driver='browser')
        qoder_store.update_job(jid, 'uncertain', 'interrupted', 'fixture')
        self.assertEqual(qoder_store.unresolved()['items'][0]['email'], self.email)
        qoder_store.resolve_uncertain(jid)
        self.assertNotEqual(qoder_store.create_jobs([self.item], driver='browser')[0], jid)

    def test_pool_lists_qoder_status_independently(self):
        qoder_store.create_jobs([self.item], driver='browser')
        rows = db.list_email_pool_page(source='all', limit=20, offset=0)['items']
        row = next(r for r in rows if r['email'] == self.email)
        self.assertNotEqual(row['qoder_registration_status'], 'registered')

    def test_platform_filter_for_qoder_registered_and_processing(self):
        qoder_store.create_jobs([self.item], driver='browser')
        processing = db.list_email_pool_page(source='all', platform='qoder', platform_status='processing',
                                            limit=20, offset=0)['items']
        self.assertIn(self.email, [r['email'] for r in processing])


class QoderServiceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        self.stack.enter_context(patch.multiple(qoder_service, _PENDING=[], _RUNNING={}, _EXECUTOR=None,
                                               _WORKERS=1, _PAUSED=False, _INITIALIZED=False))
        self.email = 'qoder-success@icloud.com'
        db.import_generic_api_emails([{'email': self.email, 'code_url': 'https://icapi.oaibx.com/api?token=fixture'}])

    def test_success_path_saves_pat_and_marks_job_complete(self):
        jid = qoder_store.create_jobs([{'email': self.email, 'source': 'generic_api'}], driver='browser')[0]
        relay = SimpleNamespace(proxy_url='http://127.0.0.1:29999', close=lambda: None)
        token = 'pt-' + 'z' * 70
        with patch('core.grok_service._dynamic_pool_route', return_value=(relay, 'socks5://***')), \
             patch('core.grok_browser.verify_proxy_transport'), \
             patch('core.qoder_browser.run', return_value={'pat': token, 'pat_rw': ''}) as runner:
            runner.side_effect = lambda record, mailbox, signals, update, **kw: (
                update('running', 'save', 'Qoder PAT 已创建',
                       profile_submitted=True, password_confirmed=True,
                       registration_origin='browser', session_validation_status='browser_identity') or
                {'pat': token, 'pat_rw': ''})
            qoder_service._run(jid, qoder_service.Signals())
        record = qoder_store.job(jid, private=True)
        self.assertEqual(record['status'], 'success')
        self.assertEqual(record['stage'], 'complete')
        self.assertEqual(qoder_store.secret(qoder_store.account_id_for_email(self.email), 'pat'), token)


class QoderMailTests(unittest.TestCase):
    def test_numeric_six_digit_code_only(self):
        self.assertEqual(qoder_mail.validate_code('123456'), '123456')
        for bad in ('12345', '1234567', 'ABC-123', '', None):
            self.assertEqual(qoder_mail.validate_code(bad), '')

    def test_viewer_mailbox_accepts_any_sender_six_digit_code(self):
        from core.otp_read import OTPRead
        mailbox = {'email': 'qoder@example.com', 'source': 'generic_api',
                   'code_url': 'https://icapi.oaibx.com/v#token=' + 'f' * 40}
        with patch('core.icapi_mailbox.latest_code_any',
                   return_value=OTPRead('123456', ['123456', 'ABC-123'])) as reader:
            self.assertEqual(qoder_mail.read_once(mailbox), '123456')
            self.assertTrue(reader.called)


class QoderRouteTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        self.client = create_app(local_no_auth=True).test_client()

    def test_routes_exist_and_are_private(self):
        response = self.client.get('/api/qoder/accounts?page=1')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertTrue(response.get_json()['ok'])
        response = self.client.get('/api/qoder/queue')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['ok'])


if __name__ == '__main__':
    unittest.main()
