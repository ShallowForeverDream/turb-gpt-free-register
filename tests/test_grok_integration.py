import json
import os
import tempfile
import threading
import unittest
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from core import db, grok_mail as mail, grok_service as service, grok_store as store
from core.grok_browser import GrokBrowserError, session_cookies
from core.grok_browser import response_diagnostic, diagnostic_message
from core.grok_browser import show_browser_window, interactive_auth_error
from core.grok_browser import request_sso
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class GrokStorageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        self.stack.enter_context(patch.multiple(service, _PENDING=deque(), _RUNNING={}, _EXECUTOR=None,
                                               _WORKERS=1, _PAUSED=False))
        self.email = 'fixture@icloud.com'
        db.import_generic_api_emails([{'email': self.email, 'code_url': 'https://icapi.oaibx.com/api?token=private-fixture'}])
        self.item = {'email': self.email, 'source': 'generic_api'}

    def create(self):
        return store.create_jobs([self.item])[0]

    def complete(self, jid=None, token='private-sso'):
        jid = jid or self.create()
        store.update_job(jid, 'running', 'profile_submit', 'fixture', private={'profile_submitted': True, 'password_confirmed': True})
        store.save_account(jid, {'sso': token, 'sso-rw': 'private-rw'})
        store.update_job(jid, 'success', 'complete', 'fixture')
        return jid

    def test_same_email_gpt_and_grok_are_separate_and_pool_not_consumed(self):
        aid = db.insert_account(email=self.email, access_token='gpt-token')
        before = db.get_account(aid)
        self.complete()
        self.assertEqual(db.get_account(aid), before)
        self.assertEqual(db.get_generic_api_email_by_email(self.email)['status'], 'available')
        item = db.list_email_pool_page(source='generic_api')['items'][0]
        self.assertEqual((item['gpt_registration_status'], item['grok_registration_status']), ('registered', 'registered'))
        self.assertTrue(store.mailboxes()['items'][0]['gpt_registered'])
        self.assertTrue(store.mailboxes()['items'][0]['grok_registered'])

    def test_queued_jobs_are_not_logs_and_no_secrets_in_public_records(self):
        jid = self.create()
        self.assertEqual(store.jobs()['total'], 0)
        record = store.job(jid)
        self.assertNotIn('private', record)
        self.assertNotIn('password', json.dumps(record))
        store.update_job(jid, 'running', 'open', 'fixture')
        self.assertEqual(store.jobs()['total'], 1)
        self.assertNotIn('private-fixture', json.dumps(store.jobs()))

    def test_password_candidate_has_all_basic_character_classes(self):
        value = store.job(self.create(), private=True)['private']['password']
        self.assertGreaterEqual(len(value), 24)
        for pattern in ('[A-Z]', '[a-z]', '[0-9]', '[^A-Za-z0-9]'):
            self.assertRegex(value, pattern)

    def test_duplicate_pending_and_uncertain_block_resubmission(self):
        jid = self.create()
        with self.assertRaises(ValueError): self.create()
        store.update_job(jid, 'uncertain', 'submit', 'fixture')
        with self.assertRaises(ValueError): self.create()

    def test_atomic_batch_rolls_back_if_one_mailbox_is_busy(self):
        self.create()
        db.import_generic_api_emails([{'email': 'second@icloud.com', 'code_url': 'https://fixture.test/api'}])
        with self.assertRaises(ValueError):
            store.create_jobs([{'email': 'second@icloud.com', 'source': 'generic_api'}, self.item])
        with closing(store.connect()) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM grok_jobs').fetchone()[0], 1)

    def test_gpt_active_job_prevents_grok_start_and_grok_prevents_gpt_claim(self):
        job = db.create_job('generic_api', self.email)
        with self.assertRaises(ValueError): self.create()
        db.update_job(job['id'], status='cancelled')
        self.create()
        self.assertIsNone(db.claim_pool_email(self.email, 'generic_api'))
        self.assertIsNone(db.claim_next_generic_api_email())
        selected, rejected = db.claim_pool_emails([self.item], reserve=False)
        self.assertEqual(selected, []); self.assertEqual(len(rejected), 1)

    def test_gpt_twofa_inflight_prevents_mailbox_challenge_collision(self):
        aid = db.insert_account(email=self.email, access_token='fixture')
        db.claim_account_totp_setup(aid)
        with self.assertRaises(ValueError): self.create()

    def test_grok_blocks_gpt_email_auth_claims_in_the_other_direction(self):
        aid = db.insert_account(email=self.email, access_token='fixture')
        self.create()
        self.assertFalse(db.claim_account_totp_setup(aid))
        self.assertFalse(db.claim_account_live_check(aid))
        self.assertFalse(db.claim_account_email_change(aid, 'generic_api'))
        self.assertFalse(db.claim_account_codex_agent(aid))
        client = create_app(auth_code='fixture').test_client()
        with patch('core.codex_retry_service.reserve') as reserve:
            response = client.post('/api/codex/retry', headers={'X-Auth-Code': 'fixture'}, json={'email': self.email})
        self.assertEqual(response.status_code, 409)
        reserve.assert_not_called()

    def test_manual_profile_password_is_not_assumed_to_be_generated_password(self):
        jid = self.create()
        store.update_job(jid, 'running', 'profile_submit', 'fixture', private={'profile_submitted': True})
        store.save_account(jid, {'sso': 'manual-password-fixture'})
        row = store.accounts()['items'][0]
        self.assertFalse(row['has_password'])
        self.assertEqual(store.secret(row['id'], 'password'), '')

    def test_logs_filter_by_platform_id_date_status_and_email(self):
        jid = self.create()
        store.update_job(jid, 'running', 'open', 'fixture')
        with closing(store.connect()) as conn, conn:
            conn.execute("UPDATE grok_jobs SET created_at='2026-10-30T12:00:00' WHERE id=?", (jid,))
        self.assertEqual(store.jobs(query=f'G#{jid}', date_from='2026-10-30', date_to='2026-10-30')['total'], 1)
        self.assertEqual(store.jobs(query='FIXTURE@ICLOUD', status='running')['total'], 1)
        self.assertEqual(store.jobs(date_to='2026-10-29')['total'], 0)
        client = create_app(auth_code='fixture').test_client()
        for query in ('date_from=invalid', 'date_from=2026-11-02&date_to=2026-11-01', 'status=disabled'):
            self.assertEqual(client.get('/api/grok/jobs?'+query, headers={'X-Auth-Code': 'fixture'}).status_code, 400)

    def test_refusal_has_safe_http_diagnostic_and_stops_without_retry(self):
        jid = self.create()
        with patch('core.grok_protocol.run', side_effect=GrokBrowserError('private-content', http_status=429)) as run:
            service._run(jid, service.Signals())
        record = store.job(jid)
        self.assertEqual(record['status'], 'blocked')
        self.assertIn('HTTP 429', str(record['events']))
        self.assertNotIn('private-content', str(record))
        run.assert_called_once()

    def test_missing_native_security_is_blocked_not_an_automatic_browser_fallback(self):
        from core.grok_protocol import ManualVerificationRequired
        jid=self.create()
        with patch('core.grok_protocol.run',side_effect=ManualVerificationRequired('fixture',reason='native_security')), \
             patch('core.grok_browser.run',side_effect=AssertionError('must not open')) as browser:
            service._run(jid,service.Signals())
        browser.assert_not_called()
        record=store.job(jid)
        self.assertEqual(record['status'],'blocked')
        self.assertIn('原生SDK安全上下文尚未接通',str(record['events']))

    def test_sdk_verification_window_requires_explicit_active_task_consent(self):
        jid=self.create();signals=service.Signals()
        client=create_app(auth_code='fixture').test_client();headers={'X-Auth-Code':'fixture'}
        path=f'/api/grok/jobs/{jid}/verify-native'
        with patch.dict(service._RUNNING,{jid:signals}):
            self.assertEqual(client.post(path,json={'confirmed':True},headers=headers).status_code,400)
            store.update_job(jid,'manual_required','native_challenge','fixture')
            self.assertEqual(client.post(path,json={},headers=headers).status_code,400)
            self.assertFalse(signals.native_verify.is_set())
            self.assertEqual(client.post(path,json={'confirmed':True},headers=headers).status_code,200)
            self.assertTrue(signals.native_verify.is_set())

    def test_stop_pending_does_not_touch_running_or_gpt(self):
        first = self.create()
        store.update_job(first, 'running', 'open', 'fixture')
        db.import_generic_api_emails([{'email': 'second@icloud.com', 'code_url': 'https://fixture.test/api'}])
        other = store.create_jobs([{'email': 'second@icloud.com', 'source': 'generic_api'}])[0]
        self.assertEqual(store.cancel_pending(), 1)
        self.assertEqual(store.job(first)['status'], 'running')
        self.assertEqual(store.job(other)['status'], 'cancelled')

    def test_recovery_never_replays_creation_or_crosses_owner(self):
        jid = self.create()
        store.update_job(jid, 'running', 'profile_submit', 'fixture', private={'profile_submitted': True})
        store.recover(); self.assertEqual(store.job(jid)['status'], 'running')
        with closing(store.connect()) as conn, conn:
            conn.execute('UPDATE grok_jobs SET owner_pid=-1 WHERE id=?', (jid,))
        store.recover()
        self.assertEqual(store.job(jid)['status'], 'uncertain')
        self.assertTrue(store.job(jid, private=True)['private']['profile_submitted'])

    def test_cookie_dedupe_and_identity_safeguards(self):
        with self.assertRaises(ValueError): store.save_account(self.create(), {'sso': 'fixture'})
        cookies = [{'name': 'sso', 'value': 'fixture', 'domain': '.grok.com'},
                   {'name': 'unrelated', 'value': 'private', 'domain': '.grok.com'}]
        self.assertEqual(session_cookies(cookies), {'sso': 'fixture'})
        with self.assertRaises(GrokBrowserError):
            session_cookies(cookies + [{'name': 'sso', 'value': 'different', 'domain': '.x.ai'}])
        self.assertEqual(session_cookies([{'name': 'sso', 'value': 'bad', 'domain': 'evil.test'}]), {})

    def test_concurrent_duplicate_email_has_only_one_winner(self):
        def create():
            try: return self.create()
            except ValueError: return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: create(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_native_cookie_scope_does_not_mix_cross_domain_sync(self):
        cookies = [{'name': 'sso', 'value': 'grok-fixture', 'domain': '.grok.com', 'path': '/'},
                   {'name': 'sso-rw', 'value': 'grok-rw-fixture', 'domain': '.grok.com', 'path': '/'},
                   {'name': 'sso', 'value': 'cross-domain-fixture', 'domain': '.x.ai', 'path': '/'},
                   {'name': 'sso', 'value': 'path-scoped-fixture', 'domain': '.grok.com', 'path': '/other'}]
        self.assertEqual(session_cookies(cookies, native=True), {'sso': 'grok-fixture', 'sso-rw': 'grok-rw-fixture'})
        with self.assertRaises(GrokBrowserError):
            session_cookies(cookies + [{'name': 'sso', 'value': 'conflicting', 'domain': '.grok.com'}], native=True)

    def test_request_cookie_uses_full_headers_and_missing_value_is_not_identity(self):
        request = SimpleNamespace(headers={}, all_headers=lambda: {'cookie': 'other=x; sso=fixture-sso; sso-rw=fixture-rw'})
        self.assertEqual(request_sso(request), 'fixture-sso')
        self.assertEqual(request_sso(SimpleNamespace(all_headers=lambda: {})), '')
        self.assertEqual(request_sso(SimpleNamespace()), '')

    def test_browser_error_after_submit_is_uncertain_without_logging_secrets(self):
        jid = self.create()
        def run(record, mailbox, signals, update):
            update('running', 'profile_submit', 'fixture', profile_submitted=True)
            raise TimeoutError('private-password https://private-url/?token=private')
        with patch('core.grok_protocol.run', side_effect=run): service._run(jid, service.Signals())
        record = store.job(jid)
        self.assertEqual(record['status'], 'uncertain')
        self.assertNotIn('private-password', json.dumps(record))

    def test_credential_access_requires_auth_and_does_not_leak_in_lists(self):
        self.complete()
        client = create_app(auth_code='fixture').test_client()
        headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}
        self.assertEqual(client.get('/api/grok/accounts').status_code, 401)
        row = client.get('/api/grok/accounts', headers=headers).get_json()['items'][0]
        self.assertNotIn('private-sso', json.dumps(row)); self.assertNotIn('password', row)
        path = f"/api/grok/accounts/{row['id']}/secret?field=sso"
        self.assertEqual(client.get(path).status_code, 401)
        response = client.get(path, headers=headers)
        self.assertEqual(response.get_json()['value'], 'private-sso')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(client.get(path.replace('sso', 'token'), headers=headers).status_code, 400)

    def test_grok_api_validation_does_not_dispatch_or_require_gpt_driver(self):
        client = create_app(auth_code='fixture').test_client()
        headers = {'X-Auth-Code': 'fixture'}
        with patch('core.grok_service.submit', return_value=[1]) as submit, \
             patch('core.workflow_driver.require_driver_ready', side_effect=AssertionError('GPT driver not involved')):
            self.assertEqual(client.post('/api/grok/jobs', json={'emails': [self.item]}, headers=headers).status_code, 400)
            self.assertEqual(client.post('/api/grok/jobs', json=[1], headers=headers).status_code, 400)
            submit.assert_not_called()
            response = client.post('/api/grok/jobs', json={'emails': [self.item], 'authorized': True}, headers=headers)
            self.assertEqual(response.status_code, 202)

    def test_grok_queue_save_is_persistent_and_independent_of_gpt(self):
        from core import registration_service
        before = registration_service.get_executor_workers()
        service.control('configure', 3)
        self.assertEqual(store.workers(), 3)
        self.assertEqual(service.state()['workers'], 3)
        self.assertEqual(registration_service.get_executor_workers(), before)
        for bad in (0, 5, True, '2', 2.5):
            with self.assertRaises(ValueError): service.control('configure', bad)

    def test_protocol_default_does_not_require_browser_and_persists_driver(self):
        executor = Mock()
        executor.submit.return_value = Future()
        with patch.object(service, '_EXECUTOR', executor), \
             patch('core.grok_browser.require_browser', side_effect=RuntimeError('no browser')) as browser:
            jid = service.submit([self.item])[0]
            browser.assert_not_called()
            self.assertEqual(store.job(jid, private=True)['private']['driver'], 'protocol')
            with self.assertRaises(RuntimeError): service.submit([self.item], driver='browser')
        client = create_app(auth_code='fixture').test_client()
        result = client.post('/api/grok/jobs', headers={'X-Auth-Code':'fixture'},
            json={'authorized':True, 'emails':[self.item], 'driver':'invalid'})
        self.assertEqual(result.status_code, 400)

    def test_cli_auth_status_is_listed_and_download_secret_is_explicit(self):
        jid = self.create()
        store.update_job(jid, 'running', 'save', 'fixture', private={'profile_submitted': True})
        saved = store.save_account(jid, {'sso': 'cli-fixture-sso'})
        store.set_cli_auth(saved['account_id'], {'status': 'ready', 'authorized_at': '2026-11-04T00:00:00Z',
            'expires_at': '2026-11-04T06:00:00Z', 'error': '', 'auth_json': {'scope': {'key': 'fixture'}}})
        row = store.accounts()['items'][0]
        self.assertTrue(row['has_cli_auth']); self.assertEqual(row['cli_auth_status'], 'ready')
        self.assertNotIn('auth_json', row)
        client = create_app(auth_code='fixture').test_client(); headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}
        value = client.get(f"/api/grok/accounts/{row['id']}/secret?field=cli_auth", headers=headers).get_json()['value']
        self.assertEqual(json.loads(value), {'scope': {'key': 'fixture'}})
        download = client.get(f"/api/grok/accounts/{row['id']}/cli-auth/download", headers=headers)
        self.assertEqual(download.status_code, 200); self.assertEqual(download.mimetype, 'application/json')
        self.assertIn('attachment', download.headers['Content-Disposition'])

    def test_registration_success_auto_saves_cli_auth(self):
        jid = self.create()
        def run(record, mailbox, signals, update):
            update('running', 'profile_submit', 'fixture', profile_submitted=True, password_confirmed=True)
            return {'sso': 'cli-success-sso', 'sso-rw': 'cli-success-rw'}
        fake = {'status': 'success', 'authorized_at': '2026-11-04T00:00:00Z', 'expires_at': '2026-11-04T06:00:00Z',
                'auth_json': {'scope': {'key': 'fixture-key'}}}
        with patch('core.grok_protocol.run', side_effect=run), \
             patch('core.grok_cli_auth.authorize_account', return_value=fake):
            service._run(jid, service.Signals())
        self.assertEqual(store.job(jid)['status'], 'success')
        row = store.accounts()['items'][0]
        self.assertEqual(row['cli_auth_status'], 'ready'); self.assertTrue(row['has_cli_auth'])
        self.assertEqual(json.loads(store.secret(row['id'], 'cli_auth')), {'scope': {'key': 'fixture-key'}})

    def test_cli_auth_failure_marks_retryable_and_never_blocks_registration(self):
        jid = self.create()
        def run(record, mailbox, signals, update):
            update('running', 'profile_submit', 'fixture', profile_submitted=True, password_confirmed=True)
            return {'sso': 'cli-failure-sso', 'sso-rw': 'cli-failure-rw'}
        with patch('core.grok_protocol.run', side_effect=run), \
             patch('core.grok_cli_auth.authorize_account', side_effect=RuntimeError('fixture cli failure')):
            service._run(jid, service.Signals())
        record = store.job(jid)
        self.assertEqual(record['status'], 'success')
        self.assertIn('Grok CLI 授权未完成', str(record['events']))
        row = store.accounts()['items'][0]
        self.assertEqual(row['cli_auth_status'], 'failed')
        self.assertFalse(row['has_cli_auth'])

    def test_cli_auth_builder_uses_official_registry_shape(self):
        from core import grok_cli_auth
        import base64
        claims = base64.urlsafe_b64encode(json.dumps({'sub': 'principal-fixture', 'email': 'fixture@icloud.com',
            'principal_type': 'User'}).encode()).decode().rstrip('=')
        token = 'header.' + claims + '.signature'
        value = grok_cli_auth.build_auth_json('fixture@icloud.com', {'access_token': token, 'refresh_token': 'refresh-fixture',
            'expires_in': 3600, 'token_type': 'Bearer'})
        auth = value[grok_cli_auth.AUTH_REGISTRY_KEY]
        self.assertEqual(auth['auth_mode'], 'oidc'); self.assertEqual(auth['email'], 'fixture@icloud.com')
        self.assertEqual(auth['principal_id'], 'principal-fixture'); self.assertEqual(auth['key'], token)
        self.assertEqual(auth['refresh_token'], 'refresh-fixture')
        self.assertTrue(auth['expires_at'].endswith('Z'))

    def test_protocol_account_origin_is_not_mislabeled_browser_or_capture(self):
        jid = self.create()
        store.update_job(jid, 'running', 'save', 'fixture', private={'profile_submitted':True,
            'password_confirmed':True, 'registration_origin':'protocol','session_validation_status':'protocol_identity'})
        store.save_account(jid, {'sso':'protocol-fixture-sso'})
        item = store.accounts()['items'][0]
        self.assertEqual(item['registration_origin'], 'protocol')
        self.assertEqual(item['session_validation_status'], 'protocol_identity')

    def test_bounded_dispatch_pause_resume_and_stop_do_not_cancel_admitted_work(self):
        class Executor:
            def __init__(self): self.futures = []
            def submit(self, *args):
                f = Future(); self.futures.append(f); return f
        executor = Executor()
        boxes = [self.item]
        for i in range(4):
            email = f'fixture{i}@icloud.com'
            db.import_generic_api_emails([{'email': email, 'code_url': 'https://fixture.test/api'}])
            boxes.append({'email': email, 'source': 'generic_api'})
        with patch.object(service, '_EXECUTOR', executor), patch('core.grok_browser.require_browser', return_value={}):
            service.control('configure', 2)
            ids = service.submit(boxes)
            self.assertEqual((service.state()['active'], service.state()['waiting']), (2, 3))
            self.assertEqual(store.jobs()['total'], 0)
            service.control('pause')
            store.update_job(ids[0], 'failed', 'fixture', 'fixture')
            executor.futures[0].set_result(None)
            self.assertEqual((service.state()['active'], service.state()['waiting']), (1, 3))
            service.control('resume')
            self.assertEqual((service.state()['active'], service.state()['waiting']), (2, 2))
            service.control('stop')
            self.assertEqual((service.state()['active'], service.state()['waiting']), (2, 0))
            for jid in ids[1:3]:
                self.assertEqual(store.job(jid)['status'], 'pending')
                self.assertFalse(service._RUNNING[jid].stop.is_set())
            for jid in ids[3:]:
                self.assertEqual(store.job(jid)['status'], 'cancelled')
            self.assertEqual(store.jobs()['total'], 1)

    def test_manual_code_is_one_time_and_never_logged(self):
        jid = self.create(); signals = service.Signals()
        with patch.dict(service._RUNNING, {jid: signals}):
            with self.assertRaises(ValueError): service.manual_code(jid, 'ABC-DEF')
            store.update_job(jid, 'manual_required', 'email_code', 'fixture')
            service.manual_code(jid, 'a1b-c2d')
            self.assertEqual(signals.take_code(), 'A1B-C2D'); self.assertEqual(signals.take_code(), '')
            service.manual_code(jid, '123456')
            self.assertEqual(signals.take_code(), '123-456')
            with self.assertRaises(ValueError): service.manual_code(jid, '12345')
        self.assertNotIn('A1B-C2D', json.dumps(store.job(jid)))

    def test_continue_requires_explicit_confirmation_and_only_signals_active_handoff(self):
        jid = self.create(); signals = service.Signals()
        client = create_app(auth_code='fixture').test_client()
        path = f'/api/grok/jobs/{jid}/continue'; headers = {'X-Auth-Code': 'fixture'}
        with patch.dict(service._RUNNING, {jid: signals}):
            self.assertEqual(client.post(path, json={'confirmed': True}).status_code, 401)
            self.assertEqual(client.post(path, headers=headers, json={}).status_code, 400)
            self.assertEqual(client.post(path, headers=headers, json={'confirmed': True}).status_code, 400)
            store.update_job(jid, 'manual_required', 'access_check', 'fixture')
            self.assertEqual(client.post(path, headers=headers, json={'confirmed': True}).status_code, 200)
            self.assertTrue(signals.resume.is_set())

    def test_browser_diagnostic_only_keeps_safe_identifiers_and_redacted_json(self):
        response = SimpleNamespace(url='https://accounts.x.ai/twirp/auth/CreateEmailValidationCode?token=private-url',
            status=403, headers={'Content-Type': 'application/json', 'x-request-id': 'req-fixture', 'cf-ray': 'ray-fixture',
                                 'set-cookie': 'sso=do-not-log-cookie'}, request=SimpleNamespace(resource_type='fetch'),
            body=lambda: json.dumps({'code': 'permission_denied', 'message': 'fixture@icloud.com private-password ABC-DEF sso=secret-cookie https://private.test'}).encode())
        detail = response_diagnostic(response, sensitive_values=('private-password',))
        text = diagnostic_message(detail)
        self.assertEqual(detail['endpoint'], 'CreateEmailValidationCode')
        self.assertEqual(detail['error_code'], 'permission_denied')
        self.assertIn('req-fixture', text)
        for secret in ('private-url', 'fixture@icloud.com', 'private-password', 'ABC-DEF', 'secret-cookie', 'private.test', 'do-not-log-cookie'):
            self.assertNotIn(secret, json.dumps(detail))


class GrokMailTests(unittest.TestCase):
    def test_prefetch_403_is_not_signup_failure_but_real_submit_is(self):
        frame=object();page=SimpleNamespace(main_frame=frame)
        def request(method='GET',headers=None,navigate=False):
            return SimpleNamespace(method=method,headers=headers or {},frame=frame,is_navigation_request=lambda:navigate)
        for path in ('/','/sign-in','/monitoring'):
            self.assertFalse(interactive_auth_error(SimpleNamespace(url='https://grok.com'+path,request=request()),page))
        actual=SimpleNamespace(url='https://grok.com/api/auth/send-verification-code',request=request('POST'))
        self.assertTrue(interactive_auth_error(actual,page))
        actual.request=request('POST',{'Next-Router-Prefetch':'1'})
        self.assertFalse(interactive_auth_error(actual,page))
        self.assertTrue(interactive_auth_error(SimpleNamespace(url='https://grok.com/',request=request(navigate=True)),page))
    def test_visible_browser_restore_is_scoped_and_does_not_change_browser_security(self):
        context, page, session = Mock(), Mock(), Mock()
        context.new_cdp_session.return_value = session
        session.send.side_effect = [{'windowId': 17}, {}]
        self.assertTrue(show_browser_window(context, page))
        context.new_cdp_session.assert_called_once_with(page)
        self.assertEqual(session.send.call_args_list[1].args, ('Browser.setWindowBounds', {'windowId': 17, 'bounds': {'windowState': 'normal'}}))
        page.bring_to_front.assert_called_once(); session.detach.assert_called_once()
        session.send.side_effect = RuntimeError('private browser exception')
        self.assertFalse(show_browser_window(context, page))

    def test_api_diagnostics_distinguish_business_failure_empty_and_numeric_without_secrets(self):
        box = {'source': 'generic_api', 'code_url': 'https://fixture.test/api?token=private'}
        for status, value, shape in ((0, '', 'empty'), (1, '', 'empty'), (1, '123456', 'numeric_not_grok'), (1, 'A1B-C2D', 'grok_alphanumeric')):
            http = Mock(); http.get.return_value = Mock(status_code=200, json=lambda: {'code': status, 'data': {'code': value}})
            seen = []
            mail.read_once(box, http=http, diagnostic=seen.append)
            self.assertEqual(seen[0]['business_status'], status)
            self.assertEqual(seen[0]['code_shape'], shape)
            for secret in ('123456', 'A1B-C2D', 'private'):
                self.assertNotIn(secret, json.dumps(seen))

    def test_grok_code_contract_never_reuses_openai_numeric_code(self):
        self.assertEqual(mail.extract_code({'code': 1, 'data': {'code': 'A1B-C2D'}}), 'A1B-C2D')
        self.assertEqual(mail.extract_code({'code': 1, 'data': {'code': 'a1bc2d'}}), 'A1B-C2D')
        self.assertEqual(mail.extract_code({'status': 1, 'code': 'A1B-C2D'}), 'A1B-C2D')
        for code in ('123456', '123-456', '', 'sm-w-per-100', '１２３４５６'):
            self.assertEqual(mail.extract_code({'code': 1, 'data': {'code': code}}), '')
        self.assertEqual(mail.extract_code({'code': False, 'data': {'code': 'ABC-DEF'}}), '')
        self.assertEqual(mail.extract_code({'status': 'success', 'data': {'subject': 'xAI verification code ABC-DEF'}}), 'ABC-DEF')
        self.assertEqual(mail.extract_code({'code': 1, 'data': {'subject': 'ticket ABC-DEF'}}), '')

    def test_api_read_is_once_no_redirect_no_proxy_fallback(self):
        http = Mock(); http.get.return_value = Mock(status_code=200, json=lambda: {'code': 1, 'data': {'code': 'A1B-C2D'}})
        box = {'source': 'generic_api', 'code_url': 'https://icapi.oaibx.com/api?token=private'}
        self.assertEqual(mail.read_once(box, http=http), 'A1B-C2D')
        self.assertEqual(http.get.call_count, 1); self.assertFalse(http.get.call_args.kwargs['allow_redirects'])
        http.get.side_effect = requests.Timeout('https://private/?token=secret')
        with self.assertRaises(mail.GrokMailError) as ctx: mail.read_once(box, http=http)
        self.assertNotIn('secret', str(ctx.exception))

    def test_service_refusals_and_invalid_urls_do_not_fall_back(self):
        for status in (401, 403, 429):
            http = Mock(); http.get.return_value = Mock(status_code=status)
            with self.assertRaises(mail.GrokMailError):
                mail.read_once({'source': 'generic_api', 'code_url': 'https://example.test/api'}, http=http)
            http.get.assert_called_once()
        for url in ('http://example.test/api', 'https://user:password@example.test', 'https://example.test:abc'):
            http = Mock()
            with self.assertRaises(mail.GrokMailError): mail.read_once({'source': 'generic_api', 'code_url': url}, http=http)
            http.get.assert_not_called()


if __name__ == '__main__':
    unittest.main()
