import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main
from core import db, registration_service as svc
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class FailureDesignTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        state = patch.multiple(db, **storage(self.root), _LOG_DIR=self.root / "logs")
        state.start()
        self.addCleanup(state.stop)
        self.was_paused = not svc._PAUSE_GATE.is_set()
        self.addCleanup(lambda: svc._PAUSE_GATE.clear() if self.was_paused else svc._PAUSE_GATE.set())

    def test_failure_categories_do_not_invent_deactivation_or_echo_secrets(self):
        cases = [
            ("wrong_email_otp_code private-signature", "email_otp_rejected", "attention_required"),
            ("MissingSchema signed-url private-signature", "mail_url_invalid", "configuration_error"),
            ("等待通用 API 验证码超时: ConnectTimeout", "mail_network_timeout", "mail_timeout"),
            ("等待通用 API 验证码超时", "mail_timeout", "mail_timeout"),
            ("curl: (35) SSL_connect", "network_error", "network_error"),
            ("curl: (28) timed out", "network_error", "network_error"),
            ("注册尚未到达邮箱验证页", "unexpected_auth_page", "attention_required"),
            ("注册尚未到达邮箱验证页（当前路径 /v3/signin/identifier）", "gmail_login_required", "attention_required"),
        ]
        for error, code, state in cases:
            with self.subTest(code=code):
                info = svc.failure_info(error)
                self.assertEqual((info['failure_code'], info['display_status']), (code, state))
                self.assertNotIn('private-signature', str(info))
                self.assertNotEqual(info['display_status'], 'disabled')

    def test_google_login_redirect_is_manual_and_not_an_email_otp_failure(self):
        error = "注册尚未到达邮箱验证页（当前路径 /v3/signin/identifier），已停止"
        info = svc.failure_info(error)
        self.assertEqual(info['failure_code'], 'gmail_login_required')
        self.assertIn('需 Gmail 登录', info['status_message'])
        self.assertIn('尚未发送邮箱验证码', info['status_message'])
        self.assertTrue(info['needs_manual_review'])
        self.assertFalse(svc._should_disable_failed_registration_email(error))
        job = db.create_job('generic_api', 'fixture@gmail.com')
        db.update_job(job['id'], status='failed', error=error)
        client = create_app(auth_code='fixture').test_client()
        headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}
        response = client.get(f"/api/jobs/{job['id']}/log", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('需 Gmail 登录', response.json['job']['status_message'])
        self.assertFalse(response.json['job']['retryable'])

    def test_google_redirect_stops_before_any_email_otp_send(self):
        with patch.object(main, 'send_email_otp') as send:
            with self.assertRaisesRegex(RuntimeError, '需 Gmail 登录'):
                main._prepare_registration_otp(
                    None, 'fixture@gmail.com',
                    'https://accounts.google.com/v3/signin/identifier?state=fixture',
                )
            send.assert_not_called()

    def test_imap_timeout_is_classified_without_exception_class_in_saved_error(self):
        info = svc.failure_info("等待 fixture@example.test 的 OTP 超时（>180s）；本地检查 60 次，远端刷新 0 次，匹配目标邮件 0 封")
        self.assertEqual(info['failure_code'], 'imap_otp_timeout')
        self.assertEqual(info['display_status'], 'mail_timeout')
        self.assertIn('共享收件箱', info['status_message'])
        self.assertIn('转发收件箱', info['status_message'])
        self.assertNotIn('fixture@example.test', info['status_message'])

    def test_ambiguous_login_or_session_errors_do_not_disable_mailboxes(self):
        errors = [
            "邮箱提交后进入登录密码页 https://auth.openai.com/log-in/password",
            "等待 /api/auth/session accessToken 超时 WARNING_BANNER '_http_status': 200",
            "未拿到 accessToken，登录态可能未建立",
            "wrong_email_otp_code", "SSLError", "账号已废弃，但未核实",
        ]
        for error in errors:
            with self.subTest(error=error):
                self.assertFalse(svc._should_disable_failed_registration_email(error))
        for code in ("account_deactivated", "account_deleted", "account_banned"):
            self.assertTrue(svc._should_disable_failed_registration_email(code))

    def test_incomplete_session_and_existing_login_require_manual_review(self):
        for error, code in [
            ("邮箱提交后进入登录密码页 /log-in/password", "existing_login_required"),
            ("等待 /api/auth/session accessToken 超时 WARNING_BANNER", "session_incomplete"),
        ]:
            with self.subTest(code=code):
                info = svc.failure_info(error)
                self.assertEqual(info['failure_code'], code)
                self.assertTrue(info['needs_manual_review'])
                self.assertEqual(info['display_status'], 'attention_required')

    def test_pause_states_distinguish_waiting_in_flight_queued_and_orphaned(self):
        q = {'paused': True, 'active_job_ids': [1, 2], 'paused_job_ids': [1]}
        for jid, status, expected in [(1, 'running', 'running'), (2, 'running', 'running'),
                                      (3, 'pending', 'paused_queue'), (4, 'running', 'interrupted')]:
            info = svc.job_display_info({'id': jid, 'status': status}, q)
            self.assertEqual(info.get('display_status', status), expected)
        self.assertEqual(svc.job_display_info({'id': 1, 'status': 'stopping'}, q), {})
        self.assertEqual(svc.job_display_info({'id': 2, 'status': 'running'}, {**q, 'paused': False}), {})
        self.assertEqual(svc.job_display_info({'id': 1, 'status': 'success', 'display_status': 'disabled'}, q), {})

    def test_admitted_worker_continues_during_intake_pause(self):
        job = db.create_job('generic_api', 'fixture@example.test')
        svc._PAUSE_GATE.clear()
        with patch.object(main, 'run_registration', return_value={'success':True,'email':'fixture@example.test'}) as run, \
             patch.object(svc, '_prepare_registration_args', return_value=('fixture@example.test','Fixture','1990-01-01')) as prepare, \
             patch.object(db, 'claim_pool_email') as claim:
            worker = threading.Thread(target=svc._run_one_job, args=(job['id'], job['log_file']))
            worker.start()
            try:
                worker.join(3)
                self.assertFalse(worker.is_alive())
                prepare.assert_called_once(); claim.assert_called_once(); run.assert_called_once()
            finally:
                with svc._STOP_LOCK:
                    if job['id'] in svc._STOP_EVENTS:
                        svc._STOP_EVENTS[job['id']].set()
                svc._PAUSE_GATE.set()
                worker.join(3)
        self.assertEqual(db.get_job(job['id'])['status'], 'success')
        self.assertNotIn(job['id'], svc._PAUSED_JOBS)
        self.assertNotIn(job['id'], svc._ACTIVE_JOBS)

    def test_job_api_and_log_have_consistent_pause_explanation_without_db_mutation(self):
        job = db.create_job('generic_api', 'fixture@example.test')
        db.update_job(job['id'], status='running')
        client = create_app(auth_code='fixture').test_client()
        before = db.get_job(job['id'])
        q = {'paused': True, 'active_job_ids': [job['id']], 'paused_job_ids': [job['id']]}
        headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}
        with patch.object(svc, 'registration_pause_status', return_value=q):
            row = client.get('/api/jobs?paged=1', headers=headers).get_json()['items'][0]
            log = client.get(f"/api/jobs/{job['id']}/log", headers=headers).get_json()['job']
        self.assertEqual(row['display_status'], 'running')
        self.assertIn('继续完成', row['status_message'])
        self.assertEqual(row['status_message'], log['status_message'])
        self.assertEqual(row['status'], 'running')
        self.assertEqual(db.get_job(job['id']), before)

    def test_rejected_verification_is_not_blindly_requeued(self):
        job = db.create_job('generic_api', 'fixture@example.test')
        db.update_job(job['id'], status='failed', error='wrong_email_otp_code')
        info = svc.get_retry_info(db.get_job(job['id']))
        self.assertTrue(info['needs_manual_review'])
        self.assertFalse(info['retryable'])
        with patch('core.workflow_driver.require_driver_ready'), patch.object(svc, 'get_executor') as executor:
            result = svc.retry_job(job['id'])
        self.assertEqual(result['status'], 409)
        executor.assert_not_called()
        self.assertEqual(db.get_job(job['id'])['status'], 'failed')

    def test_invalid_otp_stops_after_one_validation_without_resending(self):
        session = SimpleNamespace(proxy='', device_id='fixture', auth_session_logging_id='fixture', sentinel_sid='fixture', browser_profile={})
        with ExitStack() as stack:
            for name, value in [
                ('BrowserSession', session), ('network_preflight', None), ('get_providers', {}),
                ('get_csrf_token', 'fixture'), ('signin_openai', 'fixture'),
                ('follow_authorize', 'https://example.test/email-verification'),
                ('_prepare_registration_otp', ('', 100)), ('wait_for_otp', '001234'),
                ('human_delay', None), ('close_browser_session', None),
            ]:
                stack.enter_context(patch.object(main, name, return_value=value))
            for cfg, name, value in [
                (main._email_cfg, 'USE_EMAIL_SERVICE', True),
                (main._roxy_cfg, 'REGISTRATION_DRIVER', 'protocol'),
                (main._protocol_cfg, 'CHATGPT_ANON_BOOTSTRAP_ENABLED', False),
                (main._protocol_cfg, 'SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE', False),
            ]:
                stack.enter_context(patch.object(cfg, name, value))
            release = stack.enter_context(patch('core.email_provider.release_email'))
            stack.enter_context(patch('core.protocol_traffic.current_traffic'))
            send = stack.enter_context(patch.object(main, 'send_email_otp'))
            save = stack.enter_context(patch.object(main, 'save_account_data'))
            validate = stack.enter_context(patch.object(main, 'validate_email_otp', side_effect=main.EmailOtpInvalidError('wrong_email_otp_code')))
            with self.assertLogs(main.logger, level='WARNING'):
                result = main.run_registration('fixture@example.test', 'Fixture User', '1990-01-01')
        self.assertFalse(result['success'])
        validate.assert_called_once()
        send.assert_not_called(); save.assert_not_called()
        release.assert_called_once()
        self.assertEqual(release.call_args.kwargs['status'], 'failed')
        self.assertIn('未判定账号停用', release.call_args.kwargs['note'])

    def test_unverified_freshness_never_reaches_otp_validation(self):
        from core.otp_freshness import OtpFreshnessError
        session = SimpleNamespace(proxy='', device_id='fixture', auth_session_logging_id='fixture',
                                  sentinel_sid='fixture', browser_profile={})
        with ExitStack() as stack:
            for name, value in [
                ('BrowserSession', session), ('network_preflight', None), ('get_providers', {}),
                ('get_csrf_token', 'fixture'), ('signin_openai', 'fixture'),
                ('follow_authorize', 'https://example.test/email-verification'),
                ('_prepare_registration_otp', ('', 100)), ('human_delay', None), ('close_browser_session', None),
            ]:
                stack.enter_context(patch.object(main, name, return_value=value))
            for cfg, name, value in [
                (main._email_cfg, 'USE_EMAIL_SERVICE', True),
                (main._roxy_cfg, 'REGISTRATION_DRIVER', 'protocol'),
                (main._protocol_cfg, 'CHATGPT_ANON_BOOTSTRAP_ENABLED', False),
                (main._protocol_cfg, 'SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE', False),
            ]:
                stack.enter_context(patch.object(cfg, name, value))
            stack.enter_context(patch.object(main, 'wait_for_otp', side_effect=OtpFreshnessError('missing_metadata')))
            stack.enter_context(patch('core.protocol_traffic.current_traffic'))
            validate = stack.enter_context(patch.object(main, 'validate_email_otp'))
            send = stack.enter_context(patch.object(main, 'send_email_otp'))
            save = stack.enter_context(patch.object(main, 'save_account_data'))
            release = stack.enter_context(patch('core.email_provider.release_email'))
            with self.assertLogs(main.logger, level='WARNING'):
                result = main.run_registration('fixture@example.test', 'Fixture User', '1990-01-01')
        self.assertFalse(result['success'])
        self.assertIn('mail_otp_freshness_unverified', result['error'])
        validate.assert_not_called(); send.assert_not_called(); save.assert_not_called()
        self.assertEqual(release.call_args.kwargs['status'], 'failed')
        self.assertIn('未判定账号停用', release.call_args.kwargs['note'])


if __name__ == '__main__':
    unittest.main()
