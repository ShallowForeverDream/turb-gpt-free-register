"""Password settings contracts; isolated SQLite, no live account mutations."""
from concurrent.futures import Future
from contextlib import ExitStack
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from core import db, password_setup as pw, registration_completion as completion
from core.auth_page_state import read_auth_page_session
from tests.test_auth_page_initial_delivery import document
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import _compact_account_for_list, create_app


def response(data, status=200):
    result=Mock(status_code=status)
    result.headers={}
    result.json.return_value=data
    return result


class PasswordSetupTests(unittest.TestCase):
    def test_password_polling_updates_same_second_without_returning_password(self):
        with patch.object(db,'_now',return_value='2026-10-31T20:00:00'):
            db.update_account_password_setup(self.aid,'running')
            before=db.list_account_plan_check_statuses()
            self.assertFalse(before['items'][0]['has_gpt_password'])
            db.update_account_password_setup(self.aid,'success',password='Private-password-20!')
            after=db.list_account_plan_check_statuses()
        self.assertNotEqual(before['revision'],after['revision'])
        self.assertTrue(after['items'][0]['has_gpt_password'])
        self.assertEqual(after['items'][0]['password_setup_status'],'success')
        self.assertNotIn('Private-password-20!',json.dumps(after))

    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db,**storage(root)))
        self.aid=db.insert_account(email='fixture@example.test',access_token='fixture-at',
            totp_secret='JBSWY3DPEHPK3PXP',email_source='generic_api',extra={'keep':'metadata'})
        self.session=SimpleNamespace(device_id='fixture-device',is_browser_workflow=False,
            get_chatgpt_headers=Mock(return_value={}),get_nextauth_headers=Mock(return_value={}),
            get_auth_headers=Mock(return_value={}),post=Mock(),get=Mock())
        self.stack.enter_context(patch('core.openai_auth.request_sentinel_token',return_value={}))
        self.stack.enter_context(patch('core.openai_auth.build_sentinel_header',return_value=('fixture-sentinel',None)))
        self.generate=self.stack.enter_context(patch('core.openai_auth.generate_registration_password',return_value='Fixture-password-20!'))
        self.close=self.stack.enter_context(patch('core.session.close_browser_session'))
        self.refresh=self.stack.enter_context(patch('core.account_export.fetch_session',return_value={
            'accessToken':'refreshed-at','user':{'email':'fixture@example.test'}}))
        self.wait=self.stack.enter_context(patch('core.email_provider.wait_for_otp',return_value='123456'))
        self.stack.enter_context(patch('core.generic_api_mail_client.create_signature_poll_state',return_value=None))
        self.stack.enter_context(patch('core.generic_api_mail_client.uses_direct_icapi_polling',return_value=True))
        self.stack.enter_context(patch('core.openai_auth.initialize_passwordless_login_otp',return_value=False))
        self.submissions=[]
        def get(url,**kwargs):
            if url.endswith('/add_password/eligibility'):return response({'eligible':True})
            if url.endswith('/api/auth/csrf'):return response({'csrfToken':'fixture-csrf'})
            raise AssertionError('unexpected GET')
        self.session.get.side_effect=get
        def post(url,**kwargs):
            self.submissions.append(url.split('?')[0])
            if '/signin/openai?' in url:return response({'url':'https://auth.openai.com/oauth/authorize?fixture=1'})
            if url.endswith('/email-otp/validate'):
                return response({'continue_url':'https://auth.openai.com/mfa-challenge/factor-fixture',
                                 'page':{'type':'mfa_challenge'}})
            if url.endswith('/mfa/issue_challenge'):return response({'success':True})
            if url.endswith('/mfa/verify'):
                return response({'continue_url':'https://auth.openai.com/reset-password/new-password',
                                 'page':{'type':'reset_password_new_password'}})
            if url.endswith('/password/add'):return response({'page':{'type':'reset_password_success'}})
            raise AssertionError('unexpected POST')
        self.session.post.side_effect=post
        self.navigate=self.stack.enter_context(patch('core.openai_auth.follow_authorize',
            side_effect=self.setUpNavigate()))

    def setUpNavigate(self):
        def navigate(session,url):
            if '/oauth/authorize' in url:return 'https://auth.openai.com/email-verification?auth_page=fixture'
            session._registration_auth_page_state={'session_id':'fixture-session','email':'fixture@example.test',
                                                  'post_login_add_password':True}
            return url
        return navigate

    def run_setup(self):
        return pw.set_missing_password(self.aid,session=self.session)

    def test_confirmed_password_is_added_after_email_and_totp_and_saved_separately(self):
        with self.assertLogs('core.password_setup',level='INFO') as logs:
            result=self.run_setup()
        self.assertTrue(result['ok'])
        self.assertEqual(self.submissions[-1],'https://auth.openai.com/api/accounts/password/add')
        self.assertIn('https://auth.openai.com/api/accounts/mfa/verify',self.submissions)
        signin=self.session.post.call_args_list[0]
        self.assertIn('post_login_add_password=true',signin.args[0])
        self.assertEqual(self.wait.call_args.kwargs['first_read_delay_seconds'],30)
        saved=db.get_account(self.aid)
        self.assertEqual(saved['password_setup_status'],'success')
        self.assertEqual(db._extract_registration_password(saved),'Fixture-password-20!')
        self.assertEqual(saved['totp_secret'],'JBSWY3DPEHPK3PXP')
        self.assertEqual(json.loads(saved['extra_json'])['keep'],'metadata')
        self.assertNotIn('password_setup_candidate',json.loads(saved['extra_json']))
        self.assertEqual(saved['access_token'],'refreshed-at')
        self.assertNotIn('Fixture-password-20!','\n'.join(logs.output))
        self.assertNotIn('123456','\n'.join(logs.output))
        self.assertNotIn('Fixture-password-20!',json.dumps(_compact_account_for_list(saved)))
        self.close.assert_not_called()

    def test_official_continue_url_success_without_legacy_flags_is_saved(self):
        original=self.session.post.side_effect
        def post(url,**kwargs):
            if url.endswith('/password/add'):
                return response({'continue_url':'https://auth.openai.com/reset-password/success?auth_page=fixture',
                                 'method':'GET'})
            return original(url,**kwargs)
        self.session.post.side_effect=post
        self.assertTrue(self.run_setup()['ok'])
        saved=db.get_account(self.aid)
        self.assertEqual(saved['password_setup_status'],'success')
        self.assertEqual(db._extract_registration_password(saved),'Fixture-password-20!')
        self.assertNotIn('password_setup_candidate',json.loads(saved['extra_json']))
        posts=[call for call in self.session.post.call_args_list if call.args[0].endswith('/password/add')]
        self.assertEqual(len(posts),1)

    def test_official_success_continuation_without_method_and_empty_200_are_accepted(self):
        for payload in ({'continue_url':'https://auth.openai.com/reset-password/success?auth_page=fixture'}, {}):
            with self.subTest(payload=payload):
                self.session.post.side_effect=self.setUpPost(payload)
                result=self.run_setup()
                self.assertTrue(result['ok'])
                saved=db.get_account(self.aid)
                self.assertEqual(saved['password_setup_status'],'success')
                self.assertEqual(db._extract_registration_password(saved),'Fixture-password-20!')
                posts=[c for c in self.session.post.call_args_list if c.args[0].endswith('/password/add')]
                self.assertEqual(len(posts),1)

    def setUpPost(self, add_payload):
        def get(url,**kwargs):
            if url.endswith('/add_password/eligibility'):return response({'eligible':True})
            if url.endswith('/api/auth/csrf'):return response({'csrfToken':'fixture-csrf'})
            raise AssertionError('unexpected GET')
        def post(url,**kwargs):
            if '/signin/openai?' in url:return response({'url':'https://auth.openai.com/oauth/authorize?fixture=1'})
            if url.endswith('/email-otp/validate'):
                return response({'continue_url':'https://auth.openai.com/mfa-challenge/factor-fixture',
                                 'page':{'type':'mfa_challenge'}})
            if url.endswith('/mfa/issue_challenge'):return response({'success':True})
            if url.endswith('/mfa/verify'):
                return response({'continue_url':'https://auth.openai.com/reset-password/new-password',
                                 'page':{'type':'reset_password_new_password'}})
            if url.endswith('/password/add'):return response(add_payload)
            raise AssertionError('unexpected POST '+url)
        self.session.post.side_effect=post
        self.session.get.side_effect=get
        return post

    def test_only_bound_success_continuation_confirms_a_password(self):
        for data in (
            {'continue_url':'https://evil.example.test/reset-password/success'},
            {'continue_url':'https://auth.openai.com/log-in/password'},
            {'continue_url':'https://auth.openai.com/reset-password/new-password'},
            {'continue_url':'https://auth.openai.com/reset-password/success','method':'POST'},
            {'continue_url':'https://auth.openai.com/reset-password/success','page':{'type':'login'}},
            {'page':{'type':'reset_password_success'},'success':False},
        ):
            with self.subTest(data=data):
                try:confirmed=pw._confirmed_add_result(data)
                except pw.PasswordSetupError:confirmed=False
                self.assertFalse(confirmed)
        self.assertTrue(pw._confirmed_add_result(
            {'continue_url':'https://auth.openai.com/reset-password/success?auth_page=fixture'}))

    def test_explicit_password_rejection_records_safe_details_not_uncertainty(self):
        original=self.session.post.side_effect
        def post(url,**kwargs):
            if url.endswith('/password/add'):
                result=response({'error':{'code':'password_too_weak',
                    'message':'Rejected Fixture-password-20! for fixture@example.test using fixture-at'}},422)
                result.headers={'x-request-id':'req-password-fixture'}
                return result
            return original(url,**kwargs)
        self.session.post.side_effect=post
        with self.assertLogs(pw.logger,'WARNING') as logs:
            result=self.run_setup()
        self.assertEqual(result['status'],'failed')
        saved=db.get_account(self.aid)
        detail=saved['password_setup_diagnostic']
        self.assertEqual((detail['stage'],detail['http_status'],detail['error_code'],detail['request_id']),
                         ('password_add',422,'password_too_weak','req-password-fixture'))
        self.assertNotIn('password_setup_candidate',json.loads(saved['extra_json']))
        text=json.dumps(detail)+'\n'+'\n'.join(logs.output)+result['error']
        for private in ('Fixture-password-20!','fixture@example.test','fixture-at'):
            self.assertNotIn(private,text)
        self.assertEqual(len([c for c in self.session.post.call_args_list if c.args[0].endswith('/password/add')]),1)

    def test_unknown_success_response_retains_request_id_and_private_candidate(self):
        original=self.session.post.side_effect
        def post(url,**kwargs):
            if url.endswith('/password/add'):
                result=response({'page':{'type':'login'}})
                result.headers={'x-request-id':'req-unrecognized-fixture'}
                return result
            return original(url,**kwargs)
        self.session.post.side_effect=post
        self.assertEqual(self.run_setup()['status'],'accepted_unverified')
        row=db.get_account(self.aid)
        self.assertEqual(row['password_setup_diagnostic']['http_status'],200)
        self.assertEqual(row['password_setup_diagnostic']['request_id'],'req-unrecognized-fixture')
        self.assertEqual(json.loads(row['extra_json'])['password_setup_candidate'],'Fixture-password-20!')

    def test_mail_failure_reports_its_stage_without_revealing_private_url(self):
        self.wait.side_effect=TimeoutError('https://private.example.test/?token=private-fixture')
        with self.assertLogs(pw.logger,'WARNING') as logs:
            result=self.run_setup()
        self.assertEqual(result['status'],'failed')
        detail=db.get_account(self.aid)['password_setup_diagnostic']
        self.assertEqual(detail['stage'],'email_otp')
        self.assertEqual(detail['error_code'],'unavailable')
        self.assertEqual(detail['exception_type'],'TimeoutError')
        self.assertNotIn('private-fixture','\n'.join(logs.output))
        self.assertFalse(any(c.args[0].endswith('/password/add') for c in self.session.post.call_args_list))

    def test_unstructured_http_exception_does_not_discard_private_candidate(self):
        original=self.session.post.side_effect
        error=RuntimeError('https://private.example.test/?password=Fixture-password-20!')
        error.response=response({},400)
        def post(url,**kwargs):
            if url.endswith('/password/add'):raise error
            return original(url,**kwargs)
        self.session.post.side_effect=post
        self.assertEqual(self.run_setup()['status'],'uncertain')
        row=db.get_account(self.aid)
        self.assertEqual(row['password_setup_diagnostic']['error_code'],'unavailable')
        self.assertEqual(json.loads(row['extra_json'])['password_setup_candidate'],'Fixture-password-20!')

    def test_eligibility_failure_keeps_http_status_and_request_id_before_any_post(self):
        self.session.get.side_effect=None
        denied=response({'error':{'code':'invalid_token','message':'Expired fixture-at'}},401)
        denied.headers={'x-request-id':'req-eligibility-fixture'}
        self.session.get.return_value=denied
        result=self.run_setup()
        self.assertEqual(result['status'],'failed')
        detail=db.get_account(self.aid)['password_setup_diagnostic']
        self.assertEqual((detail['stage'],detail['http_status'],detail['request_id']),
                         ('eligibility_add',401,'req-eligibility-fixture'))
        self.assertNotIn('fixture-at',json.dumps(detail))
        self.session.post.assert_not_called()

    def test_refresh_failure_does_not_undo_confirmed_password_or_repost(self):
        self.refresh.side_effect=TimeoutError('private-refresh-url')
        with self.assertLogs(pw.logger,'WARNING') as logs:
            result=self.run_setup()
        self.assertTrue(result['ok'])
        row=db.get_account(self.aid)
        self.assertEqual(row['password_setup_status'],'success')
        self.assertEqual(db._extract_registration_password(row),'Fixture-password-20!')
        self.assertNotIn('password_setup_candidate',json.loads(row['extra_json']))
        self.assertNotIn('private-refresh-url','\n'.join(logs.output))
        self.assertEqual(len([c for c in self.session.post.call_args_list if c.args[0].endswith('/password/add')]),1)

    def test_saved_password_never_calls_network_or_generates_replacement(self):
        db.update_account_password_setup(self.aid,'success',password='keep-existing-password')
        self.assertEqual(self.run_setup()['reason'],'already_saved')
        self.session.get.assert_not_called();self.session.post.assert_not_called();self.generate.assert_not_called()
        self.assertEqual(db._extract_registration_password(db.get_account(self.aid)),'keep-existing-password')

    def test_remote_existing_password_is_not_reset_or_fabricated_locally(self):
        self.session.get.side_effect=lambda url,**kw:response({'eligible':'/change_password/' in url})
        result=self.run_setup()
        self.assertEqual((result['ok'],result['reason']),(True,'already_set'))
        self.session.post.assert_not_called();self.generate.assert_not_called()
        self.assertEqual(db._extract_registration_password(db.get_account(self.aid)),'')

    def test_ineligible_or_unknown_eligibility_does_not_submit(self):
        for value in (False,1,None,'true'):
            with self.subTest(value=value):
                def get(url,**kwargs):
                    if url.endswith('/add_password/eligibility'):return response({'eligible':value})
                    if url.endswith('/change_password/eligibility'):return response({'eligible':False})
                    raise AssertionError('unexpected GET')
                self.session.get.side_effect=get
                self.assertFalse(self.run_setup()['ok'])
                self.session.post.assert_not_called();self.generate.assert_not_called()

    def test_password_already_set_is_not_failed_or_reported_as_new_password(self):
        original=self.session.post.side_effect
        def post(url,**kwargs):
            self.submissions.append(url.split('?')[0])
            if url.endswith('/password/add'):
                return response({'error':{'code':'password_already_set',
                                          'message':'You already have a password. Please reset it instead.'}},400)
            return original(url,**kwargs)
        self.session.post.side_effect=post
        result=self.run_setup()
        self.assertTrue(result['ok'])
        self.assertEqual(result['status'],'already_set')
        saved=db.get_account(self.aid)
        self.assertEqual(saved['password_setup_status'],'already_set')
        self.assertFalse(db._extract_registration_password(saved))
        self.assertEqual(len([u for u in self.submissions if u.endswith('/password/add')]),1)

    def test_bare_success_acknowledgement_is_confirmed(self):
        self.assertTrue(pw._confirmed_add_result({'success':True},200))
        self.assertFalse(pw._confirmed_add_result({'success':False},200))
        self.assertFalse(pw._confirmed_add_result({'page':{'type':'login'}},200))

    def test_password_login_page_after_reauth_marks_existing_password(self):
        self.stack.enter_context(patch('core.openai_auth.follow_authorize',
                                       return_value='https://auth.openai.com/log-in/password'))
        with self.assertLogs('core.password_setup',level='INFO') as logs:
            result=self.run_setup()
        self.assertTrue(result['ok'])
        self.assertEqual(result['reason'],'already_set')
        saved=db.get_account(self.aid)
        self.assertEqual(saved['password_setup_status'],'already_set')
        self.assertFalse(db._extract_registration_password(saved))
        self.assertNotIn('password/add',self.submissions)
        self.assertFalse(any('Fixture-password' in line for line in logs.output))

    def test_missing_twofa_blocks_password_changes(self):
        row=db.get_account(self.aid);row['totp_secret']='';db._save_accounts([row])
        self.assertEqual(self.run_setup()['status'],'blocked')
        self.session.get.assert_not_called();self.session.post.assert_not_called()

    def test_new_password_page_requires_add_flag_and_matching_identity(self):
        for changes in ({'post_login_add_password':False},{'email':'another@example.test'},
                        {'is_missing_session':True},{'session_id':''}):
            with self.subTest(changes=changes):
                self.session._registration_auth_page_state={'session_id':'fixture','email':'fixture@example.test',
                                                          'post_login_add_password':True,**changes}
                self.navigate.side_effect=lambda s,u:'https://auth.openai.com/reset-password/new-password'
                self.assertFalse(self.run_setup()['ok'])
                self.assertFalse(any(u.endswith('/password/add') for u in self.submissions))
                self.generate.assert_not_called()

    def test_timeout_preserves_private_candidate_and_never_automatically_reposts(self):
        original=self.session.post.side_effect
        def post(url,**kwargs):
            if url.endswith('/password/add'):raise TimeoutError('private-url-and-password')
            return original(url,**kwargs)
        self.session.post.side_effect=post
        with self.assertLogs('core.password_setup',level='WARNING') as logs:
            self.assertEqual(self.run_setup()['status'],'uncertain')
        self.assertNotIn('private-url-and-password','\n'.join(logs.output))
        saved=db.get_account(self.aid)
        self.assertEqual(db._extract_registration_password(saved),'')
        self.assertEqual(json.loads(saved['extra_json'])['password_setup_candidate'],'Fixture-password-20!')
        self.assertNotIn('Fixture-password-20!',json.dumps(_compact_account_for_list(saved)))
        # A retry first proves the retained candidate by logging in. It never
        # re-POSTs that candidate to the add-password endpoint.
        self.generate.return_value='Second-password-20!!'
        self.session.post.side_effect=original
        self.session.post.reset_mock();self.session.get.reset_mock()
        self.navigate.side_effect=self.setUpNavigate()
        def use_original_session(*args,**kwargs):
            return False
        with patch.object(pw,'verify_private_candidate',side_effect=use_original_session) as verify:
            self.assertEqual(self.run_setup()['status'],'success')
        verify.assert_called_once()
        self.assertFalse(any(c.kwargs.get('data')==json.dumps({'password':'Fixture-password-20!'})
                             for c in self.session.post.call_args_list))
        self.assertEqual(db.get_account(self.aid)['password_setup_status'],'success')
        self.assertEqual(db._extract_registration_password(db.get_account(self.aid)),'Second-password-20!!')

    def test_official_bare_200_is_success_and_unexpected_page_is_not(self):
        original=self.session.post.side_effect
        self.session.post.side_effect=lambda url,**kw: response({}) if url.endswith('/password/add') else original(url,**kw)
        self.assertEqual(self.run_setup()['status'],'success')
        self.assertTrue(db._extract_registration_password(db.get_account(self.aid)))
    def test_200_without_success_ack_never_becomes_saved_password(self):
        original=self.session.post.side_effect
        self.session.post.side_effect=lambda url,**kw: response({'page':{'type':'login'}}) if url.endswith('/password/add') else original(url,**kw)
        self.assertEqual(self.run_setup()['status'],'accepted_unverified')
        self.assertEqual(db._extract_registration_password(db.get_account(self.aid)),'')

    def test_403_or_429_never_switches_routes_or_replays_mutation(self):
        for status in (403,429):
            with self.subTest(status=status):
                self.session.get.side_effect=None;self.session.get.return_value=response({},status)
                self.assertFalse(self.run_setup()['ok'])
                self.session.post.assert_not_called()

    def test_wrong_origin_or_password_reset_page_never_receives_password(self):
        outcomes=('https://evil.example.test/reset-password/new-password',
                  'https://auth.openai.com/reset-password',
                  'https://auth.openai.com/log-in/password')
        expected=(False,False,True)  # log-in/password is positive existing-password evidence
        for target,accepted in zip(outcomes,expected):
            with self.subTest(target=target):
                self.navigate.side_effect=lambda *a:target
                self.assertEqual(self.run_setup()['ok'],accepted)
                self.generate.assert_not_called()

    def test_browser_session_does_not_fall_back_to_protocol(self):
        self.session.is_browser_workflow=True
        self.assertFalse(self.run_setup()['ok'])
        self.session.get.assert_not_called();self.session.post.assert_not_called()

    def test_owned_session_is_closed_and_saved_proxy_is_preserved(self):
        row=db.get_account(self.aid);row['proxy_used']='http://fixture.proxy:123';db._save_accounts([row])
        relay=Mock()
        with patch('core.workflow_driver.resolve_driver',return_value='protocol'), \
             patch('core.proxy_chain.open_proxy_pool_proxy',return_value=('http://127.0.0.1:1234',relay)) as route, \
             patch('core.workflow_driver.create_account_session',return_value=self.session) as create:
            self.assertTrue(pw.set_missing_password(self.aid)['ok'])
        route.assert_called_once_with('http://fixture.proxy:123')
        self.assertEqual(create.call_args.kwargs['proxy'],'http://127.0.0.1:1234')
        self.close.assert_called_once_with(self.session);relay.close.assert_called_once()

    def test_password_save_preserves_mail_password_and_rejects_overwriting_gpt_password(self):
        row=db.get_account(self.aid);row['password']='mail-password';db._save_accounts([row])
        db.update_account_password_setup(self.aid,'success',password='saved-gpt-password')
        self.assertEqual(db.get_account(self.aid)['password'],'mail-password')
        with self.assertRaises(ValueError):db.update_account_password_setup(self.aid,'failed',password='not-confirmed')
        with self.assertRaises(ValueError):db.update_account_password_setup(self.aid,'success',password='replacement')

    def test_page_parser_only_reads_bound_session_username_and_add_flag(self):
        state=read_auth_page_session(document({'session_id':'fixture','post_login_add_password':True,
            'username':{'kind':'email','value':'fixture@example.test'},'unrelated_secret':'hidden'}))
        self.assertEqual(state,{'session_id':'fixture','post_login_add_password':True,'username_email':'fixture@example.test'})

    def test_completion_waits_for_twofa_then_password_then_final_token_check(self):
        events=[]
        row=db.get_account(self.aid);row['totp_secret']='';db._save_accounts([row])
        def setup(**kwargs):
            events.append('twofa');future=Future();future.set_result({'ok':True})
            return {'accepted':True,'future':future}
        def password(*args,**kwargs):
            self.assertEqual(events,['twofa']);self.assertIs(kwargs['session'],self.session)
            events.append('password');return {'ok':True,'status':'success'}
        with patch('config.register.AUTO_PLAN_CHECK_AFTER_REGISTER',False), \
             patch('config.twofa.ENABLE_2FA',True), \
             patch('config.register.SET_PASSWORD_AFTER_REGISTRATION',True), \
             patch('core.twofa_service.enqueue_account_totp_setup',side_effect=setup), \
             patch.object(pw,'set_missing_password',side_effect=password), \
             patch.object(completion,'_wait_plan_check',side_effect=lambda *a,**kw:events.append('verify') or {'ok':True}):
            outcome=completion.finish_account(self.aid,session=self.session)
        self.assertEqual(events,['twofa','password','verify'])
        self.assertEqual(outcome['status'],'success')

    def test_password_helper_is_optional_and_disabled_never_calls_it(self):
        with patch('config.register.AUTO_PLAN_CHECK_AFTER_REGISTER',False), \
             patch('config.twofa.ENABLE_2FA',True), \
             patch('config.register.SET_PASSWORD_AFTER_REGISTRATION',False), \
             patch.object(pw,'set_missing_password') as password:
            outcome=completion.finish_account(self.aid,session=self.session)
        password.assert_not_called()
        self.assertEqual(outcome['password'],'skipped')
        self.assertEqual(outcome['status'],'success')

    def test_failed_twofa_never_starts_password_and_failed_password_is_partial(self):
        row=db.get_account(self.aid);row['totp_secret']='';db._save_accounts([row])
        with patch('config.register.AUTO_PLAN_CHECK_AFTER_REGISTER',False),patch('config.twofa.ENABLE_2FA',True), \
             patch('core.twofa_service.enqueue_account_totp_setup',return_value={'ok':False}), \
             patch.object(pw,'set_missing_password') as password:
            self.assertEqual(completion.finish_account(self.aid)['status'],'partial');password.assert_not_called()
        row['totp_secret']='JBSWY3DPEHPK3PXP';db._save_accounts([row])
        with patch('config.register.AUTO_PLAN_CHECK_AFTER_REGISTER',False),patch('config.twofa.ENABLE_2FA',True), \
             patch.object(pw,'set_missing_password',return_value={'ok':False,'status':'failed'}):
            result=completion.finish_account(self.aid)
        self.assertEqual((result['twofa'],result['password']),('success','skipped'))
        self.assertEqual(result['status'],'success')
        self.assertEqual(db.get_account(self.aid)['access_token'],'fixture-at')

    def test_progress_exposes_password_status_but_not_candidate_or_credentials(self):
        db.update_account_password_setup(self.aid,'running',candidate='private-candidate')
        job=db.create_job(email_source='generic_api');db.update_job(job['id'],account_id=self.aid,status='running')
        with patch('core.registration_service.read_job_log',return_value='fixture'):
            result=create_app(auth_code='fixture').test_client().get(f"/api/jobs/{job['id']}/log",headers={'X-Auth-Code':'fixture'}).get_json()
        self.assertEqual(result['progress']['password'],'running')
        self.assertNotIn('private-candidate',json.dumps(result));self.assertNotIn('fixture-at',json.dumps(result))


if __name__=='__main__':unittest.main()
