"""Only local fixtures: no purchase, authentication, or live SMS-send requests."""
from contextlib import ExitStack
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.auth_diagnostics import auth_error_diagnostic, redact_error_text, PhoneVerificationFailure
from core import codex_oauth as oauth, sms_provider as sms, db, codex_retry_service as retry
from tests.test_auth_page_initial_delivery import document
from tests.test_forwarded_imap_and_account_import import storage


def response(payload=None,status=400,headers=None,text=''):
    return SimpleNamespace(status_code=status,headers=headers or {},text=text,json=lambda:payload)


class AuthDiagnosticTests(unittest.TestCase):
    def test_structured_error_and_request_id_are_retained_without_other_fields(self):
        r=response({'error':{'code':'phone_number_not_supported','message':'This number is not supported.'},
                    'accessToken':'private-at','auth_session':'private-session'},headers={
                    'X-Request-ID':'req_123456abcdef','CF-Ray':'deadbeef01234567-IAD','Set-Cookie':'private-cookie'})
        result=auth_error_diagnostic(r,stage='add-phone/send')
        self.assertEqual(result,{'stage':'add-phone/send','http_status':400,
            'error_code':'phone_number_not_supported','error_message':'This number is not supported.',
            'request_id':'req_123456abcdef','cf_ray':'deadbeef01234567-IAD'})
        self.assertNotIn('private-',json.dumps(result))

    def test_message_redacts_phone_email_otp_tokens_password_and_urls(self):
        message=('Phone +966 50 555 0101 user@icloud.com OTP 123456 password="private-password" '
                 'api_key=private-key access_token=private-access session_id=private-session '
                 'Bearer private-bearer https://fixture.test/code?token=private-url '
                 'eyJfixture.eyJclaims.signature sk-proj-privatekey\r\n\u202e injected')
        result=redact_error_text(message)
        for secret in ('+966 50 555 0101','user@icloud.com','123456','private-password','private-key',
                       'private-access','private-session','private-bearer','private-url','eyJclaims','sk-proj-privatekey','\r','\n','\u202e'):
            self.assertNotIn(secret,result)
        self.assertIn('[',result)
        self.assertLessEqual(len(redact_error_text('x'*10000)),480)

    def test_exact_sensitive_values_are_removed_before_formatting(self):
        r=response({'error':{'code':'invalid_otp','message':'Rejected fixture-code and 966500000000'}})
        d=auth_error_diagnostic(r,stage='phone-otp/validate',sensitive_values=('fixture-code','966500000000'))
        self.assertNotIn('fixture-code',str(PhoneVerificationFailure(d)))
        self.assertNotIn('966500000000',str(PhoneVerificationFailure(d)))

    def test_header_priority_body_fallback_and_cf_ray_are_distinct(self):
        for header in ('openai-request-id','x-openai-request-id','request-id'):
            r=response({'request_id':'req_body'},headers={header:'req_header','cf-ray':'trace-IAD'})
            d=auth_error_diagnostic(r,stage='add-phone/send')
            self.assertEqual(d['request_id'],'req_header');self.assertEqual(d['cf_ray'],'trace-IAD')
        self.assertEqual(auth_error_diagnostic(response({'request_id':'req_body'}),stage='x')['request_id'],'req_body')
        self.assertEqual(auth_error_diagnostic(response({},headers={'cf-ray':'trace-IAD'}),stage='x')['request_id'],'unavailable')

    def test_non_json_body_is_never_dumped_and_injected_identifiers_are_not_logged(self):
        for payload in (None,[],['private'],{'error':{'message':{'token':'private'}}}):
            r=response(payload,headers={'x-request-id':'req\r\nInjected: secret','cf-ray':'Bearer private'},text='<html>private-password</html>')
            d=auth_error_diagnostic(r,stage='add-phone/send')
            self.assertEqual(d['request_id'],'unavailable');self.assertEqual(d['cf_ray'],'unavailable')
            self.assertNotIn('private',json.dumps(d))
        for value in ('sk-private','eyJheader.payload.signature','966500000000'):
            self.assertEqual(auth_error_diagnostic(response({},headers={'x-request-id':value}),stage='x')['request_id'],'unavailable')

    def test_top_level_and_string_error_messages_are_supported(self):
        for payload in ({'error':'Unable to send now'},{'message':'Unable to send now'},{'detail':'Unable to send now'}):
            self.assertEqual(auth_error_diagnostic(response(payload),stage='x')['error_message'],'Unable to send now')


class PhoneFlowDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.multiple(sms._cfg,SMS_PROVIDER='smsbower',SMS_MAX_RETRIES=5))
        self.http=Mock()
        self.stack.enter_context(patch.object(sms,'_http',return_value=self.http))
        self.session=SimpleNamespace(_codex_phone_channel_policy={'multi':{},'single':{'sms':['SA'],'whatsapp':[]}})
        self.acquire=self.stack.enter_context(patch.object(sms,'acquire_number',return_value=('fixture-order','966500000000')))
        self.cancel=self.stack.enter_context(patch.object(sms,'cancel'))
        self.wait=self.stack.enter_context(patch.object(sms,'wait_for_sms_code',return_value='123456'))

    def test_send_400_has_full_safe_diagnostic_and_never_buys_another_number(self):
        r=response({'error':{'code':'phone_number_not_supported','message':'Phone +966500000000 is not supported for fixture@icloud.com'}},
                   headers={'x-request-id':'req_send400','cf-ray':'ray_send400-IAD'})
        with patch.object(oauth,'_post_json',return_value=r) as post,self.assertLogs('core.codex_oauth',level='WARNING') as logs:
            with self.assertRaises(PhoneVerificationFailure) as caught:oauth._do_phone_verification(self.session)
        self.acquire.assert_called_once();post.assert_called_once();self.cancel.assert_called_once();self.wait.assert_not_called()
        self.assertEqual(post.call_args.args[2],{'phone_number':'+966500000000'})
        output='\n'.join(logs.output)+str(caught.exception)
        for value in ('phone_number_not_supported','req_send400','ray_send400-IAD'):self.assertIn(value,output)
        for secret in ('966500000000','fixture@icloud.com'):self.assertNotIn(secret,output)

    def test_phone_otp_failure_preserves_diagnostic_but_not_submitted_code(self):
        r=response({'error':{'code':'invalid_otp','message':'Code 123456 for 966500000000 is invalid'}},headers={'x-request-id':'req_otp400'})
        with patch.object(oauth,'_post_json',side_effect=[response({},200),r]):
            with self.assertRaises(PhoneVerificationFailure) as caught:oauth._do_phone_verification(self.session)
        self.assertIn('req_otp400',str(caught.exception));self.assertNotIn('123456',str(caught.exception))
        self.cancel.assert_called_once();self.acquire.assert_called_once()

    def test_successful_json_mentioning_whatsapp_is_not_classified_as_a_send_error(self):
        success=response({'page':{'type':'phone_otp_verification'},'available_channels':['sms','whatsapp']},200)
        with patch.object(oauth,'_post_json',side_effect=[success,response({'page':{'type':'workspace'}},200)]),patch.object(sms,'set_status'),patch.object(sms,'complete'):
            self.assertEqual(oauth._do_phone_verification(self.session)['page']['type'],'workspace')
        self.wait.assert_called_once();self.cancel.assert_not_called()

    def test_known_whatsapp_requirement_stops_before_purchase(self):
        session=SimpleNamespace(_codex_phone_page_state={'phone_verification_channel':'whatsapp'})
        with self.assertRaisesRegex(RuntimeError,'未购号'):oauth._do_phone_verification(session)
        self.acquire.assert_not_called();self.wait.assert_not_called()

    def test_payload_matches_official_optional_channel_and_normalizes_plus_once(self):
        self.assertEqual(oauth._phone_send_payload('+966500000000',object()),{'phone_number':'+966500000000'})
        session=SimpleNamespace(_codex_phone_page_state={'phone_verification_channel':'sms','multi_channel_allowed':True})
        self.assertEqual(oauth._phone_send_payload('966500000000',session),{'phone_number':'+966500000000','channel':'sms'})
        session._codex_phone_page_state['multi_channel_allowed']=False
        self.assertNotIn('channel',oauth._phone_send_payload('966500000000',session))
        for value in ('++966500000000','invalid','123','0123456789'):
            with self.assertRaises(ValueError):oauth._phone_send_payload(value,object())

    def test_auth_document_error_stops_before_purchase_with_request_id(self):
        session=SimpleNamespace(get_auth_navigate_headers=lambda **kw:{},get=Mock(return_value=response(
            {'error':{'code':'invalid_auth_step','message':'Authentication state expired'}},headers={'x-request-id':'req_context'})))
        with self.assertRaises(PhoneVerificationFailure) as caught:
            oauth._follow_login_continue(session,'https://auth.openai.com/add-phone','fixture-state')
        self.assertEqual(caught.exception.diagnostic['request_id'],'req_context');self.acquire.assert_not_called()

    def test_auth_document_caches_only_channel_metadata_not_phone_or_credentials(self):
        state={'session_id':'private-session','phone_number':'+966500000000','phone_verification_channel':'sms','multi_channel_allowed':True}
        session=SimpleNamespace(get_auth_navigate_headers=lambda **kw:{},get=Mock(return_value=response({},200,text=document(state))))
        oauth._follow_login_continue(session,'https://auth.openai.com/add-phone','fixture-state')
        self.assertEqual(session._codex_phone_page_state,{'phone_verification_channel':'sms','multi_channel_allowed':True})

    def test_worker_keeps_safe_error_details_in_account_error_and_log(self):
        with tempfile.TemporaryDirectory() as td,patch.multiple(db,**storage(Path(td))):
            aid=db.insert_account(email='fixture@example.test',access_token='private-at')
            detail=auth_error_diagnostic(response({'error':{'code':'phone_number_not_supported','message':'Not supported'}},headers={'x-request-id':'req_worker'}),stage='add-phone/send')
            failure=PhoneVerificationFailure(detail)
            result={'ok':False,'status':'failed','message':str(failure),'phone_error':detail}
            log=Path(td)/'fixture.log'
            with patch.object(oauth,'run_codex_oauth',return_value=result),patch('config.reload_all'),patch.object(retry,'release'):
                actual=retry.run_worker('fixture@example.test',target_log_path=log)
            self.assertEqual(actual['phone_error']['request_id'],'req_worker')
            self.assertIn('req_worker',db.get_account(aid)['codex_error'])
            self.assertIn('phone_number_not_supported',log.read_text(encoding='utf8'))

    def test_oauth_result_keeps_safe_diagnostic_without_truncating_request_id(self):
        detail=auth_error_diagnostic(response({'error':{'code':'invalid_request','message':'m'*700}},
            headers={'x-request-id':'req_complete_trace'}),stage='add-phone/send')
        session=SimpleNamespace(device_id='fixture',oai_session_id='fixture',auth_session_logging_id='fixture',
                                fingerprint_summary_text=lambda:'fixture')
        with patch.object(oauth,'BrowserSession',return_value=session), \
             patch.object(oauth,'_codex_auth_url_source',return_value='local'), \
             patch.object(oauth,'_generate_pkce',return_value=('fixture','fixture')), \
             patch.object(oauth,'_codex_auth_preflight',side_effect=PhoneVerificationFailure(detail)):
            result=oauth.run_codex_oauth('fixture@example.test',force=True)
        self.assertFalse(result['ok']);self.assertEqual(result['phone_error'],detail)
        self.assertIn('req_complete_trace',result['message'])
        self.assertIn('m'*480,result['message']);self.acquire.assert_not_called()


if __name__=='__main__':unittest.main()
