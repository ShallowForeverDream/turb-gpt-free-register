"""Offline fixtures only; no real account, phone purchase, or OTP send."""
from contextlib import ExitStack
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core import codex_oauth as oauth, sms_provider as sms
from core.phone_verification_channels import (
    MULTI_CHANNEL_CONFIG, SINGLE_CHANNEL_CONFIG, _config_hash,
    read_phone_channel_policy, phone_country, sms_choice, SmsChannelUnavailableError,
)
from tests.test_auth_page_initial_delivery import document
from tests.test_phone_auth_diagnostics import response


POLICY = {'multi': {'BR': ['whatsapp', 'sms'], 'US': ['sms', 'whatsapp'], 'GB': ['whatsapp']},
          'single': {'sms': ['US'], 'whatsapp': ['BR', 'GB']}}


def bootstrap(policy=POLICY, *, hashed=True, as_string=True):
    configs = {}
    for name, key in ((MULTI_CHANNEL_CONFIG, 'multi'), (SINGLE_CHANNEL_CONFIG, 'single')):
        configs[_config_hash(name) if hashed else name] = {'value': policy[key]}
    data = {'dynamic_configs': configs, 'private-token': 'not-allowed'}
    value = {'statsigClientInitData': {'bootstrap': json.dumps(data) if as_string else data},
             'private-session': 'not-allowed'}
    return '<script id="bootstrap-inert-script" type="application/json">' + json.dumps(value) + '</script>'


class PhoneChannelPolicyTests(unittest.TestCase):
    def test_only_two_named_configs_are_decoded(self):
        for hashed in (True, False):
            for as_string in (True, False):
                self.assertEqual(read_phone_channel_policy(bootstrap(hashed=hashed, as_string=as_string)), POLICY)

    def test_hash_matches_auth_bootstrap_key_contract(self):
        self.assertEqual(_config_hash(MULTI_CHANNEL_CONFIG), '232171259')
        self.assertEqual(_config_hash(SINGLE_CHANNEL_CONFIG), '2516824722')

    def test_malformed_or_unrelated_script_does_not_grant_sms(self):
        for source in ('', '<script>sms=true</script>', bootstrap().replace('bootstrap-inert-script','untrusted'),
                       '<script id="bootstrap-inert-script">not json</script>', 'x'*(8*1024*1024+1)):
            self.assertIsNone(read_phone_channel_policy(source))

    def test_invalid_channel_config_fails_closed(self):
        bad = {'multi': {'BR': ['sms','unsupported']}, 'single': POLICY['single']}
        self.assertIsNone(read_phone_channel_policy(bootstrap(bad)))

    def test_countries_are_normalized_and_deduplicated(self):
        policy = {'multi': {' br ': ['whatsapp'], 'BR':['sms','sms']},
                  'single': {'sms':['us',' US '], 'whatsapp':['br']}}
        self.assertEqual(read_phone_channel_policy(bootstrap(policy)),
                         {'multi': {'BR':['whatsapp','sms']}, 'single': {'sms':['US'],'whatsapp':['BR']}})

    def test_brazil_sms_is_selectable_only_when_current_session_allows_it(self):
        self.assertEqual(sms_choice(POLICY,'BR',True),'sms')
        for flag in (False,None):
            with self.assertRaises(SmsChannelUnavailableError):sms_choice(POLICY,'BR',flag)

    def test_single_channel_sms_and_no_picker_omit_channel(self):
        self.assertIsNone(sms_choice(POLICY,'US',False))
        self.assertIsNone(sms_choice(POLICY,'ID',False))
        self.assertIsNone(sms_choice(POLICY,'ID',True))

    def test_whatsapp_only_picker_and_unknown_country_are_not_overridden(self):
        for policy,country,multi in ((POLICY,'GB',True),(POLICY,None,True),(None,'BR',True)):
            with self.assertRaises(SmsChannelUnavailableError):sms_choice(policy,country,multi)

    def test_phone_country_uses_number_not_proxy_country(self):
        self.assertEqual(phone_country('5511999990000'),'BR')
        self.assertEqual(phone_country('966500000000'),'SA')
        self.assertIsNone(phone_country('invalid'))


class SmsOnlyFlowTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.multiple(sms._cfg,SMS_PROVIDER='smsbower',SMS_MAX_RETRIES=1))
        self.stack.enter_context(patch.object(sms,'_http'))
        self.acquire=self.stack.enter_context(patch.object(sms,'acquire_number',return_value=('fixture-id','5511999990000')))
        self.cancel=self.stack.enter_context(patch.object(sms,'cancel'))
        self.wait=self.stack.enter_context(patch.object(sms,'wait_for_sms_code',return_value='123456'))
        self.stack.enter_context(patch.object(sms,'set_status'))
        self.stack.enter_context(patch.object(sms,'complete'))
        self.session=SimpleNamespace(_codex_phone_channel_policy=POLICY,_codex_phone_country_iso='BR',
            _codex_phone_page_state={'multi_channel_allowed':True,'phone_verification_channel':'whatsapp'})

    def test_sms_form_selection_does_not_use_default_whatsapp(self):
        self.assertEqual(oauth._phone_send_payload('5511999990000',self.session),
                         {'phone_number':'+5511999990000','channel':'sms'})

    def test_whatsapp_only_country_stops_before_purchase(self):
        self.session._codex_phone_page_state['multi_channel_allowed']=False
        with self.assertRaises(SmsChannelUnavailableError):oauth._do_phone_verification(self.session)
        self.acquire.assert_not_called();self.wait.assert_not_called()

    def test_missing_actual_page_policy_stops_before_purchase(self):
        del self.session._codex_phone_channel_policy
        with self.assertRaisesRegex(SmsChannelUnavailableError,'未购号'):
            oauth._do_phone_verification(self.session)
        self.acquire.assert_not_called();self.wait.assert_not_called()

    def test_pending_sms_channel_overrides_existing_whatsapp_login_channel(self):
        sent=response({'auth_session':{'phone_verification_channel':'whatsapp','set_phone_verification_channel':'sms'}},200)
        with patch.object(oauth,'_post_json',side_effect=[sent,response({'page':{'type':'workspace'}},200)]) as post:
            self.assertEqual(oauth._do_phone_verification(self.session)['page']['type'],'workspace')
        self.assertEqual(post.call_args_list[0].args[2]['channel'],'sms')
        self.wait.assert_called_once();self.cancel.assert_not_called()

    def test_server_whatsapp_response_cancels_without_sms_polling(self):
        sent=response({'auth_session':{'set_phone_verification_channel':'whatsapp'}},200)
        with patch.object(oauth,'_post_json',return_value=sent):
            with self.assertRaisesRegex(RuntimeError,'WhatsApp'):oauth._do_phone_verification(self.session)
        self.cancel.assert_called_once();self.wait.assert_not_called()

    def test_actual_country_mismatch_never_sends(self):
        with self.assertRaises(SmsChannelUnavailableError):oauth._phone_send_payload('966500000000',self.session)

    def test_auth_document_refresh_caches_only_policy_and_safe_state(self):
        html=document({'multi_channel_allowed':True,'set_phone_verification_channel':'sms','phone_number':'private'})+bootstrap()
        session=SimpleNamespace(get_auth_navigate_headers=lambda **kw:{},get=lambda *a,**kw:response({},200,text=html))
        oauth._follow_login_continue(session,'https://auth.openai.com/add-phone','fixture-state')
        self.assertEqual(session._codex_phone_channel_policy,POLICY)
        self.assertEqual(session._codex_phone_page_state,{'multi_channel_allowed':True,'set_phone_verification_channel':'sms'})


if __name__=='__main__':unittest.main()
