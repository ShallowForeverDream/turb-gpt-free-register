"""Bounded purchase contracts. Fake provider/auth responses; never spend money."""
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from core import sms_provider as sms, codex_oauth as oauth


def response(text,status=200):
    return SimpleNamespace(status_code=status,text=text,json=lambda:{'page':{'type':'workspace'}})


class StrictSmsBowerTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.multiple(sms._cfg,SMS_PROVIDER='smsbower',SMS_COUNTRY='53',SMS_SERVICE='dr',
            SMS_MAX_PRICE='0.004',SMSBOWER_MIN_PRICE='',SMSBOWER_PROVIDER_IDS='2377',SMSBOWER_EXCEPT_PROVIDER_IDS='',
            SMSBOWER_PHONE_EXCEPTION='',SMSBOWER_USE_V2=False,SMSBOWER_API_KEY='fixture-key',SMS_MAX_RETRIES=5))
        self.stack.enter_context(patch.object(sms,'_ACQUIRED_AT',{}))
        self.http=Mock();self.http.get.return_value=response('ACCESS_NUMBER:fixture-id:966500000000')
        self.auth_session=SimpleNamespace(_codex_phone_channel_policy={'multi':{},'single':{'sms':['SA'],'whatsapp':[]}})

    def test_exact_parameters_are_sent_once_without_redirects(self):
        self.assertEqual(sms.acquire_number(self.http),('fixture-id','966500000000'))
        self.http.get.assert_called_once()
        params=self.http.get.call_args.kwargs['params']
        self.assertEqual(params,{'api_key':'fixture-key','action':'getNumber','service':'dr','country':'53',
                                 'maxPrice':'0.004','providerIds':'2377'})
        self.assertFalse(self.http.get.call_args.kwargs['allow_redirects'])

    def test_no_stock_never_removes_provider_or_changes_country_price_or_method(self):
        for v2 in (False,True):
            with self.subTest(v2=v2),patch.object(sms._cfg,'SMSBOWER_USE_V2',v2):
                self.http.get.reset_mock();self.http.get.return_value=response('NO_NUMBERS')
                with self.assertRaises(sms.SmsNoNumbersError):sms.acquire_number(self.http)
                self.http.get.assert_called_once()
                params=self.http.get.call_args.kwargs['params']
                self.assertEqual((params['providerIds'],params['maxPrice'],params['country'],params['service']),('2377','0.004','53','dr'))
                self.assertEqual(params['action'],'getNumberV2' if v2 else 'getNumber')

    def test_bad_v2_action_does_not_fall_back_to_paid_v1(self):
        self.http.get.return_value=response('BAD_ACTION')
        with patch.object(sms._cfg,'SMSBOWER_USE_V2',True),self.assertRaises(sms.SmsProviderError):
            sms.acquire_number(self.http)
        self.http.get.assert_called_once()

    def test_one_purchase_budget_survives_error_and_does_not_replay_timeout(self):
        self.http.get.side_effect=TimeoutError('https://private/?api_key=fixture-key')
        with sms.purchase_budget(1) as budget:
            with self.assertRaises(sms.SmsPurchaseUncertainError) as caught:sms.acquire_number(self.http)
            self.assertNotIn('fixture-key',str(caught.exception))
            with self.assertRaises(sms.SmsPurchaseLimitError):sms.acquire_number(self.http)
            self.assertEqual(budget['attempts'],1)
        self.http.get.assert_called_once()

    def test_unrecognized_purchase_response_never_becomes_permission_to_rebuy(self):
        for value in ('not-an-order','ACCESS_NUMBER::','ACCESS_NUMBER:missing-phone:'):
            self.http.get.return_value=response(value);self.http.get.reset_mock()
            with sms.purchase_budget(1):
                with self.assertRaises(sms.SmsPurchaseUncertainError):sms.acquire_number(self.http)
                with self.assertRaises(sms.SmsPurchaseLimitError):sms.acquire_number(self.http)
            self.http.get.assert_called_once()

    def test_http_errors_stop_and_do_not_echo_provider_response(self):
        for status in (302,403,429,500):
            self.http.get.reset_mock();self.http.get.return_value=response('fixture-key private-response',status)
            with self.assertRaises(sms.SmsPurchaseUncertainError) as caught:sms.acquire_number(self.http)
            self.http.get.assert_called_once();self.assertNotIn('fixture-key',str(caught.exception))

    def test_invalid_prices_are_rejected_before_purchase(self):
        for value in ('-1','0','NaN','Infinity','invalid'):
            with patch.object(sms._cfg,'SMS_MAX_PRICE',value),self.assertRaises(ValueError):sms.acquire_number(self.http)
        self.http.get.assert_not_called()
        with patch.multiple(sms._cfg,SMSBOWER_MIN_PRICE='0.005',SMS_MAX_PRICE='0.004'),self.assertRaises(ValueError):
            sms.acquire_number(self.http)

    def test_outer_phone_flow_stops_on_no_stock_even_with_five_retries(self):
        self.http.get.return_value=response('NO_NUMBERS')
        with patch.object(sms,'_http',return_value=self.http),patch.object(oauth,'_post_json') as send, \
             patch.object(oauth,'_sleep_before_phone_retry') as sleep:
            with self.assertRaises(sms.SmsNoNumbersError):oauth._do_phone_verification(self.auth_session)
        self.http.get.assert_called_once();send.assert_not_called();sleep.assert_not_called()

    def test_outer_phone_flow_never_retries_uncertain_purchase(self):
        self.http.get.side_effect=TimeoutError('private')
        with patch.object(sms,'_http',return_value=self.http),patch.object(oauth,'_post_json') as send:
            with self.assertRaises(sms.SmsPurchaseUncertainError):oauth._do_phone_verification(self.auth_session)
        self.http.get.assert_called_once();send.assert_not_called()

    def test_single_number_sms_success_submits_once_then_completes(self):
        with patch.object(sms,'_http',return_value=self.http), \
             patch.object(oauth,'_post_json',side_effect=[response('{}'),response('{}')]) as submit, \
             patch.object(sms,'set_status'),patch.object(sms,'wait_for_sms_code',return_value='001234'), \
             patch.object(sms,'complete') as complete,patch.object(sms,'cancel') as cancel,sms.purchase_budget(1) as budget:
            self.assertEqual(oauth._do_phone_verification(self.auth_session)['page']['type'],'workspace')
        self.assertEqual(budget['attempts'],1);self.assertEqual(submit.call_count,2)
        complete.assert_called_once();cancel.assert_not_called();self.http.get.assert_called_once()

    def test_auth_refusal_stops_without_changing_number(self):
        for status in (403,429):
            self.http.get.reset_mock()
            with patch.object(sms,'_http',return_value=self.http), \
                 patch.object(oauth,'_post_json',return_value=response('{}',status)) as send,patch.object(sms,'cancel') as cancel:
                with self.assertRaises(oauth.PhoneVerificationFailure):oauth._do_phone_verification(self.auth_session)
            self.http.get.assert_called_once();send.assert_called_once();cancel.assert_called_once()

    def test_auth_transport_error_cleans_up_known_activation(self):
        with patch.object(sms,'_http',return_value=self.http),patch.object(oauth,'_post_json',side_effect=TimeoutError()), \
             patch.object(sms,'cancel') as cancel:
            with self.assertRaises(TimeoutError):oauth._do_phone_verification(self.auth_session)
        cancel.assert_called_once()

    def test_received_code_is_validated_without_logging_its_contents(self):
        self.http.get.return_value=response("STATUS_OK:'001234'")
        with self.assertLogs('core.sms_provider',level='INFO') as logs:
            self.assertEqual(sms.wait_for_sms_code('fixture-id',self.http,max_wait=1),'001234')
        self.assertNotIn('001234','\n'.join(logs.output))
        for code in ('','１２３４５６','invalid-secret'):
            self.http.get.return_value=response('STATUS_OK:'+code)
            with self.assertRaises(sms.SmsProviderError):sms.wait_for_sms_code('fixture-id',self.http,max_wait=1)

    def test_cancel_waits_for_platform_minimum_and_requires_acknowledgement(self):
        sms._ACQUIRED_AT['fixture-id']=1000
        with patch.object(sms.time,'time',return_value=1000),patch.object(sms.time,'sleep') as sleep, \
             patch.object(sms,'set_status',return_value='ACCESS_CANCEL') as status:
            sms.cancel('fixture-id',self.http)
        sleep.assert_called_once_with(125);status.assert_called_once_with('fixture-id',8,http=self.http)
        self.assertNotIn('fixture-id',sms._ACQUIRED_AT)

    def test_cancel_failure_keeps_activation_for_manual_review(self):
        sms._ACQUIRED_AT['fixture-id']=0
        with patch.object(sms,'set_status',side_effect=sms.SmsProviderError('not-confirmed')):
            sms.cancel('fixture-id',self.http)
        self.assertIn('fixture-id',sms._ACQUIRED_AT)


if __name__=='__main__':unittest.main()
