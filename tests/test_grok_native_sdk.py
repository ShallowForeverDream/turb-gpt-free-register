"""SDK bridge isolation/consent tests. All proofs and pages here are fixtures."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import requests

from core import grok_native_sdk as native, grok_protocol as protocol
from core.grok_service import Signals


KEY = 'fixture-public-key-123456'
SITE = '0x4AAAAAAA_fixture_site_key'


class NativeSDKTests(unittest.TestCase):
    def make(self):
        return native.NativeSDK(requests.Session(), Signals(), Mock())

    def test_public_configuration_is_data_only_unique_and_not_from_captured_proofs(self):
        self.assertEqual(native.public_key([json.dumps({'CASTLE_PK':KEY})]),KEY)
        flight='self.__next_f.push('+json.dumps([1,json.dumps({'CASTLE_PK':KEY})])+')'
        self.assertEqual(native.public_key([flight]),KEY)
        for scripts in ([],[json.dumps({'CASTLE_PK':'short'})],
                        [json.dumps({'CASTLE_PK':KEY}),json.dumps({'CASTLE_PK':'different-public-key'})]):
            with self.assertRaises(protocol.GrokProtocolError):native.public_key(scripts)
        self.assertEqual(native.site_key(['turnstile.render(n,{sitekey:"'+SITE+'"})']),SITE)
        for sources in ([],['unrelated '+SITE],['turnstile sitekey:"'+SITE+'",sitekey:"'+SITE+'other"']):
            with self.assertRaises(protocol.GrokProtocolError):native.site_key(sources)

    def test_cf_sitekey_configuration_is_accepted(self):
        self.assertEqual(native.site_key([json.dumps({'CF_SITEKEY':SITE})]),SITE)

    def test_lazy_native_auth_component_reads_inline_cf_sitekey_without_navigation(self):
        sdk=self.make();sdk.page=Mock()
        sdk.responses=[SimpleNamespace(status=200,body=lambda:json.dumps({'CF_SITEKEY':SITE}).encode())]
        sdk.page.locator.return_value.all_text_contents.return_value=[]
        value=sdk._site_configuration()
        self.assertEqual(value,SITE)
        sdk.page.locator.assert_called_once_with('script:not([src])')

    def test_fixed_proxy_credentials_are_not_rewritten_or_logged(self):
        http=SimpleNamespace(proxies={'https':'http://fixture%40user:fixture%2Fsecret@127.0.0.1:28080'})
        proxy=native.browser_proxy(http)
        self.assertEqual(proxy,{'server':'http://127.0.0.1:28080','username':'fixture@user','password':'fixture/secret'})
        self.assertIsNone(native.browser_proxy(SimpleNamespace(proxies={})))
        with self.assertRaises(protocol.GrokProtocolError) as error:
            native.browser_proxy(SimpleNamespace(proxies={'https':'socks5://user:secret@127.0.0.1:28080'}))
        self.assertNotIn('secret',str(error.exception))

    def test_sdk_context_cannot_send_account_mutations(self):
        sdk=self.make()
        route=Mock(request=SimpleNamespace(method='POST',url='https://grok.com/api/auth/send-verification-code'))
        sdk._route(route)
        route.abort.assert_called_once();route.continue_.assert_not_called()
        with self.assertRaises(protocol.GrokProtocolError) as error:sdk._stop()
        self.assertEqual(error.exception.reason,'sdk_isolation')

    def test_normal_runtime_uses_direct_chrome_cdp_without_automation_marker(self):
        sdk=self.make();sdk.playwright=Mock();sdk.binary='/fixture/chrome.exe'
        browser=Mock()
        page=browser.new_context.return_value.new_page.return_value
        response=SimpleNamespace(status=200)
        page.goto.return_value=response;page.url='https://grok.com/'
        page.locator.return_value.all_text_contents.return_value=[json.dumps({'CASTLE_PK':KEY})]
        with patch.object(native,'site_key',return_value=SITE),patch.object(sdk,'_sync'),patch.object(sdk,'_load_script'),patch.object(sdk,'_wait_for_security_context'),patch.object(sdk,'_launch_chrome_cdp',return_value=(browser, Mock())) as launch:
            sdk._open()
        launch.assert_called_once_with(None)
        browser.new_context.assert_called_once_with()
        self.assertFalse(sdk.interactive_window)
        page.route.assert_called_once()

    def test_real_runtime_cookie_scope_and_ua_are_preserved_without_identity_mixing(self):
        sdk=self.make();sdk.page=Mock();sdk.context=Mock()
        sdk.page.url='https://grok.com/'
        sdk.page.evaluate.return_value='HeadlessChrome/fixture-actual-UA'
        sdk.http.cookies.set('__cuid','old-fixture',domain='grok.com',path='/')
        sdk.context.cookies.return_value=[{'name':'__cuid','value':'fresh-fixture','domain':'.grok.com','path':'/',
            'secure':True,'expires':-1}]
        sdk._sync()
        self.assertIn('HeadlessChrome',sdk.http.headers['User-Agent'])
        self.assertEqual(len(list(sdk.http.cookies)),1)
        self.assertEqual(list(sdk.http.cookies)[0].value,'fresh-fixture')
        sdk.context.cookies.return_value=[{'name':'sso','value':'another-identity'}]
        with self.assertRaises(protocol.GrokProtocolError):sdk._sync()
        sdk.context.cookies.return_value=[]
        sdk.page.url='https://unrelated.invalid/'
        with self.assertRaises(protocol.GrokProtocolError) as error:sdk._sync()
        self.assertEqual(error.exception.reason,'sdk_isolation')

    def test_each_proof_is_new_and_tokens_are_not_logged(self):
        sdk=self.make();sdk.page=Mock()
        sdk.primed_navigation=True
        sdk.page.evaluate.side_effect=['fixture-token-'+str(i)+'x'*40 for i in range(3)]
        with patch.object(sdk,'_sync'),patch.object(sdk,'_turnstile',return_value='fixture-turnstile-token'):
            results=[sdk.proof(stage) for stage in ('check','send','create')]
        self.assertEqual(len({r['castleRequestToken'] for r in results}),3)
        self.assertIn('turnstileToken',results[2])
        self.assertNotIn('fixture-token',str(sdk.update.call_args_list))
        self.assertNotIn('fixture-turnstile-token',str(sdk.update.call_args_list))

    def test_sign_up_component_is_opened_once_before_every_token_mint(self):
        sdk=self.make();sdk.page=Mock();sdk.primed_navigation=None
        sdk.page.evaluate.return_value='fixture-token'+'x'*40
        with patch.object(sdk,'_sync'),patch.object(sdk,'_turnstile',return_value='fixture-turnstile-token'),patch.object(sdk,'_open_sign_up_component') as opener:
            sdk.proof('check');opener.assert_called_once_with()
            sdk.primed_navigation=True
            sdk.proof('send');opener.assert_called_once_with()

    def test_missing_sign_up_entry_is_never_forged_or_faked(self):
        sdk=self.make();sdk.page=Mock();sdk.primed_navigation=False
        entry=sdk.page.locator.return_value;entry.count.return_value=0
        with patch.object(native.time,'monotonic',side_effect=[0,21]):
            with self.assertRaises(protocol.GrokProtocolError) as error:sdk._open_sign_up_component()
        self.assertEqual(error.exception.reason,'sdk_page')
        entry.click.assert_not_called()
        entry.evaluate.assert_not_called()

    def test_sign_up_entry_appears_after_a_bounded_wait(self):
        sdk=self.make();sdk.page=Mock();sdk.primed_navigation=False
        sdk.page.url='https://grok.com/'
        entry=Mock();entry.count.side_effect=[0,0,1];entry.is_visible.return_value=True
        email=Mock();email.count.return_value=1;email.is_visible.return_value=True
        sdk.page.locator.side_effect=lambda selector: entry if selector.startswith('a[') else email
        with patch.object(sdk,'_sync') as sync:
            with patch.object(native.time,'monotonic',side_effect=[0,0.25,0.5,0.75,1.0,1.25,1.5,1.75,2.0,2.25,2.5,2.75,3.0,3.25,3.5,3.75,4.0,4.25,4.5,4.75,5.0,5.25,5.5,5.75,6.0,6.25,6.5,6.75,7.0,7.25,7.5,7.75,8.0,8.25,8.5,8.75,9.0,9.25,9.5,9.75,10.0,10.25]):
                sdk._open_sign_up_component()
        entry.evaluate.assert_called_once_with('el => el.click()')
        sync.assert_called_once()

    def test_complete_fresh_anonymous_context_is_synced_without_capture_or_identity(self):
        sdk=self.make();sdk.page=Mock(url='https://grok.com/');sdk.context=Mock()
        sdk.page.evaluate.return_value='HeadlessChrome/fixture-actual-UA'
        sdk.http.cookies.set('cf_clearance','stale-fixture',domain='.grok.com',path='/')
        sdk.context.cookies.return_value=[{'name':name,'value':'fresh-'+name,'domain':domain,'path':'/',
            'secure':True,'httpOnly':True,'sameSite':'Strict','expires':-1}
            for name,domain in [('cf_clearance','.grok.com'),('__Host-id-token-nonce','grok.com'),('__cuid','.grok.com')]]
        sdk._sync()
        headers=sdk.http.prepare_request(requests.Request('POST','https://grok.com/api/auth/sso/check')).headers
        meta=sdk.request_context(headers)
        self.assertEqual(meta,{'sdk_cookie_match':True,'sdk_user_agent_match':True,'clearance_present':True,'nonce_present':True,
            'sdk_document_status':None,'sdk_document_path':''})
        nonce=next(c for c in sdk.http.cookies if c.name=='__Host-id-token-nonce')
        self.assertFalse(nonce.domain_specified);self.assertTrue(nonce.secure)
        self.assertTrue(nonce.get_nonstandard_attr('HttpOnly'))
        self.assertNotIn('fresh-',str(meta));self.assertNotIn('fresh-',str(sdk.update.call_args_list))
        sdk.context.cookies.return_value=[];sdk._sync()
        self.assertEqual(len(list(sdk.http.cookies)),0)

    def test_bad_scope_is_rejected_before_changing_existing_http_context(self):
        sdk=self.make();sdk.page=Mock(url='https://grok.com/');sdk.context=Mock()
        sdk.http.cookies.set('cf_clearance','existing-fixture',domain='.grok.com',path='/')
        sdk.context.cookies.return_value=[{'name':'__Host-id-token-nonce','value':'bad-fixture','domain':'.grok.com',
            'path':'/','secure':True,'expires':-1}]
        with self.assertRaises(protocol.GrokProtocolError):sdk._sync()
        self.assertEqual(list(sdk.http.cookies)[0].value,'existing-fixture')

    def test_http_security_cookie_updates_reach_sdk_but_login_identity_never_does(self):
        sdk=self.make();sdk.context=Mock()
        cookies=requests.cookies.RequestsCookieJar()
        cookies.set('__cf_bm','updated-fixture',domain='.grok.com',path='/',secure=True)
        cookies.set('sso','identity-fixture',domain='.grok.com',path='/',secure=True)
        with patch.object(sdk,'_sync') as sync:sdk.accept_response_cookies(cookies)
        sync.assert_called_once()
        updates=sdk.context.add_cookies.call_args.args[0]
        self.assertEqual([c['name'] for c in updates],['__cf_bm'])
        self.assertEqual(updates[0]['value'],'updated-fixture')
        self.assertNotIn('identity-fixture',str(sdk.context.add_cookies.call_args))

    def test_interactive_window_requires_explicit_event_and_timeout_does_not_open_it(self):
        sdk=self.make();sdk.page=Mock();sdk.browser=Mock();sdk.context=Mock()
        with patch.object(native.time,'monotonic',side_effect=[0,301]),patch.object(sdk,'_open') as open_window:
            with self.assertRaises(protocol.ManualVerificationRequired):sdk._human_verification()
        open_window.assert_not_called()
        sdk.signals.native_verify.set();sdk.context.storage_state.return_value={'cookies':[],'origins':[]}
        with patch.object(native.time,'monotonic',return_value=0),patch.object(sdk,'_open') as open_window,patch.object(sdk,'_render_widget'):
            sdk._human_verification()
        open_window.assert_called_once_with(headless=False,storage={'cookies':[],'origins':[]})
        self.assertTrue(sdk.interactive_window)

    def test_widget_error_is_not_reclassified_as_success_or_auto_solved(self):
        sdk=self.make();sdk.page=Mock();sdk.widget_started=True
        sdk.page.evaluate.return_value={'token':'','error':'widget_error','interactive':False}
        with self.assertRaises(protocol.GrokProtocolError) as error:sdk._turnstile()
        self.assertEqual(error.exception.reason,'sdk_widget')

    def test_verification_dialog_renders_above_the_native_auth_component(self):
        from playwright.sync_api import sync_playwright
        from core.grok_browser import require_browser
        options=require_browser()
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,chromium_sandbox=True,**options)
            try:
                page=browser.new_page();page.set_content('<div style="position:fixed;inset:0;z-index:9999">Empty auth component</div>')
                page.evaluate("window.turnstile={render:(box,options)=>{options.callback('LOCAL_FIXTURE_ONLY');return 'fixture-widget'}}")
                sdk=self.make();sdk.page=page;sdk.sitekey=SITE
                with patch.object(sdk,'_load_script'):sdk._render_widget()
                self.assertTrue(page.locator('#native-sdk-verification').is_visible())
                self.assertTrue(page.locator('#native-sdk-verification').evaluate("d=>d.matches(':modal')"))
                self.assertEqual(sdk._turnstile(),'LOCAL_FIXTURE_ONLY')
                self.assertEqual(page.locator('input').count(),0)
            finally:browser.close()

    def test_cleanup_failure_does_not_discard_a_confirmed_result(self):
        sdk=self.make();sdk.browser=Mock();sdk.playwright=Mock()
        sdk.browser.close.side_effect=RuntimeError('fixture closed runtime')
        sdk.playwright.stop.side_effect=RuntimeError('fixture closed driver')
        sdk.close()
        self.assertIsNone(sdk.page);self.assertIsNone(sdk.playwright)

    def test_sdk_document_rejection_after_homepage_never_mints_on_an_error_page(self):
        for status,headers in ((403,{}),(200,{'cf-mitigated':'challenge'})):
            sdk=self.make();sdk.page=Mock();sdk.context=Mock()
            response=SimpleNamespace(url='https://grok.com/sign-up?private=not-recorded',status=status,headers={'cf-ray':'fixture-ray',**headers},
                request=SimpleNamespace(resource_type='document'),frame=sdk.page.main_frame)
            sdk._observe_response(response)
            self.assertEqual(sdk.document_status,status)
            with self.assertRaises(protocol.GrokProtocolError) as error:sdk.proof('check')
            self.assertEqual(error.exception.reason,'sdk_page')
            self.assertEqual(error.exception.http_status,status)
            sdk.page.evaluate.assert_not_called()
            self.assertNotIn('not-recorded',str(sdk.update.call_args_list))

    def test_sdk_subresource_denial_is_not_a_document_denial(self):
        sdk=self.make();sdk.page=Mock()
        sdk._observe_response(SimpleNamespace(url='https://grok.com/background.png',status=403,
            request=SimpleNamespace(resource_type='image')))
        sdk._stop()
        self.assertIsNone(sdk.document_error)


if __name__=='__main__':unittest.main()
