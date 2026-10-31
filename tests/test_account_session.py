"""Saved Session credentials stay bound to the account and out of list responses."""
from contextlib import ExitStack
from http.cookiejar import Cookie, CookieJar
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from core import account_session as saved, db, registration_completion
from core.account_export import fetch_session, save_account_data
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app

BASE='__Secure-next-auth.session-token'


def browser(cookies):
    return SimpleNamespace(driver=SimpleNamespace(get_cookies=lambda:cookies))


class SessionCookieTests(unittest.TestCase):
    def test_protocol_cookiejar_and_both_browser_adapters(self):
        jar=CookieJar()
        jar.set_cookie(Cookie(0,BASE,'fixture-session',None,False,'.chatgpt.com',True,True,
                              '/',True,True,None,True,None,None,{}))
        protocol=SimpleNamespace(session=SimpleNamespace(cookies=SimpleNamespace(jar=jar)))
        record={'domain':'.chatgpt.com','name':BASE,'value':'fixture-session','path':'/'}
        for session in (protocol,browser([record]),SimpleNamespace(get_cookies=lambda:[record]),
                        SimpleNamespace(cookies=lambda:[record])):
            self.assertEqual(saved.session_cookie_token(session),'fixture-session')

    def test_chunked_cookie_is_joined_numerically_not_lexicographically(self):
        cookies=[{'domain':'chatgpt.com','name':BASE+'.'+str(i),'value':str(i)+'|'} for i in reversed(range(12))]
        self.assertEqual(saved.session_cookie_token(browser(cookies)),''.join(str(i)+'|' for i in range(12)))
        self.assertEqual(saved.session_cookie_token(browser(cookies[:-1])),'')

    def test_foreign_expired_invalid_or_ambiguous_cookie_is_not_saved(self):
        record={'domain':'chatgpt.com','name':BASE,'value':'private-session','path':'/'}
        for changes in ({'domain':'auth.openai.com'},{'domain':'evilchatgpt.com'},
                        {'name':BASE+'-not-real'},{'expires':time.time()-1},{'path':'/other'},
                        {'value':'private;other=x'},{'value':'private\r\nheader'}):
            with self.subTest(changes=changes):
                self.assertEqual(saved.session_cookie_token(browser([{**record,**changes}])),'')
        self.assertEqual(saved.session_cookie_token(browser([record,{**record,'value':'conflicting'}])),'')
        self.assertEqual(saved.session_cookie_token(None),'')
        self.assertEqual(saved.session_cookie_token(SimpleNamespace(driver=Mock(get_cookies=Mock(side_effect=RuntimeError('closed'))))),'')

    def test_host_cookie_is_supported_without_copying_other_cookies(self):
        self.assertEqual(saved.session_cookie_token(browser([
            {'domain':'chatgpt.com','name':'__Host-next-auth.session-token','value':'host-session'},
            {'domain':'chatgpt.com','name':'__cf_bm','value':'never-export'}])),'host-session')


class AccountSessionTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db,**storage(root)))
        self.aid=db.insert_account(email='fixture@icloud.com',access_token='fixture-at',
            totp_secret='fixture-totp',email_source='generic_api',extra={'registration_password':'fixture-gpt-password','keep':'metadata'})
        self.info={'user':{'email':'fixture@icloud.com','name':'Fixture'},'account':{'planType':'free'},
                   'accessToken':'fixture-at','expires':'2030-01-01T00:00:00Z','actual_extra':{'from_endpoint':True}}
        self.session=browser([{'domain':'.chatgpt.com','name':BASE+'.1','value':'part-b'},
                              {'domain':'.chatgpt.com','name':BASE+'.0','value':'part-a'}])
        self.client=create_app(auth_code='fixture').test_client()
        self.headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}

    def test_save_separate_cookie_and_exact_json_preserves_other_credentials(self):
        saved.remember_session(self.session,self.info)
        self.assertTrue(saved.save_account_session(self.aid,self.session))
        row=db.get_account(self.aid)
        self.assertEqual(row['session_token'],'part-apart-b');self.assertEqual(row['session_json'],self.info)
        self.assertEqual(row['access_token'],'fixture-at');self.assertEqual(row['totp_secret'],'fixture-totp')
        self.assertEqual(json.loads(row['extra_json'])['registration_password'],'fixture-gpt-password')
        self.info['user']['name']='mutated'
        self.assertEqual(row['session_json']['user']['name'],'Fixture')

    def test_foreign_identity_missing_user_or_token_never_persists_a_session(self):
        for info in ({**self.info,'user':{'email':'other@icloud.com'}},{**self.info,'user':{}},
                     {**self.info,'accessToken':''},{'expires':'2030-01-01'}):
            self.assertFalse(saved.save_account_session(self.aid,self.session,info))
        row=db.get_account(self.aid)
        self.assertNotIn('session_token',row);self.assertNotIn('session_json',row)

    def test_json_without_cookie_is_saved_but_cookie_is_not_fabricated_from_at(self):
        self.assertTrue(saved.save_account_session(self.aid,None,self.info))
        self.assertEqual(db.get_account(self.aid)['session_json'],self.info)
        self.assertNotIn('session_token',db.get_account(self.aid))
        legacy=self.client.get(f'/api/accounts/{self.aid}/secret?field=session_token',headers=self.headers).get_json()
        self.assertEqual(legacy['value'],'')

    def test_list_and_poll_expose_only_presence_flags_copy_is_authenticated_and_no_store(self):
        saved.save_account_session(self.aid,self.session,self.info)
        for path in ('/api/accounts?paged=1','/api/accounts','/api/accounts/plan-check-status?page=1'):
            response=self.client.get(path,headers=self.headers)
            self.assertEqual(response.status_code,200)
            text=response.get_data(as_text=True)
            self.assertNotIn('part-apart-b',text)
            if path!='/api/accounts':self.assertNotIn('fixture-at',text)
            self.assertNotIn('actual_extra',text)
            payload=response.get_json();row=payload['items'][0] if isinstance(payload,dict) else payload[0]
            self.assertTrue(row['has_session_token']);self.assertTrue(row['has_session_json'])
        for field in ('session_token','session_json'):
            url=f'/api/accounts/{self.aid}/secret?field={field}'
            self.assertEqual(self.client.get(url).status_code,401)
            response=self.client.get(url,headers=self.headers)
            self.assertEqual(response.headers['Cache-Control'],'no-store')
            value=response.get_json()['value']
            self.assertEqual(value,'part-apart-b') if field=='session_token' else self.assertEqual(json.loads(value),self.info)

    def test_fetch_remembers_real_response_without_changing_its_json(self):
        self.session.get_nextauth_headers=lambda **kw:{}
        response=Mock();response.json.return_value=self.info
        self.session.get=Mock(return_value=response)
        self.assertEqual(fetch_session(self.session),self.info)
        self.assertEqual(saved.session_fields(self.session)['session'],self.info)

    def test_registration_persists_before_and_after_joined_twofa_and_before_close(self):
        saved.remember_session(self.session,self.info)
        def finish(*a,**kw):
            self.assertEqual(db.get_account(self.aid)['session_json'],self.info)
            latest={**self.info,'accessToken':'final-at'}
            saved.remember_session(self.session,latest)
            self.session.driver.get_cookies=lambda:[{'domain':'chatgpt.com','name':BASE,'value':'final-session'}]
            return {'status':'success'}
        with patch.object(registration_completion,'finish_account',side_effect=finish):
            result=registration_completion.complete_registration_result({'success':True,'account_id':self.aid},session=self.session)
        self.assertTrue(result['success'])
        self.assertEqual(db.get_account(self.aid)['session_token'],'final-session')
        self.assertEqual(db.get_account(self.aid)['session_json']['accessToken'],'final-at')

    def test_save_account_data_accepts_actual_browser_session_before_it_closes(self):
        with patch('core.registration_completion.completion_managed',return_value=True), \
             patch('core.account_export._append_batch_archive'):
            aid=save_account_data(email='fixture@icloud.com',access_token='fixture-at',
                session=self.session,session_info=self.info)
        self.assertEqual(db.get_account(aid)['session_token'],'part-apart-b')

    def test_liveness_refreshes_actual_json_and_cookie_but_failures_preserve_saved_session(self):
        saved.save_account_session(self.aid,self.session,self.info)
        info={**self.info,'accessToken':'refreshed-at'}
        db.update_account_liveness(self.aid,{'ok':True,'access_token':'refreshed-at','session':info,'session_token':'refreshed-cookie'})
        row=db.get_account(self.aid)
        self.assertEqual(row['session_json'],info);self.assertEqual(row['session_token'],'refreshed-cookie')
        db.update_account_liveness(self.aid,{'ok':False,'error':'network unavailable','session':self.info,'session_token':'wrong-cookie'})
        row=db.get_account(self.aid)
        self.assertEqual(row['session_json'],info);self.assertEqual(row['session_token'],'refreshed-cookie')


if __name__=='__main__':unittest.main()
