"""Account-page ICAPI/signature queries read once without sending or claiming mail."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from core import db, generic_api_mail_client as mail
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class AccountApiEmailOtpTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db,**storage(root)))
        self.email='fixture@icloud.com';self.url='https://icapi.oaibx.com/api?token=private-fixture-token'
        db.import_generic_api_emails([{'email':self.email,'code_url':self.url}])
        self.aid=db.insert_account(email=self.email,access_token='private-at',email_source='generic_api')
        self.client=create_app(auth_code='fixture').test_client()
        self.headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}
        self.response=Mock(status_code=200);self.response.json.return_value={'code':1,'data':{'code':'001234','code_time':'2026-10-30 10:00:00'}}
        self.http=Mock();self.http.get.return_value=self.response
        self.factory=self.stack.enter_context(patch.object(mail,'_new_http_session',return_value=self.http))
        self.delay=self.stack.enter_context(patch.object(mail,'_wait_icapi_delay',side_effect=AssertionError('UI query must not wait for a send')))
        self.claim=self.stack.enter_context(patch.object(db,'claim_next_generic_api_email',side_effect=AssertionError('read-only')))
        self.send=self.stack.enter_context(patch('core.openai_auth.send_email_otp',side_effect=AssertionError('read-only')))

    def query(self,headers=None):
        return self.client.get(f'/api/accounts/{self.aid}/email-otp',headers=self.headers if headers is None else headers)

    def test_icapi_query_reads_exact_saved_url_once_without_wait_or_mutation(self):
        accounts=db._load_accounts();pool=db._load_generic_api_emails()
        response=self.query()
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.get_json()['code'],'001234')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.http.get.assert_called_once()
        self.assertEqual(self.http.get.call_args.args[0],self.url)
        self.assertFalse(self.http.get.call_args.kwargs['allow_redirects'])
        self.assertTrue(self.http.get.call_args.kwargs['verify'])
        self.http.close.assert_called_once();self.delay.assert_not_called();self.send.assert_not_called()
        self.assertEqual(db._load_accounts(),accounts);self.assertEqual(db._load_generic_api_emails(),pool)
        self.assertNotIn('private-fixture-token',response.get_data(as_text=True))

    def test_signature_query_uses_top_level_code_not_all_codes(self):
        rows=db._load_generic_api_emails();rows[0]['code_url']='https://smsbower.page/api/mail/getCodeBySignature?s=private-signature'
        db._save_generic_api_emails(rows)
        self.response.json.return_value={'status':1,'code':'001234','all_codes':['987654']}
        self.assertEqual(self.query().get_json()['code'],'001234');self.http.get.assert_called_once()

    def test_invalid_payload_empty_error_or_non_ascii_code_is_not_success(self):
        for value in ({'code':True,'data':{'code':'001234'}},{'code':0,'data':{'code':'001234'}},
                      {'code':1,'data':{'code':'１２３４５６'}},{'code':1,'data':{'code':'abc123'}},
                      {'code':1,'data':None},[],None):
            with self.subTest(value=value):
                self.response.json.return_value=value;self.http.get.reset_mock()
                result=self.query();self.assertEqual(result.status_code,404)
                self.assertNotIn('private-fixture-token',result.get_data(as_text=True))
                self.http.get.assert_called_once()

    def test_http_errors_and_transport_exceptions_do_not_retry_or_echo_tokens(self):
        for status in (302,401,403,429,500):
            self.response.status_code=status;self.http.get.reset_mock()
            self.assertEqual(self.query().status_code,404);self.http.get.assert_called_once()
        self.http.get.side_effect=mail.requests.RequestException(self.url)
        result=self.query();self.assertEqual(result.status_code,404)
        self.assertNotIn('private-fixture-token',result.get_data(as_text=True))

    def test_lookup_uses_bound_email_and_source_and_requires_authentication(self):
        self.assertEqual(self.query(headers={}).status_code,401);self.http.get.assert_not_called()
        db.delete_email_pool(self.email,source='generic_api')
        self.assertEqual(self.query().status_code,404);self.http.get.assert_not_called()
        db.import_outlook_accounts([{'email':self.email,'password':'private-mail','client_id':'fixture','refresh_token':'private-refresh'}])
        self.assertEqual(self.query().status_code,404);self.http.get.assert_not_called()

    def test_account_column_filter_reports_api_source_as_supported(self):
        query={'paged':1,'filters':json.dumps({'email_otp':{'values':['supported']}})}
        data=self.client.get('/api/accounts',query_string=query,headers=self.headers).get_json()
        self.assertEqual(data['total'],1);self.assertEqual(data['items'][0]['email_source'],'generic_api')

    def test_generic_unrecognized_api_preserves_existing_mail_parser(self):
        rows=db._load_generic_api_emails();rows[0]['code_url']='https://mail.example.test/custom-api'
        db._save_generic_api_emails(rows)
        with patch.object(mail,'fetch_latest_otp',return_value='001234') as fetch:
            self.assertEqual(self.query().get_json()['code'],'001234')
        self.http.get.assert_not_called();self.assertEqual(fetch.call_args.kwargs['max_wait'],2)


if __name__=='__main__':unittest.main()
