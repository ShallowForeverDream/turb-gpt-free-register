"""Native HTTP fixtures only; no real credentials, SDK proofs or external requests."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from core import grok_protocol as protocol
from core.grok_service import Signals

EMAIL = 'fixture@icloud.com'
PASSWORD = 'fixture-private-password'
RECORD = {'email': EMAIL, 'private': {'password': PASSWORD}}
MAILBOX = {'email': EMAIL, 'source': 'generic_api'}


class SecurityFixture:
    def proof(self, stage):
        return {'castleRequestToken': 'fixture-security-' + stage, 'turnstileToken': 'fixture-challenge-proof'}


class HttpFixture:
    def __init__(self, *, fail=None, identity=None, sign_in_methods=None, redirect=None, rotate=False, check_flags=None):
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.fail, self.identity, self.redirect, self.rotate = fail or {}, identity, redirect, rotate
        self.sign_in_methods = sign_in_methods or []
        self.check_flags=check_flags
        self.request = Mock(side_effect=self.handle)
        self.close = Mock()

    def handle(self, method, url, **options):
        from urllib.parse import urlsplit
        assert options['verify'] is True and options['allow_redirects'] is False
        assert url.startswith('https://grok.com/') or url.startswith('https://auth.grok.com/')
        path = urlsplit(url).path
        payload = options.get('json')
        if method == 'POST':
            assert payload['email'] == EMAIL
        response_headers = {'Content-Type': 'application/json'}
        status = 200
        if path in self.fail:
            status, data, extra = self.fail[path]
            response_headers.update(extra)
        elif path == '/':
            data = '<html>Grok</html>'
            response_headers = {'Content-Type': 'text/html'}
        elif path == protocol.PATHS['check']:
            data = self.check_flags or {'enabled': False, 'passwordSignInAvailable': False}
        elif path == protocol.PATHS['send']:
            data = {'ok': True}
        elif path == protocol.PATHS['verify']:
            data = {'ok': True, 'signInMethods': self.sign_in_methods}
        elif path == protocol.PATHS['create']:
            self.cookies.set('sso', 'fixture-sso', domain='.grok.com', path='/', secure=True)
            self.cookies.set('sso-rw', 'fixture-rw', domain='.grok.com', path='/', secure=True)
            data = {'session': {'email': EMAIL, 'userId': 'user-fixture', 'emailConfirmed': False, 'hasPassword': False},
                    'redirectUrl': self.redirect}
        elif path == protocol.PATHS['session']:
            data = {'session': self.identity or {'email': EMAIL, 'userId': 'user-fixture', 'emailConfirmed': True, 'hasPassword': True}}
            if self.rotate:
                self.cookies.set('sso', 'different-sso', domain='.grok.com', path='/', secure=True)
        elif path == '/set-cookie':
            data = '<html>Session sync</html>'
            response_headers = {'Content-Type': 'text/html'}
        else:
            raise AssertionError('unexpected fixture endpoint')
        raw = data.encode() if isinstance(data, str) else json.dumps(data).encode()
        return SimpleNamespace(headers=response_headers, status_code=status, iter_content=lambda size: iter([raw]), close=lambda: None)


class ProtocolTests(unittest.TestCase):
    def run_flow(self, http=None, *, codes=None, security=True, stopped=False):
        http = http or HttpFixture()
        events = []
        update = lambda state, stage, message, **private: events.append((state, stage, message, private))
        signals = Signals()
        if stopped:
            signals.stop.set()
        with patch.object(signals.stop, 'wait', return_value=False) as wait, \
             patch.object(protocol.grok_mail, 'read_once', side_effect=codes or ['123-456']) as read:
            result = protocol.run(RECORD, MAILBOX, signals, update, http=http,
                                  security=SecurityFixture() if security else None)
        return result, http, events, wait, read

    def test_native_http_flow_and_three_delayed_reads_no_browser(self):
        with patch('core.grok_browser.run', side_effect=AssertionError('browser must not start')):
            result, http, events, wait, read = self.run_flow(codes=['', '', '123-456'])
        self.assertEqual(result, {'sso': 'fixture-sso', 'sso-rw': 'fixture-rw'})
        paths = [c.args[1].removeprefix(protocol.ORIGIN) for c in http.request.call_args_list]
        self.assertEqual(paths, ['/', *[protocol.PATHS[k] for k in ('check','send','verify','create','session')]])
        self.assertEqual([c.args[0] for c in wait.call_args_list], [30, 30, 30])
        self.assertEqual(read.call_count, 3)
        self.assertTrue(all(c.kwargs['after_ts'] > 0 for c in read.call_args_list))
        self.assertTrue(events[-1][3]['password_confirmed'])
        for secret in ('123456', '123-456', PASSWORD, 'fixture-sso', 'fixture-security-'):
            self.assertNotIn(secret, json.dumps(events))

    def test_production_driver_binds_and_closes_real_sdk_provider_not_none(self):
        from core import grok_native_sdk
        signals=Signals();http=HttpFixture();fixture=SecurityFixture()
        with patch.object(grok_native_sdk,'NativeSDK') as provider, \
             patch.object(signals.stop,'wait',return_value=False), \
             patch.object(protocol.grok_mail,'read_once',return_value='123-456'):
            provider.return_value.proof.side_effect=fixture.proof
            result=protocol.run(RECORD,MAILBOX,signals,Mock(),http=http)
        self.assertEqual(result['sso'],'fixture-sso')
        provider.assert_called_once()
        self.assertEqual([c.args[0] for c in provider.return_value.proof.call_args_list],['check','send','create'])
        provider.return_value.close.assert_called_once()

    def test_missing_native_security_context_stops_before_any_auth_post_without_browser(self):
        http = HttpFixture()
        with patch('core.grok_browser.run', return_value=None) as browser:
            with self.assertRaises(protocol.ManualVerificationRequired) as error:
                self.run_flow(http, security=False)
        self.assertEqual(error.exception.reason, 'native_security')
        self.assertEqual([c.args[0] for c in http.request.call_args_list], ['GET'])
        browser.assert_not_called()

    def test_challenge_rejections_and_429_all_stop_without_browser_fallback(self):
        for status, challenge in ((403,True),(403,False),(429,True),(500,False)):
            http = HttpFixture(fail={'/':(status, {}, {'cf-mitigated':'challenge'} if challenge else {})})
            with self.subTest(status=status, challenge=challenge), patch('core.grok_browser.run', return_value=None) as browser:
                with self.assertRaises(protocol.GrokProtocolError) as error:
                    self.run_flow(http)
                self.assertEqual(error.exception.http_status, status)
                self.assertEqual(isinstance(error.exception, protocol.ManualVerificationRequired), challenge and status != 429)
                browser.assert_not_called()
            self.assertEqual(http.request.call_count, 1)

    def test_business_send_rejection_does_not_read_mail_open_browser_or_retry(self):
        http = HttpFixture(fail={protocol.PATHS['send']:(400,
            {'code':'account:email-signup-unavailable','error':'Failed to send verification code'}, {})})
        with patch('core.grok_browser.run', side_effect=AssertionError('not a challenge')):
            with self.assertRaises(protocol.GrokProtocolError) as error:
                self.run_flow(http)
        self.assertEqual(error.exception.http_status, 400)
        self.assertEqual(error.exception.reason, 'protocol_email_unavailable')
        self.assertEqual(http.request.call_count, 3)

    def test_http_200_business_error_is_not_success_and_is_redacted(self):
        events=[]
        http=HttpFixture(fail={protocol.PATHS['send']:(200,
            {'ok':False,'code':'account:email-signup-unavailable','error':'Failed for '+EMAIL},
            {'x-request-id':'fixture-request-id'})})
        client=protocol.NativeClient(EMAIL,PASSWORD,lambda *args,**kw:events.append((args,kw)),http=http,security=SecurityFixture())
        with self.assertRaises(protocol.GrokProtocolError) as error:client.send_code()
        self.assertEqual(error.exception.reason,'protocol_rejected')
        self.assertIn('account:email-signup-unavailable',str(events))
        self.assertIn('fixture-request-id',str(events))
        self.assertNotIn(EMAIL,str(events))
        http.request.assert_called_once()

    def test_wire_context_and_nested_error_diagnostics_are_value_free(self):
        events=[];http=HttpFixture(fail={protocol.PATHS['send']:(400,
            {'code':'account:email-signup-unavailable','error':{'message':'Failed for '+EMAIL,
                'reason':'delivery_unavailable','details':{'description':PASSWORD}},
             'email':EMAIL,'unknown_token':'opaque-fixture-token-that-must-not-leak'},
            {'x-request-id':'fixture-request-id'})})
        original=http.request.side_effect
        def wire(*args,**kwargs):
            response=original(*args,**kwargs)
            response.request=SimpleNamespace(headers={'Origin':protocol.ORIGIN,'Referer':protocol.ORIGIN+'/',
                'Content-Type':'application/json','Cookie':'__cuid=private-fixture-cookie'})
            return response
        http.request.side_effect=wire
        client=protocol.NativeClient(EMAIL,PASSWORD,lambda *args,**kw:events.append((args,kw)),http=http,security=SecurityFixture())
        with self.assertRaises(protocol.GrokProtocolError):client.send_code()
        detail=events[-1][1]['http_diagnostic']
        self.assertEqual(detail['response_structure']['unknown_token'],'str')
        self.assertEqual(detail['error_details']['error.reason'],'delivery_unavailable')
        self.assertEqual(events[-2][1]['http_contexts'][0]['cookie_names'],['__cuid'])
        for secret in (EMAIL,PASSWORD,'private-fixture-cookie','opaque-fixture-token-that-must-not-leak'):
            self.assertNotIn(secret,str(events))

    def test_sdk_accepts_only_current_success_response_cookies_not_captured_values(self):
        http=HttpFixture();security=SecurityFixture();security.accept_response_cookies=Mock()
        client=protocol.NativeClient(EMAIL,PASSWORD,Mock(),http=http,security=security)
        client.check_email()
        security.accept_response_cookies.assert_called_once_with(())

    def test_empty_mail_exhausts_exactly_three_rounds_without_resend(self):
        http = HttpFixture()
        with patch('core.grok_browser.run', side_effect=AssertionError('no restart')):
            with self.assertRaises(protocol.GrokProtocolError) as error:
                self.run_flow(http, codes=['','',''])
        self.assertEqual(error.exception.reason, 'mail_timeout')
        self.assertEqual(http.request.call_count, 3)

    def test_existing_login_methods_stop_before_create(self):
        result, http, events, _, _ = self.run_flow(HttpFixture(sign_in_methods=['password']))
        self.assertIsNone(result)
        self.assertEqual(events[-1][0], 'already_registered')
        self.assertEqual(http.request.call_count, 4)

    def test_existing_email_at_send_stops_without_mail_read_or_creation(self):
        http=HttpFixture(fail={protocol.PATHS['send']:(400,
            {'code':'account:existing-email','error':'Account already exists'}, {})})
        result,_,events,wait,read=self.run_flow(http)
        self.assertIsNone(result);self.assertEqual(events[-1][0],'already_registered')
        read.assert_not_called();wait.assert_not_called();self.assertEqual(http.request.call_count,3)

    def test_mixed_sso_password_route_matches_native_client_and_is_not_existence_proof(self):
        http=HttpFixture(check_flags={'enabled':True,'passwordSignInAvailable':True})
        result,_,events,_,_=self.run_flow(http)
        self.assertTrue(result['sso'])
        check=next(item[3]['email_check'] for item in events if 'email_check' in item[3])
        self.assertEqual(check,{'sso_enabled':True,'password_sign_in_available':True})

    def test_sso_only_route_stops_without_sending_code(self):
        http=HttpFixture(check_flags={'enabled':True,'passwordSignInAvailable':False})
        with self.assertRaises(protocol.GrokProtocolError) as error:self.run_flow(http)
        self.assertEqual(error.exception.reason,'protocol_sso');self.assertEqual(http.request.call_count,2)

    def test_rejected_code_reads_a_new_code_after_delay_without_resending(self):
        for error_code in ('email:invalid-validation-code','email:validation-code-expired'):
            http=HttpFixture(fail={protocol.PATHS['verify']:(400,{'code':error_code,'error':'Code rejected'}, {})})
            original=http.request.side_effect
            def once(method,url,**kwargs):
                response=original(method,url,**kwargs)
                if url.endswith(protocol.PATHS['verify']):http.fail.clear()
                return response
            http.request.side_effect=once
            with self.subTest(code=error_code):
                result,_,_,wait,read=self.run_flow(http,codes=['111-111','222-222'])
                self.assertTrue(result['sso']);self.assertEqual(read.call_count,2)
                self.assertEqual([c.args[0] for c in wait.call_args_list],[30,30])
                paths=[c.args[1] for c in http.request.call_args_list]
                self.assertEqual(paths.count(protocol.ORIGIN+protocol.PATHS['send']),1)
                self.assertEqual(paths.count(protocol.ORIGIN+protocol.PATHS['verify']),2)

    def test_duplicate_rejected_code_is_not_submitted_again_and_has_three_read_limit(self):
        http=HttpFixture(fail={protocol.PATHS['verify']:(400,
            {'code':'email:invalid-validation-code','error':'Code rejected'}, {})})
        with self.assertRaises(protocol.GrokProtocolError) as error:self.run_flow(http,codes=['111-111','111111','111-111'])
        self.assertEqual(error.exception.reason,'protocol_verify')
        self.assertEqual(sum(c.args[1].endswith(protocol.PATHS['verify']) for c in http.request.call_args_list),1)
        self.assertEqual(sum(c.args[1].endswith(protocol.PATHS['send']) for c in http.request.call_args_list),1)

    def test_generic_verify_error_is_not_retried_as_an_invalid_otp(self):
        http=HttpFixture(fail={protocol.PATHS['verify']:(400,
            {'code':'account:email-signup-unavailable','error':'Verification unavailable'}, {})})
        with self.assertRaises(protocol.GrokProtocolError) as error:self.run_flow(http,codes=['111-111','222-222'])
        self.assertEqual(error.exception.reason,'protocol_rejected')
        self.assertEqual(http.request.call_count,4)

    def test_identity_user_id_verification_and_cookie_must_all_match(self):
        for change in ({'email':'other@icloud.com'}, {'userId':'other-user'}, {'emailConfirmed':False}):
            identity = {'email':EMAIL, 'userId':'user-fixture', 'emailConfirmed':True, **change}
            with self.subTest(change=change), self.assertRaises(protocol.GrokProtocolError) as error:
                self.run_flow(HttpFixture(identity=identity))
            self.assertEqual(error.exception.reason, 'protocol_identity')
        with self.assertRaises(protocol.GrokProtocolError):
            self.run_flow(HttpFixture(rotate=True))

    def test_unconfirmed_password_is_not_saved(self):
        _, _, events, _, _ = self.run_flow(HttpFixture(identity={'email':EMAIL, 'userId':'user-fixture', 'emailConfirmed':True, 'hasPassword':False}))
        self.assertFalse(events[-1][3]['password_confirmed'])

    def test_stop_before_start_does_not_make_requests_or_open_browser(self):
        http = HttpFixture()
        with patch('core.grok_browser.run', side_effect=AssertionError('must not open')):
            with self.assertRaises(protocol.GrokProtocolError) as error:
                self.run_flow(http, stopped=True)
        self.assertEqual(error.exception.reason, 'user_stop')
        http.request.assert_not_called()

    def test_existing_system_proxy_is_used_without_netrc_or_route_fallback(self):
        proxy = 'http://fixture-user:fixture-proxy-secret@127.0.0.1:28080'
        with patch('urllib.request.getproxies',return_value={'http':proxy,'https':proxy}), \
             patch('urllib.request.proxy_bypass',return_value=False):
            client = protocol.NativeClient(EMAIL,PASSWORD,Mock())
        self.addCleanup(client.close)
        self.assertFalse(client.http.trust_env)
        self.assertEqual(client.route,'existing_proxy')
        self.assertEqual(client.http.proxies,{'http':proxy,'https':proxy})
        events=[];client.update=lambda *args,**kw: events.append((args,kw))
        client.http.request=Mock(side_effect=requests.exceptions.ProxyError('private-proxy-credentials'))
        with self.assertRaises(protocol.GrokProtocolError):client.bootstrap()
        client.http.request.assert_called_once()
        self.assertEqual(client.http.proxies,{'http':proxy,'https':proxy})
        self.assertIn('ProxyError',str(events))
        for secret in ('fixture-proxy-secret','private-proxy-credentials','fixture-user'):
            self.assertNotIn(secret,str(events))

    def test_existing_proxy_bypass_is_respected_and_bad_proxy_is_not_used(self):
        with patch('urllib.request.getproxies',return_value={'https':'http://127.0.0.1:28080'}), \
             patch('urllib.request.proxy_bypass',return_value=True):
            client=protocol.NativeClient(EMAIL,PASSWORD,Mock())
        self.addCleanup(client.close)
        self.assertEqual(client.route,'direct')
        self.assertEqual(client.http.proxies,{})
        with patch('urllib.request.getproxies',return_value={'https':'file:///private'}), \
             patch('urllib.request.proxy_bypass',return_value=False), self.assertRaises(protocol.GrokProtocolError) as error:
            protocol.NativeClient(EMAIL,PASSWORD,Mock())
        self.assertEqual(error.exception.reason,'protocol_proxy')

    def test_registry_proxy_is_used_when_environment_proxy_is_missing(self):
        proxy='http://127.0.0.1:28080'
        with patch('urllib.request.getproxies',return_value={}), \
             patch('urllib.request.getproxies_registry',return_value={'http':proxy,'https':proxy}), \
             patch('urllib.request.proxy_bypass',return_value=False):
            client=protocol.NativeClient('fixture@example.com','fixture-password',Mock())
        self.assertEqual(client.route,'existing_proxy')
        self.assertEqual(client.http.proxies,{'http':proxy,'https':proxy})

    def test_transport_failure_never_replays_creation(self):
        http = HttpFixture()
        original = http.handle
        def request(method, url, **kwargs):
            if url.endswith(protocol.PATHS['create']):
                raise requests.Timeout('private-url private-password')
            return original(method, url, **kwargs)
        http.request.side_effect = request
        with self.assertRaises(protocol.GrokProtocolError) as error:
            self.run_flow(http)
        self.assertEqual(error.exception.reason, 'protocol_network')
        self.assertNotIn('private', str(error.exception))
        self.assertEqual(http.request.call_count, 5)

    def test_proofs_not_fabricated_or_echoed_in_errors(self):
        events = []
        http = HttpFixture(fail={protocol.PATHS['check']:(400,
            {'error':'castleRequestToken=fixture-security-check '+PASSWORD}, {})})
        client = protocol.NativeClient(EMAIL, PASSWORD, lambda *args,**kw: events.append((args,kw)), http=http, security=SecurityFixture())
        with self.assertRaises(protocol.GrokProtocolError): client.check_email()
        self.assertNotIn('fixture-security-check', str(events))
        self.assertNotIn(PASSWORD, str(events))

    def test_requests_transport_real_loopback_cookies_and_json_flow(self):
        paths, session_cookie_seen = [], []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def respond(self, value, cookie=False):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                if cookie:
                    self.send_header('Set-Cookie', 'sso=loopback-only-sso; Path=/; HttpOnly')
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())
            def do_GET(self):
                paths.append(self.path)
                if self.path == '/':
                    self.respond({'page':'fixture'})
                else:
                    session_cookie_seen.append(self.headers.get('Cookie',''))
                    self.respond({'session':{'email':EMAIL,'userId':'loopback-user','emailConfirmed':True,'hasPassword':True}})
            def do_POST(self):
                paths.append(self.path)
                payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
                if payload.get('email') != EMAIL:
                    self.send_error(400); return
                if self.path == protocol.PATHS['check']:
                    self.respond({'enabled':False,'passwordSignInAvailable':False})
                elif self.path == protocol.PATHS['send']:
                    self.respond({'ok':True})
                elif self.path == protocol.PATHS['verify']:
                    self.respond({'ok':True,'signInMethods':[]})
                else:
                    self.respond({'session':{'email':EMAIL,'userId':'loopback-user'}},cookie=True)
        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.shutdown)
        http = requests.Session(); http.trust_env = False
        self.addCleanup(http.close)
        original = protocol.collect_session_cookies
        def local_cookies(cookies, **kwargs):
            return original([{**cookie,'domain':'.grok.com'} for cookie in cookies], **kwargs)
        with patch.object(protocol,'ORIGIN',f'http://127.0.0.1:{server.server_port}'), \
             patch.object(protocol,'collect_session_cookies',side_effect=local_cookies), \
             patch('core.grok_browser.run',side_effect=AssertionError('no browser')):
            result, _, _, _, _ = self.run_flow(http)
        self.assertEqual(result['sso'],'loopback-only-sso')
        self.assertEqual(session_cookie_seen,['sso=loopback-only-sso'])
        self.assertEqual(paths,['/', *[protocol.PATHS[k] for k in ('check','send','verify','create','session')]])

    def test_protocol_import_does_not_require_browser_or_playwright(self):
        result=subprocess.run([sys.executable,'-c',
            "import sys; sys.modules['playwright']=None; sys.modules['core.grok_browser']=None; "
            "import core.grok_protocol; core.grok_protocol.require_protocol(); print('HTTP_ONLY_OK')"],
            capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('HTTP_ONLY_OK',result.stdout)


if __name__ == '__main__':
    unittest.main()
