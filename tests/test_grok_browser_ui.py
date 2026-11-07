"""Real browser tests against a loopback fixture, never the xAI service."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from core import db, grok_browser as browser, grok_service, grok_store
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


_UNSAFE_PORTS = {1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
    101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389,
    427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989,
    990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667,
    6668, 6669, 6697, 10080}


def _safe_http_server(handler):
    for _ in range(20):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        if server.server_port not in _UNSAFE_PORTS:
            return server
        server.server_close()
    raise RuntimeError('no safe local test port')


class GrokBrowserTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        browser._LAST_LAUNCH = None
        try:
            self.launch_options = browser.require_browser()
        except (RuntimeError, ImportError):
            self.skipTest('Ordinary Chrome/Edge/Chromium is not installed')

    def test_visible_browser_uses_only_the_task_relay_and_is_not_automation_flagged(self):
        ready = MagicMock()
        ready.__enter__.return_value.status = 200
        with patch.object(browser.subprocess, 'Popen') as popen, \
             patch('urllib.request.urlopen', return_value=ready):
            process, port = browser.launch_ordinary_browser('http://127.0.0.1:18431')
        args = popen.call_args.args[0]
        self.assertIn('--proxy-server=http://127.0.0.1:18431', args)
        self.assertIn('--proxy-bypass-list=<-loopback>', args)
        self.assertIn('--disable-blink-features=AutomationControlled', args)
        self.assertFalse(any('--enable-automation' in arg for arg in args))
        self.assertFalse(any('--no-proxy-server' in arg for arg in args))
        self.assertIs(process, popen.return_value)
        self.assertIsInstance(port, int)

    def test_complete_signup_in_real_browser_with_fake_site_and_manual_code(self):
        self._complete_signup_fixture()

    def test_manual_continue_after_403_does_not_resend_and_can_complete(self):
        self._complete_signup_fixture(blocked=True)

    def _complete_signup_fixture(self, blocked=False):
        from playwright.sync_api import BrowserType
        paths, bodies = [], []
        email = 'fixture@icloud.com'
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def send(self, html, cookie=False, denied=False):
                self.send_response(403 if denied else 200); self.send_header('Content-Type', 'text/html; charset=utf-8')
                if denied: self.send_header('cf-mitigated', 'challenge')
                if cookie: self.send_header('Set-Cookie', 'sso=fixture-local-sso; Path=/; HttpOnly')
                self.end_headers(); self.wfile.write(html.encode())
            def do_GET(self):
                self.send('<form method="post" action="/email"><input type="email" name="email"><button type="submit">Continue</button></form>')
            def do_POST(self):
                bodies.append(self.rfile.read(int(self.headers.get('Content-Length', '0')))); paths.append(self.path)
                if self.path == '/email':
                    self.send('<form method="post" action="/verify"><input name="code" autocomplete="one-time-code" maxlength="6"><button type="submit">Verify</button></form>', denied=blocked)
                elif self.path == '/verify':
                    self.send('<form method="post" action="/profile"><input name="givenName"><input name="familyName"><input name="password" type="password"><button type="submit">Create</button></form>')
                else: self.send('<h1>Account</h1><p>'+email+'</p>', cookie=True)
        server = _safe_http_server(Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.shutdown)
        db.import_generic_api_emails([{'email': email, 'code_url': 'https://fixture.test/api'}])
        jid = grok_store.create_jobs([{'email': email, 'source': 'generic_api'}])[0]
        record = grok_store.job(jid, private=True)
        signals = grok_service.Signals(); signals.put_code('A1B-C2D')
        original_launch = BrowserType.launch
        launch_options = dict(self.launch_options)
        def headless(self, **kwargs):
            return original_launch(self, **{**launch_options, **kwargs, 'headless': True})
        original_connect = BrowserType.connect_over_cdp
        def fake_connect(self, endpoint, **kwargs):
            return headless(self)
        real_cookies = browser.session_cookies
        def local_cookies(cookies, **kwargs):
            return real_cookies([{**c, 'domain': '.grok.com'} for c in cookies], **kwargs)
        def update(status, stage, message, **private):
            grok_store.update_job(jid, status, stage, message, private=private)
            if stage == 'access_check': signals.resume.set()
        with patch.object(browser, 'SIGNUP_URL', f'http://127.0.0.1:{server.server_port}/sign-up'), \
             patch.object(browser, 'ALLOWED_HOSTS', {'127.0.0.1'}), \
             patch.object(BrowserType, 'launch', headless), patch.object(BrowserType, 'connect_over_cdp', fake_connect), \
             patch.object(browser, 'session_cookies', side_effect=local_cookies):
            with patch.object(browser, 'verify_proxy_transport'):
                cookies = browser.run(record, grok_store.mailbox(email, 'generic_api'), signals, update)
        self.assertEqual(paths, ['/email', '/verify', '/profile'])
        self.assertIn(b'code=A1BC2D', bodies[1])
        self.assertEqual(cookies['sso'], 'fixture-local-sso')
        grok_store.save_account(jid, cookies)
        self.assertTrue(grok_store.accounts()['items'][0]['has_password'])
        self.assertNotIn('A1B-C2D', str(grok_store.job(jid)))

    def test_modern_and_legacy_grok_page_have_no_script_errors(self):
        from playwright.sync_api import sync_playwright
        from werkzeug.serving import make_server, WSGIRequestHandler
        class Quiet(WSGIRequestHandler):
            def log_request(self, *args, **kwargs): pass
        app = create_app(auth_code='fixture')
        server = make_server('127.0.0.1', 0, app, request_handler=Quiet, threaded=True)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start(); self.addCleanup(server.shutdown)
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, **self.launch_options)
            try:
                for ui in ('modern', 'legacy'):
                    with self.subTest(ui=ui):
                        context = b.new_context(extra_http_headers={'X-Auth-Code': 'fixture'})
                        context.route('**/*', lambda route: route.continue_() if route.request.url.startswith('http://127.0.0.1:') else route.abort())
                        page = context.new_page(); errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
                        page.goto(f'http://127.0.0.1:{server.server_port}/?ui={ui}', wait_until='domcontentloaded')
                        page.locator('nav button[data-tab="grok"]').click()
                        page.wait_for_function("document.getElementById('grokAccountRows').textContent.includes('暂无已注册的 Grok 账号')")
                        self.assertTrue(page.locator('#tab-grok').is_visible())
                        self.assertEqual(page.locator('nav button').evaluate_all('(nodes)=>nodes.map(n=>n.dataset.tab)'),
                                         ['outlook', 'accounts', 'grok', 'qoder', 'register', 'config'])
                        self.assertEqual(errors, [])
                        context.close()
            finally: b.close()

    def test_403_keeps_browser_for_explicit_handoff_without_replaying_and_429_stops(self):
        from playwright.sync_api import BrowserType
        original_launch = BrowserType.launch
        for status in (400, 403, 429):
            with self.subTest(status=status):
                paths, events = [], []
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *args): pass
                    def do_GET(self):
                        self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
                        self.wfile.write(b'<form method="post" action="/CreateEmailValidationCode"><input type="email"><button type="submit">Continue</button></form>')
                    def do_POST(self):
                        self.rfile.read(int(self.headers.get('Content-Length', 0))); paths.append(self.path)
                        self.send_response(status); self.send_header('Content-Type', 'application/json' if status == 400 else 'text/html')
                        if status == 403: self.send_header('cf-mitigated', 'challenge')
                        self.send_header('cf-ray', 'ray-fixture-abc')
                        self.end_headers(); self.wfile.write(b'{"code":"account:email-signup-unavailable","message":"Failed to send verification code"}' if status == 400 else b'<p>private-raw-html-token</p>')
                server = _safe_http_server(Handler)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                signals = grok_service.Signals()
                def update(state, stage, message, **private):
                    events.append((state, stage, message))
                    if stage == 'access_check': signals.stop.set()
                def launch(self, **kwargs): return original_launch(self, **{**kwargs, 'headless': True})
                try:
                    with patch.object(browser, 'SIGNUP_URL', f'http://127.0.0.1:{server.server_port}/sign-up'), \
                         patch.object(browser, 'ALLOWED_HOSTS', {'127.0.0.1'}), patch.object(BrowserType, 'launch', launch):
                        with self.assertRaises(browser.GrokBrowserError) as error:
                            browser.run({'email': 'fixture@icloud.com', 'private': {'password': 'fixture-private-password'}},
                                        {'source': 'generic_api'}, signals, update)
                    self.assertEqual(paths, ['/CreateEmailValidationCode'])
                    self.assertEqual(any(e[1] == 'access_check' for e in events), status in (400, 403))
                    if status == 429: self.assertEqual(error.exception.http_status, 429)
                    self.assertIn('ray-fixture-abc', str(events))
                    self.assertNotIn('private-raw-html-token', str(events))
                finally:
                    server.shutdown(); server.server_close()

    def test_identity_check_never_accepts_another_email_containing_the_target(self):
        self.assertTrue(browser.identity_matches('Email: fixture@icloud.com', 'fixture@icloud.com'))
        self.assertFalse(browser.identity_matches('otherfixture@icloud.com', 'fixture@icloud.com'))
        self.assertFalse(browser.identity_matches('fixture@icloud.com.evil.test', 'fixture@icloud.com'))

    def test_visible_controls_prioritize_email_entry_and_reject_ambiguous_forms(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, **self.launch_options)
            try:
                page = b.new_page()
                page.set_content('<button>Sign in</button><button>Sign up</button><a href="#">Sign up with email</a>')
                self.assertEqual(browser.signup_entry(page).inner_text(), 'Sign up with email')
                page.set_content('<button hidden>Sign up with email</button><button>Sign up</button>')
                self.assertEqual(browser.signup_entry(page).inner_text(), 'Sign up')
                page.set_content('<button>Sign up with email</button><a href="#">Sign up with email</a>')
                self.assertIsNone(browser.signup_entry(page))
                page.set_content('<form>' + '<input maxlength="1">' * 3 + '</form><form>' + '<input maxlength="1">' * 3 + '</form>')
                self.assertEqual(browser.otp_inputs(page), [])
                page.set_content('<form><input name="code" hidden>' + '<input maxlength="1">' * 6 + '</form>')
                self.assertEqual(len(browser.otp_inputs(page)), 6)
                page.set_content('<form><input name="code"><input autocomplete="one-time-code"></form>')
                self.assertEqual(browser.otp_inputs(page), [])
                page.set_content('<form onsubmit="event.preventDefault()"><input type="email"><button>Continue</button></form>')
                calls = []
                self.assertTrue(browser.submit_form(page, page.locator('input'), before_click=lambda: calls.append('submit')))
                self.assertEqual(calls, ['submit'])
                page.set_content('<form><input type="email"><button type="button">Resend</button></form>')
                self.assertFalse(browser.submit_form(page, page.locator('input'), before_click=lambda: calls.append('resend')))
                self.assertEqual(calls, ['submit'])
                page.set_content('<form><input type="email"><button>Continue</button><button>Other</button></form>')
                self.assertFalse(browser.submit_form(page, page.locator('input')))
                page.set_content('<form><input type="email"><button type="button" onclick="this.dataset.clicked=1">Continue</button></form>')
                self.assertTrue(browser.submit_form(page, page.locator('input')))
                self.assertEqual(page.locator('button').get_attribute('data-clicked'), '1')
            finally:
                b.close()

    def test_native_grok_flow_confirms_json_session_and_ignores_unrelated_403(self):
        self._native_fixture('fixture@icloud.com')

    def test_native_grok_flow_does_not_save_another_session_identity(self):
        self._native_fixture('other@icloud.com')

    def test_six_unnamed_otp_boxes_and_hidden_stale_input_are_supported(self):
        self._native_fixture('fixture@icloud.com', boxes=True)

    def test_last_character_auto_verification_is_not_submitted_twice(self):
        self._native_fixture('fixture@icloud.com', auto_verify=True)

    def test_native_session_requires_same_user_id_even_when_page_shows_email(self):
        self._native_fixture('fixture@icloud.com', session_user='different-user')

    def test_native_session_requires_cookie_used_by_session_request(self):
        self._native_fixture('fixture@icloud.com', rotate_cookie=True)

    def test_password_is_saved_only_when_request_and_server_both_confirm_it(self):
        self._native_fixture('fixture@icloud.com', has_password=True)

    def test_password_changed_by_page_is_not_saved_as_candidate(self):
        self._native_fixture('fixture@icloud.com', has_password=True, change_password=True)

    def test_successful_http_without_send_acceptance_does_not_read_mail(self):
        self._native_fixture('fixture@icloud.com', send_ok=False)

    def test_native_server_failure_holds_without_resending_or_reading_mail(self):
        self._native_fixture('fixture@icloud.com', send_status=500)

    def test_native_network_failure_holds_without_resending_or_reading_mail(self):
        self._native_fixture('fixture@icloud.com', abort_send=True)

    def test_mail_polling_is_bounded_and_does_not_resend(self):
        self._native_fixture('fixture@icloud.com', api_codes=['', '', '123-456'])

    def test_empty_mail_stops_after_three_reads(self):
        self._native_fixture('fixture@icloud.com', api_codes=['', '', ''])

    def _native_fixture(self, confirmed_email, *, boxes=False, auto_verify=False, session_user='fixture-user',
                        rotate_cookie=False, has_password=False, change_password=False, send_ok=True,
                        send_status=200, abort_send=False, api_codes=None):
        from playwright.sync_api import BrowserType
        import json
        paths, events = [], []
        email = 'fixture@icloud.com'
        html = '''<form id="signup"><input name="email" type="email"><button type="submit">Continue</button></form>
<script>
let step=0;const form=document.getElementById('signup');
fetch('/sign-in',{headers:{'Next-Router-Prefetch':'1'}});
form.onsubmit=async e=>{e.preventDefault();
 if(step===0){await fetch('/api/auth/send-verification-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@icloud.com'})});form.innerHTML=OTP_HTML;step=1;AUTO_VERIFY}
 else if(step===1){await fetch('/api/auth/sign-up/verify-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@icloud.com',code:CODE_VALUE})});form.innerHTML='<input name="givenName"><input name="familyName"><input name="password" type="password"><button type="submit">Create</button>';step=2;}
 else{await fetch('/api/auth/sign-up/create-account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@icloud.com',password:PASSWORD_VALUE})});document.body.innerHTML='<h1>Grok Home</h1><p>fixture@icloud.com</p>';await fetch('/api/auth/session');}
};</script>'''
        otp_html = ('<input name="code" autocomplete="one-time-code" maxlength="6" hidden>' + '<input maxlength="1">' * 6
                    if boxes else '<input name="code" autocomplete="one-time-code" maxlength="6">')
        otp_html += '<button type="submit">Verify</button>'
        html = html.replace('OTP_HTML', json.dumps(otp_html)).replace('CODE_VALUE',
            "Array.from(form.querySelectorAll('input[maxlength=\"1\"]')).map(n=>n.value).join('')" if boxes else 'form.elements.code.value')
        html = html.replace('PASSWORD_VALUE', "'manually-changed-password'" if change_password else 'form.elements.password.value')
        html = html.replace('AUTO_VERIFY', "form.elements.code.oninput=()=>{if(form.elements.code.value.length===6)form.requestSubmit();};" if auto_verify else '')
        reject_identity = confirmed_email != email or session_user != 'fixture-user' or rotate_cookie
        reject_send = not send_ok or send_status != 200 or abort_send
        empty_mail = api_codes is not None and not any(api_codes)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def send(self, value, status=200, cookie=False, html=False):
                self.send_response(status); self.send_header('Content-Type','text/html' if html else 'application/json')
                if cookie: self.send_header('Set-Cookie', f'sso={cookie if isinstance(cookie, str) else "fake-native-sso"}; Path=/; HttpOnly')
                self.end_headers(); self.wfile.write(value.encode() if html else json.dumps(value).encode())
            def do_GET(self):
                if self.path=='/api/auth/session':
                    self.send({'session':{'email':confirmed_email,'userId':session_user,'emailConfirmed':True,'hasPassword':has_password}},
                              cookie='rotated-session-sso' if rotate_cookie else False)
                elif self.path=='/sign-in': self.send('prefetch denied',403,html=True)
                else: self.send(html,html=True)
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))));paths.append(self.path)
                if self.path.endswith('create-account'):
                    self.send({'session':{'email':email,'userId':'fixture-user','emailConfirmed':False,'hasPassword':False}},cookie=True)
                else: self.send({'ok':send_ok if self.path.endswith('send-verification-code') else True},
                                status=send_status if self.path.endswith('send-verification-code') else 200)
        server=_safe_http_server(Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        db.import_generic_api_emails([{'email':email,'code_url':'https://fixture.test/api'}])
        jid=grok_store.create_jobs([{'email':email,'source':'generic_api'}])[0]
        record=grok_store.job(jid,private=True);signals=grok_service.Signals()
        if api_codes is None: signals.put_code('123456')
        def update(status,stage,message,**private):
            events.append(stage);grok_store.update_job(jid,status,stage,message,private=private)
            if (stage=='identity' and reject_identity) or (stage=='access_check' and reject_send):signals.stop.set()
        original_launch=BrowserType.launch
        launch_options=dict(self.launch_options)
        def headless(self,**kwargs):
            launched = original_launch(self,**{**launch_options,**kwargs,'headless':True})
            if abort_send:
                # Routing is limited to the local fake site's send request.
                original_new_context = launched.new_context
                def new_context(**options):
                    context = original_new_context(**options)
                    context.route('**/api/auth/send-verification-code', lambda route: route.abort('connectionreset'))
                    return context
                launched.new_context = new_context
            return launched
        original_connect=BrowserType.connect_over_cdp
        def fake_connect(self,endpoint,**kwargs):
            return headless(self)
        original_cookies=browser.session_cookies
        def cookies(items, **kwargs):return original_cookies([{**c,'domain':'.grok.com'} for c in items], **kwargs)
        with patch.object(browser,'SIGNUP_URL',f'http://127.0.0.1:{server.server_port}/'), \
             patch.object(browser,'ALLOWED_HOSTS',{'127.0.0.1'}),patch.object(browser,'NATIVE_HOSTS',{'127.0.0.1'}), \
             patch.object(BrowserType,'launch',headless),patch.object(BrowserType,'connect_over_cdp',fake_connect),patch.object(browser,'session_cookies',side_effect=cookies), \
             patch.object(browser,'OTP_READ_INTERVAL',0 if api_codes is not None else 30), \
             patch.object(browser.grok_mail,'read_once',side_effect=api_codes if api_codes is not None else AssertionError('must not read mail')) as read:
            if reject_identity or reject_send or empty_mail:
                if api_codes is None:
                    with self.assertRaises(browser.GrokBrowserError):browser.run(record,{'source':'generic_api','email':email},signals,update)
                else:
                    with self.assertRaises(browser.GrokBrowserError) as caught:
                        browser.run(record,{'source':'generic_api','email':email},signals,update)
                    self.assertEqual(caught.exception.reason, 'mail_timeout')
                self.assertFalse(grok_store.job(jid, private=True)['private'].get('password_confirmed'))
            else:
                result=browser.run(record,{'source':'generic_api','email':email},signals,update)
                self.assertEqual(result['sso'],'fake-native-sso')
                self.assertIn('save',events)
                grok_store.save_account(jid, result)
                self.assertEqual(grok_store.accounts()['items'][0]['has_password'], has_password and not change_password)
            self.assertEqual(read.call_count, 3 if api_codes is not None else 0)
            if api_codes is not None:
                self.assertTrue(all(call.kwargs['after_ts'] > 0 for call in read.call_args_list))
        self.assertEqual('access_check' in events, reject_send)
        self.assertEqual(paths,[] if abort_send else ['/api/auth/send-verification-code'] if reject_send or empty_mail else
                         ['/api/auth/send-verification-code','/api/auth/sign-up/verify-email','/api/auth/sign-up/create-account'])


if __name__ == '__main__': unittest.main()
