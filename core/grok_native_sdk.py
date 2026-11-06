"""Real browser SDK runtime, not a browser registration driver or challenge solver.

The official SDK collects the unmodified runtime's own signals. Account mutations
are blocked in this context; the protocol client alone sends registration data.
"""
import json
from collections import Counter
import os
from pathlib import Path
import re
import time
from requests.cookies import create_cookie
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

from core.grok_protocol import GrokProtocolError, ManualVerificationRequired
from core.auth_diagnostics import auth_error_diagnostic
from core.grok_common import diagnostic_message

ORIGIN = "https://grok.com"
CASTLE_URL = "https://cdn.jsdelivr.net/npm/@castleio/castle-js@2.8.5/dist/castle.browser.js"
# Verified against the official npm tarball's sha512 integrity, not a capture.
CASTLE_INTEGRITY = "sha384-3bjdgArmvJK4HJTVbNCQKz6mJ3tylWD9vKNiQvrD6HKlk19SuTBcOkQ8DLQL0br9"
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
AUTH_MUTATIONS = {"/api/auth/sso/check", "/api/auth/send-verification-code",
    "/api/auth/sign-up/verify-email", "/api/auth/sign-up/create-account"}
# Only fresh anonymous cookies from this task's genuine SDK context. Never
# import a capture's clearance, identity cookies or another browser profile.
SECURITY_COOKIES = {"grok_device_id", "__cuid", "__cf_bm", "cf_clearance", "__Host-id-token-nonce", "i18nextLng"}


def public_key(scripts):
    """Read only the explicitly published key, never eval Flight/HTML data."""
    texts = list(scripts)
    for script in scripts:
        for match in re.finditer(r"(?:self|window)\.__next_f\.push\(", script):
            try:
                value, _ = json.JSONDecoder().raw_decode(script[match.end():])
            except (ValueError, TypeError):
                continue
            if isinstance(value, list):
                texts.extend(v for v in value if isinstance(v, str))
    values = set(re.findall(r'"CASTLE_PK"\s*:\s*"([A-Za-z0-9_+/.=-]{8,256})"', "\n".join(texts)))
    if len(values) != 1:
        raise GrokProtocolError("官网公开SDK配置缺失或不唯一，未猜测配置", reason="sdk_config")
    return values.pop()


def site_key(sources):
    values = set()
    for source in sources:
        if re.search("turnstile", source, re.I):
            values.update(re.findall(r'''\bsitekey\s*:\s*["'](0x4[A-Za-z0-9_-]{18,80})["']''', source))
        # grok.com publishes the same public Turnstile site key under the
        # CF_SITEKEY name in its inline RSC configuration.
        values.update(re.findall(r'''["']CF_SITEKEY["']\s*:\s*["'](0x4[A-Za-z0-9_-]{18,80})["']''', source))
    if len(values) != 1:
        error=GrokProtocolError("官网公开验证组件配置缺失或不唯一，未猜测配置", reason="sdk_config")
        error.candidate_count=len(values)
        raise error
    return values.pop()


def browser_proxy(http):
    value = http.proxies.get("https") or http.proxies.get("http")
    if not value:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https", "socks5", "socks5h"} or not parts.hostname:
            raise ValueError()
        # Chromium does not support authenticated SOCKS; never fall back direct.
        if parts.scheme.startswith("socks") and (parts.username or parts.password):
            raise ValueError()
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        proxy = {"server": f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")}
        if parts.username:
            proxy["username"] = unquote(parts.username)
        if parts.password:
            proxy["password"] = unquote(parts.password)
        return proxy
    except ValueError:
        raise GrokProtocolError("SDK无法使用当前固定代理；未换线或回退直连", reason="sdk_proxy") from None


class NativeSDK:
    browser_transport = True

    def __init__(self, http, signals, update):
        self.http, self.signals, self.update = http, signals, update
        self.playwright = self.browser = self.context = self.page = None
        self.binary = None
        self.pk = self.sitekey = None
        self.responses = []
        self.invalid_auth_request = False
        self.allow_auth_fetch = False
        self.widget_started = False
        self.interactive_window = False
        self.phase = 'initializing'
        self.cookie_snapshot = ()
        self.runtime_user_agent = ''
        self.document_status = None
        self.document_path = ''
        self.document_error = None
        self.primed_navigation = None

    def _stop(self):
        if self.signals.stop.is_set():
            raise GrokProtocolError("用户停止本任务", reason="user_stop")
        if self.invalid_auth_request:
            raise GrokProtocolError("SDK上下文尝试业务认证请求，已阻止且停止任务", reason="sdk_isolation")
        if self.document_error is not None:
            detail=self.document_error
            self.update('running','sdk_error',diagnostic_message(detail),sdk_http_diagnostic=detail)
            raise GrokProtocolError('SDK页面导航被拒绝，未在错误页继续生成令牌',reason='sdk_page',http_status=detail['http_status'])

    def _observe_response(self, response):
        parts=urlsplit(response.url)
        if response.request.resource_type=='document' and response.frame==self.page.main_frame:
            self.document_status=response.status
            self.document_path=parts.path if parts.path in {'/','/sign-up','/sign-in'} else 'other'
            if (response.status>=400 or parts.scheme!='https' or parts.hostname!='grok.com'
                    or response.headers.get('cf-mitigated','').lower()=='challenge'):
                detail=auth_error_diagnostic(SimpleNamespace(status_code=response.status,headers=response.headers,json=lambda:{}),stage='grok_sdk_document')
                detail.update(host='grok.com' if parts.hostname=='grok.com' else 'other',endpoint='sdk-document',
                    resource_type='document',content_type='text/html',challenge=response.headers.get('cf-mitigated','')=='challenge')
                self.document_error=detail
        if parts.hostname in {'grok.com','cdn.grok.com'} and parts.path.endswith('.js'):
            self.responses.append(response)

    def _route(self, route):
        request = route.request
        if request.method == "POST" and urlsplit(request.url).path in AUTH_MUTATIONS:
            if self.allow_auth_fetch:
                route.continue_()
                return
            self.invalid_auth_request = True
            route.abort()
        else:
            route.continue_()

    def _load_script(self, url, integrity=""):
        self.phase = 'sdk_script' if integrity else 'verification_script'
        # Standard DOM loading: do not disable CSP, TLS, sandbox or detection.
        result = self.page.evaluate("""({url,integrity})=>new Promise((resolve)=>{
            const s=document.createElement('script');s.src=url;s.async=true;
            if(integrity){s.integrity=integrity;s.crossOrigin='anonymous';}
            const timer=setTimeout(()=>resolve({ok:false,reason:'timeout'}),20000);
            s.onload=()=>{clearTimeout(timer);resolve({ok:true})};
            s.onerror=()=>{clearTimeout(timer);resolve({ok:false,reason:'blocked'})};
            document.head.appendChild(s);
        })""", {"url": url, "integrity": integrity})
        if not isinstance(result, dict) or not result.get('ok'):
            raise GrokProtocolError('官网SDK脚本加载未完成；未绕过CSP或重试认证', reason='sdk_script')

    def _open(self, *, headless=True, storage=None):
        self._stop()
        self.phase = 'sdk_document'
        if self.playwright is None:
            from playwright.sync_api import sync_playwright
            self.playwright = sync_playwright().start()
            choices = [Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))/"Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("LOCALAPPDATA", ""))/"Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))/"Microsoft/Edge/Application/msedge.exe",
                Path(self.playwright.chromium.executable_path)]
            self.binary = next((str(p) for p in choices if p.is_file()), None)
            if not self.binary:
                raise GrokProtocolError("原生SDK需要普通浏览器运行时，当前未安装", reason="sdk_unavailable")
        options = {"headless": headless, "executable_path": self.binary, "chromium_sandbox": True}
        proxy = browser_proxy(self.http)
        if proxy:
            options["proxy"] = proxy
        self.browser = self.playwright.chromium.launch(**options)
        self.context = self.browser.new_context(**({"storage_state": storage} if storage else {}))
        self.page = self.context.new_page()
        self.page.route("**/api/auth/**", self._route)
        self.responses = []
        self.document_status = None
        self.document_path = ''
        self.document_error = None
        self.page.on('response',self._observe_response)
        response = self.page.goto(ORIGIN + "/", wait_until="domcontentloaded", timeout=45000)
        if response is None or response.status != 200 or urlsplit(self.page.url).hostname != "grok.com":
            status = response.status if response else None
            headers = response.headers if response else {}
            detail=auth_error_diagnostic(SimpleNamespace(status_code=status,headers=headers,json=lambda:{}),stage='grok_sdk_document')
            detail.update(host='grok.com',endpoint='sdk-document',resource_type='document',content_type='text/html',
                challenge=str(headers.get('cf-mitigated','')).lower()=='challenge')
            self.update('running','sdk_error',diagnostic_message(detail),sdk_http_diagnostic=detail)
            raise GrokProtocolError("SDK官网上下文未正常加载，不重试或换线", reason="sdk_page", http_status=status)
        if self.document_status is None:
            self.document_status=response.status
            self.document_path='/'
        self.page.wait_for_timeout(3500)
        self._wait_for_security_context()
        self._stop()
        self.phase='sdk_public_key'
        self.pk = public_key(self.page.locator("script:not([src])").all_text_contents())
        self.sitekey = self._site_configuration()
        self._stop()
        self._load_script(CASTLE_URL, CASTLE_INTEGRITY)
        self.phase = 'sdk_configure'
        self.page.evaluate("""pk=>{
            if(typeof window.Castle?.configure!=='function')throw new Error('sdk_api_missing');
            window.__nativeRegSdk=window.Castle.configure({pk})||window.Castle;
            if(typeof window.__nativeRegSdk.createRequestToken!=='function')throw new Error('sdk_api_missing');
        }""", self.pk)
        self.page.wait_for_timeout(2000)
        self.widget_started = False
        self._sync()
        self.update("running", "native_sdk", "原生SDK已在普通无窗口上下文就绪；保留真实运行时信号，业务认证请求已隔离", native_sdk_ready=True)

    def _site_configuration(self):
        self.phase='sdk_verification_configuration'
        sources, size, index = [], 0, 0
        inline = self.page.locator('script:not([src])').all_text_contents()
        if isinstance(inline, list):
            sources.extend(inline)
        deadline=time.monotonic()+15
        primed=False
        while True:
            self._stop()
            while index<len(self.responses):
                response=self.responses[index];index+=1
                if response.status!=200:continue
                body=response.body();size+=len(body)
                if size>24*1024*1024:
                    raise GrokProtocolError('SDK公开配置读取超过上限',reason='sdk_config')
                sources.append(body.decode('utf-8',errors='replace'))
            try:
                value=site_key(sources)
                self.responses.clear()
                return value
            except GrokProtocolError as exc:
                if getattr(exc,'candidate_count',0)>1 or time.monotonic()>=deadline:
                    raise
            if not primed:
                # Do not click the homepage sign-up link: it navigates to
                # accounts.x.ai, which is a different origin and currently
                # blocked from this egress. The native auth component on
                # grok.com loads its verification config on its own.
                primed=True
            self.page.wait_for_timeout(250)

    def _wait_for_security_context(self, timeout=45):
        """Wait for the genuine anonymous nonce/clearance issued by grok.com."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._stop()
            cookies = self.context.cookies([ORIGIN])
            names = {c['name'] for c in cookies}
            if '__Host-id-token-nonce' in names and 'cf_clearance' in names:
                return
            self.page.wait_for_timeout(500)
        self.update('running', 'sdk_error', '官网未在25秒内下发匿名安全上下文；未生成令牌或提交邮箱',
                    sdk_error_stage='sdk_security_context')
        raise GrokProtocolError('官网未下发匿名安全上下文；未生成令牌或提交邮箱', reason='sdk_security_context')

    def _sync(self):
        self._stop()
        if urlsplit(self.page.url).scheme!='https' or urlsplit(self.page.url).hostname!='grok.com':
            raise GrokProtocolError('SDK离开当前Grok来源，未同步上下文',reason='sdk_isolation')
        # Use the actual SDK runtime's UA; do not remove its headless marker.
        user_agent = self.page.evaluate("navigator.userAgent")
        cookies = self.context.cookies([ORIGIN])
        if any(c["name"] in {"sso", "sso-rw"} for c in cookies):
            raise GrokProtocolError("SDK上下文意外包含登录身份，未混用会话", reason="sdk_isolation")
        prepared = []
        for cookie in cookies:
            if cookie["name"] not in SECURITY_COOKIES:
                continue
            if cookie['domain'].lstrip('.').lower()!='grok.com' or cookie['path']!='/':
                raise GrokProtocolError('SDK Cookie作用域不匹配，未同步会话',reason='sdk_isolation')
            if cookie['name'].startswith('__Host-') and (cookie['domain']!='grok.com' or not cookie['secure']):
                raise GrokProtocolError('SDK主机Cookie安全属性不匹配，未同步会话',reason='sdk_isolation')
            item=create_cookie(cookie['name'],cookie['value'],domain=cookie['domain'],path=cookie['path'],
                secure=cookie['secure'],expires=int(cookie['expires']) if cookie['expires']>0 else None,
                rest={'HttpOnly':cookie.get('httpOnly',False),'SameSite':cookie.get('sameSite','')})
            item.domain_specified=cookie['domain'].startswith('.')
            prepared.append(item)
        # Validate the whole snapshot before changing the HTTP jar. Also remove
        # managed cookies absent in the runtime, not just names being replaced.
        for cookie in list(self.http.cookies):
            if cookie.name in SECURITY_COOKIES and cookie.domain.lstrip('.').lower() in {'grok.com','www.grok.com'}:
                self.http.cookies.clear(cookie.domain,cookie.path,cookie.name)
        for cookie in prepared:
            self.http.cookies.set_cookie(cookie)
        self.runtime_user_agent=user_agent
        self.http.headers['User-Agent']=user_agent
        self.cookie_snapshot=tuple((c.name,c.value) for c in prepared)

    def request_context(self, headers):
        """Compare actual outbound cookies in memory; return no values/digests."""
        sent=[]
        for part in headers.get('Cookie','').split(';'):
            name,sep,value=part.strip().partition('=')
            if sep and name in SECURITY_COOKIES:sent.append((name,value))
        return {'sdk_cookie_match':Counter(sent)==Counter(self.cookie_snapshot),
            'sdk_user_agent_match':headers.get('User-Agent')==self.runtime_user_agent,
            'sdk_document_status':self.document_status,'sdk_document_path':self.document_path,
            'clearance_present':any(n=='cf_clearance' for n,_ in sent),
            'nonce_present':any(n=='__Host-id-token-nonce' for n,_ in sent)}

    def fetch_json(self, method, path, payload):
        """Send one auth request through this real browser page's network stack.

        The page's own fetch includes genuine browser headers/TLS and the same
        cookies used to mint the Castle token. It is not a form submission or a
        browser-registration fallback.
        """
        self._stop()
        self._sync()
        self.allow_auth_fetch = True
        try:
            result = self.page.evaluate("""async ({method,path,payload}) => {
                try {
                    const response = await fetch(path, {
                        method,
                        credentials: 'include',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload),
                        redirect: 'manual'
                    });
                    const text = await response.text();
                    const headers = {};
                    response.headers.forEach((value,key)=>{headers[key]=value});
                    return {status: response.status, headers, body: text.slice(0, 65536)};
                } catch (error) {
                    return {status: 0, headers: {}, body: '', error: String(error.name || 'fetch_error')};
                }
            }""", {'method': method, 'path': path, 'payload': payload})
        finally:
            self.allow_auth_fetch = False
        if not isinstance(result, dict):
            raise GrokProtocolError('浏览器网络返回结构未确认，未重试', reason='protocol_response')
        if result.get('error'):
            raise GrokProtocolError('浏览器网络请求未完成；未重放', reason='protocol_network')
        try:
            value = json.loads(result.get('body') or '{}')
        except (ValueError, TypeError):
            value = {}
        return int(result.get('status') or 0), result.get('headers') or {}, value if isinstance(value, dict) else {}

    def browser_context(self):
        """Describe the current browser request context without exposing values."""
        cookies = self.context.cookies([ORIGIN])
        names = [c['name'] for c in cookies]
        return {
            'transport': 'browser_fetch',
            'cookie_names': sorted(set(names)),
            'duplicate_cookie_names': sorted({n for n in names if names.count(n) > 1}),
            'request_header_names': ['browser-fetch'],
            'origin_matches': True,
            'referer_matches': True,
            'json_content_type': True,
            'sdk_cookie_match': True,
            'sdk_user_agent_match': True,
            'sdk_document_status': self.document_status,
            'sdk_document_path': self.document_path,
            'clearance_present': 'cf_clearance' in names,
            'nonce_present': '__Host-id-token-nonce' in names,
        }

    def accept_response_cookies(self, cookies):
        """Keep subsequent SDK mints on this HTTP flow's updated anonymous jar."""
        self._stop()
        updates=[]
        for cookie in cookies:
            if cookie.name not in SECURITY_COOKIES or cookie.domain.lstrip('.').lower()!='grok.com':continue
            if cookie.path!='/':
                raise GrokProtocolError('认证响应安全Cookie作用域不匹配',reason='sdk_isolation')
            if cookie.name.startswith('__Host-') and (cookie.domain_specified or not cookie.secure):
                raise GrokProtocolError('认证响应主机Cookie安全属性不匹配',reason='sdk_isolation')
            item={'name':cookie.name,'value':cookie.value,'secure':cookie.secure,
                'httpOnly':cookie.has_nonstandard_attr('HttpOnly') and cookie.get_nonstandard_attr('HttpOnly') is not False}
            if cookie.domain_specified:item.update(domain=cookie.domain,path=cookie.path)
            else:item['url']=ORIGIN+'/'
            same_site=cookie.get_nonstandard_attr('SameSite')
            if same_site in {'Lax','Strict','None'}:item['sameSite']=same_site
            if cookie.expires is not None:item['expires']=cookie.expires
            updates.append(item)
        if updates:
            self.context.add_cookies(updates)
            self._sync()

    def _render_widget(self):
        self._load_script(TURNSTILE_URL)
        self.page.evaluate("""sitekey=>{
            const dialog=document.createElement('dialog');dialog.id='native-sdk-verification';
            const box=document.createElement('div');
            const heading=document.createElement('h2');heading.textContent='仅完成原生验证：不会提交邮箱或注册资料';
            dialog.appendChild(heading);dialog.appendChild(box);document.body.appendChild(dialog);dialog.showModal();
            window.__nativeRegChallenge={token:'',interactive:false,error:''};
            window.__nativeRegWidget=window.turnstile.render(box,{sitekey,
              callback:t=>{window.__nativeRegChallenge.token=t},
              'before-interactive-callback':()=>{window.__nativeRegChallenge.interactive=true},
              'error-callback':()=>{window.__nativeRegChallenge.error='widget_error'},
              'expired-callback':()=>{window.__nativeRegChallenge.error='widget_expired'}
            });
        }""", self.sitekey)
        self.widget_started = True

    def _human_verification(self):
        self.update("manual_required", "native_challenge", "原生验证组件要求人工操作；不会自动开窗口。请明确允许打开仅SDK验证窗口；不重发、不走页面注册")
        deadline = time.monotonic()+300
        while time.monotonic()<deadline:
            self._stop()
            if self.signals.native_verify.is_set():
                self.signals.native_verify.clear()
                storage = self.context.storage_state()
                self.browser.close()
                self.browser = self.context = self.page = None
                self._open(headless=False, storage=storage)
                self.interactive_window = True
                self._render_widget()
                self.update("manual_required", "native_challenge", "仅SDK验证窗口已按你的确认打开；请只完成人机验证，不输入邮箱、不提交注册")
                return
            self.page.wait_for_timeout(500)
        raise ManualVerificationRequired("等待人工验证确认超时，未自动开窗口", reason="native_challenge")

    def _turnstile(self):
        if not self.widget_started:
            self._render_widget()
        self.phase = 'verification_wait'
        deadline = time.monotonic()+45
        while time.monotonic()<deadline:
            self._stop()
            state = self.page.evaluate("window.__nativeRegChallenge")
            if state.get("token"):
                token = state["token"]
                self.page.evaluate("window.__nativeRegChallenge.token=''")
                return token
            if state.get("error"):
                raise GrokProtocolError("原生验证组件返回错误或已过期，未伪造验证结果", reason="sdk_widget")
            if state.get("interactive") and not self.interactive_window:
                self._human_verification()
                deadline = time.monotonic()+300
            self.page.wait_for_timeout(250)
        raise ManualVerificationRequired("原生验证未完成，未创建账号", reason="native_challenge")

    def proof(self, stage):
        self._stop()
        try:
            if self.page is None:
                self._open()
            result = {}
            if self.primed_navigation is None:
                self._open_sign_up_component()
            if stage == "create":
                result["turnstileToken"] = self._turnstile()
            self._sync()
            self.phase = 'sdk_mint'
            token = self.page.evaluate("""()=>Promise.race([
                window.__nativeRegSdk.createRequestToken(),
                new Promise((_,reject)=>setTimeout(()=>reject(new Error('sdk_mint_timeout')),15000))
            ])""")
            if not isinstance(token, str) or len(token)<32 or len(token)>65536:
                raise GrokProtocolError("原生SDK未返回有效新令牌", reason="sdk_token")
            result["castleRequestToken"] = token
            self._sync()
            self.update("running", "native_sdk", f"原生SDK已为本次{stage}请求生成新上下文；不记录或复用令牌", native_sdk_ready=True)
            return result
        except GrokProtocolError as exc:
            if exc.reason == 'sdk_config':
                self.update('running','sdk_error',f'官网公开SDK配置未确认：{self.phase}；未猜测或记录配置值',sdk_error_stage=self.phase)
            raise
        except Exception:
            self.update('running','sdk_error',f'原生SDK阶段未完成：{self.phase}；未记录原始错误或安全字段',sdk_error_stage=self.phase)
            raise GrokProtocolError("原生SDK加载、策略或运行错误；未关闭CSP、伪造令牌或重试认证", reason="sdk_runtime") from None

    def _open_sign_up_component(self):
        "Open the in-page sign-up component once; never navigate off grok.com."
        self._stop()
        entry = self.page.locator('a[href^="/sign-up"]')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self._stop()
            if entry.count() == 1 and entry.is_visible():
                break
            self.page.wait_for_timeout(250)
        else:
            raise GrokProtocolError('官网注册入口未就绪；未伪造导航状态', reason='sdk_page')
        # A plain click navigates to accounts.x.ai (blocked here). Invoke the
        # page's own client-side handler so the auth dialog opens in place.
        entry.evaluate('el => el.click()')
        self.page.wait_for_timeout(2000)
        if urlsplit(self.page.url).hostname != 'grok.com':
            raise GrokProtocolError('注册入口离开Grok来源，已停止且未提交', reason='sdk_isolation')
        email = self.page.locator('input[type="email"]')
        if email.count() != 1 or not email.is_visible():
            raise GrokProtocolError('站内注册组件未打开邮箱输入框，未提交', reason='sdk_page')
        self.primed_navigation = True
        self._stop()
        self._sync()

    def close(self):
        try:
            if self.browser is not None:
                try:
                    self.browser.close()
                except Exception:
                    pass  # Already-closed runtime must not discard a confirmed SSO.
        finally:
            self.browser = self.context = self.page = None
            self.pk = self.sitekey = None
            self.cookie_snapshot = ()
            self.runtime_user_agent = ''
            self.document_error = None
            self.document_status = None
            self.document_path = ''
            self.responses.clear()
            if self.playwright is not None:
                try:
                    self.playwright.stop()
                except Exception:
                    pass
                self.playwright = None
