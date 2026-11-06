"""Native Grok HTTP transport; no browser fallback or automatic request replay.

The legacy x.ai gRPC/Server Action transport is intentionally not used here.
No challenge solver, browser impersonation or captured proof/token input.
"""
import json
import re
import time
from types import SimpleNamespace
from urllib.parse import urlsplit
import urllib.request
from collections.abc import Mapping

import requests

from core import grok_mail
from core.auth_diagnostics import auth_error_diagnostic, redact_error_text
from core.grok_common import diagnostic_message, collect_session_cookies

ORIGIN = "https://grok.com"
PATHS = {
    "check": "/api/auth/sso/check",
    "send": "/api/auth/send-verification-code",
    "verify": "/api/auth/sign-up/verify-email",
    "create": "/api/auth/sign-up/create-account",
    "session": "/api/auth/session",
}
REDIRECT_HOSTS = {"grok.com", "auth.grok.com", "auth.x.ai", "accounts.x.ai"}
READ_INTERVAL = 30
_AUTO_SDK = object()


def response_structure(value, depth=0):
    """Names/types only: unknown response fields must never leak their values."""
    if depth>=3:return type(value).__name__
    if isinstance(value,dict):
        return {key if isinstance(key,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}',key) else '[other]':
            response_structure(item,depth+1) for key,item in list(value.items())[:32]}
    if isinstance(value,list):return [response_structure(v,depth+1) for v in value[:3]]
    return type(value).__name__


def error_details(value, secrets):
    """Read known error fields, not arbitrary metadata/response bodies."""
    result={}
    def visit(node,path='',depth=0):
        if not isinstance(node,dict) or depth>2:return
        for key in ('code','error','message','reason','detail','details','cause','description','error_description'):
            item=node.get(key);name=path+key
            if isinstance(item,dict):visit(item,name+'.',depth+1)
            elif isinstance(item,str):
                text=redact_error_text(item,sensitive_values=secrets,limit=300)
                text=re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])','[opaque]',text)
                if text:result[name]=text
    visit(value)
    return result


class GrokProtocolError(RuntimeError):
    def __init__(self, message, *, reason="protocol_error", http_status=None):
        super().__init__(message)
        self.reason = reason
        self.http_status = http_status


class ManualVerificationRequired(GrokProtocolError):
    """A real challenge or missing legitimate native security context; never a solver."""


class EmailCodeRejected(GrokProtocolError):
    """Only an explicit invalid/expired email code permits another mailbox read."""


def require_protocol():
    # Do not require or launch Playwright/Chrome for an HTTP-only attempt.
    return requests.Session


class NativeClient:
    def __init__(self, email, password, update, *, http=None, security=None):
        self.email, self.password, self.update = email, password, update
        self.http = http if http is not None else requests.Session()
        self.owned = http is None
        self.route = "provided_session" if http is not None else "direct"
        self.security = security
        self.code = ""
        self.secrets = []
        self.sent_at = None
        self.create_started = False
        self.proof_created_at = None
        self.http_contexts = []
        if self.owned:
            # Match the user's existing OS/environment route, but do not load
            # netrc credentials or silently fall back to another egress.
            self.http.trust_env = False
            # Windows service processes can be launched without user proxy
            # environment variables even when the WinINET registry still has
            # them. urllib normally reads that registry, but a venv wrapper can
            # also lose it while inheriting the child interpreter. Read both
            # sources and use the fixed route found there; never add another.
            try:
                # Keep the exact OS/environment route by default. The service
                # layer may explicitly pass a fixed proxy session; it never
                # falls back to a different egress.
                proxies = urllib.request.getproxies()
                if not proxies:
                    resolver = getattr(urllib.request, "getproxies_registry", None)
                    if callable(resolver):
                        proxies = resolver() or {}
                proxy = "" if urllib.request.proxy_bypass("grok.com") else proxies.get("https") or proxies.get("all") or proxies.get("http") or ""
                if proxy:
                    parts = urlsplit(proxy)
                    if (parts.scheme not in {"http", "https", "socks5", "socks5h"} or not parts.hostname
                            or parts.fragment or any(c in proxy for c in "\r\n")):
                        raise ValueError()
                    self.http.proxies = {"http": proxy, "https": proxy}
                    self.route = "existing_proxy"
            except (OSError, ValueError, TypeError):
                self.http.close()
                raise GrokProtocolError("现有网络代理配置无效，未回退直连", reason="protocol_proxy") from None
        self.http.headers.update({"Accept": "application/json"})

    def close(self):
        try:
            relay = getattr(self, "_proxy_relay", None)
            self._proxy_relay = None
            if relay is not None:
                relay.close()
        finally:
            if self.owned:
                self.http.close()

    def _proof(self, stage):
        # Current grok.com obtains these from its native SDK. There is no
        # standalone authorized issuer in this app; do not fabricate/omit them.
        if self.security is None:
            raise ManualVerificationRequired("协议安全上下文提供器未接通；未伪造令牌或提交邮箱", reason="native_security")
        proof = self.security.proof(stage)
        needed = {"castleRequestToken", "turnstileToken"} if stage == "create" else {"castleRequestToken"}
        if not isinstance(proof, dict) or any(not isinstance(proof.get(k), str) or not proof[k] for k in needed):
            raise ManualVerificationRequired("原生安全上下文未就绪，未提交请求", reason="native_security")
        self.secrets.extend(proof[k] for k in needed)
        self.proof_created_at=time.monotonic()
        return {k: proof[k] for k in needed}

    def _request(self, method, path, *, payload=None, url=None, html=False, redirect=False):
        endpoint = path if path in PATHS.values() or path == "/" else "set-cookie"
        started=time.monotonic()
        proof_age_ms=(round((started-self.proof_created_at)*1000) if self.proof_created_at is not None
            and isinstance(payload,dict) and payload.get('castleRequestToken') else None)
        if (url is None and method == "POST" and path in PATHS.values()
                and getattr(self.security, 'browser_transport', False) is True
                and callable(getattr(self.security, 'fetch_json', None))):
            try:
                status, headers, value = self.security.fetch_json(method, path, payload)
            except GrokProtocolError:
                raise
            except Exception:
                raise GrokProtocolError("浏览器网络请求未完成；未重放", reason="protocol_network") from None
            context = {'endpoint': endpoint, 'method': method, 'status': status,
                'elapsed_ms': round((time.monotonic()-started)*1000), 'proof_age_ms': proof_age_ms,
                'wire_headers_available': True}
            if callable(getattr(self.security, 'browser_context', None)):
                context.update(self.security.browser_context())
            self.http_contexts.append(context)
            self.update('running', 'http_context', f"浏览器网络实际响应 endpoint={endpoint} status={status} "
                f"nonce_present={context.get('nonce_present','unavailable')} proof_age_ms={proof_age_ms}",
                http_contexts=self.http_contexts[-12:])
            return self._handle_response(method, path, url, status, headers, value, html, redirect, started, proof_age_ms, response=None)
        try:
            response = self.http.request(method, url or ORIGIN + path, json=payload,
                headers={"Origin": ORIGIN, "Referer": ORIGIN + "/", "Accept": "text/html" if html else "application/json"},
                timeout=(10, 20), allow_redirects=False, verify=True, stream=True)
            try:
                body = bytearray()
                limit = 2 * 1024 * 1024 if html else 65536
                for chunk in response.iter_content(16384):
                    body.extend(chunk)
                    if len(body) > limit:
                        raise GrokProtocolError("响应超过安全读取上限", reason="protocol_response")
                headers = dict(response.headers)
                status = response.status_code
            finally:
                response.close()
        except requests.RequestException as exc:
            kind = type(exc).__name__
            if kind not in {"ConnectTimeout", "ReadTimeout", "Timeout", "ProxyError", "SSLError", "ConnectionError", "InvalidSchema"}:
                kind = "transport_error"
            self.update("running", "network_error", f"原生HTTP连接未完成 endpoint={endpoint} error={kind} route={self.route}；不记录私有地址、不切换线路",
                http_transport_error={"endpoint": endpoint, "error_type": kind, "route": self.route})
            raise GrokProtocolError("原生HTTP连接未完成；未重放请求或切换线路", reason="protocol_network") from None
        try:
            value = json.loads(body) if "application/json" in headers.get("Content-Type", headers.get("content-type", "")) else {}
        except (ValueError, UnicodeError):
            value = {}
        value = value if isinstance(value, dict) else {}
        return self._handle_response(method, path, url, status, headers, value, html, redirect, started, proof_age_ms, response=response)

    def _handle_response(self, method, path, url, status, headers, value, html, redirect, started, proof_age_ms, response=None):
        endpoint = path if path in PATHS.values() or path == "/" else "set-cookie"
        lower = {k.lower(): v for k, v in headers.items()}
        challenge = lower.get("cf-mitigated", "").lower() == "challenge"
        if path in PATHS.values():
            if self.http_contexts and self.http_contexts[-1].get('endpoint')==endpoint and self.http_contexts[-1].get('status')==status:
                pass
            else:
                prepared=getattr(response,'request',None)
                actual=getattr(prepared,'headers',None)
                context={'endpoint':endpoint,'method':method,'status':status,'elapsed_ms':round((time.monotonic()-started)*1000),
                    'proof_age_ms':proof_age_ms,'wire_headers_available':isinstance(actual,Mapping)}
                if isinstance(actual,Mapping):
                    names=[piece.strip().partition('=')[0] for piece in actual.get('Cookie','').split(';') if '=' in piece]
                    context.update(cookie_names=sorted(set(names)),duplicate_cookie_names=sorted({n for n in names if names.count(n)>1}),
                        request_header_names=sorted(actual),origin_matches=actual.get('Origin')==ORIGIN,
                        referer_matches=actual.get('Referer')==ORIGIN+'/',json_content_type=actual.get('Content-Type')=='application/json')
                    if self.security is not None and callable(getattr(self.security,'request_context',None)):
                        context.update(self.security.request_context(actual))
                self.http_contexts.append(context)
                self.update('running','http_context',f"原生HTTP实际响应 endpoint={endpoint} status={status} "
                    f"sdk_cookie_match={context.get('sdk_cookie_match','unavailable')} "
                    f"sdk_ua_match={context.get('sdk_user_agent_match','unavailable')} proof_age_ms={proof_age_ms}",
                    http_contexts=self.http_contexts[-12:])
        business_rejected = bool(value.get("error")) or value.get("ok") is False
        if status >= 400 or challenge or business_rejected:
            detail = auth_error_diagnostic(SimpleNamespace(status_code=status, headers=headers, json=lambda: value),
                stage="grok_protocol", sensitive_values=(self.email, self.password, self.code, self.code.replace("-", ""), *self.secrets))
            content_type = lower.get("content-type", "unknown").split(";", 1)[0]
            content_type = content_type if re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", content_type) else "unknown"
            detail.update(host="grok.com" if url is None else urlsplit(url).hostname, endpoint=endpoint,
                resource_type="http", content_type=content_type, challenge=challenge,
                response_structure=response_structure(value),response_header_names=sorted(lower),
                error_details=error_details(value,(self.email,self.password,self.code,*self.secrets)))
            self.update("running", "http_error", diagnostic_message(detail)+'；脱敏错误结构='+json.dumps(
                {'fields':detail['response_structure'],'details':detail['error_details']},ensure_ascii=False), http_diagnostic=detail)
            if challenge and status != 429:
                raise ManualVerificationRequired("官网明确要求人机验证；未重试HTTP请求", reason="protocol_challenge", http_status=status)
            if path==PATHS['verify'] and status in (400,422) and detail['error_code'] in {
                    'email:invalid-validation-code','email:validation-code-expired'}:
                raise EmailCodeRejected('官网明确拒绝本轮邮箱验证码',reason='protocol_verify',http_status=status)
            if path==PATHS['send'] and status in (400,409) and detail['error_code']=='account:existing-email':
                raise GrokProtocolError('官网明确返回已有账号',reason='protocol_existing',http_status=status)
            if path==PATHS['send'] and status==400 and detail['error_code']=='account:email-signup-unavailable':
                # Confirmed by same-environment native-form comparison: this is a
                # server-side mailbox eligibility refusal, not a client defect.
                # Never retry the same mailbox automatically.
                raise GrokProtocolError('官网判定该邮箱当前不可用于注册发码，未重发',
                    reason='protocol_email_unavailable', http_status=status)
            raise GrokProtocolError("官网拒绝原生HTTP请求，未自动重试", reason="protocol_rejected", http_status=status)
        if redirect and status in {301, 302, 303, 307, 308}:
            return value, headers, status
        if not 200 <= status < 300:
            raise GrokProtocolError("认证接口返回未确认的跳转；未重放POST", reason="protocol_response", http_status=status)
        if not html and not value:
            raise GrokProtocolError("认证接口未返回有效JSON，未重放", reason="protocol_response", http_status=status)
        accept_cookies=getattr(self.security,'accept_response_cookies',None)
        if callable(accept_cookies) and (url is None or urlsplit(url).hostname=='grok.com'):
            if response is not None:
                accept_cookies(getattr(response,'cookies',()))
        return value, headers, status

    def bootstrap(self):
        self.update("running", "protocol_bootstrap", f"原生HTTP预检 grok.com；route={self.route}，不启动浏览器、不使用旧x.ai接口")
        self._request("GET", "/", html=True)
        self.update("running", "protocol_bootstrap", "HTTP入口可访问；尚未提交邮箱或发码")

    def check_email(self):
        payload, _, _ = self._request("POST", PATHS["check"], payload={"email": self.email, **self._proof("check")})
        if type(payload.get("enabled")) is not bool or type(payload.get("passwordSignInAvailable")) is not bool:
            raise GrokProtocolError("邮箱检查结构未确认", reason="protocol_response")
        self.update('running','email_check','邮箱登录路由检查完成；不把路由检查当作发码资格确认',
            email_check={'sso_enabled':payload['enabled'],'password_sign_in_available':payload['passwordSignInAvailable']})
        # Match the native client: mixed SSO/password domains may continue.
        if payload["enabled"] and not payload['passwordSignInAvailable']:
            raise GrokProtocolError("官网返回SSO登录方式，请人工确认；未把登录路由当作新注册", reason="protocol_sso")
        # passwordSignInAvailable is not sufficient proof that an account exists.
        return payload

    def send_code(self):
        proof = self._proof("send")
        self.sent_at = time.time()
        self.update("running", "email_send", "提交原生发码请求一次；不设置基线、不重发", email_send_started=True)
        try:
            payload, _, _ = self._request("POST", PATHS["send"], payload={"email": self.email, **proof})
        except GrokProtocolError as exc:
            if exc.reason!='protocol_existing':raise
            self.update('already_registered','existing','官网返回已有账号；未读取邮箱、重复建号或保存候选密码')
            return False
        if payload.get("ok") is not True:
            raise GrokProtocolError("发码接口未确认接收，未读取邮箱", reason="protocol_send")
        self.update("running", "email_code", "原生发码接口已接收；30秒后读取邮箱，最多3轮，不重发", email_send_accepted=True)
        return True

    def verify_code(self, code):
        self.code = code
        payload, _, _ = self._request("POST", PATHS["verify"], payload={"email": self.email, "code": code.replace("-", "")})
        if payload.get("ok") is not True or not isinstance(payload.get("signInMethods"), list):
            raise GrokProtocolError("验证码验证结果未确认，未重复提交", reason="protocol_verify")
        if payload["signInMethods"]:
            self.update("already_registered", "existing", "官网返回已有登录方式；未再次创建账号或保存候选密码")
            return False
        self.update('running','code_verified','原生接口已确认邮箱验证码；准备建号',email_verification_confirmed=True)
        return True

    def _identity(self, payload):
        session = payload.get("session")
        if (not isinstance(session, dict) or str(session.get("email") or "").strip().lower() != self.email.lower()
                or not isinstance(session.get("userId"), str) or not session["userId"]):
            raise GrokProtocolError("会话邮箱或用户标识与本次任务不匹配，未保存SSO", reason="protocol_identity")
        return session

    def cookies(self):
        try:
            return collect_session_cookies([{"domain": c.domain, "path": c.path, "name": c.name, "value": c.value}
                for c in self.http.cookies if not c.is_expired()], native=True)
        except ValueError:
            raise GrokProtocolError("包含不同Grok会话，未保存SSO", reason="protocol_identity") from None

    def _follow(self, url):
        for _ in range(4):
            try:
                parts = urlsplit(url)
                valid = (parts.scheme == "https" and parts.hostname in REDIRECT_HOSTS and parts.port in (None, 443)
                    and not parts.username and not parts.password and parts.path == "/set-cookie" and not parts.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise GrokProtocolError("会话跳转不在受信任范围，未访问", reason="protocol_redirect")
            _, headers, status = self._request("GET", "/set-cookie", url=url, html=True, redirect=True)
            if 200 <= status < 300:
                return
            url = next((v for k, v in headers.items() if k.lower() == "location"), "")
        raise GrokProtocolError("会话跳转次数超过限制，未保存SSO", reason="protocol_redirect")

    def create_account(self):
        proof = self._proof("create")
        self.create_started = True
        self.update("running", "profile_submit", "提交原生建号请求一次；超时结果保留为未确认，不重提", profile_submitted=True, password_confirmed=False)
        payload, _, _ = self._request("POST", PATHS["create"], payload={"email": self.email, "password": self.password,
            "givenName": "User", "familyName": "Account", "emailValidationCode": self.code.replace("-", ""), **proof})
        created = self._identity(payload)
        issued_sso = self.cookies().get("sso")
        if not issued_sso:
            raise GrokProtocolError("建号响应未下发本域SSO，结果未确认", reason="protocol_identity")
        redirect = payload.get("redirectUrl")
        for attempt in range(2):
            bound_sso = self.cookies().get("sso")
            confirmed, _, _ = self._request("GET", PATHS["session"])
            identity = self._identity(confirmed)
            if identity["userId"] != created["userId"]:
                raise GrokProtocolError("建号与登录态用户标识不一致，未保存SSO", reason="protocol_identity")
            cookies = self.cookies()
            if identity.get("emailConfirmed") is True and bound_sso and cookies.get("sso") == bound_sso == issued_sso:
                self.update("running", "save", "原生HTTP会话已确认同邮箱、用户ID与SSO，保存账号", password_confirmed=identity.get("hasPassword") is True,
                    registration_origin="protocol", session_validation_status="protocol_identity")
                return cookies
            if attempt == 0 and isinstance(redirect, str) and redirect:
                try:
                    self._follow(redirect)
                except GrokProtocolError as exc:
                    if exc.reason not in {"protocol_rejected", "protocol_challenge", "protocol_network"}:
                        raise
                    self.update("running", "session_confirm", "跨域会话同步未完成；仅只读确认Grok本域状态，不重试被拒绝的接口")
            else:
                break
        raise GrokProtocolError("建号后的邮箱验证状态未确认，未保存SSO", reason="protocol_identity")


def run(record, mailbox, signals, update, *, http=None, security=_AUTO_SDK):
    automatic_sdk = security is _AUTO_SDK
    sdk = None
    client = NativeClient(record["email"], record["private"]["password"], update, http=http, security=None if automatic_sdk else security)
    try:
        try:
            def check_stop():
                if signals.stop.is_set():
                    raise GrokProtocolError("用户停止任务", reason="user_stop")
            check_stop()
            client.bootstrap()
            check_stop()
            if automatic_sdk:
                from core.grok_native_sdk import NativeSDK
                sdk = NativeSDK(client.http, signals, update)
                client.security = sdk
            client.check_email()
            check_stop()
            if not client.send_code():return None
            code = ""
            rejected=False
            seen_codes=set()
            for attempt in range(3):
                update("running", "email_code", f"等待30秒后读取Grok邮件（第 {attempt+1}/3 轮，不重发）",mail_read_round=attempt+1)
                if signals.stop.wait(READ_INTERVAL):
                    raise GrokProtocolError("用户停止任务", reason="user_stop")
                code = signals.take_code()
                code_source = 'manual' if code else 'api'
                if not code and mailbox.get("source") == "generic_api":
                    try:
                        code = grok_mail.read_once(mailbox, after_ts=client.sent_at)
                    except grok_mail.GrokMailError as exc:
                        if not exc.retryable or exc.http_status in (401, 403, 429):
                            raise
                        update("running", "email_code", "本轮收信连接未完成；不切换线路、不重发")
                if code:
                    normalized=code.replace('-','').upper()
                    if normalized in seen_codes:
                        update('running','email_code','取码接口仍返回已被拒绝的验证码；本轮不重复提交、不重发')
                        continue
                    seen_codes.add(normalized)
                    check_stop()
                    update('running','email_code','已取得Grok邮箱验证码；不记录内容，提交原生验码接口',code_received=True,code_source=code_source)
                    try:
                        if not client.verify_code(code):return None
                    except EmailCodeRejected:
                        rejected=True
                        update('running','email_code','本轮验证码已被官网明确拒绝；只在剩余轮次等待30秒读取新码，不重发')
                        continue
                    break
            else:
                if rejected:raise GrokProtocolError('三轮读取后邮箱验证码仍未验证通过',reason='protocol_verify')
                raise GrokProtocolError("验证码未获取", reason="mail_timeout")
            if signals.stop.is_set():
                raise GrokProtocolError("用户停止任务", reason="user_stop")
            return client.create_account()
        except ManualVerificationRequired as exc:
            check_stop()
            if client.sent_at is not None or client.create_started:
                # A new browser would lose this native flow and could resend.
                raise GrokProtocolError("发码后需要原生验证；未重开流程或重放请求", reason="protocol_security", http_status=exc.http_status) from None
            update("running", "protocol_security", "协议安全上下文未完成；不自动打开可见窗口、不跳过校验", security_reason=exc.reason)
            raise
    finally:
        try:
            if sdk is not None:
                sdk.close()
        finally:
            client.close()
