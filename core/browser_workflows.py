"""共用真实浏览器环境：已有账号登录、工作区、2FA 和账号 API 请求。"""
import json
import logging
import time
import uuid
from contextlib import ExitStack
from urllib.parse import urlencode, urlsplit

from core import db

logger = logging.getLogger(__name__)
_ALLOWED_ORIGINS = {"https://chatgpt.com", "https://auth.openai.com"}
_ALLOWED_HEADERS = {"accept", "content-type", "authorization", "chatgpt-account-id",
                    "oai-device-id", "oai-language", "oai-client-version", "oai-client-build-number"}


class BrowserActionRequired(RuntimeError):
    pass


class BrowserHTTPError(RuntimeError):
    def __init__(self, response):
        self.response = response
        self.status_code = response.status_code
        super().__init__(f"浏览器请求 HTTP {self.status_code}: {urlsplit(response.url).path}")


class BrowserResponse:
    def __init__(self, data):
        self.status_code = int(data.get("status") or 0)
        self.headers = data.get("headers") or {}
        self.url = str(data.get("url") or "")
        self.text = str(data.get("text") or "")

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if not 200 <= self.status_code < 400:
            raise BrowserHTTPError(self)


def _close_cloud(client, opened):
    if hasattr(client, "close_browser_session") and getattr(opened, "session_id", None):
        client.close_browser_session(opened.session_id)


def _open_browser(stack, kind, proxy):
    if kind == "roxy":
        from core.roxybrowser_client import RoxyBrowserClient
        from core.roxy_registration import _build_driver
        client = RoxyBrowserClient(proxy=proxy)
        stack.callback(client.http.close)
        stack.callback(client.close_proxy_pool_relay)
        opened = client.open_profile()
        stack.callback(client.cleanup_profile, opened)
        driver = _build_driver(opened)
        stack.callback(driver.quit)
        return driver, opened
    if kind == "cloak":
        from core.cloakbrowser_driver import build_cloak_driver
        driver, opened = build_cloak_driver(proxy=proxy)
        stack.callback(driver.quit)
        return driver, opened
    if kind == "browser_use":
        from core.browser_use_client import BrowserUseClient
        client = BrowserUseClient()
    elif kind == "skyvern":
        from core.skyvern_client import SkyvernClient
        client = SkyvernClient()
    else:
        raise ValueError(f"没有浏览器适配器: {kind}")
    from playwright.sync_api import sync_playwright
    from core.cloakbrowser_driver import CloakSeleniumDriver
    opened = client.open_session()
    stack.callback(_close_cloud, client, opened)
    playwright = stack.enter_context(sync_playwright())
    args = {"headers": client.cdp_headers()} if hasattr(client, "cdp_headers") else {}
    browser = playwright.chromium.connect_over_cdp(opened.connect_url, **args)
    stack.callback(browser.close)
    context = browser.contexts[0] if browser.contexts else browser.new_context()
    page = context.pages[0] if context.pages else context.new_page()
    logger.info("[统一流程] 云端浏览器使用服务商网络，本机代理地址不会传入云端")
    return CloakSeleniumDriver(browser, context, page), opened


class BrowserAccountSession:
    is_browser_workflow = True

    def __init__(self, kind, proxy=None, *, driver=None, opened=None):
        self.kind = kind
        self.proxy = proxy
        self._stack = ExitStack()
        self.session = self  # 兼容只通过 env.session 发请求的账号 API
        self._closed = False
        self.device_id = str(uuid.uuid4())
        self.oai_session_id = str(uuid.uuid4())
        self.blocked_until = 0
        self.blocked_reason = ""
        try:
            if driver is None:
                self.driver, self.opened = _open_browser(self._stack, kind, proxy)
            else:
                self.driver, self.opened = driver, opened
            self.driver.set_page_load_timeout(60)
            if hasattr(self.driver, "set_script_timeout"):
                self.driver.set_script_timeout(40)
            self.driver._registration_log_prefix = f"[统一流程:{kind}]"
            raw = getattr(self.opened, "raw", {}) or {}
            self.proxy = (raw.get("proxy_pool_target") or raw.get("proxy") or proxy) if kind in {"roxy", "cloak"} else None
            self.browser_profile = self.driver.execute_script("""
                return {user_agent:navigator.userAgent, navigator_language:navigator.language,
                  timezone_iana:Intl.DateTimeFormat().resolvedOptions().timeZone,
                  timezone_offset_minutes:new Date().getTimezoneOffset()};
            """) or {}
        except BaseException:
            self._stack.close()
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            self._stack.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def fingerprint_summary(self):
        return {"driver": self.kind, **self.browser_profile}

    def fingerprint_summary_text(self):
        return f"driver={self.kind} browser={self.browser_profile.get('user_agent', '')}"

    def navigator_language(self):
        return self.browser_profile.get("navigator_language") or "en-US"

    def js_timezone_offset_min(self):
        return self.browser_profile.get("timezone_offset_minutes", 0)

    def reset_circuit_breaker(self):
        # 浏览器模式不把 403 清除后自动重放。
        pass

    def _get_common_headers(self):
        return {"accept": "application/json"}

    def _attach_auth_rum_headers(self, headers):
        return headers

    def get_chatgpt_headers(self, **_):
        return {"accept": "application/json", "content-type": "application/json",
                "oai-device-id": str(self.device_id), "oai-language": self.navigator_language()}

    get_auth_headers = get_chatgpt_headers
    get_nextauth_headers = get_chatgpt_headers

    def get_chatgpt_navigate_headers(self, **_):
        return {"accept": "text/html"}

    get_auth_navigate_headers = get_chatgpt_navigate_headers

    def navigate(self, url):
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" not in _ALLOWED_ORIGINS:
            raise ValueError("浏览器账号请求只允许 ChatGPT/Auth 官方来源")
        self.driver.get(url)
        self._check_page()
        self._sync_device()

    def _sync_device(self):
        value = self.driver.execute_script(r"""
            const m=document.cookie.match(/(?:^|;\s*)oai-did=([^;]+)/);
            return m ? decodeURIComponent(m[1]) : null;
        """)
        if value:
            self.device_id = str(value)

    def _check_page(self):
        state = self.driver.execute_script("""
            return {title:document.title, challenge:!!document.querySelector(
              '#challenge-running,#challenge-stage,iframe[src*="challenges.cloudflare.com"]')};
        """) or {}
        title = str(state.get("title") or "").lower()
        if state.get("challenge") or any(t in title for t in ("just a moment", "access denied", "attention required")):
            raise BrowserActionRequired("浏览器遇到访问验证，请在正常网页登录完成验证后再操作")

    def request(self, method, url, headers=None, data=None, json=None, params=None, timeout=30, **kwargs):
        from json import dumps
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in _ALLOWED_ORIGINS:
            raise ValueError("账号浏览器请求不允许外部来源")
        current = urlsplit(self.driver.current_url)
        if f"{current.scheme}://{current.netloc}" != origin:
            self.navigate(origin + ("/auth/login" if parsed.hostname == "chatgpt.com" else "/"))
        if urlsplit(self.driver.current_url).netloc != parsed.netloc:
            raise BrowserActionRequired("浏览器导航未停留在请求来源，已停止账号请求")
        self._check_page()
        safe_headers = {str(k).lower(): v for k, v in (headers or {}).items() if str(k).lower() in _ALLOWED_HEADERS}
        if json is not None:
            data = dumps(json)
            safe_headers["content-type"] = "application/json"
        if isinstance(data, dict):
            data = urlencode(data)
            safe_headers.setdefault("content-type", "application/x-www-form-urlencoded")
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        result = self.driver.execute_async_script("""
            const [url,method,headers,body,timeout]=arguments, done=arguments[arguments.length-1];
            const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),timeout);
            fetch(url,{method,headers,body:body || undefined,credentials:'include',
              redirect:'error',signal:controller.signal})
              .then(async r=>done({status:r.status,url:r.url,text:await r.text(),headers:Object.fromEntries(r.headers)}))
              .catch(()=>done({error:true})).finally(()=>clearTimeout(timer));
        """, url, method.upper(), safe_headers, data, int(min(float(timeout or 30), 30) * 1000))
        if not isinstance(result, dict) or result.get("error"):
            raise RuntimeError("浏览器请求未完成（网络、CORS 或重定向限制），已停止；不会切换协议驱动")
        response = BrowserResponse(result)
        if response.status_code in (403, 429):
            raise BrowserHTTPError(response)
        return response

    def get(self, url, headers=None, **kwargs):
        if "text/html" in str((headers or {}).get("accept") or ""):
            self.navigate(url)
            return BrowserResponse({"status":200, "url":self.driver.current_url})
        return self.request("GET", url, headers=headers, **kwargs)

    def post(self, url, headers=None, **kwargs):
        return self.request("POST", url, headers=headers, **kwargs)

    def login(self, email, *, email_source=None, auth_url=None):
        """已有账号登录状态机；页面实际要求 OTP 时才读取对应收件箱。"""
        from core import roxy_registration as ui
        from core import roxy_codex_oauth as auth
        from core.email_provider import wait_for_otp
        self.navigate(auth_url or "https://chatgpt.com/auth/login")
        deadline = time.monotonic() + 180
        submitted = set()
        after_ts = time.time()
        metadata_cleared = False
        while time.monotonic() < deadline:
            ui._check_manual_stop()
            self._check_page()
            parsed = urlsplit(self.driver.current_url)
            path = parsed.path
            if parsed.hostname == "auth.openai.com":
                if not metadata_cleared:
                    self.driver.execute_script("sessionStorage.removeItem('__accountWorkspaces')")
                    metadata_cleared = True
                self._capture_workspace_metadata()
            if parsed.hostname not in {"chatgpt.com", "auth.openai.com"}:
                raise BrowserActionRequired("登录进入外部身份提供商，请先完成该账号的正常网页登录")
            if parsed.hostname == "chatgpt.com" and not path.startswith("/auth"):
                response = self.get("https://chatgpt.com/api/auth/session")
                response.raise_for_status()
                info = response.json()
                if info.get("accessToken"):
                    actual = str((info.get("user") or {}).get("email") or "").lower()
                    if actual != email.lower():
                        raise BrowserActionRequired("浏览器登录账号与任务邮箱不一致，已停止")
                    return info
            if any(x in path for x in ("/create-account", "/about-you", "/add-phone", "/phone-verification")):
                raise BrowserActionRequired("现有账号操作进入注册资料/手机验证页面，请先完成正常网页登录")
            if "/workspace" in path:
                if "workspace" in submitted:
                    raise BrowserActionRequired("工作区提交后未完成跳转，请检查账号工作区选择")
                self._choose_workspace(email)
                submitted.add("workspace")
                self._wait_path_change(path, timeout=20)
                continue
            if auth._is_mfa_challenge_page(self.driver):
                if "mfa" in submitted or not auth._fill_mfa_challenge_if_present(self.driver, email, timeout=8):
                    raise BrowserActionRequired("账号需要 MFA 验证，缺少有效密钥或验证未完成")
                submitted.add("mfa")
            elif "/log-in/password" in path:
                if "password" in submitted:
                    raise BrowserActionRequired("密码提交后仍停留登录页，请检查账号密码")
                if auth._account_password_for_email(email):
                    auth._fill_login_password_if_present(self.driver, email, timeout=12)
                else:
                    auth._maybe_click_passwordless_after_email(self.driver, email, timeout=12)
                submitted.add("password")
            elif ui._is_email_verification_page(self.driver):
                if "otp" in submitted:
                    raise BrowserActionRequired("邮箱验证码未被接受，请查看日志后重试")
                self._capture_workspace_metadata()
                code = wait_for_otp(email, after_ts=after_ts, email_source=email_source)
                ui._clear_otp_inputs(self.driver)
                ui._type_otp(self.driver, code)
                ui._click_continue(self.driver)
                submitted.add("otp")
                ui._wait_after_email_otp_submit(self.driver, timeout=30)
            elif "email" not in submitted:
                ui._type_email_address(self.driver, email, timeout=12)
                after_ts = time.time()
                ui._submit_email_step(self.driver, email)
                submitted.add("email")
            time.sleep(1)
        raise BrowserActionRequired("浏览器登录超时，未获取 Session/AT")

    def _wait_path_change(self, path, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._check_page()
            if urlsplit(self.driver.current_url).path != path:
                return
            time.sleep(0.5)
        raise BrowserActionRequired("提交后页面未跳转，请检查页面提示后重试")

    def _capture_workspace_metadata(self):
        self.driver.execute_script("""
            if(window.__accountWorkspaceHook) return;
            window.__accountWorkspaceHook=true;
            const keep=j=>{
              const w=j?.['oai-client-auth-session']?.workspaces;
              if(Array.isArray(w)) sessionStorage.setItem('__accountWorkspaces',
                JSON.stringify(w.map(x=>({id:x.id,name:x.name,kind:x.kind}))));
            };
            const original=window.fetch;
            const send=XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send=function(...args){
              this.addEventListener('load',()=>{
                if(this.responseURL.includes('/api/accounts/')){
                  try { keep(this.responseType==='json' ? this.response : JSON.parse(this.responseText)); } catch {}
                }
              });
              return send.apply(this,args);
            };
            window.fetch=async function(...args){
              const r=await original.apply(this,args);
              if(r.url.includes('/api/accounts/')) r.clone().json().then(keep).catch(()=>{});
              return r;
            };
        """)

    def _choose_workspace(self, email):
        raw = self.driver.execute_script("""
            try{return JSON.parse(sessionStorage.getItem('__accountWorkspaces') || '[]')}catch{return []}
        """)
        options = db._normalize_workspace_options(raw)
        if options:
            db.update_account_workspace_options(email, options)
        preference = (db.get_account_by_email(email) or {}).get("workspace_preference") or "organization"
        if preference.startswith("id:"):
            matches = [x for x in options if x["id"] == preference[3:]]
        else:
            matches = [x for x in options if x["kind"] == preference]
        if len(matches) != 1:
            raise BrowserActionRequired("请在账号页“登录工作区”指定组织/个人工作区；本次可用清单已保存")
        selected = matches[0]
        result = self.driver.execute_script("""
            const id=arguments[0], name=arguments[1];
            const visible=el=>!!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
            const all=[...document.querySelectorAll('button,[role=button],input[type=radio]')].filter(visible);
            const byId=all.filter(el=>[el.value,el.getAttribute('data-workspace-id')].includes(id));
            const byName=name ? all.filter(el=>(el.innerText||el.textContent||'').trim()===name) : [];
            const candidates=byId.length ? byId : byName;
            return candidates.length===1 ? candidates[0] : null;
        """, selected["id"], selected["name"])
        if result is None:
            raise BrowserActionRequired("未找到明确匹配的工作区按钮，请在正常网页登录选择工作区")
        from core.roxy_registration import _human_click
        _human_click(self.driver, result, label="workspace")
        self._live_workspace_selected = selected

    def setup_twofa(self, email, email_source=None):
        from core.account_export import _enroll_totp, _activate_totp
        info = self.login(email, email_source=email_source)
        if (info.get("user") or {}).get("mfa"):
            raise BrowserActionRequired("服务端显示此账号已开启 MFA；请导入已有密钥，勿重复开启")
        token = self.reauthenticate(email, email_source)
        secret, enrollment = _enroll_totp(self, token)
        _activate_totp(self, token, secret, enrollment)
        return secret

    def reauthenticate(self, email, email_source=None):
        from core.account_export import _trigger_reauth
        auth_url = _trigger_reauth(self, email)
        info = self.login(email, email_source=email_source, auth_url=auth_url)
        self._latest_session_info = info
        return info["accessToken"]
