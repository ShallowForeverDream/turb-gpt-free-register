"""Visible, ordinary browser signup. No stealth, challenge solving or protocol replay."""
import re
import time
from datetime import datetime
from http.cookies import SimpleCookie
from types import SimpleNamespace
from urllib.parse import urlsplit
import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path

from core import grok_mail
from core.auth_diagnostics import auth_error_diagnostic
from core.grok_common import collect_session_cookies, diagnostic_message

SIGNUP_URL = "https://grok.com/"
ORIGIN_SESSION = "https://grok.com/api/auth/session"
ALLOWED_HOSTS = {"accounts.x.ai", "auth.x.ai", "auth.grok.com", "grok.com", "www.grok.com"}
EMAIL = 'input[data-testid="email"],input[name="email"],input[type="email"],input[autocomplete="email"]'
OTP = 'input[data-input-otp="true"],input[name="code"],input[autocomplete="one-time-code"]'
GIVEN = 'input[data-testid="givenName"],input[name="givenName"],input[autocomplete="given-name"]'
FAMILY = 'input[data-testid="familyName"],input[name="familyName"],input[autocomplete="family-name"]'
PASSWORD = 'input[data-testid="password"],input[name="password"],input[type="password"]'
AUTH_METHODS = {"CreateEmailValidationCode", "VerifyEmailValidationCode", "ValidateEmailValidationCode", "CreateUserAndSession"}
NATIVE_AUTH_PATHS = {
    "/api/auth/sso/check": "sso-check",
    "/api/auth/send-verification-code": "send-verification-code",
    "/api/auth/sign-up/verify-email": "verify-email",
    "/api/auth/sign-up/create-account": "create-account",
    "/api/auth/session": "auth-session",
}
NATIVE_HOSTS = {"grok.com", "www.grok.com"}
OTP_READ_INTERVAL = 30


class GrokBrowserError(RuntimeError):
    def __init__(self, message, *, reason="browser_error", http_status=None):
        super().__init__(message)
        self.reason = reason
        self.http_status = http_status


def require_browser():
    choices = [Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
               Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
               Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe"]
    for binary in choices:
        if binary.exists():
            return {"executable_path": str(binary)}
    raise GrokBrowserError("未找到 Chrome/Edge 或 Playwright Chromium，请先安装普通浏览器")


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def launch_ordinary_browser(proxy_url=None):
    """Start installed Chrome without Playwright's automation switch.

    Playwright's launch() adds --enable-automation, which sets
    navigator.webdriver=true. The official signup page treats that as a
    non-interactive client and refuses email signup. Starting Chrome directly
    and attaching over CDP keeps navigator.webdriver=false while still using
    Playwright for page control.

    ``proxy_url`` must be a fixed, per-task local HTTP CONNECT relay (the
    caller owns its lifetime).  It is deliberately not read from the ambient
    environment: a visible Grok signup must use one chosen dynamic residential
    exit for the whole flow, not the user's general Clash/system proxy.
    """
    info = require_browser()
    binary = info["executable_path"]
    port = _free_port()
    profile = tempfile.mkdtemp(prefix="grok-browser-")
    args = [binary, f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check", "--disable-features=Translate"]
    proxy = str(proxy_url or "").strip()
    if proxy:
        args.append(f"--proxy-server={proxy}")
        # The CDP control channel is loopback and must never go through the
        # residential proxy.  Business pages still use only this proxy.
        args.append("--proxy-bypass-list=<-loopback>")
    args.append("about:blank")
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for the DevTools endpoint; Chrome needs a moment to open it.
    import urllib.request
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1) as response:
                if response.status == 200:
                    return process, port
        except Exception:
            time.sleep(0.25)
    process.terminate()
    raise GrokBrowserError("普通浏览器调试端口未就绪", reason="browser_unavailable")


_BROWSER_OVERRIDE = None


def launch_browser(proxy_url=None):
    """Return (process, debug_port) or a test-provided browser handle."""
    if _BROWSER_OVERRIDE is not None:
        try:
            return _BROWSER_OVERRIDE(proxy_url=proxy_url)
        except TypeError:
            return _BROWSER_OVERRIDE()
    return launch_ordinary_browser(proxy_url=proxy_url)


def session_cookies(cookies, *, native=False):
    try:
        return collect_session_cookies(cookies, native=native)
    except ValueError as exc:
        raise GrokBrowserError(str(exc)) from None


def visible(page, selector):
    nodes = page.locator(selector)
    for i in range(min(nodes.count(), 12)):
        node = nodes.nth(i)
        if node.is_visible():
            return node
    return None


def identity_matches(text, email):
    return re.search(r"(?<![\w.+-])" + re.escape(email) + r"(?![\w.-])", text, re.I) is not None


def otp_inputs(page):
    """Accept one aggregate input or six editable boxes in the same form."""
    candidates = page.locator(OTP + ',input[inputmode="numeric"][maxlength="6"]')
    aggregate = [node for node in candidates.all() if node.is_visible() and node.is_editable()
                 and node.get_attribute("maxlength") != "1"]
    if aggregate:
        return aggregate if len(aggregate) == 1 else []
    boxes = [node for node in page.locator('input[maxlength="1"]').all()
             if node.is_visible() and node.is_editable()]
    if len(boxes) != 6:
        return []
    form = boxes[0].locator("xpath=ancestor::form")
    if form.count() != 1:
        return []
    siblings = [node for node in form.locator('input[maxlength="1"]').all()
                if node.is_visible() and node.is_editable()]
    return siblings if len(siblings) == 6 else []


def signup_entry(page):
    # Email-specific entry wins over generic sign-in/sign-up on the same page.
    for pattern in (r"sign up with email|continue with email|使用邮箱注册|邮箱注册|使用电子邮件注册",
                    r"sign up|注册|create account|创建账号|创建账户", r"sign in|登录"):
        candidates = []
        for role in ("button", "link"):
            candidates.extend(node for node in page.get_by_role(role, name=re.compile("^(?:" + pattern + ")$", re.I)).all()
                              if node.is_visible() and node.is_enabled())
        if candidates:
            return candidates[0] if len(candidates) == 1 else None
    return None


def submit_form(page, input_node, *, before_click=None):
    form = input_node.locator("xpath=ancestor::form")
    if form.count() != 1:
        return False
    buttons = form.locator('button[type="submit"],input[type="submit"],button:not([type])')
    ready = [node for node in buttons.all() if node.is_visible() and node.is_enabled()]
    if not ready:
        buttons = form.get_by_role("button", name=re.compile(
            r"^(?:continue|next|verify|confirm email|sign up|create account|继续|下一步|确认邮箱|验证|注册|创建账号|创建账户|完成注册)$", re.I))
        ready = [node for node in buttons.all() if node.is_visible() and node.is_enabled()]
    if len(ready) != 1:
        return False
    if before_click is not None:
        before_click()
    ready[0].click(timeout=5000)
    return True


def request_sso(request):
    """Read only in memory to bind a native session response to its Cookie."""
    try:
        cookies = SimpleCookie()
        cookies.load(request.all_headers().get("cookie", ""))
        return cookies["sso"].value if "sso" in cookies else ""
    except Exception:
        return ""


def response_diagnostic(response, *, sensitive_values=()):
    """Only allowlisted identifiers and redacted JSON errors, never HTML/URLs/headers."""
    parts = urlsplit(response.url)
    name = parts.path.rstrip("/").rsplit("/", 1)[-1]
    endpoint = NATIVE_AUTH_PATHS.get(parts.path) or (name if name in AUTH_METHODS else parts.path if parts.path in {"/", "/sign-up", "/sign-in", "/set-cookie"} else "other")
    headers = {str(k).lower(): v for k, v in response.headers.items()}
    content_type = headers.get("content-type", "").split(";", 1)[0].lower()
    content_type = content_type if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", content_type) else "unknown"
    payload = {}
    if content_type == "application/json":
        try:
            body = response.body()
            if len(body) <= 65536:
                import json
                payload = json.loads(body)
        except Exception:
            pass
    detail = auth_error_diagnostic(SimpleNamespace(status_code=response.status, headers=headers, json=lambda: payload),
                                   stage="grok_response", sensitive_values=sensitive_values)
    # xAI OTPs are alphanumeric, unlike the numeric codes redacted by shared Auth diagnostics.
    detail["error_message"] = re.sub(r"(?<![A-Z0-9])([A-Z0-9]{3}-[A-Z0-9]{3})(?![A-Z0-9])", "[验证码已隐藏]", detail["error_message"])
    detail["error_message"] = re.sub(r"(?i)\b(sso(?:-rw)?|token|signature)\s*[:=]\s*\S+", r"\1=[已隐藏]", detail["error_message"])
    detail.update(host=parts.hostname if parts.hostname in ALLOWED_HOSTS else "other", endpoint=endpoint,
                  resource_type=response.request.resource_type if response.request.resource_type in {"document", "xhr", "fetch", "script", "image", "font", "stylesheet", "media", "manifest"} else "other",
                  content_type=content_type, challenge=headers.get("cf-mitigated", "").lower() == "challenge")
    return detail


def interactive_auth_error(response, page):
    """A failed prefetch/telemetry request is not a failed signup submission."""
    request = response.request
    headers = {key.lower(): value for key, value in request.headers.items()}
    if (headers.get("next-router-prefetch") or "prefetch" in headers.get("purpose", "").lower()
            or "prefetch" in headers.get("sec-purpose", "").lower()):
        return False
    try:
        if request.is_navigation_request() and request.frame == page.main_frame:
            return True
    except Exception:
        pass
    path = urlsplit(response.url).path
    return request.method == "POST" and (path in NATIVE_AUTH_PATHS or path.rstrip("/").rsplit("/", 1)[-1] in AUTH_METHODS)


def request_email_matches(request, email):
    try:
        payload = request.post_data_json
        return isinstance(payload, dict) and str(payload.get("email") or "").strip().lower() == email.lower()
    except Exception:
        return False


def show_browser_window(context, page):
    """Restore only this task's ordinary browser before opening the signup site."""
    session = None
    try:
        session = context.new_cdp_session(page)
        window = session.send("Browser.getWindowForTarget")
        if type(window.get("windowId")) is not int:
            return False
        session.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": {"windowState": "normal"}})
        page.bring_to_front()
        return True
    except Exception:
        return False
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def verify_proxy_transport(proxy_url):
    """Fail before opening a page if the chosen residential exit is unusable.

    The grok.com homepage itself may return a Cloudflare 403 to a bare
    urllib probe while the ordinary browser (with its full TLS/header stack)
    can load it normally.  Therefore probe a neutral HTTPS endpoint through
    the same local CONNECT relay: it proves the proxy tunnel and TLS path,
    without treating a site-specific WAF status as a dead exit.
    """
    import urllib.request
    if not proxy_url:
        return
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    try:
        with opener.open("https://www.gstatic.com/generate_204", timeout=20) as response:
            if response.status not in (200, 204):
                raise GrokBrowserError("动态家宽出口预检未通过，未打开注册页", reason="proxy_unavailable")
    except GrokBrowserError:
        raise
    except Exception:
        raise GrokBrowserError("动态家宽出口预检未通过，未打开注册页", reason="proxy_unavailable") from None


def run(record, mailbox, signals, update, *, proxy_url=None):
    from playwright.sync_api import sync_playwright
    launch_options = require_browser()
    issued = False
    email_submitted = False
    send_accepted = False
    otp_submitted = False
    otp_request_started = False
    profile_filled = False
    profile_submitted = False
    attempts, next_read = 0, None
    pending_errors = []
    pending_failures = []
    pending_auth_success = []
    manual_hold = False
    hold_status = 403
    code_page_ready = False
    submitted_code = ""
    send_started_at = None
    native_flow = urlsplit(SIGNUP_URL).hostname in NATIVE_HOSTS
    created_user_id = ""
    confirmed_session_sso = ""
    candidate_was_submitted = False
    effective_proxy = proxy_url or record.get("private", {}).get("proxy_transport")
    # The service prechecks before it reserves and opens the browser; a direct
    # caller still gets the same fail-closed check.
    if record.get("private", {}).get("proxy_prechecked") is not True:
        verify_proxy_transport(effective_proxy)
    process, debug_port = launch_browser(proxy_url=effective_proxy)
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{debug_port}")
            try:
                context = browser.new_context()  # no shared storage or GPT cookies
                page = context.new_page()
                if not show_browser_window(context, page):
                    raise GrokBrowserError("无法展开本任务浏览器窗口，未访问官网或发码", reason="window_unavailable")
                def observe(response):
                    host = urlsplit(response.url).hostname
                    if host in ALLOWED_HOSTS and response.status >= 400:
                        pending_errors.append(response)
                    if host in NATIVE_HOSTS and 200 <= response.status < 300 and urlsplit(response.url).path in NATIVE_AUTH_PATHS:
                        pending_auth_success.append(response)
                page.on("response", observe)
                def observe_failure(request):
                    parts = urlsplit(request.url)
                    if (parts.hostname in NATIVE_HOSTS and parts.path in NATIVE_AUTH_PATHS
                            and (request.method == "POST" or (profile_submitted and parts.path == "/api/auth/session"))):
                        pending_failures.append(request)
                page.on("requestfailed", observe_failure)
                def observe_request(request):
                    nonlocal issued, next_read, profile_submitted, send_started_at, email_submitted
                    nonlocal native_flow, candidate_was_submitted, otp_request_started, otp_submitted
                    parts = urlsplit(request.url)
                    if parts.hostname not in ALLOWED_HOSTS or request.method != "POST":
                        return
                    native = parts.hostname in NATIVE_HOSTS
                    matched = request_email_matches(request, record["email"])
                    if native and parts.path in NATIVE_AUTH_PATHS and matched:
                        native_flow = True
                    if parts.path.endswith("/CreateEmailValidationCode") or (native and parts.path == "/api/auth/send-verification-code" and matched):
                        issued = True
                        email_submitted = True
                        send_started_at = time.time()
                        next_read = time.monotonic() + OTP_READ_INTERVAL
                        update("running", "email_send", "浏览器已提交邮箱发码请求一次；30秒后只读API，不重发")
                    if (native and parts.path == "/api/auth/sign-up/verify-email" and matched) or parts.path.rstrip("/").rsplit("/", 1)[-1] in {"VerifyEmailValidationCode", "ValidateEmailValidationCode"}:
                        otp_request_started = otp_submitted = True
                        update("running", "code_submitted", "浏览器已提交验码请求；等待下一步，不重复点击确认或重发")
                    if native and parts.path == "/api/auth/sign-up/create-account" and matched:
                        candidate_was_submitted = request.post_data_json.get("password") == record["private"]["password"]
                        profile_submitted = True
                        update("running", "profile_submit", "浏览器已提交原生建号请求；等待服务端确认，不重提", profile_submitted=True, password_confirmed=False)
                    elif parts.path.endswith("/CreateUserAndSession") and not profile_submitted:
                        profile_submitted = True
                        update("running", "profile_submit", "检测到人工提交建号；尚未确认密码内容，不记录为已知密码", profile_submitted=True, password_confirmed=False)
                page.on("request", observe_request)
                update("running", "open", "已打开独立的普通浏览器；人机验证请在浏览器中人工完成")
                page.goto(SIGNUP_URL, wait_until="load", timeout=45000)
                deadline = time.monotonic() + 600
                while time.monotonic() < deadline:
                    if signals.stop.is_set():
                        raise GrokBrowserError("用户已停止本邮箱任务", reason="user_stop")
                    if page.is_closed():
                        raise GrokBrowserError("注册浏览器已关闭", reason="browser_closed")
                    while pending_auth_success:
                        response = pending_auth_success.pop(0)
                        path = urlsplit(response.url).path
                        try:
                            payload = response.json()
                        except Exception:
                            continue
                        if not isinstance(payload, dict): continue
                        if path == "/api/auth/send-verification-code" and request_email_matches(response.request, record["email"]):
                            send_accepted = payload.get("ok") is True
                            if send_accepted:
                                update("running", "email_send", "Grok原生发码接口已确认接收请求；等待邮件到达，不重发", email_send_accepted=True)
                            else:
                                manual_hold, hold_status = True, response.status
                                signals.resume.clear()
                        session = payload.get("session")
                        identity = isinstance(session, dict) and str(session.get("email") or "").lower() == record["email"].lower() and bool(session.get("userId"))
                        if path == "/api/auth/sign-up/create-account" and request_email_matches(response.request, record["email"]) and identity:
                            created_user_id = session["userId"]
                            confirmed_session_sso = ""
                            update("running", "session_confirm", "Grok原生创建账号接口返回匹配邮箱的会话；等待登录态归属确认", registration_response_confirmed=True)
                        if path == "/api/auth/session" and created_user_id:
                            confirmed_session_sso = ""
                            bound_sso = request_sso(response.request)
                            current_sso = session_cookies(context.cookies(), native=True).get("sso")
                            if not (identity and session.get("userId") == created_user_id and session.get("emailConfirmed") is True
                                    and bound_sso and bound_sso == current_sso):
                                update("manual_required", "identity", "原生会话的邮箱、用户标识或Cookie尚未与本次建号一致；未保存SSO或密码", password_confirmed=False)
                                continue
                            confirmed_session_sso = bound_sso
                            update("running", "session_confirm", "Grok原生登录态已确认邮箱验证状态；密码仅在本次提交且服务端确认存在时留存",
                                   password_confirmed=candidate_was_submitted and session.get("hasPassword") is True)
                    if profile_submitted and created_user_id and confirmed_session_sso:
                        cookies = session_cookies(context.cookies(), native=True)
                        if cookies.get("sso") == confirmed_session_sso:
                            update("running", "save", "Grok原生会话已确认当前邮箱，保存本任务SSO；不把后续跨域同步当作重复建号条件")
                            return cookies
                    while pending_errors:
                        response = pending_errors.pop(0)
                        detail = response_diagnostic(response, sensitive_values=(record["email"], record["private"]["password"], submitted_code, submitted_code.replace("-", "")))
                        update("running", "http_error", diagnostic_message(detail), http_diagnostic=detail)
                        if detail["http_status"] == 429:
                            raise GrokBrowserError("Grok 限流，已停止且不重试", http_status=429)
                        rejected = (interactive_auth_error(response, page) or detail["challenge"]
                                    or (profile_submitted and urlsplit(response.url).path == "/api/auth/session"))
                        if rejected:
                            manual_hold = True
                            hold_status = detail["http_status"]
                            signals.resume.clear()
                    while pending_failures:
                        request = pending_failures.pop(0)
                        failure = request.failure or ""
                        # Never echo a raw browser error, URL, header or request body.
                        kind = failure if failure in {"net::ERR_CONNECTION_RESET", "net::ERR_CONNECTION_CLOSED",
                            "net::ERR_CONNECTION_TIMED_OUT", "net::ERR_TIMED_OUT", "net::ERR_NAME_NOT_RESOLVED",
                            "net::ERR_CERT_AUTHORITY_INVALID", "net::ERR_CERT_DATE_INVALID", "net::ERR_SSL_PROTOCOL_ERROR",
                            "net::ERR_ABORTED", "net::ERR_FAILED"} else "network_error"
                        update("manual_required", "network_error", f"原生认证请求连接未完成：{NATIVE_AUTH_PATHS[urlsplit(request.url).path]} {kind}；结果未确认，不重放")
                        manual_hold, hold_status = True, None
                        signals.resume.clear()
                    if manual_hold:
                        label = f"HTTP {hold_status}" if hold_status is not None else "连接中断"
                        update("manual_required", "access_check", f"官网认证未确认（{label}）：已暂停自动步骤并保留浏览器。请人工查看/处理官网提示，再点“已人工处理，继续”；不自动刷新、重发或换线")
                        if not signals.resume.is_set():
                            page.wait_for_timeout(500)
                            continue
                        signals.resume.clear()
                        email_visible = visible(page, EMAIL) is not None
                        ready = (bool(otp_inputs(page)) or visible(page, PASSWORD) is not None
                                 or (email_visible and not issued) or profile_submitted)
                        if not ready:
                            update("manual_required", "access_check", "当前仍未进入可继续的注册步骤；请在官网人工处理。本程序不会自动再次发码")
                            page.wait_for_timeout(500)
                            continue
                        manual_hold = False
                        next_read = time.monotonic() + OTP_READ_INTERVAL if issued else next_read
                        update("running", "continued", "已收到人工继续确认；不重发验证码，验证页就绪后再等待30秒读取API")
                    if urlsplit(page.url).hostname not in ALLOWED_HOSTS:
                        raise GrokBrowserError("进入第三方页面，已停止且未提交后续信息", reason="third_party")
                    text = page.locator("body").inner_text(timeout=3000)[:30000]
                    if re.search(r"existing account found|account already exists|邮箱已注册|账号已存在", text, re.I):
                        update("already_registered", "existing", "官网提示已有 Grok 账号；未将本次候选保存为密码")
                        return None
                    cookies = session_cookies(context.cookies(), native=native_flow)
                    if profile_submitted and cookies.get("sso"):
                        # Bind the visible identity before accepting an SSO cookie.
                        if not native_flow and identity_matches(text, record["email"]):
                            update("running", "save", "已确认浏览器账号邮箱与当前任务一致，保存 Grok SSO")
                            return cookies
                        if native_flow and not confirmed_session_sso and not created_user_id:
                            # Some create-account responses omit the session.
                            # Read it once through the page itself and bind the
                            # SSO Cookie actually sent on that request.
                            sent_sso = {"value": ""}
                            def capture_session_cookie(request):
                                try:
                                    if urlsplit(request.url).path == "/api/auth/session":
                                        sent_sso["value"] = request_sso(request)
                                except Exception:
                                    pass
                            page.on("request", capture_session_cookie)
                            try:
                                raw = page.evaluate("""async () => {
                                    const r = await fetch('/api/auth/session', {credentials:'include'});
                                    return {status:r.status, body:(await r.text()).slice(0,65536)};
                                }""")
                                payload = json.loads(raw.get('body') or '{}') if isinstance(raw, dict) else {}
                                session = payload.get('session') if isinstance(payload, dict) else None
                                after = session_cookies(context.cookies(), native=True)
                                if (isinstance(session, dict)
                                        and str(session.get("email") or "").strip().lower() == record["email"].lower()
                                        and isinstance(session.get("userId"), str) and session["userId"]
                                        and session.get("emailConfirmed") is True
                                        and sent_sso["value"] and after.get("sso") == sent_sso["value"]):
                                    confirmed_session_sso = sent_sso["value"]
                                    update("running", "session_confirm",
                                           "浏览器登录态已确认本任务邮箱与验证状态；保存 Grok SSO",
                                           password_confirmed=candidate_was_submitted and session.get("hasPassword") is True)
                                    return cookies
                            except Exception:
                                pass
                            finally:
                                try:
                                    page.remove_listener("request", capture_session_cookie)
                                except Exception:
                                    pass
                        update("manual_required", "identity", "已取得 SSO，但页面邮箱尚未确认；请在当前浏览器打开账号资料页")
                    password = visible(page, PASSWORD)
                    code_fields = otp_inputs(page)
                    code_input = code_fields[0] if code_fields else None
                    email_input = visible(page, EMAIL)
                    if password is not None:
                        if not profile_filled:
                            given, family = visible(page, GIVEN), visible(page, FAMILY)
                            if given is None or family is None:
                                update("manual_required", "profile", "页面未出现完整的新账号资料表单，请人工确认；未按登录表单提交密码")
                            else:
                                given.fill("User"); family.fill("Account")
                                password.fill(record["private"]["password"])
                                profile_filled = True
                        if profile_filled and not profile_submitted:
                            # Record uncertainty BEFORE the mutation. A timeout must never cause an automatic replay.
                            update("manual_required", "profile", "请在浏览器完成服务条款与人机验证；只提交可用的正常按钮")
                            def mark_profile_submit():
                                nonlocal profile_submitted, candidate_was_submitted
                                profile_submitted = True
                                candidate_was_submitted = password.input_value() == record["private"]["password"]
                                update("running", "profile_submit", "资料已准备，提交一次；后续异常保留为未确认", profile_submitted=True,
                                       password_confirmed=candidate_was_submitted and not native_flow)
                            submit_form(page, password, before_click=mark_profile_submit)
                    elif code_input is not None and not otp_submitted:
                        if not native_flow and email_submitted and not issued:
                            # Legacy form navigation has no native JSON acceptance response.
                            issued = True
                        if not issued:
                            raise GrokBrowserError("未在本任务确认发码，未读取或提交历史验证码")
                        if native_flow and not send_accepted:
                            update("manual_required", "email_send", "原生发码请求尚未确认接收；未读取或提交验证码，请人工查看官网")
                            page.wait_for_timeout(500)
                            continue
                        if not code_page_ready:
                            code_page_ready = True
                            next_read = time.monotonic() + OTP_READ_INTERVAL
                            update("running", "email_code", "已进入邮箱验证码页；页面就绪后再等待30秒读取API，不把提交邮箱等同于发码成功")
                        code = signals.take_code()
                        if not code and mailbox.get("source") == "generic_api" and attempts < 3 and time.monotonic() >= next_read:
                            attempts += 1
                            try:
                                code = grok_mail.read_once(mailbox, after_ts=send_started_at or datetime.fromisoformat(record["created_at"]).timestamp(), diagnostic=lambda d: update("running", "email_code",
                                    f"取码API：HTTP {d['http_status']} business_status={d['business_status']} code_shape={d['code_shape']} has_code_time={d['has_code_time']}"))
                                update("running", "email_code", f"第 {attempts}/3 次 API 读取：" + ("取得 Grok 格式验证码（不记录内容）" if code else "无有效 Grok 验证码"))
                            except grok_mail.GrokMailError as exc:
                                if exc.http_status in (401, 403, 429) or not exc.retryable:
                                    raise
                                update("running", "email_code", f"第 {attempts}/3 次 API 读取失败；未切换线路或重发")
                            next_read = time.monotonic() + OTP_READ_INTERVAL
                        if code:
                            submitted_code = code
                            otp_submitted = True
                            chars = code.replace("-", "")
                            if len(code_fields) == 6:
                                for i, char in enumerate(chars):
                                    code_fields[i].fill(char)
                            else:
                                code_input.fill(chars)
                            # Some forms verify on the final character. Let that native request
                            # dispatch before deciding whether an explicit submit is necessary.
                            page.wait_for_timeout(100)
                            if not otp_request_started and code_input.is_visible():
                                submit_form(page, code_input)
                            update("manual_required", "code_submitted", "验证码已填写一次；如有错误请人工处理，不重复发码")
                        else:
                            if mailbox.get("source") == "generic_api" and attempts >= 3:
                                raise GrokBrowserError("验证码未获取", reason="mail_timeout")
                            update("manual_required", "email_code", "等待 Grok 邮件码；最多读取3轮，每轮间隔30秒，也可手动输入当前Grok邮件的六位验证码")
                    elif email_input is not None and not issued and not email_submitted:
                        email_input.fill(record["email"])
                        def mark_email_submit():
                            nonlocal email_submitted, send_started_at
                            email_submitted = True
                            send_started_at = time.time()
                            update("running", "email_submit", "提交邮箱表单一次；等待真实发码请求与验证码页，不把按钮点击当作发码成功")
                        if not submit_form(page, email_input, before_click=mark_email_submit):
                            update("manual_required", "email", "请在浏览器完成页面验证，使正常发码按钮可用")
                    elif not issued and not email_submitted and not profile_filled:
                        button = signup_entry(page)
                        if button is not None:
                            # The homepage "注册" anchor normally navigates to
                            # accounts.x.ai, which is blocked here. Invoke the
                            # page's own client-side handler so the in-page auth
                            # dialog opens instead of leaving grok.com.
                            try:
                                button.evaluate("el => el.click()")
                            except Exception:
                                button.click(timeout=5000)
                            page.wait_for_timeout(1500)
                        else:
                            update("manual_required", "open", "请在浏览器选择使用邮箱注册并完成页面要求；不自动处理人机挑战")
                    page.wait_for_timeout(500)
                raise GrokBrowserError("等待浏览器或人工操作超过10分钟，已停止；不自动重试", reason="timeout")
            finally:
                browser.close()
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            pass
