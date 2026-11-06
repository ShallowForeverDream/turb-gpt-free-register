# -*- coding: utf-8 -*-
"""
通用 API 取码邮箱客户端。

邮箱池导入格式：
    email----code_url

注册时领取 email；取码时直接 GET code_url，并从响应中提取 6 位验证码。
对仅返回验证码数值的接口，先保存发码前快照，等待 60 秒后排除旧码。
快照差分只确认新增候选，不保证邮件归属；带邮件时间或 ID 的来源继续优先校验元数据。
例外：ICAPI 与 SMSBower 签名接口按各自契约直接读取，无基线，30秒间隔，最多3轮。
"""
import json
import logging
import re
import time
import base64
import html as html_lib
import hashlib
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse

import requests
from core.mail_traffic import track_mail_session
from core.import_formats import normalize_generic_api_url
from core.icapi_mailbox import is_viewer_url, latest_code as _mailbox_latest_code, MailboxError
from core.otp_freshness import (MailBaseline, OtpFreshnessError, new_mail_baseline,
                                new_code_candidates, verify_mail_freshness, parse_mail_time)

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード")
_CODE_FIELD_KEYS = (
    "code", "otp", "verification_code", "verificationCode", "email_code", "emailCode",
)
_MAIL_BODY_KEYS = (
    "subject", "text", "textBody", "bodyText", "bodyPreview", "body", "content", "html", "htmlBody",
)
_MAIL_TIME_KEYS = (
    "time", "date", "received_at", "receivedAt", "created_at", "createdAt", "timestamp",
    "code_time", "codeTime",
)
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_YANGYANG_MESSAGES_RE = re.compile(r"/messages/([^/]+)/([^/?#]+)", re.IGNORECASE)
_PUBLIC_INBOX_LINK_RE = re.compile(r"^/i/([^/?#]+)/*$", re.IGNORECASE)
_PUBLIC_INBOX_API_RE = re.compile(
    r"^/api/public/inboxes/([^/?#]+)/latest-code/*$", re.IGNORECASE,
)
_YANGYANG_OPENAI_SUBJECT_HINTS = (
    "temporary chatgpt",
    "chatgpt verification code",
    "chatgpt login code",
    "临时 chatgpt",
    "chatgpt 登录代码",
    "chatgpt 验证码",
    "一時的な認証コード",
    "一時ログインコード",
)


class GenericApiMailError(RuntimeError):
    """通用 API 取码邮箱错误。"""


ICAPI_OTP_DELAY_SECONDS = 30
ICAPI_OTP_MAX_ATTEMPTS = 3
ICAPI_OTP_POLICY = "direct_api_30s_x3_no_baseline_no_resend"
SIGNATURE_OTP_POLICY = "smsbower_signature_30s_x3_shared_read_validate_budget"


def is_direct_icapi_url(url: str) -> bool:
    """Only this supplied API contract opts out of generic snapshot filtering."""
    try:
        parsed = urlparse(str(url or ""))
        return (parsed.scheme == "https" and parsed.hostname == "icapi.oaibx.com"
                and parsed.path.rstrip("/") == "/api" and parsed.port in (None, 443)
                and not parsed.username and not parsed.password)
    except (TypeError, ValueError):
        return False


def uses_direct_icapi_polling(email: str) -> bool:
    account = get_account_context(email)
    return account is not None and (is_direct_icapi_url(account.code_url) or is_viewer_url(account.code_url))


def is_smsbower_signature_url(url: str) -> bool:
    try:
        from urllib.parse import parse_qsl
        parsed = urlparse(str(url or ""))
        signatures = [v for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k == "s"]
        return (parsed.scheme == "https" and parsed.hostname == "smsbower.page"
                and parsed.path == "/api/mail/getCodeBySignature" and parsed.port in (None, 443)
                and not parsed.username and not parsed.password
                and len(signatures) == 1 and bool(signatures[0]))
    except (TypeError, ValueError):
        return False


def uses_smsbower_signature_polling(email: str) -> bool:
    account = get_account_context(email)
    return account is not None and is_smsbower_signature_url(account.code_url)


def query_latest_otp(email: str) -> str:
    """Explicit UI query: one read of existing ICAPI/signature data, never a send."""
    from core import db
    row = db.get_generic_api_email_by_email(email)
    if not row or not row.get("code_url"):
        raise GenericApiMailError("未找到该邮箱已导入的取码 API 配置")
    url = row["code_url"]
    if is_viewer_url(url):
        try:
            return _mailbox_latest_code(email, url, platform="gpt")
        except MailboxError as exc:
            raise GenericApiMailError(str(exc)) from None
    icapi = is_direct_icapi_url(url)
    signature = is_smsbower_signature_url(url)
    if not icapi and not signature:
        return fetch_latest_otp(email, after_ts=time.time()-900, max_wait=2, poll_interval=1, settle_seconds=0)
    http = _new_http_session(str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip())
    try:
        response = http.get(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"},
                            timeout=20, verify=True, allow_redirects=False)
        if response.status_code != 200:
            raise GenericApiMailError(f"取码接口返回 HTTP {response.status_code}，未重试或切换路线")
        payload = response.json()
        status = payload.get("code" if icapi else "status") if isinstance(payload, dict) else None
        if not (type(status) is int and status == 1 or type(status) is str and status == "1"):
            raise GenericApiMailError("取码 API 暂无可用验证码")
        data = payload.get("data") if icapi else payload
        code = str(data.get("code") or "").strip() if isinstance(data, dict) else ""
        if not re.fullmatch(r"[0-9]{6}", code):
            raise GenericApiMailError("取码 API 暂无有效的六位验证码")
        return code
    except (requests.RequestException, ValueError):
        raise GenericApiMailError("取码 API 请求失败或响应无效；未重试，不记录地址及响应") from None
    finally:
        http.close()


def _signature_binding(account) -> str:
    return hashlib.sha256((account.email.lower() + "\0" + account.code_url).encode()).hexdigest()


@dataclass
class SignatureOtpPollState:
    """One verification challenge's budget, shared across reads and invalid submissions."""
    binding: str
    ready_at: float | None = None
    attempts: int = 0
    next_read_at: float | None = None

    @property
    def can_retry(self) -> bool:
        return self.attempts < 3

    def defer_after_rejection(self) -> None:
        # The 30s interval starts at the rejection, not the earlier API read.
        self.next_read_at = time.monotonic() + 30


def create_signature_poll_state(email: str, *, ready_at=None) -> SignatureOtpPollState | None:
    account = get_account_context(email)
    if account is None or not is_smsbower_signature_url(account.code_url):
        return None
    return SignatureOtpPollState(binding=_signature_binding(account), ready_at=ready_at)


def _fetch_signature_otp(account, *, ready_at=None, poll_state=None) -> str:
    from core.registration_service import check_stop_requested
    state = poll_state or SignatureOtpPollState(_signature_binding(account), ready_at)
    if not isinstance(state, SignatureOtpPollState) or state.binding != _signature_binding(account):
        raise GenericApiMailError("签名取码上下文不匹配，已停止")
    proxy = str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip()
    http = _new_http_session(proxy)
    try:
        while state.can_retry:
            if state.next_read_at is None:
                elapsed = max(0, time.time() - state.ready_at) if state.ready_at is not None else 0
                delay = max(0, 30 - elapsed)
            else:
                delay = max(0, state.next_read_at - time.monotonic())
            logger.info("[SMSBower签名API] 等待后读取验证码（第 %s/3 轮，间隔30s；不设基线、不重发）",
                        state.attempts + 1)
            _wait_icapi_delay(delay)
            check_stop_requested()
            state.attempts += 1
            try:
                response = http.get(account.code_url, headers={"Accept": "application/json", "Cache-Control": "no-cache"},
                                    timeout=20, verify=True, allow_redirects=False)
                if response.status_code in (401, 403, 429):
                    raise GenericApiMailError(f"签名取码接口拒绝请求（HTTP {response.status_code}），已停止")
                payload = response.json() if response.status_code == 200 else None
                if isinstance(payload, dict):
                    status = payload.get("status")
                    ok = type(status) is int and status == 1 or type(status) is str and status == "1"
                    code = str(payload.get("code") or "").strip()
                    # all_codes is history, not an ordering or freshness contract.
                    if ok and re.fullmatch(r"[0-9]{6}", code):
                        logger.info("[SMSBower签名API] 已取得六位验证码，交由当前会话验证（不记录验证码）")
                        return code
                    safe_status = str(status) if type(status) in (int, str) and status in (0, 1, "0", "1") else "other"
                    logger.info("[SMSBower签名API] HTTP=%s，业务状态=%s，验证码字段=%s（不记录响应正文）",
                                response.status_code, safe_status, "empty" if not code else "invalid")
                else:
                    logger.info("[SMSBower签名API] HTTP=%s，响应结构无效", response.status_code)
            except GenericApiMailError:
                raise
            except (requests.RequestException, ValueError):
                logger.warning("[SMSBower签名API] 本轮请求失败或 JSON 无效（不记录地址及响应）")
            finally:
                state.next_read_at = time.monotonic() + 30
        raise GenericApiMailError("验证码未获取")
    finally:
        try:
            http.close()
        except Exception:
            pass


def _wait_icapi_delay(seconds: float) -> None:
    from core.registration_service import check_stop_requested
    deadline = time.monotonic() + max(0, seconds)
    while True:
        check_stop_requested()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.25, remaining))


def _fetch_direct_icapi_otp(account, *, ready_at=None, exclude_codes=None, after_ts=None) -> str:
    """Wait 30s after the ready page, then perform at most three direct GETs.

    No baseline, timestamp gate, settle delay, cache-busting URL rewrite or
    automatic proxy fallback. Never echo the token-bearing URL or returned OTP.
    """
    from core.registration_service import check_stop_requested
    excluded = set(exclude_codes or [])
    proxy_url = str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip()
    http = _new_http_session(proxy_url)
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    # time.time is the API boundary's page-ready anchor; subsequent scheduling
    # is monotonic and cannot issue another request before the 30s delay.
    initial_delay = ICAPI_OTP_DELAY_SECONDS
    if ready_at is not None:
        initial_delay = max(0, ICAPI_OTP_DELAY_SECONDS - max(0, time.time() - ready_at))
    # ICAPI's mailbox page has no pre-send baseline request, but its messages
    # carry a received_at time.  Use the caller's send anchor with a 90s
    # tolerance so a historical code cannot be mistaken for this challenge;
    # the tolerance covers ordinary clock skew without requiring a baseline.
    fresh_after = None
    if after_ts is not None:
        try:
            fresh_after = max(0.0, float(after_ts) - 90.0)
        except (TypeError, ValueError):
            fresh_after = None
    try:
        for attempt in range(1, ICAPI_OTP_MAX_ATTEMPTS + 1):
            logger.info("[ICAPI] 页面已就绪；等待后读取验证码（第 %s/%s 次，间隔 %ss；不设基线、不重发）",
                        attempt, ICAPI_OTP_MAX_ATTEMPTS, ICAPI_OTP_DELAY_SECONDS)
            _wait_icapi_delay(initial_delay if attempt == 1 else ICAPI_OTP_DELAY_SECONDS)
            check_stop_requested()
            try:
                if is_viewer_url(account.code_url):
                    # Direct ICAPI has no baseline by design.  The mailbox page
                    # may show a newer "New sign-in" notification after the OTP
                    # message; latest_code skips that notification and returns
                    # the first actual code.  Do not pass the page-ready anchor:
                    # clock skew between the mail host and this process would
                    # otherwise discard the very OTP that triggered the read.
                    code = _mailbox_latest_code(account.email, account.code_url, platform="gpt", http=http,
                                                after_ts=fresh_after, exclude_codes=excluded)
                    if code:
                        logger.info("[ICAPI邮件页面] 已匹配本邮箱最新 OpenAI 邮件（不记录验证码）")
                        return code
                    logger.info("[ICAPI邮件页面] 本次没有符合平台/时间的验证码邮件，不重发")
                    continue
                response = http.get(account.code_url, headers=headers, timeout=20,
                                    verify=True, allow_redirects=False)
                if response.status_code in (401, 403, 429):
                    raise GenericApiMailError(f"取码接口拒绝请求（HTTP {response.status_code}），已停止")
                payload = response.json() if response.status_code == 200 else None
                if isinstance(payload, dict):
                    ok = (type(payload.get("code")) is int and payload["code"] == 1
                          or payload.get("code") == "1")
                    data = payload.get("data")
                    code = str(data.get("code") or "").strip() if isinstance(data, dict) else ""
                    if ok and re.fullmatch(r"[0-9]{6}", code) and code not in excluded:
                        logger.info("[ICAPI] 已取得六位验证码，交由当前会话验证（不记录验证码）")
                        return code
                    business_code = payload.get("code")
                    safe_status = str(business_code) if type(business_code) in (int, str) and business_code in (0, 1, "0", "1") else "other"
                    logger.info("[ICAPI] HTTP=%s，业务状态=%s，验证码字段=%s（不记录响应正文）",
                                response.status_code, safe_status,
                                "empty" if not code else "excluded" if code in excluded else "invalid")
                else:
                    logger.info("[ICAPI] HTTP=%s，响应结构无效（不记录响应正文）", response.status_code)
            except GenericApiMailError:
                raise
            except MailboxError as exc:
                if exc.http_status in (401, 403, 429) or not exc.retryable:
                    raise GenericApiMailError(str(exc)) from None
                logger.warning("[ICAPI邮件页面] 本次读取失败，未切换线路或重发")
            except requests.RequestException as exc:
                # Never print the exception's credential-bearing URL.
                logger.warning("[ICAPI] 本次 API 请求失败，类型=%s，未取得验证码（不记录地址或响应）", type(exc).__name__)
            except ValueError:
                logger.warning("[ICAPI] 本次 API 响应 JSON 无效，未取得验证码（不记录响应正文）")
            if attempt < ICAPI_OTP_MAX_ATTEMPTS:
                logger.info("[ICAPI] 本次未取得有效验证码，再等待 %ss", ICAPI_OTP_DELAY_SECONDS)
        raise GenericApiMailError("验证码未获取")
    finally:
        try:
            http.close()
        except Exception:
            pass


def _redact_proxy_url(proxy_url: str) -> str:
    """日志中保留代理地址和协议，但隐藏认证信息。"""
    raw = str(proxy_url or "").strip()
    if not raw:
        return "direct"
    try:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return "configured-proxy"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***@" if parsed.username or parsed.password else ""
        return f"{parsed.scheme}://{auth}{host}{port}"
    except Exception:
        return "configured-proxy"


def _new_http_session(proxy_url: str = "") -> requests.Session:
    """创建不继承系统代理的取码会话；传入代理时 HTTP/HTTPS 均走该代理。"""
    session = requests.Session()
    session.trust_env = False
    proxy_url = str(proxy_url or "").strip()
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    return track_mail_session(session)


def _cache_busted_url(url: str, attempt: int) -> str:
    """给取码接口加缓存破坏参数，避免 CDN/反向代理一直返回上一封验证码。"""
    try:
        parsed = urlparse(str(url))
        suffix = f"_otp_poll={int(time.time() * 1000)}-{attempt}"
        query = parsed.query + ("&" if parsed.query else "") + suffix
        return urlunparse(parsed._replace(query=query))
    except Exception:
        return url


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str

    def __post_init__(self):
        self.code_url = normalize_generic_api_url(self.code_url)


def _public_inbox_latest_code_url(code_url: str) -> str | None:
    """把公开收件链接 /i/{token} 转成 /api/public/inboxes/{token}/latest-code。"""
    try:
        parsed = urlparse(str(code_url or "").strip())
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    match = _PUBLIC_INBOX_LINK_RE.match(parsed.path or "")
    if not match:
        # 也接受用户直接导入 latest-code API 地址。
        match = _PUBLIC_INBOX_API_RE.match(parsed.path or "")
    if not match:
        return None
    token = unquote(match.group(1)).strip()
    if not token or "/" in token:
        return None
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
    return f"{origin}/api/public/inboxes/{quote(token, safe='')}/latest-code"


def _public_inbox_page_api_url(code_url: str) -> str | None:
    """返回公开收件页面实际使用的收件箱列表 API。"""
    latest_url = _public_inbox_latest_code_url(code_url)
    if not latest_url:
        return None
    return latest_url.rsplit("/latest-code", 1)[0]


def _fetch_public_inbox_page_otp(
    session: requests.Session,
    api_url: str,
    email: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """按 /i/{token} 页面使用的 inbox API，从最新邮件预览/正文提取验证码。"""
    resp = session.get(
        api_url,
        headers={**headers, "Accept": "application/json"},
        timeout=20,
        verify=True,
    )
    if resp.status_code != 200:
        logger.debug("[GenericAPI] public inbox 页面 API HTTP %s", resp.status_code)
        return None
    try:
        data = resp.json()
    except Exception:
        try:
            data = json.loads(resp.text or "")
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    mailbox = data.get("mailbox") or {}
    actual_email = str(mailbox.get("address") if isinstance(mailbox, dict) else mailbox or "").strip()
    if actual_email and actual_email.lower() != email.lower():
        raise GenericApiMailError(
            f"公开收件链接邮箱不匹配: expected={email}, actual={actual_email}"
        )
    items = [x for x in (data.get("messages") or []) if isinstance(x, dict)]
    items.sort(
        key=lambda x: _parse_generic_api_ts(x.get("receivedAt") or x.get("received_at")) or 0,
        reverse=True,
    )
    origin = api_url.split("/api/public/inboxes/", 1)[0]
    token_path = api_url.split("/api/public/inboxes/", 1)[1].split("?", 1)[0].strip("/")
    for item in items:
        received_at = item.get("receivedAt") or item.get("received_at")
        msg_ts = _parse_generic_api_ts(received_at)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            continue
        raw_codes = item.get("verificationCodes") or item.get("verification_codes") or []
        code = next(
            (m.group(1) for value in raw_codes if (m := _CODE_REGEX.search(str(value)))),
            None,
        )
        subject = str(item.get("subject") or "")
        preview = str(item.get("preview") or "")
        if not code:
            code = _extract_yangyang_openai_code(subject, preview)
        msg_id = str(item.get("id") or "").strip()
        # 页面列表预览仍未抽到时，读取页面点击邮件时使用的详情 API。
        if not code and msg_id:
            detail_url = (
                f"{origin}/api/public/inboxes/{quote(unquote(token_path), safe='')}"
                f"/messages/{quote(msg_id, safe='')}"
            )
            try:
                detail_resp = session.get(
                    detail_url,
                    headers={**headers, "Accept": "application/json"},
                    timeout=20,
                    verify=True,
                )
                if detail_resp.status_code == 200:
                    detail = detail_resp.json()
                    detail_text = "\n".join([
                        str(detail.get("subject") or subject),
                        str(detail.get("preview") or preview),
                        str(detail.get("textBody") or ""),
                        str(detail.get("htmlBody") or ""),
                    ])
                    code = _extract_yangyang_openai_code(subject, detail_text)
            except Exception as exc:
                logger.debug("[GenericAPI] public inbox 邮件详情读取失败: %s", type(exc).__name__)
        if code:
            return code, {
                "source": "public_inbox_page",
                "mail_id": msg_id,
                "received_at": received_at,
                "msg_ts": msg_ts,
                "subject": subject,
                "from": item.get("fromAddress") or item.get("sender"),
            }
    return None


def _flatten_json(obj) -> str:
    parts: list[str] = []
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


def _decode_data_uri(text: str) -> str:
    """把 data:text/html;base64,... 正文解码成可抽取 OTP 的 HTML/文本。"""
    if not isinstance(text, str):
        return ""
    if not text.startswith("data:"):
        return text
    try:
        _meta, payload = text.split(",", 1)
    except ValueError:
        return text
    if ";base64" in _meta.lower():
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return text
    try:
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception:
        return text


def _extract_code(text: str) -> str | None:
    """从纯文本/HTML/JSON 文本中提取 6 位 OTP。"""
    if not text:
        return None

    # 兼容 JSON：优先把所有 value 拉平再抽取。
    candidates_text = [_decode_data_uri(text), text]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _decode_data_uri(_flatten_json(parsed)))
    except Exception:
        pass

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _extract_yangyang_openai_code(subject: str, body: str) -> str | None:
    """
    yangyang 邮件详情里 OpenAI 模板常混入多个 6 位数字：
    - 202123 / 353740 这类 CSS/模板数字
    - 真正 OTP 在 “Your code is / code:” 附近，通常是正文最后一个业务 6 位数
    所以不能直接复用通用 _extract_code 的“第一个上下文命中”。
    """
    body = _decode_data_uri(body or "")
    subject_l = (subject or "").lower()
    text = "\n".join([subject or "", body])

    # 去掉 style/script，减少 CSS 颜色、宽高等 6 位数字干扰。
    clean = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script[^>]*>.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"#[0-9a-fA-F]{6}\b", " ", clean)
    clean = re.sub(r"(?:color|background|border|width|height|font-size|line-height)\s*:\s*[^;\"']+", " ", clean, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    codes = _CODE_REGEX.findall(clean)
    if not codes:
        return None

    # 过滤已知模板噪声；保留其它 6 位候选。
    noise = {"000000", "202123", "353740"}
    candidates = [c for c in codes if c not in noise]
    if not candidates:
        candidates = codes

    lower = clean.lower()
    patterns = (
        r"(?:code is|code:|verification code is|login code is|your code is)\D{0,80}(\d{6})",
        r"(?:验证码|驗證碼|登录代码|登入代碼|確認コード|認証コード|ログインコード)\D{0,80}(\d{6})",
        r"(\d{6})\D{0,80}(?:code|验证码|驗證碼|確認コード|認証コード)",
    )
    for pat in patterns:
        matches = re.findall(pat, clean, flags=re.IGNORECASE)
        matches = [m for m in matches if m not in noise]
        if matches:
            return matches[-1]

    # OpenAI 临时代码邮件：清理噪声后最后一个业务 6 位数最稳定。
    if any(h in subject_l for h in _YANGYANG_OPENAI_SUBJECT_HINTS) or "openai" in lower or "chatgpt" in lower:
        return candidates[-1]

    return _extract_code(clean)


def _parse_yangyang_code_url(code_url: str) -> tuple[str, str, str] | None:
    """
    解析 yangyang.website 这类邮箱页面：
        /messages/{token}/{email}
    返回 (origin, token, email)。
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    m = _YANGYANG_MESSAGES_RE.search(parsed.path or "")
    if not m:
        return None
    origin = urlunparse((parsed.scheme or "http", parsed.netloc, "", "", "", ""))
    token = unquote(m.group(1))
    email = unquote(m.group(2))
    if not origin or not token or not email:
        return None
    return origin.rstrip("/"), token, email


def _parse_yangyang_ts(value: str | None) -> float | None:
    if not value:
        return None
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _parse_generic_api_ts(value) -> float | None:
    """解析通用 API 返回的时间字段，兼容 ISO8601/Z 和常见本地时间格式。"""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # 数字时间戳：秒 / 毫秒
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        try:
            ts = float(raw)
            return ts / 1000.0 if ts > 10_000_000_000 else ts
        except Exception:
            return None
    # ISO8601: 2026-08-05T01:10:17.000Z
    try:
        iso = raw
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        pass
    # 常见字符串格式
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _structured_mail_view(data: dict) -> dict:
    """展开把邮件字段包在 ``data`` 里的 API 响应。

    有些取码接口返回 ``{"code": 0, "msg": "...", "data": {"code": "123456",
    "code_time": "..."}}``。外层 ``code`` 是业务状态码，内层才是验证码；
    不能把外层 0 当验证码，也不能把任意 ``data.order_id`` 当邮件。
    """
    if not isinstance(data, dict):
        return {}
    inner = data.get("data")
    if not isinstance(inner, dict):
        return data
    mail_keys = (*_CODE_FIELD_KEYS, *_MAIL_BODY_KEYS, *_MAIL_TIME_KEYS, "expired_date")
    if not any(key in inner for key in mail_keys):
        return data
    view = dict(inner)
    for key in ("from", "fromAddress", "sender", "mailbox", "email", "messageId",
                "message_id", "mailId", "mail_id", "all_codes"):
        if key not in view and data.get(key) is not None:
            view[key] = data[key]
    # 外层状态仍用于拒绝业务错误；不能让内层字段掩盖顶层 error/success/status。
    for key in ("error", "success", "status"):
        if key in data and key not in view:
            view[key] = data[key]
    return view


def _is_nested_code_payload(data: dict) -> bool:
    """判断响应是否是 ``data.code`` 型验证码接口（用于建立空码基线）。"""
    if not isinstance(data, dict):
        return False
    inner = data.get("data")
    return isinstance(inner, dict) and any(
        key in inner for key in ("code", "code_time", "codeTime", "expired_date")
    )


def _nested_payload_failed(data: dict) -> bool:
    """``data.code`` 型接口的外层 code 是状态码：非 0 表示业务失败。"""
    if not _is_nested_code_payload(data):
        return False
    status = data.get("code")
    if isinstance(status, bool) or status is None or status == "":
        return False
    if isinstance(status, (int, float)):
        return status != 0
    return bool(re.fullmatch(r"[+-]?\d+(?:\.0+)?", str(status).strip())) and float(status) != 0


def _extract_structured_api_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """
    兼容 newzoe 这类直接返回 JSON 的取码接口：
      {"code":"784207","from":"...","subject":"Your temporary ChatGPT login code","time":"2026-08-05T01:10:17.000Z"}

    也兼容把邮件字段包在 data 里的接口：
      {"code":0,"msg":"...","data":{"code":"784207","code_time":"..."}}

    如果响应里有 time/date/received_at，会按 after_ts 过滤旧码，避免拿到上一次缓存验证码。
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    if data.get("error") or data.get("success") in (False, 0, "false", "False") or data.get("status") is False:
        return None
    if str(data.get("status") or "").lower() in {"error", "failed", "failure", "false"}:
        return None
    if _nested_payload_failed(data):
        return None

    view = _structured_mail_view(data)

    # 只读明确的验证码字段和邮件正文，不扫描订单号、错误信息等任意值。
    raw_code = next((view[key] for key in _CODE_FIELD_KEYS
                     if view.get(key) is not None and view.get(key) != ""), None)
    code = None
    if raw_code is not None:
        m = re.fullmatch(r"[0-9]{6}", str(raw_code).strip())
        if m:
            code = m.group(0)
    if not code:
        body = "\n".join(view[k] for k in _MAIL_BODY_KEYS if isinstance(view.get(k), str))
        if any(word in body.lower() for word in _CONTEXT_WORDS):
            code = _extract_code(body)
    if not code or re.fullmatch(r"[0-9]{6}", code) is None:
        return None

    ts_raw = next((view[key] for key in _MAIL_TIME_KEYS
                   if view.get(key) is not None and view.get(key) != ""), None)
    msg_ts = _parse_generic_api_ts(ts_raw)
    if after_ts is not None and ts_raw is not None and msg_ts is None:
        return None
    if after_ts is not None and msg_ts is not None and msg_ts < after_ts:
        logger.debug("[GenericAPI] structured API 跳过早于本次等待基准的邮件")
        return None

    return code, {
        "source": "structured_api",
        "received_at": ts_raw,
        "msg_ts": msg_ts,
        "subject": view.get("subject"),
        "from": view.get("from") or view.get("fromAddress") or view.get("sender"),
        **_mail_identity(view),
    }


def _mail_identity(data: dict) -> dict:
    mail_id = next((data[k] for k in ("messageId", "message_id", "mailId", "mail_id")
                    if data.get(k) is not None and data.get(k) != ""), "")
    if isinstance(mail_id, bool) or not isinstance(mail_id, (str, int)):
        mail_id = ""
    recipient = data.get("mailbox") or data.get("email") or ""
    if isinstance(recipient, dict):
        recipient = recipient.get("address") or ""
    raw_history = data.get("all_codes")
    if raw_history is not None and (not isinstance(raw_history, list) or len(raw_history) > 100):
        raise OtpFreshnessError("code_history_invalid")
    if isinstance(raw_history, list) and any(
        isinstance(value, bool) or not isinstance(value, (str, int))
        or re.fullmatch(r"[0-9]{6}", str(value).strip()) is None for value in raw_history
    ):
        raise OtpFreshnessError("code_history_invalid")
    code_history = tuple(raw_history) if isinstance(raw_history, list) else None
    return {"mail_id": str(mail_id).strip(), "recipient": str(recipient).strip(),
            "code_history": code_history}


def capture_mail_baseline(email: str) -> MailBaseline | None:
    """Read a single pre-send snapshot; no sending, login or mailbox claiming."""
    account = get_account_context(email)
    if account is None:
        raise OtpFreshnessError("snapshot_mailbox_missing")
    if is_direct_icapi_url(account.code_url) or is_viewer_url(account.code_url) or is_smsbower_signature_url(account.code_url):
        # User-selected fixed API polling policy: do not make a pre-send GET.
        return None
    if _public_inbox_page_api_url(account.code_url) or _parse_yangyang_code_url(account.code_url):
        # These adapters read a page/list plus message details, not the standard
        # JSON endpoint. Do not mistake a page fetch for an ID snapshot.
        logger.info("[GenericAPI] 页面型来源未建立邮件 ID 基线；后续只允许凭收件时间确认")
        return new_mail_baseline(email=email, url=account.code_url, observed_at=time.time(),
                                 mail_ids=None, codes=None)
    ids = None
    codes = None
    session = _new_http_session(str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip())
    try:
        response = session.get(_cache_busted_url(account.code_url, 0), timeout=2, verify=True)
        if response.status_code != 200:
            logger.warning("[GenericAPI] 发码前基线 HTTP 状态=%s；未继续后续步骤", response.status_code)
            raise OtpFreshnessError("snapshot_http_error")
        data = response.json()
        if (isinstance(data, dict) and not data.get("error")
                and data.get("success") not in (False, 0, "false", "False")
                and data.get("status") is not False
                and str(data.get("status") or "").lower() not in {"error", "failed", "failure", "false"}
                and not _nested_payload_failed(data)):
            view = _structured_mail_view(data)
            identity = _mail_identity(view)
            if identity["recipient"] and identity["recipient"].lower() != email.strip().lower():
                raise OtpFreshnessError("recipient_mismatch")
            if identity["mail_id"]:
                ids = frozenset({identity["mail_id"]})
            elif (any(k in view for k in ("messageId", "message_id", "mailId", "mail_id"))
                  and all(view.get(k) is None or view.get(k) == "" for k in ("messageId", "message_id", "mailId", "mail_id"))) and not any(
                view.get(k) for k in _CODE_FIELD_KEYS
            ):
                ids = frozenset()
            codes = identity["code_history"]
            explicit = next((view[k] for k in _CODE_FIELD_KEYS
                             if view.get(k) is not None and view.get(k) != ""), None)
            if codes is not None:
                codes = tuple(codes) + ((explicit,) if explicit is not None else ())
            elif explicit is not None:
                codes = (explicit,)
            elif _is_nested_code_payload(data):
                # data.code 型接口在“暂无验证码”时返回空字符串。这是一个
                # 已确认的空基线，不是未知响应；后续只接受变化后的新码。
                codes = ()
            raw_stamp = next((view[k] for k in _MAIL_TIME_KEYS
                              if view.get(k) is not None and view.get(k) != ""), None)
            stamp, _ = parse_mail_time(raw_stamp)
            if ids is None and stamp is None and codes is None:
                raise OtpFreshnessError("missing_metadata")
        else:
            raise OtpFreshnessError("snapshot_invalid_response")
    except OtpFreshnessError:
        raise
    except requests.exceptions.SSLError:
        raise OtpFreshnessError("snapshot_tls_error") from None
    except requests.exceptions.Timeout:
        raise OtpFreshnessError("snapshot_timeout") from None
    except requests.exceptions.RequestException:
        raise OtpFreshnessError("snapshot_network_error") from None
    except Exception as exc:
        logger.warning("[GenericAPI] 发码前基线响应不可用：%s；未继续后续步骤", type(exc).__name__)
        raise OtpFreshnessError("snapshot_invalid_response") from None
    finally:
        try:
            session.close()
        except Exception as exc:
            logger.warning("[GenericAPI] 基线会话清理异常：%s；保留原始诊断", type(exc).__name__)
    return new_mail_baseline(email=email, url=account.code_url, observed_at=time.time(),
                             mail_ids=ids, codes=codes)


def _fetch_yangyang_otp(
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """从 yangyang 邮箱页面的列表 API + 详情 API 中抽取最新 6 位验证码。"""
    parsed = _parse_yangyang_code_url(code_url)
    if not parsed:
        return None
    origin, token, email = parsed
    token_q = quote(token, safe="")
    email_q = quote(email, safe="@._+-")
    api_url = f"{origin}/api/messages/{token_q}/{email_q}"

    items: list[dict] = []
    cursor: str | None = None
    # 一般第一页足够；保守支持最多翻 5 页。
    for _ in range(5):
        url = api_url if not cursor else f"{api_url}?cursor={quote(str(cursor), safe='')}"
        resp = session.get(url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=True)
        if resp.status_code != 200:
            if resp.status_code == 404:
                # 兼容 mail.ai1998.xyz 这类同样是 /messages/{token}/{email}，
                # 但没有 /api/messages，邮件直接内嵌在 HTML 页面中的实现。
                return _fetch_inline_messages_page_otp(
                    session=session,
                    code_url=code_url,
                    headers=headers,
                    after_ts=after_ts,
                )
            logger.debug("[GenericAPI] yangyang 邮件列表 HTTP %s", resp.status_code)
            return None
        data = resp.json()
        page_items = data.get("items") or []
        if isinstance(page_items, list):
            items.extend([x for x in page_items if isinstance(x, dict)])
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        cursor = str(data.get("next_cursor"))

    # API 默认新邮件在前；再次按时间倒序，尽量取最新验证码。
    items.sort(key=lambda x: _parse_yangyang_ts(x.get("received_at") or x.get("receivedAt")) or 0, reverse=True)
    for item in items:
        msg_ts_raw = item.get("received_at") or item.get("receivedAt")
        msg_ts = _parse_yangyang_ts(msg_ts_raw)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] yangyang 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("id"), msg_ts_raw, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        msg_id = item.get("id")
        if not msg_id:
            continue
        detail_url = f"{origin}/message/{quote(str(msg_id), safe='')}/{token_q}/{email_q}"
        try:
            detail_resp = session.get(detail_url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=True)
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
        except Exception as exc:
            logger.debug("[GenericAPI] yangyang 邮件详情读取失败: %s", type(exc).__name__)
            continue

        raw_body = str(detail.get("body") or "")
        body = _decode_data_uri(raw_body)
        subject = str(detail.get("subject") or item.get("subject") or "")
        text = "\n".join([
            subject,
            str(detail.get("fromAddress") or item.get("from_address") or ""),
            str(detail.get("receivedAt") or item.get("received_at") or ""),
            body,
        ])
        code = _extract_yangyang_openai_code(subject, body)
        if code:
            logger.info("[GenericAPI] yangyang 页面发现邮件候选，尚待新旧校验")
            return code, {
                "mail_id": msg_id,
                "received_at": detail.get("receivedAt") or item.get("received_at"),
                "subject": subject,
                "msg_ts": msg_ts,
            }
    return None


def _strip_html_fragment(value: str) -> str:
    value = str(value or "")
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s+", "\n", value)
    return value.strip()


def _fetch_inline_messages_page_otp(
    *,
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """解析无 JSON API、直接把邮件卡片渲染在 HTML 里的 /messages 页面。"""
    try:
        resp = session.get(
            code_url,
            headers={**headers, "Accept": "text/html,application/xhtml+xml,text/plain,*/*"},
            timeout=20,
            verify=True,
        )
        if resp.status_code != 200:
            logger.debug("[GenericAPI] inline messages 页面 HTTP %s", resp.status_code)
            return None
        html = resp.text or ""
    except Exception as exc:
        logger.debug("[GenericAPI] inline messages 页面读取失败: %s", type(exc).__name__)
        return None

    cards = re.findall(r"<article\b[^>]*class=[\"'][^\"']*mail-card[^\"']*[\"'][^>]*>(.*?)</article>", html, flags=re.DOTALL | re.IGNORECASE)
    # 没有 article 时退一步按 details 分块，避免 class 名细微变化。
    if not cards:
        cards = re.findall(r"<details\b[^>]*>(.*?)</details>", html, flags=re.DOTALL | re.IGNORECASE)

    items: list[dict] = []
    for idx, card in enumerate(cards):
        subject_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*subject[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        date_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*date[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        from_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*meta[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)
        body_m = re.search(r"<pre\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</pre>", card, flags=re.DOTALL | re.IGNORECASE)
        if not body_m:
            body_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)

        subject = _strip_html_fragment(subject_m.group(1) if subject_m else "")
        received_at = _strip_html_fragment(date_m.group(1) if date_m else "")
        from_addr = _strip_html_fragment(from_m.group(1) if from_m else "")
        body = _strip_html_fragment(body_m.group(1) if body_m else card)
        msg_ts = _parse_yangyang_ts(received_at)
        items.append({
            "mail_id": f"inline-{idx}",
            "subject": subject,
            "received_at": received_at,
            "from": from_addr,
            "body": body,
            "msg_ts": msg_ts or 0.0,
        })

    items.sort(key=lambda x: float(x.get("msg_ts") or 0.0), reverse=True)
    for item in items:
        msg_ts = float(item.get("msg_ts") or 0.0)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] inline messages 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("mail_id"), item.get("received_at"),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        code = _extract_yangyang_openai_code(str(item.get("subject") or ""), str(item.get("body") or ""))
        if code:
            logger.info("[GenericAPI] inline messages 页面发现邮件候选，尚待新旧校验")
            return code, {
                "mail_id": item.get("mail_id"),
                "received_at": item.get("received_at"),
                "subject": item.get("subject"),
                "msg_ts": msg_ts,
            }
    return None


def pick_account() -> GenericApiEmailAccount:
    """直接从 SQLite 邮箱库领取一个可用通用 API 邮箱。"""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"通用 API 邮箱池没有可用账号: {summary}. 请在 WebUI 邮箱池导入：邮箱----取码地址"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] 选中邮箱: {account.email}（DB id={row.get('id')}）")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """从文本文件导入通用 API 邮箱，每行：email----code_url 或 email====code_url。"""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def _fetch_poll_payload(
    *,
    proxy_url: str,
    poll_url: str,
    email: str,
    headers: dict,
    after_ts: float | None,
    is_yangyang: bool,
    public_inbox_api_url: str | None,
):
    """执行单次取码请求，网络路由由调用方指定。"""
    session = _new_http_session(proxy_url)
    yy_result = (
        _fetch_yangyang_otp(session, poll_url, headers, after_ts=after_ts)
        if is_yangyang else None
    )
    public_result = (
        _fetch_public_inbox_page_otp(
            session, poll_url, email, headers, after_ts=after_ts,
        )
        if public_inbox_api_url else None
    )
    page_result = yy_result or public_result
    if page_result or is_yangyang or public_inbox_api_url:
        return page_result, yy_result, None, ""
    resp = session.get(poll_url, headers=headers, timeout=20, verify=True)
    return None, None, resp, resp.text or ""


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    mail_baseline: MailBaseline | None = None,
    exclude_codes: set[str] | None = None,
    first_read_delay_seconds: int = 0,
    first_read_anchor_ts: float | None = None,
    signature_poll_state: SignatureOtpPollState | None = None,
) -> str:
    """
    轮询该邮箱配置的 code_url，直到提取到 6 位验证码或超时。

    settle 机制：首次拿到验证码后不立刻返回，而是继续等 OTP_SETTLE_SECONDS 秒。
    如果期间取码地址返回了不同验证码，则替换候选并重置 settle 倒计时；
    连续 settle 秒没有变化后才返回，避免取到接口缓存中的旧码。
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"通用 API 邮箱不存在或未导入: {email}")
    if is_direct_icapi_url(account.code_url) or is_viewer_url(account.code_url):
        return _fetch_direct_icapi_otp(account, ready_at=first_read_anchor_ts,
                                       exclude_codes=exclude_codes, after_ts=after_ts)
    if is_smsbower_signature_url(account.code_url):
        return _fetch_signature_otp(account, ready_at=first_read_anchor_ts, poll_state=signature_poll_state)
    if after_ts is None:
        raise OtpFreshnessError("missing_send_time")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    if first_read_delay_seconds:
        if not 0 < first_read_delay_seconds <= 60:
            raise ValueError("首次读取延时必须为 1–60 秒")
        anchor = max(after_ts, first_read_anchor_ts) if first_read_anchor_ts is not None else after_ts
        earliest = anchor + first_read_delay_seconds
        if deadline <= earliest:
            raise GenericApiMailError("邮箱等待期限不足以完成首次读取延时")
        remaining = earliest - time.time()
        if remaining > 0:
            logger.info("[GenericAPI] 发码前快照已保存，等待至发码后 %ss 再读取", first_read_delay_seconds)
            time.sleep(remaining)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    }
    last_error = ""
    last_freshness_error = None
    excluded = exclude_codes or set()
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        f"[GenericAPI] 开始轮询取码地址: {email}，"
        f"最长 {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )
    is_yangyang = _parse_yangyang_code_url(account.code_url) is not None
    public_inbox_api_url = _public_inbox_page_api_url(account.code_url)
    if public_inbox_api_url:
        logger.info(
            "[GenericAPI] 已识别公开收件页面，使用页面 inbox API: host=%s email=%s",
            urlparse(public_inbox_api_url).netloc,
            email,
        )

    selected_proxy = str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip()
    # Mail fetching never borrows a registration/residential proxy. An explicit
    # dedicated mail proxy is allowed; an empty setting means direct access.
    routes: list[tuple[str, str]] = []
    if selected_proxy:
        routes.append(("generic_api_local_proxy", selected_proxy))
    routes.append(("direct", ""))
    logger.info(
        "[GenericAPI] HTTP 路由：代理=%s，网络异常时%s",
        _redact_proxy_url(selected_proxy),
        "回退直连" if selected_proxy else "使用直连",
    )

    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            # 不修改 yangyang 的路径型 URL；其列表接口本身按邮件 ID 返回数据。
            base_poll_url = public_inbox_api_url or account.code_url
            poll_url = base_poll_url if is_yangyang else _cache_busted_url(base_poll_url, attempt)
            route_error: Exception | None = None
            page_result = yy_result = resp = None
            text = ""
            for route_index, (_route_name, route_proxy) in enumerate(routes):
                relay = None
                try:
                    effective_proxy = route_proxy
                    page_result, yy_result, resp, text = _fetch_poll_payload(
                        proxy_url=effective_proxy,
                        poll_url=poll_url,
                        email=email,
                        headers=headers,
                        after_ts=None,
                        is_yangyang=is_yangyang,
                        public_inbox_api_url=public_inbox_api_url,
                    )
                    route_error = None
                    break
                except requests.exceptions.SSLError:
                    raise OtpFreshnessError("mail_tls_error") from None
                except requests.RequestException as exc:
                    route_error = exc
                    last_error = f"{type(exc).__name__}: 取码请求失败"
                    has_fallback = route_index + 1 < len(routes)
                    logger.warning(
                        "[GenericAPI] 页面/API 请求失败：route=%s %s%s",
                        _redact_proxy_url(route_proxy),
                        type(exc).__name__,
                        "，切换直连重试" if has_fallback else "",
                    )
                finally:
                    if relay is not None:
                        relay.close()
            if route_error is not None:
                raise route_error

            if page_result:
                code, yy_meta = page_result
                if code in excluded:
                    raise OtpFreshnessError("excluded_code", waitable=True)
                proof = verify_mail_freshness(yy_meta, email=email, url=account.code_url,
                                              after_ts=after_ts, now=time.time(), baseline=mail_baseline,
                                              candidate_code=code, code_history=yy_meta.get("code_history"))
                result_source = str(yy_meta.get("source") or ("yangyang" if yy_result else "public_inbox_page"))
                now_seen = time.time()
                if not best_otp:
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                    logger.info("[GenericAPI] 已观察到候选，source=%s method=%s；等 %ss 检查更新",
                                result_source, proof, settle)
                elif code != best_otp:
                    logger.info("[GenericAPI] 候选已更新，source=%s method=%s；重置 settle",
                                result_source, proof)
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                else:
                    logger.debug("[GenericAPI] 取码接口仍返回已验证的候选")
                resp = None
                text = ""
            else:
                if is_yangyang or public_inbox_api_url:
                    last_error = (
                        "yangyang 列表中尚未出现 after_ts 之后的新验证码邮件"
                        if is_yangyang else
                        "公开收件页面中尚未出现 after_ts 之后的新验证码邮件"
                    )
                    resp = None
                    text = ""
            if resp is None:
                pass
            elif resp.status_code == 200:
                try:
                    payload = json.loads(text)
                    is_json = True
                except (ValueError, TypeError):
                    payload = None
                    is_json = text.lstrip().startswith(("{", "["))
                public_payload = payload if isinstance(payload, dict) else {}
                mailbox = public_payload.get("mailbox") or public_payload.get("email") or ""
                if isinstance(mailbox, dict):
                    mailbox = mailbox.get("address") or ""
                mailbox = str(mailbox).strip()
                mailbox_mismatch = bool(mailbox and mailbox.lower() != email.lower())
                if mailbox_mismatch:
                    raise OtpFreshnessError("recipient_mismatch")
                else:
                    structured = _extract_structured_api_code(text, after_ts=None)
                structured_meta = structured[1] if structured else {}
                # JSON 已被判为过期、业务错误或未知结构时，不能绕过判定再扫六位数。
                code = structured[0] if structured else (None if is_json else _extract_code(text))
                if code and structured_meta and mail_baseline is not None:
                    history = structured_meta.get("code_history")
                    if (history is not None and not structured_meta.get("received_at")
                            and not structured_meta.get("mail_id")):
                        delta = new_code_candidates(mail_baseline, history)
                        if code not in delta and len(delta) == 1:
                            code = delta[0]
                        elif code not in delta and len(delta) > 1:
                            raise OtpFreshnessError("multiple_new_codes", waitable=True)
                if mailbox_mismatch:
                    code = None
                if code:
                    if code in excluded:
                        raise OtpFreshnessError("excluded_code", waitable=True)
                    proof = verify_mail_freshness(structured_meta, email=email, url=account.code_url,
                                                  after_ts=after_ts, now=time.time(), baseline=mail_baseline,
                                                  candidate_code=code,
                                                  code_history=structured_meta.get("code_history"))
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        if structured_meta:
                            logger.info("[GenericAPI] 已观察到候选，source=structured_api method=%s；等 %ss 检查更新",
                                        proof, settle)
                        else:
                            logger.info("[GenericAPI] 已观察到候选，method=%s；等 %ss 检查更新", proof, settle)
                    elif code != best_otp:
                        if structured_meta:
                            logger.info("[GenericAPI] 候选已更新，source=structured_api method=%s；重置 settle", proof)
                        else:
                            logger.info("[GenericAPI] 候选已更新，method=%s；重置 settle", proof)
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug("[GenericAPI] 取码接口仍返回已验证的候选")
                else:
                    if not mailbox_mismatch:
                        if public_inbox_api_url and isinstance(public_payload, dict) and public_payload.get("code") is None:
                            last_error = "latest-code 返回 code=null，邮箱暂未收到验证码"
                        else:
                            last_error = "HTTP 200 但没有通过校验的验证码，需核对接口数据格式及邮件时间"
            else:
                last_error = f"HTTP {resp.status_code}: 取码接口未成功返回"
        except OtpFreshnessError as exc:
            if not exc.waitable:
                logger.warning("[GenericAPI] 无法确认验证码时效，reason=%s；已停止，未提交验证码", exc.reason)
                raise
            last_freshness_error = exc
            last_error = str(exc)
            logger.info("[GenericAPI] 跳过旧邮件或已拒绝候选，reason=%s；继续等待本次新邮件", exc.reason)
        except Exception as exc:
            # requests 异常经常带完整签名地址，不写入任务错误和日志。
            last_error = f"{type(exc).__name__}: 取码请求失败"

        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle 完成，返回发码前后差分/元数据筛选的候选；"
                f"候选锁定时间={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] 已验证新邮件候选，等待 settle"
                f"（剩余 settle ~{max(0, int(settle_until - now))}s, 总剩余 {remaining}s）..."
            )
        else:
            logger.info(
                f"[GenericAPI] 暂未从取码接口拿到验证码，"
                f"{interval}s 后重试（剩余 {remaining}s）..."
            )
        time.sleep(interval)

    if best_otp:
        logger.warning("[GenericAPI] 等待结束，返回此前观察到的候选")
        return best_otp

    if last_freshness_error is not None:
        raise last_freshness_error
    raise GenericApiMailError(f"等待通用 API 验证码超时: {email}; {last_error}")
