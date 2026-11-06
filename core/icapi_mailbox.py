"""The ICAPI mail viewer's read-only public API, scoped to one supplied mailbox token."""
import re
import time
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import requests

from config import email as config
from core.otp_freshness import parse_mail_time

ORIGIN = "https://icapi.oaibx.com"


class MailboxError(RuntimeError):
    def __init__(self, message, *, http_status=None, retryable=False):
        super().__init__(message)
        self.http_status = http_status
        self.retryable = retryable


def viewer_token(url):
    try:
        p = urlsplit(str(url or ""))
        values = parse_qs(p.fragment, keep_blank_values=True)
        token = values.get("token", [])
        if (p.scheme != "https" or p.hostname != "icapi.oaibx.com" or p.path != "/v" or p.query
                or p.username or p.password or p.port not in (None, 443) or set(values) != {"token"}
                or len(token) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token[0])):
            raise ValueError()
        return token[0]
    except (ValueError, TypeError):
        raise MailboxError("邮件页面链接必须是本站提供的 HTTPS /v#token= 格式；未请求其他地址") from None


def is_viewer_url(url):
    try:
        viewer_token(url)
        return True
    except MailboxError:
        return False


def _addresses(value):
    return {address.strip().lower() for _, address in getaddresses([str(value or "")]) if address}


def _platform(message, platform):
    subject = str(message.get("subject") or "")
    senders = set().union(*(_addresses(message.get(k)) for k in ("from", "sender", "reply_to")))
    domains = {s.rsplit("@", 1)[-1] for s in senders if "@" in s}
    grok = bool(re.search(r"\b(?:grok|xai|x\.ai|spacexai|spacexsi)\b", subject, re.I)) or any(d == "x.ai" or d.endswith(".x.ai") or d == "grok.com" for d in domains)
    gpt = bool(re.search(r"\b(?:openai|chatgpt)\b", subject, re.I)) or any(d in {"openai.com", "chatgpt.com"} or d.endswith(".openai.com") for d in domains)
    return (grok and not gpt) if platform == "grok" else (gpt and not grok)


def code_from_text(text, platform):
    text = str(text or "")[:262144].upper()
    patterns = (
        # OpenAI's current English template: "Enter this temporary verification
        # code to continue: 123456" / "temporary login code: 123456".
        r"(?:TEMPORARY|LOGIN|VERIFICATION|CONFIRMATION|SECURITY|ONE[ -]TIME)\s+(?:CODE|PASSWORD)[^0-9]{0,80}([0-9]{6})(?![0-9])",
        r"(?:CONFIRMATION|VERIFICATION|SECURITY|ONE[ -]TIME)\s+(?:CODE|PASSWORD)\s*[:：]?\s*([A-Z0-9]{3}[-‐‑–—]?[A-Z0-9]{3})(?![A-Z0-9])",
        r"(?:验证码|安全代码|验证代码|検証コード|認証コード|コード|验证代码|验证码)\s*[:：为是]?\s*([0-9]{6})(?![0-9])",
        r"(?:КОД|код)\s*(?:[:：]|для)?\s*[^0-9]{0,40}([0-9]{6})(?![0-9])",
        r"\b(?:CODE|OTP)\s*(?:IS|为|是)?\s*[:：]?\s*([0-9]{6})(?![0-9])",
        r"(?:^|[^0-9])([0-9]{6})(?:[^0-9]|$)",
        r"^\s*([A-Z0-9]{3}[-‐‑–—]?[A-Z0-9]{3})\s*$",
    )
    for index, pattern in enumerate(patterns):
        for match in re.finditer(pattern, text, re.M):
            code = re.sub(r"[-‐‑–—]", "", match.group(1))
            if index == 2 and code.isalpha() and len(match.group(1)) == 6:
                continue  # A bare word such as VERIFY is not an unlabeled OTP.
            if index == 6 and code.isalpha():
                continue  # A bare six-letter word is not a numeric/OTP code.
            if re.fullmatch(r"[A-Z0-9]{6}" if platform == "grok" else r"[0-9]{6}", code):
                return code
    return ""


class _MailText(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.hidden = 0
    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}: self.hidden += 1
    def handle_endtag(self, tag):
        if tag in {"script", "style"}: self.hidden = max(0, self.hidden - 1)
    def handle_data(self, text):
        if not self.hidden: self.parts.append(text)


def latest_code(email, view_url, *, platform, http=None, after_ts=None, exclude_codes=()):
    if platform not in {"gpt", "grok"}:
        raise ValueError("邮件平台不合法")
    token = viewer_token(view_url)
    owned = http is None
    if owned:
        http = requests.Session(); http.trust_env = False
        proxy = str(config.GENERIC_API_PROXY or "").strip()
        if proxy: http.proxies = {"http": proxy, "https": proxy}
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "Cache-Control": "no-cache"}
    def get(path):
        response = http.get(ORIGIN + path, headers=headers, timeout=15, verify=True, allow_redirects=False)
        if response.status_code != 200:
            raise MailboxError(f"邮件页面取信接口 HTTP {response.status_code}，未重试、重发或切换线路", http_status=response.status_code,
                               retryable=response.status_code in {408, 500, 502, 503, 504})
        payload = response.json()
        if not isinstance(payload, dict): raise MailboxError("邮件接口结构不合法，未记录响应正文")
        return payload
    try:
        payload = get("/api/v1/public/messages")
        if str(payload.get("mailbox") or "").lower() != email.strip().lower():
            raise MailboxError("邮件页面绑定的邮箱不匹配，未读取或提交其他邮箱验证码")
        messages = payload.get("messages")
        if not isinstance(messages, list) or len(messages) > 1000:
            raise MailboxError("邮件列表结构不合法")
        candidates = []
        for message in messages:
            if not isinstance(message, dict) or email.lower() not in _addresses(message.get("recipient")) or not _platform(message, platform):
                continue
            stamp, _ = parse_mail_time(message.get("received_at"))
            if stamp is None or stamp > time.time() + 300:
                raise MailboxError("平台验证码邮件的时间无法可靠排序，未回退历史邮件")
            # Keep the 90-second clock skew tolerance only for callers that
            # explicitly pass a send-time anchor.  Direct ICAPI/Grok reads pass
            # after_ts=None and therefore never inherit an old code.
            # Direct ICAPI/Grok reads pass after_ts=None.  Only explicit
            # send-time anchors are filtered; the anchor is a lower bound, not a
            # 90-second skew window (a newer code can arrive after the anchor).
            if after_ts is not None and stamp < after_ts:
                continue
            mid = str(message.get("id") or "")
            if not re.fullmatch(r"[1-9][0-9]{0,19}", mid): raise MailboxError("邮件 ID 不合法，未读取任意地址")
            candidates.append((stamp, int(mid), message))
        if not candidates: return ""
        # Newer mail is not necessarily the OTP: OpenAI sends a separate
        # "New sign-in" notification that can arrive after the code mail and
        # has no code in its subject/body.  Skip only that known notification
        # and continue to the older OTP; an actual verification/confirmation
        # message without a code is terminal so a historical code is never
        # reused.  ``exclude_codes`` still suppresses rejected candidates.
        excluded = set(exclude_codes or ())
        for _, _, message in sorted(candidates, key=lambda item: item[:2], reverse=True):
            subject = str(message.get("subject") or "")
            if re.search(r"\b(?:new sign-in|sign-in notification|登录通知|新登录)\b", subject, re.I):
                continue
            code = code_from_text(subject, platform)
            if not code:
                mid = str(message.get("id") or "")
                if not re.fullmatch(r"[0-9]{1,20}", mid): raise MailboxError("邮件 ID 不合法，未读取任意地址")
                detail = get("/api/v1/public/messages/" + mid)
                if str(detail.get("id")) != mid or email.lower() not in _addresses(detail.get("recipient")) or not _platform(detail, platform):
                    raise MailboxError("邮件详情归属或平台不匹配，未提取验证码")
                code = code_from_text(detail.get("subject"), platform) or code_from_text(detail.get("text_body"), platform)
                if not code:
                    parser = _MailText(); parser.feed(str(detail.get("sanitized_html") or "")[:262144])
                    code = code_from_text("\n".join(parser.parts), platform)
            if code and code not in excluded:
                return code
            # A platform-bound verification/confirmation message with no code
            # is the newest authoritative message; do not fall back to older.
            if re.search(r"\b(?:verification|confirmation|code|验证码|验证|コード)\b", subject, re.I):
                return ""
        return ""
    except requests.RequestException:
        raise MailboxError("邮件页面网络请求失败；未记录私有链接或请求详情", retryable=True) from None
    except (ValueError, TypeError):
        raise MailboxError("邮件页面取信失败或 JSON 无效；不记录私有链接、Token 或邮件正文") from None
    finally:
        if owned: http.close()
