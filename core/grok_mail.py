"""Read existing mailbox APIs for xAI codes; no sends, purchases or GPT fallback."""
import re
from urllib.parse import urlsplit

import requests

from config import email as email_config

_CODE = re.compile(r"(?<![A-Z0-9])([A-Z0-9]{3}-[A-Z0-9]{3})(?![A-Z0-9])")


class GrokMailError(RuntimeError):
    def __init__(self, message, *, http_status=None, retryable=True):
        super().__init__(message)
        self.http_status = http_status
        self.retryable = retryable


def validate_code(value, *, allow_numeric=False):
    value = str(value or "").strip().upper()
    if re.fullmatch(r"[A-Z0-9]{6}", value):
        value = value[:3] + "-" + value[3:]
    # Do not mistake an OpenAI six-digit code, a CSS class or a numeric range for xAI OTP.
    return value if _CODE.fullmatch(value) and (allow_numeric or any(c.isalpha() for c in value)) else ""


def extract_code(payload):
    if not isinstance(payload, dict):
        return ""
    status = payload.get("status", payload.get("code"))
    if status not in (1, "1", "success", "ok") or isinstance(status, bool):
        return ""
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        return ""
    code = validate_code(data.get("code") or data.get("otp") or data.get("verification_code"))
    if code:
        return code
    # Only examine mail bodies when the source explicitly identifies xAI/Grok.
    subject = str(data.get("subject") or "")
    sender = str(data.get("from") or data.get("sender") or "")
    if not re.search(r"\b(?:xai|x\.ai|grok)\b", subject + " " + sender, re.I):
        return ""
    body = subject + " " + str(data.get("text") or data.get("body") or "")[:65536]
    match = _CODE.search(body.upper())
    return validate_code(match.group(1)) if match else ""


def read_once(mailbox, *, http=None, diagnostic=None, after_ts=None):
    if mailbox.get("source") != "generic_api":
        raise GrokMailError("此邮箱来源暂需手动输入 Grok 验证码；未调用 GPT 收码接口")
    url = str(mailbox.get("code_url") or "")
    from core.icapi_mailbox import is_viewer_url, latest_code, MailboxError
    if is_viewer_url(url):
        try:
            code = latest_code(mailbox['email'], url, platform="grok", http=http, after_ts=after_ts)
            if diagnostic is not None:
                diagnostic({"http_status": 200, "business_status": "mailbox_verified",
                            "code_shape": "grok_attributed" if code else "empty", "has_code_time": bool(code)})
            return validate_code(code, allow_numeric=True) if code else ""
        except MailboxError as exc:
            raise GrokMailError(str(exc), http_status=exc.http_status, retryable=exc.retryable) from None
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.port not in (None, 443)):
            raise ValueError()
    except ValueError:
        raise GrokMailError("取码 API 必须是合法的 HTTPS 地址") from None
    owned = http is None
    if owned:
        http = requests.Session()
        http.trust_env = False
        proxy = str(email_config.GENERIC_API_PROXY or "").strip()
        if proxy:
            http.proxies = {"http": proxy, "https": proxy}
    try:
        response = http.get(url, timeout=10, allow_redirects=False,
                            headers={"Accept": "application/json", "Cache-Control": "no-cache"})
        if response.status_code in (401, 403, 429):
            raise GrokMailError(f"取码接口拒绝请求 HTTP {response.status_code}，已停止，不切换路线", http_status=response.status_code)
        if response.status_code != 200:
            raise GrokMailError(f"取码接口 HTTP {response.status_code}，不记录地址或正文")
        payload = response.json()
        code = extract_code(payload)
        if diagnostic is not None:
            status = payload.get("status", payload.get("code")) if isinstance(payload, dict) else None
            data = payload.get("data", payload) if isinstance(payload, dict) else {}
            data = data if isinstance(data, dict) else {}
            value = str(data.get("code") or data.get("otp") or data.get("verification_code") or "")
            diagnostic({"http_status": 200,
                        "business_status": status if not isinstance(status, bool) and status in (0, 1, "0", "1", "ok", "success", "error", "fail") else "other",
                        "code_shape": "grok_alphanumeric" if code else "empty" if not value else "numeric_not_grok" if value.isascii() and value.isdigit() else "unsupported",
                        "has_code_time": bool(data.get("code_time"))})
        return code
    except (requests.RequestException, ValueError) as exc:
        raise GrokMailError(f"取码 API 请求失败或 JSON 无效（{type(exc).__name__}；不记录私有地址）") from None
    finally:
        if owned:
            http.close()
