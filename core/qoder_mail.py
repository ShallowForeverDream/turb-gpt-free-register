"""Read the shared mailbox APIs for Qoder 6-digit codes; never send mail."""
import re
from urllib.parse import urlsplit

import requests

from config import email as email_config

_CODE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


class QoderMailError(RuntimeError):
    def __init__(self, message, *, http_status=None, retryable=True):
        super().__init__(message)
        self.http_status = http_status
        self.retryable = retryable


def validate_code(value):
    value = str(value or "").strip()
    return value if re.fullmatch(r"\d{6}", value) else ""


def read_once(mailbox, *, http=None, after_ts=None):
    if mailbox.get("source") != "generic_api":
        raise QoderMailError("此邮箱来源暂需手动输入 Qoder 验证码；未调用其他平台收码接口")
    url = str(mailbox.get("code_url") or "")
    from core.icapi_mailbox import is_viewer_url, latest_code_any, MailboxError
    from core.otp_formats import normalize_otp
    if is_viewer_url(url):
        try:
            read = latest_code_any(mailbox["email"], url, after_ts=after_ts)
            seen = []
            for item in [read.code, *(getattr(read, "candidates", None) or [])]:
                value = normalize_otp(item)
                plain = value.replace("-", "")
                if re.fullmatch(r"\d{6}", plain) and plain not in seen:
                    seen.append(plain)
            return seen[0] if seen else ""
        except MailboxError as exc:
            raise QoderMailError(str(exc), http_status=exc.http_status, retryable=exc.retryable) from None
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.port not in (None, 443)):
            raise ValueError()
    except ValueError:
        raise QoderMailError("取码 API 必须是合法的 HTTPS 地址") from None
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
            raise QoderMailError(f"取码接口拒绝请求 HTTP {response.status_code}，已停止，不切换路线", http_status=response.status_code)
        if response.status_code != 200:
            raise QoderMailError(f"取码接口 HTTP {response.status_code}，不记录地址或正文")
        payload = response.json()
        if not isinstance(payload, dict):
            return ""
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        if not isinstance(data, dict):
            return ""
        code = validate_code(data.get("code") or data.get("otp") or data.get("verification_code"))
        return code
    except (requests.RequestException, ValueError):
        raise QoderMailError("取码 API 请求失败或 JSON 无效；不记录私有地址") from None
    finally:
        if owned:
            http.close()
