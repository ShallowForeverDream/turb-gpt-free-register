"""Allowlisted Auth error details; never retain request headers or raw bodies."""
import re
import unicodedata


PHONE_DIAGNOSTIC_POLICY = "allowlisted_redacted_error_and_request_id"


def redact_error_text(value, *, sensitive_values=(), limit=480) -> str:
    if not isinstance(value, str):
        return ""
    text = value[:8192]
    for secret in sensitive_values:
        if isinstance(secret, str) and len(secret) >= 4:
            text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"(?:https?://|socks5h?://|https?%3[aA])\S+", "[链接已隐藏]", text, flags=re.I)
    text = re.sub(r"\bBearer\s+[^\s,;]+", "Bearer [已隐藏]", text, flags=re.I)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}", "[Token已隐藏]", text)
    text = re.sub(r"\b(?:sk|sess)-[A-Za-z0-9_-]+", "[密钥已隐藏]", text)
    text = re.sub(
        r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|csrf[_-]?token|"
        r"password|session[_-]?(?:token|id)|oai-client-auth-session|__Secure-next-auth\.session-token|"
        r"__Host-next-auth\.session-token|code|state)[\"']?\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)",
        r"\1[已隐藏]", text,
    )
    text = re.sub(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "[邮箱已隐藏]", text)
    text = re.sub(r"(?<![A-Za-z0-9])\+?(?:\d[ ()\-]*){9,18}(?!\d)", "[号码已隐藏]", text)
    text = re.sub(r"(?<![A-Za-z0-9])\d{4,8}(?![A-Za-z0-9])", "[验证码已隐藏]", text)
    text = "".join(" " if char.isspace() else char for char in text if not unicodedata.category(char).startswith("C") or char.isspace())
    return " ".join(text.split())[:limit]


def _identifier(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        return ""
    if value.isdigit() or value.startswith(("sk-", "sess-", "eyJ")):
        return ""
    return value


def auth_error_diagnostic(response, *, stage: str, sensitive_values=()) -> dict:
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    payload = {}
    try:
        value = response.json()
        if isinstance(value, dict):
            payload = value
    except Exception:
        pass
    error = payload.get("error")
    detail = error if isinstance(error, dict) else {}
    code = detail.get("code") or payload.get("code")
    message = detail.get("message") or (error if isinstance(error, str) else None) or payload.get("message") or payload.get("detail")
    headers = getattr(response, "headers", None)
    headers = {str(k).lower(): v for k, v in headers.items()} if hasattr(headers, "items") else {}
    request_id = next((_identifier(headers.get(name)) for name in (
        "x-request-id", "openai-request-id", "x-openai-request-id", "request-id") if _identifier(headers.get(name))), "")
    request_id = request_id or _identifier(detail.get("request_id")) or _identifier(payload.get("request_id"))
    code = _identifier(code)
    if code and redact_error_text(code, sensitive_values=sensitive_values) != code:
        code = ""
    safe_message = redact_error_text(message, sensitive_values=sensitive_values)
    return {
        "stage": stage, "http_status": status, "error_code": code or "unavailable",
        "error_message": safe_message or "未取得结构化错误信息；未记录原始响应正文",
        "request_id": request_id or "unavailable", "cf_ray": _identifier(headers.get("cf-ray")) or "unavailable",
    }


class PhoneVerificationFailure(RuntimeError):
    def __init__(self, diagnostic: dict):
        self.diagnostic = diagnostic
        super().__init__(
            f"{diagnostic['stage']} HTTP {diagnostic['http_status']} "
            f"error_code={diagnostic['error_code']} request_id={diagnostic['request_id']} "
            f"cf_ray={diagnostic['cf_ray']} message={diagnostic['error_message']}"
        )
