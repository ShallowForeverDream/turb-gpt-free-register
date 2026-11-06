"""Transport-independent Grok Cookie checks and sanitized diagnostic formatting."""


def collect_session_cookies(cookies, *, native=False):
    values = {}
    domains = {"grok.com", "www.grok.com"} if native else {"x.ai", "accounts.x.ai", "grok.com", "www.grok.com"}
    for cookie in cookies:
        domain = str(cookie.get("domain") or "").lstrip(".").lower()
        name = cookie.get("name")
        if domain not in domains or name not in {"sso", "sso-rw"} or cookie.get("path", "/") != "/":
            continue
        value = cookie.get("value")
        if not isinstance(value, str) or not value or any(c in value for c in "\r\n;"):
            continue
        values.setdefault(name, set()).add(value)
    if any(len(v) != 1 for v in values.values()):
        raise ValueError("包含多个不同Grok身份，未保存会话")
    return {name: next(iter(v)) for name, v in values.items()}


def diagnostic_message(detail):
    return (f"HTTP {detail['http_status']} host={detail['host']} endpoint={detail['endpoint']} "
            f"type={detail['resource_type']} content_type={detail['content_type']} "
            f"challenge={detail['challenge']} error_code={detail['error_code']} "
            f"request_id={detail['request_id']} cf_ray={detail['cf_ray']}；{detail['error_message']}")
