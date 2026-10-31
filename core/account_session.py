"""Capture only ChatGPT's authenticated session, never unrelated cookies."""
from copy import deepcopy
import json
import re
import time


def session_cookie_token(session) -> str:
    if session is None:
        return ""
    try:
        driver = getattr(session, "driver", None)
        if driver is not None:
            cookies = driver.get_cookies()
        elif callable(getattr(session, "get_cookies", None)):
            cookies = session.get_cookies()
        elif callable(getattr(session, "cookies", None)):
            cookies = session.cookies()
        else:
            cookies = [vars(cookie) for cookie in session.session.cookies.jar]
        now = time.time()
        values = {}
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            domain = str(cookie.get("domain") or "").lstrip(".").lower()
            name = str(cookie.get("name") or "")
            value = cookie.get("value")
            expires = cookie.get("expires", cookie.get("expiry"))
            if (domain != "chatgpt.com" or cookie.get("path", "/") != "/"
                    or not isinstance(value, str) or not value or any(c in value for c in "\r\n;")):
                continue
            if isinstance(expires, (int, float)) and expires > 0 and expires <= now:
                continue
            values.setdefault(name, set()).add(value)
        for base in ("__Secure-next-auth.session-token", "__Host-next-auth.session-token"):
            if len(values.get(base, ())) == 1:
                return next(iter(values[base]))
            parts = {int(name[len(base)+1:]): value for name, value in values.items()
                     if re.fullmatch(re.escape(base) + r"\.(0|[1-9][0-9]*)", name)}
            if parts and sorted(parts) == list(range(len(parts))) and all(len(v) == 1 for v in parts.values()):
                return "".join(next(iter(parts[i])) for i in range(len(parts)))
    except Exception:
        # Saving the actual Session JSON must survive an optional cookie read.
        pass
    return ""


def remember_session(session, info: dict) -> None:
    if isinstance(info, dict) and info.get("accessToken"):
        session._saved_session_info = deepcopy(info)


def session_fields(session, info: dict | None = None) -> dict:
    if info is None:
        info = getattr(session, "_saved_session_info", None)
    result = {}
    if isinstance(info, dict) and info.get("accessToken"):
        # Ensure a JSON object, not a caller's mutable dict or cookie container.
        result["session"] = json.loads(json.dumps(info, ensure_ascii=False))
        token = session_cookie_token(session)
        if token:
            result["session_token"] = token
    return result


def apply_session_fields(row: dict, fields: dict) -> bool:
    info = fields.get("session")
    if not isinstance(info, dict) or not isinstance(info.get("accessToken"), str) or not info["accessToken"].strip():
        return False
    user = info.get("user")
    identity = str(user.get("email") or "").strip().lower() if isinstance(user, dict) else ""
    if not identity or identity != str(row.get("email") or "").strip().lower():
        return False
    row["session_json"] = deepcopy(info)
    token = fields.get("session_token")
    if isinstance(token, str) and token.strip() and not any(c in token for c in "\r\n;"):
        row["session_token"] = token.strip()
    return True


def save_account_session(account_id: int, session, info: dict | None = None) -> bool:
    from core import db
    fields = session_fields(session, info)
    return db.update_account_session(account_id, fields) if fields else False
