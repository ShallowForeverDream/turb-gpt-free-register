"""Import only an explicitly selected mailbox's SSO from an offline Burp capture.

No HTTP requests, replay, passwords, challenge tokens or raw capture export.
"""
import base64
import gzip
import hashlib
import json
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

from core import db
from core.import_formats import valid_email


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class CapturedSession:
    email: str
    sso: str = field(repr=False)
    sso_rw: str = field(repr=False)
    source_sha256: str
    registered_at: str
    confirmed_at: str
    capture_session_verified: bool


def _envelope(element):
    if element is None or not element.text:
        raise CaptureError("抓包缺少请求或响应")
    try:
        raw = base64.b64decode(element.text) if element.get("base64") == "true" else element.text.encode()
        header, separator, body = raw.partition(b"\r\n\r\n")
        if not separator: header, separator, body = raw.partition(b"\n\n")
        lines = header.decode("latin1").splitlines()
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers.setdefault(key.lower().strip(), []).append(value.strip())
        if headers.get("content-encoding") == ["gzip"]: body = gzip.decompress(body)
        if len(body) > 4*1024*1024: raise CaptureError("认证响应超过安全读取上限")
        return lines[0], headers, body
    except CaptureError:
        raise
    except Exception:
        raise CaptureError("抓包认证记录格式无效，未记录原文") from None


def _payload(body):
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _stamp(headers):
    try:
        stamp = parsedate_to_datetime(headers.get("date", [""])[0])
        if stamp.tzinfo is not None:
            return stamp.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass
    return ""


def _request_cookies(headers):
    jar = SimpleCookie()
    try:
        for value in headers.get("cookie", []): jar.load(value)
    except Exception:
        return {}
    return {name: value.value for name, value in jar.items() if name in {"sso", "sso-rw"}}


def inspect_capture(path, email):
    email = str(email or "").strip().lower()
    if not valid_email(email): raise CaptureError("目标邮箱不合法")
    path = Path(path)
    if path.stat().st_size > 100*1024*1024: raise CaptureError("抓包文件超过100MB")
    raw = path.read_bytes()
    if b"<!ENTITY" in raw[:65536].upper(): raise CaptureError("不接受包含实体定义的抓包文件")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise CaptureError("文件不是有效的 Burp XML 导出") from None
    if root.tag != "items": raise CaptureError("不支持的抓包格式")
    candidate = None
    for item in root.findall("item"):
        try:
            url = urlsplit(item.findtext("url", ""))
            allowed = url.scheme == "https" and url.hostname == "grok.com" and url.port in (None, 443) and not url.username and not url.password
        except ValueError:
            allowed = False
        if not allowed or item.findtext("status") != "200": continue
        if url.path not in {"/api/auth/sign-up/create-account", "/api/auth/session"}: continue
        request_line, request_headers, request_body = _envelope(item.find("request"))
        status_line, response_headers, response_body = _envelope(item.find("response"))
        if not re.match(r"^HTTP/\d(?:\.\d)? 200(?:\s|$)", status_line): continue
        response = _payload(response_body)
        session = response.get("session")
        if not isinstance(session, dict) or str(session.get("email") or "").lower() != email or not session.get("userId"):
            continue
        if url.path == "/api/auth/sign-up/create-account":
            request = _payload(request_body)
            if not request_line.startswith("POST ") or str(request.get("email") or "").lower() != email:
                continue
            cookies = {}
            for value in response_headers.get("set-cookie", []):
                jar = SimpleCookie()
                try: jar.load(value)
                except Exception: raise CaptureError("注册响应的 Cookie 格式无效") from None
                for name, cookie in jar.items():
                    if name not in {"sso", "sso-rw"}: continue
                    if cookie["domain"].lstrip(".").lower() not in {"", "grok.com"} or cookie["path"] not in {"", "/"} or not cookie["secure"] or not cookie["httponly"]:
                        raise CaptureError("注册响应的 SSO 作用域或安全标志不符合预期")
                    token = cookie.value
                    if not token or len(token) > 32768 or any(c in token for c in "\r\n;"):
                        raise CaptureError("注册响应缺少有效 SSO")
                    if name in cookies and cookies[name] != token: raise CaptureError("注册响应包含多个不同 SSO")
                    try:
                        if cookie["expires"] and parsedate_to_datetime(cookie["expires"]).timestamp() <= time.time():
                            raise CaptureError("抓包中的 SSO 已到 Cookie 过期时间，未导入")
                        if cookie["max-age"]:
                            age = int(cookie["max-age"])
                            stamp = _stamp(response_headers)
                            if age <= 0 or (stamp and datetime.fromisoformat(stamp).timestamp()+age <= time.time()):
                                raise CaptureError("抓包中的 SSO 已到 Cookie 过期时间，未导入")
                    except (ValueError, TypeError, OverflowError) as exc:
                        if isinstance(exc, CaptureError): raise
                        raise CaptureError("抓包中的 Cookie 有无效的过期时间") from None
                    cookies[name] = token
            if not cookies.get("sso"): continue
            if candidate and candidate["sso"] != cookies["sso"]:
                raise CaptureError("同一邮箱存在多组注册会话，未自动选择或覆盖")
            candidate = {"sso": cookies["sso"], "sso_rw": cookies.get("sso-rw", ""),
                         "user_id": session["userId"], "registered_at": _stamp(response_headers), "confirmed_at": ""}
        elif candidate and request_line.startswith("GET "):
            cookies = _request_cookies(request_headers)
            if (cookies.get("sso") == candidate["sso"] and session.get("userId") == candidate["user_id"]
                    and session.get("emailConfirmed") is True and session.get("hasPassword") is True):
                candidate["confirmed_at"] = _stamp(response_headers) or "recorded_without_response_date"
    if not candidate or not candidate["confirmed_at"]:
        raise CaptureError("未找到该邮箱注册下发的 SSO 及其后匹配的已验证会话，未导入")
    return CapturedSession(email, candidate["sso"], candidate["sso_rw"], hashlib.sha256(raw).hexdigest(),
                           candidate["registered_at"], candidate["confirmed_at"], True)


def import_capture(path, email):
    record = inspect_capture(path, email)
    from core.grok_store import connect
    with db._LOCK, closing(connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        pool = conn.execute("SELECT source FROM email_pool WHERE email=? COLLATE NOCASE AND archived=0", (record.email,)).fetchall()
        if len(pool) != 1: raise CaptureError("目标邮箱不在唯一的可用邮箱池条目中，未导入")
        if conn.execute("SELECT 1 FROM grok_jobs WHERE email=? COLLATE NOCASE AND status IN ('pending','running','manual_required')", (record.email,)).fetchone():
            raise CaptureError("该邮箱仍有在途 Grok 任务，未覆盖状态")
        digest = hashlib.sha256(record.sso.encode()).hexdigest()
        old = conn.execute("SELECT id,sso_digest FROM grok_accounts WHERE email=?", (record.email,)).fetchone()
        if old:
            if old[1] != digest: raise CaptureError("该邮箱已有不同会话，未自动覆盖")
            return {"account_id": old[0], "imported": False, "already_present": True, "password_imported": False}
        payload = {"email": record.email, "source": pool[0][0], "sso": record.sso, "sso_rw": record.sso_rw, "password": "",
                   "registration_origin": "manual_capture", "session_validation_status": "capture_only",
                   "capture_sha256": record.source_sha256, "registered_at": record.registered_at,
                   "capture_session_confirmed_at": record.confirmed_at, "capture_session_verified": True}
        try:
            cur = conn.execute("INSERT INTO grok_accounts(email,source,created_at,payload,sso_digest) VALUES(?,?,?,?,?)",
                               (record.email, pool[0][0], db._now(), json.dumps(payload), digest))
        except sqlite3.IntegrityError:
            raise CaptureError("SSO 已关联其他账号，未重复导入") from None
    return {"account_id": cur.lastrowid, "imported": True, "already_present": False, "password_imported": False,
            "sso_saved": True, "sso_rw_saved": bool(record.sso_rw), "session_validation_status": "capture_only"}
