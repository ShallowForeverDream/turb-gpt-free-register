# -*- coding: utf-8 -*-
"""SMSBower temporary Gmail: mailId for getCode, id for setStatus.

One activation belongs to one task. Provider write intents, terminal states and
used-code digests survive restarts; uncertain writes are never auto-replayed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import secrets
import string
import threading
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

from config import email as _email_cfg
from core import mail_activation_store as store
from core.mail_traffic import record_mail_http

logger = logging.getLogger(__name__)
DEFAULT_API_BASE = "https://smsbower.page/api/mail"
DEFAULT_SERVICE = "dr"
DEFAULT_DOMAIN = "gmail.com"
REQUEST_TIMEOUT = 20
_CODE_RE = re.compile(r"[0-9]{6}")
_CONTEXT_CACHE = {}
_CONTEXT_LOCK = threading.RLock()
_ACQUIRE_LOCK = threading.Lock()


class SmsBowerMailError(RuntimeError):
    pass


class SmsBowerMailNoStock(SmsBowerMailError):
    pass


class SmsBowerMailNoBalance(SmsBowerMailError):
    pass


class SmsBowerMailTimeout(SmsBowerMailError, TimeoutError):
    pass


@dataclass
class SmsBowerMailAccount:
    email: str
    mail_id: str
    original_email: str = ""
    service: str = ""
    domain: str = ""
    codes_used: set[str] = field(default_factory=set, repr=False)
    code_digests: set[str] = field(default_factory=set, repr=False)
    closed: bool = False
    uncertain_action: str | None = None
    local_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    api_base: str = ""
    supplier: str = ""
    creation_confirmed: bool = False
    final_status: int | None = None
    lock: object = field(default_factory=threading.RLock, repr=False)


def _cache_key(email):
    return str(email or "").strip().casefold()


def _base(raw):
    value = str(raw or "").strip().rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise SmsBowerMailError("SMSBower API 地址无效：需要不含凭据、查询参数的 HTTP(S) 地址")
    return value


def _api_base():
    return _base(getattr(_email_cfg, "SMSBOWER_MAIL_API_BASE", DEFAULT_API_BASE))


def _api_key():
    from config import codex
    key = str(getattr(_email_cfg, "SMSBOWER_MAIL_API_KEY", "") or codex.SMSBOWER_API_KEY or "").strip()
    if not key or key == "REPLACE_WITH_YOUR_API_KEY":
        raise SmsBowerMailError("SMSBower API Key 未配置，请填写 SMSBOWER_MAIL_API_KEY 或 SMSBOWER_API_KEY")
    return key


def _service():
    value = str(getattr(_email_cfg, "SMSBOWER_MAIL_SERVICE", DEFAULT_SERVICE) or "").strip()
    return "dr" if value.lower() in {"openai", "chatgpt"} else value


def _domain():
    return str(getattr(_email_cfg, "SMSBOWER_MAIL_DOMAIN", DEFAULT_DOMAIN) or "").strip().lower()


def _number(name, default, *, zero=False):
    try:
        value = float(getattr(_email_cfg, name, default))
    except (TypeError, ValueError):
        value = float("nan")
    if not math.isfinite(value) or value < 0 or (value == 0 and not zero):
        raise SmsBowerMailError(f"{name} 必须是{'非负' if zero else '正'}有限数字")
    return value


def _alias_length():
    value = _number("SMSBOWER_MAIL_ALIAS_LENGTH", 0, zero=True)
    if value != int(value) or (value != 0 and not 3 <= value <= 16):
        raise SmsBowerMailError("SMSBOWER_MAIL_ALIAS_LENGTH 只能是 0 或 3~16")
    return int(value)


def _activation_wait():
    return _number("SMSBOWER_MAIL_ACTIVATION_WAIT", 120, zero=True)


def _activation_interval():
    return _number("SMSBOWER_MAIL_ACTIVATION_RETRY_INTERVAL", 5)


def _request_timeout():
    return _number("SMSBOWER_MAIL_REQUEST_TIMEOUT", REQUEST_TIMEOUT)


def validate_configuration():
    _api_base(), _api_key(), _alias_length(), _activation_wait(), _activation_interval(), _request_timeout()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", _service()):
        raise SmsBowerMailError("SMSBower Gmail 服务代码不能为空或包含特殊字符")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", _domain()):
        raise SmsBowerMailError("SMSBower Gmail 域名无效")


def _supplier(base):
    return hashlib.sha256((base + "|" + _api_key()).encode()).hexdigest()


def _success(payload):
    # bool is a subclass of int, but is not the supplier's documented status.
    return type(payload.get("status")) is int and payload["status"] == 1 or payload.get("status") == "1"


def _error(payload):
    text = str(payload.get("error") or payload.get("message") or "未知业务错误")
    return text.replace(_api_key(), "<redacted>")[:240]


def _require_success(payload):
    if not _success(payload):
        message = _error(payload)
        if "insufficient balance" in message.lower() or "余额不足" in message:
            raise SmsBowerMailNoBalance(message)
        raise SmsBowerMailError(message)


def _request(path, params=None, *, timeout=None, account=None, base=None):
    base = base or (account.api_base if account and account.api_base else _api_base())
    if account and account.supplier and account.supplier != _supplier(base):
        raise SmsBowerMailError("激活绑定的 SMSBower API Key/地址已变化；请恢复原配置，不重新领取")
    try:
        response = requests.request(
            "GET", base if path == "services" else base + "/" + path,
            params={"api_key": _api_key(), **(params or {})},
            timeout=min(_request_timeout(), timeout) if timeout is not None else _request_timeout(),
            proxies={"http": "", "https": "", "all": ""}, allow_redirects=False,
        )
        record_mail_http(response)
    except requests.RequestException as exc:
        raise SmsBowerMailError(f"SMSBower {path} 网络请求失败：{type(exc).__name__}；请核对订单") from None
    if not 200 <= response.status_code < 300:
        raise SmsBowerMailError(f"SMSBower {path} HTTP {response.status_code}；已停止，不自动重放")
    try:
        payload = response.json()
    except ValueError:
        raise SmsBowerMailError(f"SMSBower {path} 响应不是 JSON；请核对订单") from None
    if not isinstance(payload, dict):
        raise SmsBowerMailError(f"SMSBower {path} 响应不是对象；请核对订单")
    return payload


def _handler_api_base():
    from config import codex
    return _base(codex.SMSBOWER_API_BASE)


def list_services():
    payload = _request("services", {"action": "getMailServicesList"}, base=_handler_api_base())
    if payload.get("status") != "success" or not isinstance(payload.get("services"), list):
        raise SmsBowerMailError(_error(payload))
    return [x for x in payload["services"] if isinstance(x, dict)]


def get_prices():
    validate_configuration()
    payload = _request("getPriceRests", {"service": _service(), "domain": _domain()})
    _require_success(payload)
    if not isinstance(payload.get("data"), dict):
        raise SmsBowerMailError("SMSBower 价格库存响应缺少 data 对象")
    return payload["data"]


def _record(account):
    return {
        "source": "smsbower_mail", "local_id": account.local_id,
        "email": account.email, "original_email": account.original_email,
        "mail_id": account.mail_id, "service": account.service, "domain": account.domain,
        "api_base": account.api_base, "supplier": account.supplier,
        "closed": account.closed, "final_status": account.final_status,
        "uncertain_action": account.uncertain_action,
        "creation_confirmed": account.creation_confirmed,
        "code_digests": sorted(account.code_digests),
    }


def _save(account, expected_action=None):
    try:
        store.save(_record(account), expected_action=expected_action)
    except ValueError as exc:
        raise SmsBowerMailError(str(exc)) from None


def _from_record(record):
    names = ("email", "mail_id", "original_email", "service", "domain", "local_id",
             "api_base", "supplier", "closed", "final_status", "uncertain_action", "creation_confirmed")
    account = SmsBowerMailAccount(**{k: record[k] for k in names if k in record})
    account.code_digests = set(record.get("code_digests") or [])
    return account


def _check_stop():
    from core.registration_service import check_stop_requested
    check_stop_requested()


def _sleep(seconds):
    deadline = time.monotonic() + seconds
    while True:
        _check_stop()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.25, remaining))


def pick_account():
    # Serialize purchases in this process. A live purchase must not be mistaken
    # for an abandoned write by another registration worker.
    while not _ACQUIRE_LOCK.acquire(timeout=0.25):
        _check_stop()
    try:
        return _pick_account()
    finally:
        _ACQUIRE_LOCK.release()


def _pick_account():
    validate_configuration()  # Validate before a potentially billable GET.
    service, domain, base = _service(), _domain(), _api_base()
    alias = _alias_length()
    activation_wait = _activation_wait()
    deadline = time.monotonic() + activation_wait
    while True:
        _check_stop()
        account = SmsBowerMailAccount("", "", service=service, domain=domain,
                                     api_base=base, supplier=_supplier(base), uncertain_action="getActivation")
        try:
            store.begin_acquisition(_record(account))
        except ValueError as exc:
            raise SmsBowerMailError(str(exc)) from None
        # No network/HTTP/format retry: the allocation may already have occurred.
        payload = _request("getActivation", {"service": service, "domain": domain},
                           timeout=max(0.001, min(_request_timeout(), deadline-time.monotonic()))
                           if activation_wait else _request_timeout(), account=account)
        if type(payload.get("status")) not in {int, str} or payload.get("status") not in {0, 1, "0", "1"}:
            raise SmsBowerMailError("SMSBower 领取响应状态不明确；不重新购买，请核对订单")
        if not _success(payload):
            account.uncertain_action = None
            account.closed = True
            _save(account, expected_action="getActivation")
            if "no mails yet" not in _error(payload).lower():
                _require_success(payload)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmsBowerMailNoStock("等待 SMSBower Gmail 库存超时")
            _sleep(min(_activation_interval(), remaining))
            continue
        account.mail_id = str(payload.get("mailId") or "").strip()
        account.original_email = account.email = str(payload.get("mail") or "").strip()
        # Persist even malformed successful allocations for manual reconciliation.
        _save(account)
        local, sep, actual_domain = account.email.partition("@")
        if not account.mail_id or not sep or not local or actual_domain.lower() != domain or any(c.isspace() for c in account.email):
            raise SmsBowerMailError("SMSBower 领取响应缺少有效 mailId/mail 或域名不匹配；不重新购买，请核对订单")
        if alias:
            suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(alias))
            account.email = local.split("+", 1)[0] + "+" + suffix + "@" + actual_domain
        account.uncertain_action = None
        try:
            store.bind(_record(account))
        except ValueError as exc:
            account.uncertain_action = "duplicate_activation"
            record = _record(account)
            record["email"] = ""  # Keep the original owner's lookup unambiguous.
            store.save(record, expected_action="getActivation")
            raise SmsBowerMailError(str(exc)) from None
        with _CONTEXT_LOCK:
            _CONTEXT_CACHE[_cache_key(account.email)] = account
        logger.info("[SMSBowerMail] 已领取任务邮箱，激活已持久化")
        return account


def get_email():
    return pick_account().email


def get_account_context(email):
    with _CONTEXT_LOCK:
        return _CONTEXT_CACHE.get(_cache_key(email))


def get_account_context_metadata(email):
    account = get_account_context(email) or restore_account_context(email)
    return _record(account) if account else None


def restore_account_context(email):
    target = str(email or "").strip()
    with _CONTEXT_LOCK:
        cached = _CONTEXT_CACHE.get(_cache_key(target))
        if cached:
            return cached
        record = store.by_email(target)
        if not record:
            from core import db
            raw = (db.get_account_by_email(target) or {}).get("extra_json")
            extra = json.loads(raw) if isinstance(raw, str) and raw else raw
            record = extra.get("email_service") if isinstance(extra, dict) else None
            if not isinstance(record, dict) or record.get("source") != "smsbower_mail":
                return None
            record = dict(record)
            # Older records did not save terminal/uncertain states. Never reopen blindly.
            if "closed" not in record:
                record["uncertain_action"] = "legacy_state_unknown"
        if _cache_key(record.get("email")) != _cache_key(target) or not record.get("mail_id"):
            return None
        account = _from_record(record)
        _CONTEXT_CACHE[_cache_key(target)] = account
        return account


def _refresh(account):
    record = store.by_email(account.email)
    if record and record.get("local_id") == account.local_id:
        account.closed = record.get("closed", False)
        account.uncertain_action = record.get("uncertain_action")
        account.creation_confirmed = record.get("creation_confirmed", False)
        account.final_status = record.get("final_status")
        account.code_digests.update(record.get("code_digests") or [])


def _require_open(account):
    _refresh(account)
    if account.closed:
        raise SmsBowerMailError("SMSBower 激活已经确认关闭，不能继续收码或修改状态")
    if account.uncertain_action:
        raise SmsBowerMailError(f"SMSBower {account.uncertain_action} 结果未确认，请先核对平台订单")
    if account.supplier and account.supplier != _supplier(account.api_base):
        raise SmsBowerMailError("激活绑定的 SMSBower API Key/地址已变化，请恢复原配置")


def set_status(account, status, *, timeout=None):
    if type(status) is not int or status not in {2, 3, 5}:
        raise ValueError("SMSBower Gmail 状态只能为 2、3、5")
    with account.lock:
        _refresh(account)
        if account.closed and status == account.final_status:
            return {"status": 1, "message": "already closed"}
        _require_open(account)
        action = f"setStatus={status}"
        try:
            store.claim_action(_record(account), action)
        except ValueError as exc:
            raise SmsBowerMailError(str(exc)) from None
        account.uncertain_action = action
        payload = _request("setStatus", {"id": account.mail_id, "status": str(status)},
                           timeout=timeout, account=account)
        # A well-formed business rejection is known, unlike an unreadable response.
        if type(payload.get("status")) not in {int, str} or payload.get("status") not in {0, 1, "0", "1"}:
            raise SmsBowerMailError("SMSBower 状态响应不明确，请核对平台订单")
        account.uncertain_action = None
        if _success(payload) and status in {2, 3}:
            account.closed, account.final_status = True, status
        _save(account, expected_action=action)
        _require_success(payload)
        return payload


def fetch_latest_otp(email, after_ts=None, max_wait=None, poll_interval=None, settle_seconds=None, exclude_codes=None):
    # SMSBower provides no timestamp; after_ts cannot establish mail freshness.
    target = str(email or "").strip()
    account = get_account_context(target) or restore_account_context(target)
    if not account:
        raise SmsBowerMailError("SMSBower Gmail 缺少 mailId；不根据邮箱地址重新领取")
    wait = float(max_wait) if max_wait is not None else _number("OTP_MAX_WAIT", 180)
    interval = float(poll_interval) if poll_interval is not None else _number("OTP_POLL_INTERVAL", 3)
    if not math.isfinite(wait) or wait < 0 or not math.isfinite(interval) or interval <= 0:
        raise SmsBowerMailError("收码期限必须非负且轮询间隔必须大于 0")
    deadline = time.monotonic() + wait
    excluded = set(exclude_codes or [])
    with account.lock:
        _require_open(account)
        while time.monotonic() < deadline:
            _check_stop()
            payload = _request("getCode", {"mailId": account.mail_id},
                               timeout=max(0.001, deadline-time.monotonic()), account=account)
            if _success(payload):
                code = str(payload.get("code") or "").strip()
                digest = hashlib.sha256(code.encode()).hexdigest()
                if _CODE_RE.fullmatch(code) and code not in excluded and digest not in account.code_digests:
                    # Atomic consumption also prevents another process returning this code.
                    try:
                        consumed = store.consume_code(_record(account), digest)
                    except ValueError as exc:
                        raise SmsBowerMailError(str(exc)) from None
                    account.code_digests.add(digest)
                    if not consumed:
                        continue
                    account.codes_used.add(code)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SmsBowerMailTimeout("SMSBower 收码期限已用尽，未提交验证码")
                    set_status(account, 5, timeout=remaining)
                    if time.monotonic() > deadline:
                        raise SmsBowerMailTimeout("SMSBower 状态确认超过收码期限，未提交验证码")
                    return code
            elif "code has not been received yet" not in _error(payload).lower():
                _require_success(payload)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _sleep(min(interval, remaining))
    raise SmsBowerMailTimeout("等待 SMSBower Gmail 新验证码超时；未判断账号停用")


def mark_account_created(email):
    account = get_account_context(email) or restore_account_context(email)
    if account:
        with account.lock:
            _refresh(account)
            account.creation_confirmed = True
            _save(account)


def release_account(email, status="available", note=None):
    account = get_account_context(email) or restore_account_context(email)
    if not account:
        return None
    with account.lock:
        _refresh(account)
        if account.closed:
            return "closed"
        if status == "failed_created":
            account.creation_confirmed = True
            _save(account)
            return "pending"
        if status in {"used", "success", "registered", "close"}:
            final_status = 3
        elif account.creation_confirmed:
            return "pending"
        elif status in {"available", "disabled", "cancelled", "canceled", "failed"}:
            final_status = 2
        else:
            return "pending"
        try:
            set_status(account, final_status)
        except SmsBowerMailError:
            logger.warning("[SMSBowerMail] 激活收尾未确认；保留记录，禁止自动重放")
            return "pending"
        # Keep the terminal object: a second cleanup must not restore and replay it.
        return "closed"


def mark_success_closed(email):
    return release_account(email, status="used")
