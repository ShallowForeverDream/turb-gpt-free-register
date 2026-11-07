# -*- coding: utf-8 -*-
"""通用 IMAP 邮箱池客户端。"""
from __future__ import annotations

import email as email_lib
import atexit
import hashlib
import imaplib
import logging
import re
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import getaddresses

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email
from core.qqmail_client import _decode_email_header, _msg_to_dict
from core.mail_traffic import track_imap_connection
from core.imap_deadline import DeadlineIMAP4, DeadlineIMAP4SSL, ImapDeadline, ImapDeadlineExpired
from core import imap_message_cache
from core import imap_receivers

logger = logging.getLogger(__name__)
_CONTEXT_CACHE: dict[str, "ImapEmailAccount"] = {}
_REMOTE_REFRESH_SECONDS = 60.0
_OTP_WAIT_SECONDS = 180


class ImapMailError(RuntimeError):
    def __init__(self, message: str, *, stage: str = "query", error_code: str = "imap_query_failed"):
        super().__init__(message)
        self.stage = stage
        self.error_code = error_code


class ImapFetchLimitError(ImapMailError):
    retryable = False

    def __init__(self, stage: str):
        super().__init__(
            "IMAP 服务器取信流量额度已超限（FETCH Fetch volume limit exceed）。"
            "本次查询已停止，请等待邮箱服务商恢复额度；不是授权码错误。",
            stage=stage, error_code="imap_fetch_quota_exceeded",
        )


class ImapOtpTimeout(ImapMailError, TimeoutError):
    """No matching code arrived within one bounded wait; not a disabled mailbox."""

    def __init__(self, message):
        super().__init__(message, stage="wait", error_code="imap_otp_timeout")


class ImapConfigurationError(ImapMailError):
    retryable = False

    def __init__(self, message):
        super().__init__(message, stage="configuration", error_code="imap_receiver_configuration")


def _check_status(status, data, *, stage: str):
    if status == "OK":
        return
    # Only classify a server refusal; do not log arbitrary response bodies,
    # headers or authentication material.
    reason = " ".join(part.decode("ascii", errors="ignore") for part in data or [] if isinstance(part, bytes)).lower()
    if "fetch volume limit" in reason:
        raise ImapFetchLimitError(stage)
    raise ImapMailError(f"IMAP {stage} 请求失败（{status}）", stage=stage)


@dataclass
class ImapEmailAccount:
    email: str
    password: str
    server: str
    port: int = 993
    username: str = ""
    use_ssl: bool = True
    mailbox: str = "INBOX"
    forwarded: bool = False
    # Persist mail only for configured mailbox records, not ad-hoc test clients.
    cache_enabled: bool = False
    auth_key: str = ""


def _account_from_row(row: dict | None) -> ImapEmailAccount | None:
    if not row:
        return None
    forwarded = bool(row.get("imap_forwarded"))
    if forwarded:
        try:
            route = imap_receivers.route_from_row(row)
            password = imap_receivers.password_for_row(row, route,
                str(getattr(_email_cfg, "FORWARDED_IMAP_PASSWORD", "") or ""))
        except (ValueError, TypeError) as exc:
            raise ImapConfigurationError("转发收件箱配置或凭据绑定无效，请重新导入对应邮箱的收件配置") from exc
    else:
        route = {}
        password = str(row.get("imap_password") or row.get("password") or "")
    return ImapEmailAccount(
        email=str(row.get("email") or "").strip(),
        password=password,
        server=route["server"] if forwarded else str(row.get("imap_server") or row.get("server") or "").strip(),
        port=route["port"] if forwarded else int(row.get("imap_port") or row.get("port") or 993),
        username=route["username"] if forwarded else str(row.get("imap_username") or row.get("username") or "").strip(),
        use_ssl=route["ssl"] if forwarded else bool(row.get("imap_ssl", row.get("use_ssl", True))),
        mailbox=route["mailbox"] if forwarded else str(row.get("imap_mailbox") or getattr(_email_cfg, "IMAP_MAILBOX", "INBOX") or "INBOX"),
        forwarded=forwarded,
        cache_enabled=True,
        auth_key=str(row.get("imap_auth_key") or (imap_receivers.auth_key(route) if forwarded and row.get("imap_imported_route") else "")),
    )


def pick_account() -> ImapEmailAccount:
    from core import db
    row = db.claim_next_imap_email()
    try:
        account = _account_from_row(row)
    except ImapConfigurationError:
        if row:
            db.release_unconsumed_imap_email(row["email"])
        raise
    if account is None:
        raise ImapMailError("通用 IMAP 邮箱池没有可用邮箱，请先在邮箱池导入")
    if account.forwarded and not account.password:
        db.release_unconsumed_imap_email(account.email)
        raise _missing_forwarded_authorization(account)
    _CONTEXT_CACHE[account.email.lower()] = account
    return account


def get_account_context(email: str) -> ImapEmailAccount | None:
    key = str(email or "").strip().lower()
    if not key:
        return None
    cached = _CONTEXT_CACHE.get(key)
    if cached and not cached.forwarded:
        return cached
    from core import db
    account = _account_from_row(db.get_imap_email_by_email(email))
    if account:
        _CONTEXT_CACHE[key] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core import db
    db.release_imap_email(email, status=status, note=note)
    # 已注册账号后续查活仍需取码，因此只在真正回收为可用时清掉缓存。
    if status == "available":
        _CONTEXT_CACHE.pop(str(email or "").lower(), None)


def _close(mail):
    if mail is not None:
        try:
            # No LOGOUT round trip: cleanup must not extend the query deadline.
            mail.shutdown()
        except (OSError, imaplib.IMAP4.error):
            pass


def _missing_forwarded_authorization(account):
    if account.auth_key:
        return ImapConfigurationError("此转发收件箱缺少独立 IMAP 授权码，请在“配置 → 邮箱 / OTP → 转发 IMAP”填写对应邮箱的授权码；不会使用其他收件箱的授权码")
    return ImapConfigurationError("转发收件箱缺少 FORWARDED_IMAP_PASSWORD，请在配置页填写 IMAP 授权码")


def _connect(account: ImapEmailAccount, *, deadline: ImapDeadline | None = None):
    if not account.server or not account.password:
        if account.forwarded and not account.password:
            raise _missing_forwarded_authorization(account)
        raise ImapMailError(f"{account.email} 的 IMAP 服务器或密码为空")
    mail = None
    stage = "connect"
    try:
        if deadline is None:
            cls = imaplib.IMAP4_SSL if account.use_ssl else imaplib.IMAP4
            mail = cls(account.server, account.port)
        else:
            cls = DeadlineIMAP4SSL if account.use_ssl else DeadlineIMAP4
            mail = cls(account.server, account.port, deadline=deadline)
        track_imap_connection(mail)
        stage = "login"
        mail.login(account.username or account.email, account.password)
        stage = "select"
        status, _ = mail.select(account.mailbox or "INBOX", readonly=True)
        if status != "OK":
            raise ImapMailError(f"无法打开邮箱目录 {account.mailbox!r}", stage=stage)
        return mail
    except (ImapMailError, ImapDeadlineExpired):
        _close(mail)
        raise
    except imaplib.IMAP4.error as exc:
        _close(mail)
        raise ImapMailError(f"IMAP 登录失败: {exc}", stage=stage) from exc
    except Exception as exc:
        _close(mail)
        raise ImapMailError(f"IMAP 连接失败: {exc}", stage=stage) from exc


@dataclass(repr=False)
class _SearchState:
    connection: object = None
    uid_validity: bytes | None = None
    seen: set[bytes] = field(default_factory=set)
    headers: dict[bytes, bytes] = field(default_factory=dict)
    items: dict[bytes, dict] = field(default_factory=dict)
    body_uids: set[bytes] = field(default_factory=set)
    window: list[bytes] = field(default_factory=list)
    since_day: object = None
    window_limit: int = 0
    highest_uid: int = 0
    last_scan: float = 0.0
    scan_interval: float = 0.0

    def clear(self):
        self.seen.clear()
        self.headers.clear()
        self.items.clear()
        self.body_uids.clear()
        self.window.clear()
        self.since_day = None
        self.window_limit = 0
        self.highest_uid = 0
        self.last_scan = 0.0


class ImapSharedStateError(ImapMailError):
    retryable = False


@dataclass(repr=False)
class _SharedInbox:
    credential_digest: str
    lock: object = field(default_factory=threading.Lock)
    state: _SearchState = field(default_factory=lambda: _SearchState(scan_interval=1.0))
    mail: object = None
    generation: int = 0
    connection_generation: int = -1
    users: int = 0
    last_used: float = field(default_factory=time.monotonic)
    retired: bool = False
    blocked: ImapFetchLimitError | None = None
    active_deadline: ImapDeadline | None = None
    next_refresh: float = 0.0
    targets: dict[str, int] = field(default_factory=dict)


_SHARED_LOCK = threading.Lock()
_SHARED_INBOXES: dict[tuple, _SharedInbox] = {}
_SHARED_LIMIT = 16


def _inbox_key(account):
    folder = account.mailbox or "INBOX"
    if folder.upper() == "INBOX":
        folder = "INBOX"
    return (account.server.strip().lower(), account.port, account.use_ssl,
            account.username or account.email, folder)


def _disconnect_shared(inbox):
    mail, inbox.mail = inbox.mail, None
    _close(mail)
    inbox.state.connection = None


def _claim_shared_inbox(account):
    key = _inbox_key(account)
    digest = hashlib.sha256(account.password.encode()).hexdigest()
    with _SHARED_LOCK:
        inbox = _SHARED_INBOXES.get(key)
        if inbox is not None and inbox.retired:
            raise ImapSharedStateError("共享 IMAP 连接正在关闭，请稍后查询", error_code="imap_context_changed")
        if inbox is None:
            if len(_SHARED_INBOXES) >= _SHARED_LIMIT:
                idle = [(k, v) for k, v in _SHARED_INBOXES.items() if not v.users]
                if not idle:
                    raise ImapSharedStateError("共享 IMAP 收件箱连接均忙，请稍后查询", error_code="imap_pool_busy")
                old_key, old = min(idle, key=lambda item: item[1].last_used)
                old.retired = True
                _disconnect_shared(old)
                old.state.clear()
                del _SHARED_INBOXES[old_key]
            inbox = _SharedInbox(credential_digest=digest)
            _SHARED_INBOXES[key] = inbox
        elif inbox.credential_digest != digest:
            inbox.credential_digest = digest
            inbox.generation += 1
        inbox.users += 1
        target = account.email.strip().lower()
        inbox.targets[target] = inbox.targets.get(target, 0) + 1
        return inbox, inbox.generation


def _release_shared_inbox(inbox, account=None):
    with _SHARED_LOCK:
        inbox.users -= 1
        if account is not None:
            target = account.email.strip().lower()
            remaining = inbox.targets.get(target, 1) - 1
            if remaining:
                inbox.targets[target] = remaining
            else:
                inbox.targets.pop(target, None)
        inbox.last_used = time.monotonic()
        if not inbox.users and inbox.retired:
            for key in [k for k, value in _SHARED_INBOXES.items() if value is inbox]:
                del _SHARED_INBOXES[key]
            _disconnect_shared(inbox)
            inbox.state.clear()


def close_shared_imap_connections():
    """Close local clients, including cached quota errors; never sends an OTP."""
    with _SHARED_LOCK:
        entries = list(_SHARED_INBOXES.values())
        for inbox in entries:
            inbox.retired = True
        for key in [k for k, value in _SHARED_INBOXES.items() if not value.users]:
            del _SHARED_INBOXES[key]
    for inbox in entries:
        active = inbox.active_deadline
        if active is not None:
            active.cancel()
        if inbox.lock.acquire(blocking=False):
            try:
                _disconnect_shared(inbox)
                inbox.state.clear()
            finally:
                inbox.lock.release()


atexit.register(close_shared_imap_connections)


def _check_shared_generation(inbox, generation):
    if inbox.retired or inbox.generation != generation:
        raise ImapSharedStateError("IMAP 收件箱配置已变更，本次等待已停止", error_code="imap_context_changed")


@contextmanager
def _shared_connection(inbox, generation, account, deadline, *, cached_ok=False, cache_after_ts=None,
                       exclude_codes=None):
    # Waiting callers have no socket bound to their timer, so their deadline
    # cannot close the connection currently borrowed by another caller.
    if not inbox.lock.acquire(timeout=deadline.remaining()):
        raise ImapDeadlineExpired("等待共享 IMAP 连接超时")
    owns_connection = False
    try:
        _check_shared_generation(inbox, generation)
        if inbox.blocked is not None:
            raise ImapFetchLimitError(inbox.blocked.stage)
        if inbox.connection_generation != generation:
            _disconnect_shared(inbox)
            inbox.state.clear()
        if cached_ok and cache_after_ts is not None and _cached_messages(inbox.state, account, cache_after_ts, exclude_codes):
            yield None, inbox.state
            return
        if cached_ok and time.monotonic() < inbox.next_refresh:
            yield None, inbox.state
            return
        if cached_ok:
            # Reserve the receiver-wide refresh before connecting, including
            # failures. Concurrent aliases cannot turn one minute into N polls.
            inbox.next_refresh = time.monotonic() + _REMOTE_REFRESH_SECONDS
        inbox.active_deadline = deadline
        owns_connection = True
        if inbox.mail is None:
            inbox.mail = _connect(account, deadline=deadline)
            inbox.connection_generation = generation
            logger.info("[IMAP] 已建立共享收件箱连接，转发地址共用，不按目标地址另起连接")
        inbox.mail._deadline = deadline
        deadline.bind_socket(inbox.mail.sock)
        _check_shared_generation(inbox, generation)
        yield inbox.mail, inbox.state
        deadline.remaining()
        _check_shared_generation(inbox, generation)
        if not deadline.release_socket(inbox.mail.sock):
            raise ImapDeadlineExpired("IMAP 查询已到截止时间")
    except BaseException as exc:
        if isinstance(exc, ImapFetchLimitError):
            inbox.blocked = exc
            inbox.state.clear()
        if owns_connection:
            deadline.close_socket()
            _disconnect_shared(inbox)
        raise
    finally:
        inbox.active_deadline = None
        inbox.last_used = time.monotonic()
        inbox.lock.release()


_HEADER_FIELDS = (
    "DATE FROM TO SUBJECT DELIVERED-TO X-ORIGINAL-TO X-FORWARDED-TO RESENT-TO "
    "MIME-VERSION CONTENT-TYPE CONTENT-TRANSFER-ENCODING"
)
_TEXT_LIMIT = 64 * 1024


def _message_item(raw: bytes) -> dict:
    msg = email_lib.message_from_bytes(raw)
    item = _msg_to_dict(msg)
    item["xForwardedTo"] = _decode_email_header(msg.get("X-Forwarded-To") or "")
    item["resentTo"] = _decode_email_header(msg.get("Resent-To") or "")
    return item


def _message_timestamp(item):
    try:
        return datetime.fromisoformat(str(item.get("date") or "").replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _mailbox_expunged(mail):
    responses = getattr(mail, "untagged_responses", None)
    if not isinstance(responses, dict):
        return False
    expunged = responses.pop("EXPUNGE", None)
    vanished = responses.pop("VANISHED", None)
    return bool(expunged or vanished)


def _search_messages(mail, after_dt: datetime, *, account: ImapEmailAccount,
                     state: _SearchState, limit: int = 20,
                     deadline: ImapDeadline | None = None,
                     recipients: set[str] | None = None) -> list[dict]:
    reconnected = state.connection is not mail
    if reconnected:
        _name, validity = mail.response("UIDVALIDITY")
        validity = validity[0] if validity and isinstance(validity[0], bytes) else None
        if validity is None or validity != state.uid_validity:
            state.clear()
        state.connection, state.uid_validity = mail, validity
    since_day = after_dt.date()
    expunged = _mailbox_expunged(mail)
    # One inbox cursor covers the earliest requested day. A later caller must
    # not narrow it and make an older concurrent caller miss new mail.
    wider_day = state.since_day is None or since_day < state.since_day
    rescan = reconnected or wider_day or limit > state.window_limit or expunged
    if rescan or time.monotonic() - state.last_scan >= state.scan_interval:
        search_day = since_day if wider_day else state.since_day
        criteria = f'SINCE {search_day.strftime("%d-%b-%Y")}'
        lower_uid = state.highest_uid + 1
        query = criteria if rescan else f"UID {lower_uid}:* {criteria}"
        status, result = mail.uid("SEARCH", None, f"({query})")
        _check_status(status, result, stage="uid_search")
        # UID SEARCH may report EXPUNGE while it runs. Reconcile membership
        # once rather than returning a deleted message from the shared cache.
        changed = _mailbox_expunged(mail)
        if changed:
            rescan = True
            status, result = mail.uid("SEARCH", None, f"({criteria})")
            _check_status(status, result, stage="uid_search")
        ids = {uid for part in result or [] if isinstance(part, bytes)
               for uid in part.split() if uid.isdigit() and int(uid) > 0}
        if not rescan:
            # n:* can include the last OLD UID when n exceeds the maximum.
            ids = {uid for uid in ids if int(uid) >= lower_uid}
        state.highest_uid = max(state.highest_uid, max(map(int, ids), default=0))
        state.window_limit = max(limit, state.window_limit)
        members = ids if rescan else set(state.window) | ids
        state.window = sorted(members, key=int)[-state.window_limit:]
        # Keep a bounded union across date windows. A recent-mail lookup that
        # crosses midnight must not force another caller to re-download bodies.
        keep = set(sorted(set(state.headers) | set(state.window), key=int)[-state.window_limit:])
        state.headers = {uid: raw for uid, raw in state.headers.items() if uid in keep}
        state.items = {uid: item for uid, item in state.items.items() if uid in keep}
        state.body_uids.intersection_update(keep)
        state.seen.intersection_update(keep)
        state.since_day, state.last_scan = search_day, time.monotonic()
    new_ids = [uid for uid in state.window if uid not in state.headers or uid not in state.items]
    if new_ids:
        status, data = mail.uid("FETCH", b",".join(new_ids), f"(UID BODY.PEEK[HEADER.FIELDS ({_HEADER_FIELDS})])")
        _check_status(status, data, stage="fetch_headers")
        pending_header = None
        for part in data or []:
            if isinstance(part, tuple) and len(part) > 1 and isinstance(part[1], bytes):
                uid = re.search(rb"\bUID\s+(\d+)\b", part[0], re.IGNORECASE)
                pending_header = None if uid else part[1]
                if uid and uid.group(1) in new_ids:
                    state.headers[uid.group(1)] = part[1]
            elif isinstance(part, bytes) and pending_header is not None:
                # RFC-compliant servers may put UID after the literal.
                uid = re.search(rb"\bUID\s+(\d+)\b", part, re.IGNORECASE)
                if uid and uid.group(1) in new_ids:
                    state.headers[uid.group(1)] = pending_header
                    pending_header = None
        for uid in new_ids:
            if uid in state.headers:
                state.items[uid] = _message_item(state.headers[uid])
                state.seen.add(uid)
    messages: list[dict] = []
    for uid in reversed(state.window[-limit:]):
        if deadline is not None:
            deadline.remaining()
        raw_header = state.headers.get(uid)
        if not raw_header:
            continue
        item = state.items[uid]
        stamp = _message_timestamp(item)
        if (stamp or account.forwarded) and stamp < after_dt.timestamp():
            continue
        header_match = _matches_recipient(item, account.email, forwarded=False)
        wanted = header_match or bool(recipients and _recipient_addresses(item, forwarded=False) & recipients)
        if not wanted and not (
            account.forwarded and account.username and
            _matches_recipient(item, account.username, forwarded=False)
        ):
            continue
        if wanted and looks_like_openai_email(item) and extract_otp(item):
            if header_match:
                messages.append(dict(item))
            continue
        # Manual forwards can put the original recipient only in the body.
        # Read a bounded MIME text prefix once, never an entire RFC822 message.
        if uid not in state.body_uids:
            status, parts = mail.uid("FETCH", uid, f"(UID BODY.PEEK[TEXT]<0.{_TEXT_LIMIT}>)")
            _check_status(status, parts, stage="fetch_text")
            text = next((part[1] for part in parts or [] if isinstance(part, tuple)
                         and len(part) > 1 and isinstance(part[1], bytes)), None)
            if text is not None:
                item = _message_item(raw_header.rstrip(b"\r\n") + b"\r\n\r\n" + text[:_TEXT_LIMIT])
                state.items[uid] = item
                state.body_uids.add(uid)
        if uid in state.body_uids and _matches_recipient(item, account.email, forwarded=account.forwarded):
            messages.append(dict(item))
    return messages


_FORWARDED_TO_LINE = re.compile(r"^\s*(?:to|original-to|delivered-to|收件人|发送给)\s*[:：]\s*(.+)$", re.IGNORECASE)


def _recipient_addresses(item: dict, *, forwarded: bool) -> set[str]:
    values = [str(item[key]) for key in ("to", "xOriginalTo", "deliveredTo", "xForwardedTo", "resentTo")
              if item.get(key)]
    if forwarded:
        # Manual forwards commonly preserve original headers only in the body.
        values.extend(match.group(1) for line in str(item.get("text") or "").splitlines()[:40]
                      if (match := _FORWARDED_TO_LINE.match(line)))
    return {address.strip().lower() for _, address in getaddresses(values) if address}


def _matches_recipient(item: dict, email: str, *, forwarded: bool) -> bool:
    """Match the exact original recipient, never a substring of another alias."""
    return email.strip().lower() in _recipient_addresses(item, forwarded=forwarded)


def _cached_messages(state, account, after_ts, exclude_codes=None):
    cutoff = max(after_ts - 30, time.time() - imap_message_cache.TTL_SECONDS)
    return [dict(item) for item in state.items.values()
            if cutoff <= _message_timestamp(item) <= time.time() + 30
            and looks_like_openai_email(item) and extract_otp(item)
            and extract_otp(item) not in (exclude_codes or ())
            and _matches_recipient(item, account.email, forwarded=account.forwarded)]


def _cache_snapshot(account, state):
    """Retain only one day's mail; publish codes for every exact alias in a batch."""
    now = time.time()
    expired = {uid for uid, item in state.items.items()
               if _message_timestamp(item) < now - imap_message_cache.TTL_SECONDS}
    for uid in expired:
        state.headers.pop(uid, None)
        state.items.pop(uid, None)
    state.body_uids.difference_update(expired)
    state.seen.difference_update(expired)
    state.window = [uid for uid in state.window if uid not in expired]
    oldest_day = datetime.fromtimestamp(now - imap_message_cache.TTL_SECONDS, timezone.utc).date()
    if state.since_day is not None and state.since_day < oldest_day:
        state.since_day = oldest_day
    if not account.cache_enabled:
        return
    records = []
    for item in state.items.values():
        if not looks_like_openai_email(item) or not extract_otp(item):
            continue
        recipients = _recipient_addresses(item, forwarded=account.forwarded)
        if account.forwarded:
            recipients.discard(account.username.strip().lower())
        for recipient in recipients:
            # Store only the normalized code-bearing portion, not attachments,
            # full HTML, credentials or unrelated messages in the shared inbox.
            cached = {"to": recipient, "date": item.get("date"), "from": item.get("from"),
                      "subject": str(item.get("subject") or "")[:512],
                      "text": "Verification code: " + extract_otp(item)}
            records.append((recipient, cached, _message_timestamp(item)))
    try:
        imap_message_cache.write(account, records)
    except (OSError, ValueError, imap_message_cache.sqlite3.Error):
        logger.warning("[IMAP] 本地邮件缓存写入失败，保留进程缓存，不输出邮件内容")


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    account = get_account_context(email)
    if account is None:
        raise ImapMailError(f"邮箱池中找不到 IMAP 账号: {email}")
    if account.forwarded and not account.password:
        raise _missing_forwarded_authorization(account)
    after_ts = float(after_ts or time.time())
    max_wait = max(0, min(_OTP_WAIT_SECONDS, int(max_wait if max_wait is not None else _OTP_WAIT_SECONDS)))
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    after_dt = datetime.fromtimestamp(max(after_ts - 30, time.time() - imap_message_cache.TTL_SECONDS), tz=timezone.utc)
    best_otp, best_ts, settle_until = None, 0.0, None
    polls = remote_scans = matched = candidates = connection_errors = 0

    logger.info("[IMAP] 开始轮询 %s (%s:%s, SSL=%s)", email, account.server, account.port, account.use_ssl)
    inbox = None
    generation = None
    excluded = set(exclude_codes or ())
    with ImapDeadline(max_wait) as deadline:
        try:
            while time.monotonic() < deadline.expires_at:
                polls += 1
                try:
                    disk_messages = []
                    if account.cache_enabled:
                        try:
                            disk_messages = imap_message_cache.read(account, email, after_ts - 30)
                            disk_messages = [item for item in disk_messages if extract_otp(item) not in excluded]
                        except (OSError, ValueError, imap_message_cache.sqlite3.Error):
                            logger.warning("[IMAP] 本地邮件缓存读取失败，使用共享收件箱缓存")
                    if disk_messages:
                        messages = disk_messages
                    else:
                        if inbox is None:
                            inbox, generation = _claim_shared_inbox(account)
                        with _shared_connection(inbox, generation, account, deadline, cached_ok=True,
                                                cache_after_ts=after_ts, exclude_codes=excluded) as (mail, state):
                            messages = _cached_messages(state, account, after_ts, excluded)
                            if not messages and mail is not None:
                                remote_scans += 1
                                logger.info("[IMAP] 本地未命中，刷新共享收件箱；远端间隔60s，邮件缓存24小时")
                                # Refresh today's mail once for all aliases, including
                                # a request window crossing midnight (at most one day).
                                midnight = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
                                scan_after = max(min(after_dt, midnight.astimezone(timezone.utc)),
                                                 datetime.fromtimestamp(time.time() - imap_message_cache.TTL_SECONDS, timezone.utc))
                                messages = _search_messages(mail, scan_after, account=account, state=state,
                                    limit=100 if account.forwarded else 20, deadline=deadline,
                                    recipients=set(inbox.targets))
                                _cache_snapshot(account, state)
                                if account.cache_enabled:
                                    messages = _cached_messages(state, account, after_ts, excluded)
                except ImapDeadlineExpired:
                    break
                except ImapFetchLimitError as exc:
                    logger.warning("[IMAP] 查询已停止：stage=%s code=%s；邮箱服务商取信额度超限，不再重试", exc.stage, exc.error_code)
                    raise
                except (ImapMailError, imaplib.IMAP4.error, OSError) as exc:
                    if getattr(exc, "retryable", True) is False:
                        raise
                    connection_errors += 1
                    if time.monotonic() >= deadline.expires_at:
                        break
                    logger.warning("[IMAP] 查询暂时失败：stage=%s code=%s type=%s",
                                   getattr(exc, "stage", "transport"),
                                   getattr(exc, "error_code", "imap_transport_error"), type(exc).__name__)
                    messages = []

                messages.sort(key=lambda item: item.get("date") or "", reverse=True)
                for item in messages:
                    if not _matches_recipient(item, email, forwarded=account.forwarded):
                        continue
                    matched += 1
                    if not looks_like_openai_email(item):
                        continue
                    otp = extract_otp(item)
                    if not otp or otp in excluded:
                        continue
                    candidates += 1
                    ts = _message_timestamp(item)
                    if (ts or account.forwarded) and ts < after_ts - 30:
                        continue
                    if ts >= best_ts and otp != best_otp:
                        best_otp, best_ts, settle_until = otp, ts, time.monotonic() + settle
                        logger.info("[IMAP] 已找到目标邮件验证码，等待 %ss settle", settle)
                    break
                now = time.monotonic()
                if best_otp and settle_until is not None and now >= settle_until:
                    return best_otp
                wake_at = min(deadline.expires_at, now + max(1, interval), settle_until or float("inf"))
                time.sleep(max(0.0, wake_at - now))
        finally:
            deadline.close_socket()
            if inbox is not None:
                _release_shared_inbox(inbox, account)

    if best_otp:
        return best_otp
    raise ImapOtpTimeout(
        f"等待 {email} 的 OTP 超时（>{max_wait}s）；本地检查 {polls} 次，远端刷新 {remote_scans} 次，"
        f"匹配目标邮件 {matched} 封，验证码候选 {candidates} 个，连接错误 {connection_errors} 次"
    )


def fetch_latest_otp_any(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
):
    """Explicit mailbox lookup: any sender, any code shape.

    Reads the shared inbox once, reusing the same snapshot cache as the
    registration path. It never sends mail and never claims a pool account.
    """
    from core.otp_read import OTPRead
    from core.otp_utils import extract_otp_any

    account = get_account_context(email)
    if account is None:
        raise ImapMailError(f"邮箱池中找不到 IMAP 账号: {email}")
    if account.forwarded and not account.password:
        raise _missing_forwarded_authorization(account)
    after_ts = float(after_ts or time.time())
    wait = max(0, min(_OTP_WAIT_SECONDS, int(max_wait if max_wait is not None else _OTP_WAIT_SECONDS)))
    after_dt = datetime.fromtimestamp(
        max(after_ts - 30, time.time() - imap_message_cache.TTL_SECONDS), tz=timezone.utc)
    inbox = None
    generation = None
    messages = []
    with ImapDeadline(wait) as deadline:
        try:
            if account.cache_enabled:
                try:
                    messages = imap_message_cache.read(account, email, after_ts - 30)
                except (OSError, ValueError, imap_message_cache.sqlite3.Error):
                    logger.warning("[IMAP] 本地邮件缓存读取失败，使用共享收件箱缓存")
            if not messages:
                inbox, generation = _claim_shared_inbox(account)
                with _shared_connection(inbox, generation, account, deadline, cached_ok=True,
                                        cache_after_ts=after_ts) as (mail, state):
                    messages = [dict(item) for item in state.items.values()]
                    if mail is not None:
                        messages = _search_messages(
                            mail, after_dt, account=account, state=state,
                            limit=100 if account.forwarded else 20, deadline=deadline,
                            recipients=set(inbox.targets))
                        _cache_snapshot(account, state)
        except ImapDeadlineExpired:
            messages = []
        except ImapFetchLimitError:
            raise
        finally:
            deadline.close_socket()
            if inbox is not None:
                _release_shared_inbox(inbox, account)
    messages.sort(key=lambda item: _message_timestamp(item), reverse=True)
    excluded = set(exclude_codes or ())
    for item in messages:
        if not _matches_recipient(item, email, forwarded=account.forwarded):
            continue
        if _message_timestamp(item) < after_ts - 30:
            continue
        read = extract_otp_any(item)
        read.candidates = [value for value in read.candidates if value not in excluded]
        if read.candidates:
            return OTPRead(read.candidates[0], read.candidates,
                           subject=read.subject, received_at=read.received_at)
    raise ImapOtpTimeout(f"{email} 最近没有可用的验证码邮件")
