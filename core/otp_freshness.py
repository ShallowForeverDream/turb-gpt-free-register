"""Fail-closed mail freshness checks, independent of authentication requests."""
import hashlib
import math
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime


_REASONS = {
    "missing_send_time": "没有本次发码时间，无法确认验证码时效",
    "missing_metadata": "接口仅返回验证码，缺少可核验的收件时间或邮件 ID",
    "timezone_missing": "邮件时间没有时区，且无有效的发码前邮件 ID 基线",
    "invalid_time": "邮件时间无法解析，且无有效的发码前邮件 ID 基线",
    "future_time": "邮件时间晚于当前时间，无法可靠比较",
    "old_mail": "邮件时间早于本次发码，只收到旧邮件",
    "unchanged_id": "邮件 ID 与发码前相同，未检测到新邮件",
    "missing_baseline": "没有有效的发码前邮件基线，不能确认新旧",
    "missing_code_baseline": "只有验证码数据，且没有成功取得发码前对照；不能确认新旧",
    "snapshot_timeout": "发码前读取邮箱基线超时；已停止后续步骤",
    "snapshot_tls_error": "发码前邮箱接口 TLS 握手或证书校验失败；已停止后续步骤",
    "snapshot_network_error": "发码前邮箱接口连接失败；已停止后续步骤",
    "snapshot_http_error": "发码前邮箱接口返回非成功状态；已停止后续步骤",
    "snapshot_invalid_response": "发码前邮箱接口响应格式无效；已停止后续步骤",
    "snapshot_mailbox_missing": "找不到该邮箱的取码配置，无法建立发码前基线",
    "mail_tls_error": "邮箱接口 TLS 握手或证书校验失败；没有关闭证书校验或继续提交",
    "code_history_unproven": "历史验证码列表的变化不能证明属于本次发码，仍需邮件时间或邮件 ID 证据",
    "code_history_invalid": "历史码列表格式不合法或超过读取上限，不能作为完整对照",
    "unchanged_code_set": "取码接口仍返回发码前已有的历史验证码，尚未出现本次新码",
    "snapshot_wait": "仅有验证码数值时，发码后尚未等待满 60 秒",
    "code_history_mismatch": "接口当前验证码不在其历史码列表中，响应自相矛盾",
    "multiple_new_codes": "发码后出现多个不同的新验证码，接口没有指明哪一个是最新",
    "recipient_mismatch": "返回邮件的目标邮箱与当前邮箱不一致",
    "excluded_code": "候选验证码已被拒绝，不再提交",
}


class OtpFreshnessError(RuntimeError):
    retryable = False
    error_code = "mail_otp_freshness_unverified"

    def __init__(self, reason: str, *, waitable: bool = False):
        self.reason = reason
        self.waitable = waitable
        super().__init__(f"{self.error_code}: {_REASONS[reason]}；未提交验证码，需人工核验")


def endpoint_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def failure_message(error: object) -> str:
    if "返回了邮件 ID，但没有有效的发码前基线" in str(error):
        return "没有有效的发码前基线；历史错误未保留快照失败类型，不能据此断言存在邮件 ID"
    return next((msg for msg in _REASONS.values() if msg in str(error)), "缺少可靠的新邮件证据")


@dataclass(frozen=True)
class MailBaseline:
    email: str
    endpoint: str
    observed_at: float
    mail_ids: frozenset[str] | None
    code_key: bytes | None = field(default=None, repr=False, compare=False)
    code_fingerprints: frozenset[str] | None = field(default=None, repr=False)


def _valid_code(value) -> str:
    text = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    return text if len(text) == 6 and text.isascii() and text.isdigit() else ""


def _code_fingerprint(code: str, key: bytes) -> str:
    return hashlib.blake2s(code.encode("ascii"), key=key, digest_size=16).hexdigest()


def new_code_candidates(baseline: MailBaseline, codes) -> tuple[str, ...]:
    """Return only codes not observed in a known pre-send snapshot."""
    if baseline.code_key is None or baseline.code_fingerprints is None:
        return ()
    normalized = {_valid_code(value) for value in codes}
    normalized.discard("")
    return tuple(sorted(code for code in normalized
                        if _code_fingerprint(code, baseline.code_key) not in baseline.code_fingerprints))


def new_mail_baseline(*, email: str, url: str, observed_at: float,
                      mail_ids: frozenset[str] | None, codes) -> MailBaseline:
    normalized = frozenset(filter(None, (_valid_code(value) for value in (codes or ()))))
    key = secrets.token_bytes(32) if codes is not None else None
    fingerprints = frozenset(_code_fingerprint(code, key) for code in normalized) if key else None
    return MailBaseline(email.strip().lower(), endpoint_key(url), observed_at,
                        mail_ids, key, fingerprints)


def parse_mail_time(value):
    if value is None or value == "":
        return None, "missing_metadata"
    if isinstance(value, bool):
        return None, "invalid_time"
    try:
        ts = float(value)
    except (ValueError, TypeError):
        text = str(value).strip()
        try:
            date = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                date = parsedate_to_datetime(text)
            except (ValueError, TypeError):
                return None, "invalid_time"
        if date.tzinfo is None or date.utcoffset() is None:
            return None, "timezone_missing"
        try:
            ts = date.timestamp()
        except (ValueError, OverflowError, OSError):
            return None, "invalid_time"
    else:
        if ts > 10_000_000_000:
            ts /= 1000
    return (ts, None) if math.isfinite(ts) else (None, "invalid_time")


def verify_mail_freshness(meta: dict, *, email: str, url: str, after_ts: float | None,
                          now: float, baseline: MailBaseline | None = None,
                          candidate_code=None, code_history=None) -> str:
    if after_ts is None or isinstance(after_ts, bool) or not math.isfinite(after_ts):
        raise OtpFreshnessError("missing_send_time")
    recipient = str(meta.get("recipient") or "").strip().lower()
    if recipient and recipient != email.strip().lower():
        raise OtpFreshnessError("recipient_mismatch")
    value = meta.get("mail_id")
    mail_id = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    base_bound = (isinstance(baseline, MailBaseline)
                  and baseline.email == email.strip().lower()
                  and baseline.endpoint == endpoint_key(url)
                  and 0 <= after_ts - baseline.observed_at <= 30)
    candidate = _valid_code(candidate_code)
    if (base_bound and baseline.code_key and baseline.code_fingerprints is not None
            and candidate and _code_fingerprint(candidate, baseline.code_key) in baseline.code_fingerprints):
        raise OtpFreshnessError("unchanged_code_set", waitable=True)
    id_bound = base_bound and baseline.mail_ids is not None
    if id_bound and mail_id and mail_id in baseline.mail_ids:
        raise OtpFreshnessError("unchanged_id", waitable=True)
    stamp, reason = parse_mail_time(meta.get("received_at"))
    if stamp is not None:
        if stamp > now + 5:
            raise OtpFreshnessError("future_time")
        if stamp < after_ts:
            raise OtpFreshnessError("old_mail", waitable=True)
        return "received_at"
    if id_bound and mail_id and mail_id not in baseline.mail_ids:
        return "changed_mail_id"
    if base_bound and baseline.code_key and baseline.code_fingerprints is not None and candidate:
        if code_history is not None:
            current = frozenset(filter(None, (_valid_code(value) for value in code_history)))
            if candidate not in current:
                raise OtpFreshnessError("code_history_mismatch")
        if now - after_ts < 60:
            raise OtpFreshnessError("snapshot_wait", waitable=True)
        return "new_code_since_snapshot"
    if mail_id and reason == "missing_metadata":
        reason = "missing_baseline"
    elif candidate and reason == "missing_metadata":
        reason = "missing_code_baseline"
    raise OtpFreshnessError(reason)
