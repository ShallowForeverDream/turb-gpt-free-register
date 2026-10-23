"""Per-registration HTTP accounting; never stores headers, bodies or URL queries."""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime
from functools import wraps
import logging
from numbers import Real
import re
import threading
import time
from urllib.parse import unquote, urlsplit

logger = logging.getLogger(__name__)
_ACTIVE = ContextVar("protocol_registration_traffic", default=None)


def current_traffic():
    meter = _ACTIVE.get()
    # submit_with_driver copies ContextVars to background plan/2FA queues. Their
    # traffic belongs to a separate task and must not alter this registration.
    if meter is not None and meter.owner_thread == threading.get_ident() and not meter.closed:
        return meter
    return None


def endpoint_key(url: str) -> str:
    parts = urlsplit(str(url))
    # Query strings can carry email addresses, OAuth codes and proxy credentials.
    path = re.sub(r"[^/]*@[^/]*|[A-Za-z0-9_-]{24,}", ":id", unquote(parts.path))
    return f"{parts.hostname or '?'}{path or '/'}"


def _size(value):
    return max(0, int(value)) if isinstance(value, Real) and not isinstance(value, bool) else None


class ProtocolTraffic:
    def __init__(self, *, low_traffic: bool, budget_bytes: int):
        self.owner_thread = threading.get_ident()
        self.closed = False
        self.low_traffic = low_traffic
        self.budget_bytes = max(1, budget_bytes)
        self.started_at = datetime.now().isoformat(timespec="seconds")
        self.started_perf = time.perf_counter()
        self.upload = self.download = self.decoded_download = 0
        self.requests = self.failed = self.unknown = self.redirects = 0
        self.by_path = {}
        self.skipped = {}

    def record(self, url, response=None, *, failed=False):
        upload = download = decoded = 0
        self.requests += 1
        self.failed += int(failed)
        if response is not None:
            sizes = [_size(getattr(response, key, None)) for key in (
                "upload_size", "request_size", "download_size", "header_size",
            )]
            self.unknown += int(any(value is None for value in sizes))
            upload = (sizes[0] or 0) + (sizes[1] or 0)
            download = (sizes[2] or 0) + (sizes[3] or 0)
            content = getattr(response, "content", b"")
            if isinstance(content, (bytes, bytearray)):
                decoded = len(content)
            redirects = _size(getattr(response, "redirect_count", 0)) or 0
            self.redirects += redirects
            self.requests += redirects
        else:
            self.unknown += 1
        self.upload += upload
        self.download += download
        self.decoded_download += decoded
        key = endpoint_key(url)
        if key not in self.by_path and len(self.by_path) >= 80:
            key = "other"
        item = self.by_path.setdefault(key, {"request_count": 0, "upload_bytes": 0, "download_bytes": 0})
        item["request_count"] += 1
        item["upload_bytes"] += upload
        item["download_bytes"] += download

    def skip(self, label):
        self.skipped[label] = self.skipped.get(label, 0) + 1

    def snapshot(self):
        total = self.upload + self.download
        complete = bool(self.requests) and not (self.failed or self.unknown or self.redirects)
        # A missing/partial failed response or an automatically followed redirect
        # can hide transfer bytes. A small subtotal must not certify the budget.
        within = False if total > self.budget_bytes else (True if complete else None)
        return {
            "available": True,
            "method": "curl_cffi.transfer_sizes",
            "scope": "registration_thread_browser_sessions",
            "low_traffic": self.low_traffic,
            "started_at": self.started_at,
            "duration_seconds": round(time.perf_counter() - self.started_perf, 3),
            "upload_bytes": self.upload,
            "download_bytes": self.download,
            "total_bytes": total,
            "decoded_download_bytes": self.decoded_download,
            "request_count": self.requests,
            "failed_request_count": self.failed,
            "unknown_size_request_count": self.unknown,
            "automatic_redirect_count": self.redirects,
            "measurement_complete": complete,
            "budget_bytes": self.budget_bytes,
            "within_budget": within,
            "by_path": {key: dict(value) for key, value in self.by_path.items()},
            "skipped": dict(self.skipped),
            "note": "libcurl HTTP 传输估算（压缩响应体及可见头）；不含 TLS/IP/代理开销、邮箱客户端和后台任务。自动重定向及异常可能漏计，以代理商双向账单为准。",
        }

    def log_summary(self):
        data = self.snapshot()
        budget = {True: "范围内", False: "超出", None: "待核对"}[data["within_budget"]]
        logger.info(
            "[协议流量] 上传=%sB 下载=%sB 合计=%sB 请求=%s 失败=%s 预算=%sB（%s）",
            self.upload, self.download, data["total_bytes"], self.requests, self.failed, self.budget_bytes, budget,
        )
        for path, item in sorted(self.by_path.items(), key=lambda entry: entry[1]["download_bytes"], reverse=True)[:5]:
            logger.info("[协议流量] %s requests=%s download=%sB", path, item["request_count"], item["download_bytes"])
        return data


def capture_protocol_registration(fn):
    """Aggregate sessions/retries in this registration, separate from other workers."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        from config import openai_protocol as cfg
        from core.workflow_driver import resolve_driver

        if resolve_driver() != "protocol":
            return fn(*args, **kwargs)
        meter = ProtocolTraffic(
            low_traffic=bool(cfg.PROTOCOL_LOW_TRAFFIC),
            budget_bytes=int(cfg.PROTOCOL_TRAFFIC_BUDGET_BYTES),
        )
        token = _ACTIVE.set(meter)
        logger.info("[协议省流] 模式=%s，预算=%sB；任务内保留独立 Cookie/会话", "开启" if meter.low_traffic else "完整", meter.budget_bytes)
        try:
            result = fn(*args, **kwargs)
            if isinstance(result, dict):
                result["network_traffic"] = meter.snapshot()
            return result
        finally:
            try:
                meter.log_summary()
            except Exception:
                logger.warning("[协议流量] 汇总失败，注册结果保留", exc_info=True)
            finally:
                meter.closed = True
                _ACTIVE.reset(token)
    return wrapped


def skip_optional_bootstrap(session, label):
    if getattr(session, "protocol_low_traffic", False) is not True:
        return False
    meter = getattr(session, "protocol_traffic", None)
    if meter is not None:
        meter.skip(label)
    logger.info("[协议省流] 跳过 %s 的可选应用初始化", label)
    return True
