# -*- coding: utf-8 -*-
"""账号查活后台队列：协议 BrowserSession 指纹环境 + 独立日志。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core import db, account_concurrency
from core.account_liveness import check_account_liveness, log_path
from core.chatgpt_plan import _mask_proxy, open_plan_check_proxy, resolve_plan_check_route

logger = logging.getLogger(__name__)

_WORKERS = 1
_MAX_WORKERS = 16
_QUEUE_LIMIT = 500
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="live-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_CAPACITY = threading.Condition(_LOCK)
_EXECUTION_SLOTS = account_concurrency.SLOTS


def configure_workers(workers: int) -> None:
    """Adjust the shared limit without stranding jobs in an old executor."""
    global _WORKERS
    workers = max(1, min(_MAX_WORKERS, int(workers)))
    with _CAPACITY:
        previous = _WORKERS
        _WORKERS = workers
        account_concurrency.configure_workers(workers)
        _CAPACITY.notify_all()
    if previous != workers:
        logger.info("[查活] 并发线程数从 %s 调整为 %s", previous, workers)


def is_checking(email: str) -> bool:
    acc = db.get_account_by_email(email)
    if not acc:
        return False
    return str(acc.get("live_check_status") or "") in {"queued", "running"}


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _is_retryable_live_result(result: dict) -> bool:
    """Only transport failures may rotate to another exit in the same pool."""
    if not isinstance(result, dict) or result.get("ok"):
        return False
    if result.get("status") in {"deactivated", "action_required", "blocked"}:
        return False
    text = str(result.get("error") or "").lower()
    return any(marker in text for marker in (
        "curl: (7)", "curl: (28)", "curl: (35)", "curl: (56)", "curl: (97)",
        "connect tunnel failed", "connection timed out", "connection reset",
        "ssl_error_syscall", "ssl_connect", "proxyerror", "timeout",
    ))


def _run_live_check(*, account_id: int, email: str, proxy: str | None, trigger: str, queue_slot_acquired: bool = False) -> dict:
    relay = None
    acquired = False
    route: dict = {}
    selected_proxy: str | None = None
    try:
        _EXECUTION_SLOTS.acquire()
        acquired = True
        with _CAPACITY:
            while int(account_id) in _RUNNING:
                _CAPACITY.wait()
            _RUNNING.add(int(account_id))
        if not db.mark_account_live_check_running(account_id):
            _append_log(email, "[查活] 账号已删除或查活状态已被重置，取消执行")
            return {"ok": False, "status": "failed", "error": "账号已删除或查活状态已被重置"}
        # 查活必须沿用账号注册时记录的邮箱来源。不能只调用
        # resolve_email_source(email)：Remail 等临时邮箱的上下文只在领取进程
        # 内存中存在，服务重启后按当前 EMAIL_SOURCE 推断会把来源判错。
        try:
            account = db.get_account(account_id) or {}
        except Exception:
            account = {}
        email_source = str(account.get("email_source") or "").strip() or None
        if email_source:
            _append_log(email, f"[查活] 使用注册时保存的邮箱来源：{email_source}")
        from config import proxy as proxy_cfg
        timeout = float(getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0) or 15.0)
        attempted_proxies: set[str] = set()
        saved_fingerprint_state: dict = {}
        if isinstance(account.get("live_check_fingerprint"), dict):
            saved = account["live_check_fingerprint"]
            if isinstance(saved.get("browser_profile"), dict):
                saved_fingerprint_state["browser_profile"] = dict(saved["browser_profile"])
        result: dict = {}
        for route_attempt in range(1, 4):
            route = resolve_plan_check_route(explicit_proxy=proxy, exclude_proxies=attempted_proxies)
            selected_proxy = str(route.get("proxy") or "").strip() or None
            if selected_proxy:
                attempted_proxies.add(selected_proxy)
            effective_proxy, relay = open_plan_check_proxy(
                route, selected_proxy or "", timeout=timeout,
            )
            _append_log(
                email,
                "[查活] 开始后台执行 "
                f"trigger={trigger} network_route={route.get('network_route')} "
                f"proxy_mode={route.get('proxy_mode')} proxy_used={route.get('proxy_used') or '-'} "
                f"fallback_reason={route.get('proxy_fallback_reason') or '-'} "
                f"(出口 {route_attempt}/3)"
            )
            # 每个网络路由尝试拥有自己的任务级身份状态；同一路由的完整认证链及
            # 内部重试复用同一组 device/session 标识，不同账号绝不共享。
            # The account's original device/profile is stable across exits; a
            # transport retry must not rotate it into a fresh identity.
            fingerprint_state: dict = dict(saved_fingerprint_state)
            result = check_account_liveness(
                email,
                proxy=effective_proxy,
                clear_log=False,
                email_source=email_source,
                fingerprint_state=fingerprint_state,
            )
            if result.get("ok") or not _is_retryable_live_result(result) or route_attempt >= 3:
                break
            _append_log(email, f"[查活] 当前出口网络异常，切换同一代理池的下一个出口重试（{route_attempt}/3）")
            try:
                if relay is not None:
                    relay.close()
            finally:
                relay = None
        db.update_account_liveness(account_id, result)
        if result.get("ok"):
            _append_log(email, "[查活] 完成：账号正常，已刷新最新 AT/accessToken")
        elif result.get("status") == "deactivated":
            _append_log(email, f"[查活] 完成：账号已废 {result.get('error') or ''}")
        elif result.get("status") == "blocked":
            _append_log(email, f"[查活] 已停止：{result.get('error') or ''}")
        elif result.get("status") == "action_required":
            _append_log(email, f"[查活] 等待用户操作：{result.get('error') or ''}")
        else:
            _append_log(email, f"[查活] 完成：失败 {result.get('error') or ''}")
        result.update({
            "network_route": route.get("network_route"),
            "proxy_used": _mask_proxy(selected_proxy) or None,
            "upstream_proxy_used": route.get("upstream_proxy_used"),
            "proxy_mode": route.get("proxy_mode"),
            "proxy_fallback_reason": route.get("proxy_fallback_reason"),
        })
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
        try:
            db.update_account_liveness(account_id, result)
        except Exception:
            logger.exception("[查活] 写入异常状态失败: account_id=%s", account_id)
        logger.exception("[查活] 后台异常: %s", email)
        try:
            _append_log(email, f"[查活] 后台异常：{result['error']}")
        except Exception:
            pass
        return result
    finally:
        try:
            if relay is not None:
                relay.close()
        finally:
            with _CAPACITY:
                _RUNNING.discard(int(account_id))
                _CAPACITY.notify_all()
            if acquired:
                _EXECUTION_SLOTS.release()
            if queue_slot_acquired:
                _QUEUE_SLOTS.release()


def enqueue_account_live_check(*, account_id: int, email: str, trigger: str = "manual", proxy: str | None = None) -> dict:
    from core.workflow_driver import require_driver_ready
    try:
        require_driver_ready()
    except (ValueError, RuntimeError) as exc:
        return {"accepted": False, "busy": False, "error": str(exc), "stage": "driver_configuration"}
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "查活队列已满，请稍后重试"}
    if not db.claim_account_live_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查活"}

    _append_log(email, f"[查活] 已入队 account_id={account_id} trigger={trigger} workers={queue_settings()['workers']}", clear=True)
    try:
        from core.workflow_driver import submit_with_driver
        submit_with_driver(
            _EXECUTOR, _run_live_check,
            account_id=account_id,
            email=email,
            proxy=proxy,
            trigger=str(trigger or "manual"),
            queue_slot_acquired=True,
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"查活入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_liveness(account_id, result)
        _append_log(email, result["error"])
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    with _LOCK:
        return {"workers": account_concurrency.queue_settings()["workers"],
                "queue_limit": _QUEUE_LIMIT, "running": len(_RUNNING)}
