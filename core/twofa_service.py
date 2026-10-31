# -*- coding: utf-8 -*-
"""账号 2FA/TOTP 后台设置队列。"""
from __future__ import annotations

from core.workflow_driver import unified_workflow
import logging
import threading
from datetime import datetime
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from config import email as _email_cfg
from config import twofa as _twofa_cfg
from core import db
from core import account_concurrency
from core.account_export import setup_2fa, TwofaOtpBlockedError
from core.session import BrowserSession, close_browser_session
from core.proxy_utils import mask_proxy_url

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(_twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("TWOFA_WORKERS", 4, 1, 16)
_QUEUE_LIMIT = _int_setting("TWOFA_QUEUE_LIMIT", 200, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="twofa")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_EXECUTION_SLOTS = account_concurrency.SLOTS
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA 入口只接受真实代理地址。

    注册流程里有些 `proxy_used` 字段保存的是环境标签，例如 `skyvern:jp`、
    `browser_use:jp`，这类不是 curl_cffi 可用代理，会导致 Unsupported proxy syntax。
    """
    text = str(proxy or "").strip()
    if not text:
        return None
    low = text.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        return text
    return None


def _resolve_twofa_proxy(proxy: str | None):
    """按 TWOFA_PROXY_MODE 解析传输代理。"""
    from core.workflow_driver import resolve_driver
    if resolve_driver() != "protocol":
        from core.chatgpt_plan import resolve_plan_check_route, open_plan_check_proxy
        route = resolve_plan_check_route()
        transport, relay = open_plan_check_proxy(route, route["proxy"], timeout=30)
        return transport, relay, "unified"
    mode = str(getattr(_twofa_cfg, "TWOFA_PROXY_MODE", "saved") or "saved").strip().lower()
    if mode not in {"saved", "pool"}:
        raise ValueError(f"TWOFA_PROXY_MODE={mode!r} 无效，可选 saved / pool")
    if mode == "pool":
        from core.proxy_chain import open_proxy_pool_proxy
        transport, relay = open_proxy_pool_proxy(None)
        return transport or None, relay, "pool"
    target = _normalize_proxy(proxy)
    if not target:
        # 没有可复用的目标代理时交给 BrowserSession 从代理池选择；
        # BrowserSession 会自行管理代理池链式中继生命周期。
        return None, None, "pool"
    from core.proxy_chain import open_proxy_pool_proxy

    transport, relay = open_proxy_pool_proxy(target)
    return transport, relay, "saved"


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _error_context(exc: Exception) -> tuple[str, int | None, str]:
    response = getattr(exc, "response", None)
    code, status, stage = "", None, "twofa_reauth"
    if response is None:
        return code, status, stage
    try:
        status = int(response.status_code)
        payload = response.json()
        error = payload.get("error") if isinstance(payload, dict) else None
        candidate = str(error.get("code") or "") if isinstance(error, dict) else ""
        if candidate in {"account_deactivated", "account_deleted", "account_banned", "token_revoked", "token_expired", "invalid_token"}:
            code = candidate
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        path = urlsplit(str(getattr(response, "url", "") or "")).path
    except ValueError:
        path = ""
    if path.endswith("/activate_enrollment"):
        stage = "twofa_activate"
    elif path.endswith("/enroll"):
        stage = "twofa_enroll"
    return code, status, stage


@unified_workflow("twofa")
def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str, existing_session: BrowserSession | None = None,
    queue_slot_acquired: bool = True,
) -> dict:
    fh: logging.FileHandler | None = None
    session: BrowserSession | None = existing_session
    owns_session = existing_session is None
    acquired = False
    relay = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        if existing_session is not None:
            from core.registration_service import check_stop_requested
            while not _EXECUTION_SLOTS.acquire(timeout=0.25):
                check_stop_requested()
        else:
            _EXECUTION_SLOTS.acquire()
        acquired = True
        if existing_session is not None:
            check_stop_requested()
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 2FA 状态已被重置"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] 开始后台设置：email=%s trigger=%s", email, trigger)
        proxy_source = "registration_session"
        if session is None:
            real_proxy, relay, proxy_source = _resolve_twofa_proxy(proxy)
            identity = email.strip().lower()
            from core.workflow_driver import create_account_session
            session = create_account_session(proxy=real_proxy, protocol_factory=BrowserSession, fingerprint_seed=f"account:{identity}")
        else:
            logger.info("[2FA] 复用当前注册会话，在原线程完成；不重建 Cookie/代理/设备上下文")
        target_label = mask_proxy_url(getattr(session, "proxy_target", None) or session.proxy or "direct") or "direct"
        transport_label = mask_proxy_url(session.proxy or "direct") or "direct"
        _append_log(
            email,
            f"[2FA] 会话创建完成：target={target_label} transport={transport_label} "
            f"source={proxy_source} device_id={session.device_id}",
        )
        _append_log(email, f"[2FA] 指纹摘要：{session.fingerprint_summary_text()}")
        logger.info("[统一流程] operation=twofa driver=%s", getattr(session, "kind", "protocol"))
        if getattr(session, "is_browser_workflow", False) is True:
            source = (db.get_account(account_id) or {}).get("email_source")
            secret = session.setup_twofa(email, email_source=source)
        else:
            secret = setup_2fa(session, email, access_token=access_token)
        refreshed = getattr(session, "_twofa_session_info", None)
        if isinstance(refreshed, dict) and refreshed.get("accessToken"):
            from core.account_session import session_fields
            db.update_account_liveness(account_id, {
                "ok": True, "status": "live", "session": refreshed,
                "access_token": refreshed["accessToken"],
                **session_fields(session, refreshed),
            })
        db.update_account_totp_secret(
            account_id,
            {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"},
        )
        _append_log(email, "[2FA] 完成：TOTP 已激活并写回账号")
        logger.info("[2FA] 完成：email=%s", email)
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"}
    except Exception as exc:
        from core.openai_auth import detect_account_unusable_text
        error_code, http_status, stage = _error_context(exc)
        dead_code = detect_account_unusable_text(error_code) or detect_account_unusable_text(str(exc))
        if dead_code:
            db.update_account_liveness(account_id, {
                "ok": False, "status": "deactivated", "error": dead_code,
                "error_code": dead_code, "stage": stage,
            })
        elif error_code in {"token_revoked", "token_expired", "invalid_token"}:
            db.update_account_liveness(account_id, {
                "ok": False, "status": "action_required", "error_code": error_code, "stage": stage,
                "error": f"2FA 授权 Token 已失效（{error_code}），请先查活刷新；未确认账号停用。",
            })
        status = "blocked" if isinstance(exc, TwofaOtpBlockedError) else "failed"
        result = {"ok": False, "status": status, "error": f"{stage}: {type(exc).__name__}: {str(exc)[:500]}"}
        if error_code:
            result["error"] += f" [server_error_code={error_code}]"
        result.update(error_code=error_code or dead_code or None, http_status=http_status, stage=stage)
        try:
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] 写回失败状态失败: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] 失败：{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] 后台异常: %s", email)
        return result
    finally:
        if session is not None and owns_session:
            try:
                close_browser_session(session)
            except Exception:
                pass
        if relay is not None:
            try:
                relay.close()
            except Exception:
                pass
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
        if acquired:
            _EXECUTION_SLOTS.release()
        if queue_slot_acquired:
            _QUEUE_SLOTS.release()


def configure_workers(workers: int) -> None:
    global _WORKERS
    workers = int(workers)
    if not 1 <= workers <= 16:
        raise ValueError("workers 必须在 1-16 之间")
    with _LOCK:
        _WORKERS = workers
        _twofa_cfg.TWOFA_WORKERS = workers
        account_concurrency.configure_workers(workers)


def queue_settings() -> dict:
    with _LOCK:
        running = len(_RUNNING)
    return {
        "workers": account_concurrency.queue_settings()["workers"],
        "queue_limit": _QUEUE_LIMIT,
        "running": running,
    }


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
    existing_session: BrowserSession | None = None,
) -> dict:
    from core.workflow_driver import require_driver_ready
    try:
        require_driver_ready()
    except (ValueError, RuntimeError) as exc:
        return {"accepted": False, "busy": False, "error": str(exc), "stage": "driver_configuration"}
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "缺少 access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "启用 2FA 需要先开启 USE_EMAIL_SERVICE 自动收取邮箱验证码"}
    inline_registration = account_concurrency.in_registration_scope()
    if inline_registration:
        logger.info("[2FA] 沿用注册任务准入名额，在原注册线程执行；不占账号页独立队列")
    queue_slot_acquired = not inline_registration
    if queue_slot_acquired and not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA 队列已满，请稍后重试"}
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        if queue_slot_acquired:
            _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在设置 2FA"}

    _append_log(email, f"[2FA] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        from core.workflow_driver import submit_with_driver
        args = dict(account_id=account_id, email=email, access_token=access_token,
                    proxy=proxy, trigger=str(trigger or "manual"))
        if existing_session is not None or inline_registration:
            # curl_cffi uses thread-local handles. A borrowed registration
            # session must stay on its owner thread, including cleanup.
            future = Future()
            try:
                future.set_result(_run_twofa(**args, existing_session=existing_session,
                                             queue_slot_acquired=queue_slot_acquired))
            except Exception as exc:
                future.set_exception(exc)
        else:
            future = submit_with_driver(_EXECUTOR, _run_twofa, **args)
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        if queue_slot_acquired:
            _QUEUE_SLOTS.release()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
