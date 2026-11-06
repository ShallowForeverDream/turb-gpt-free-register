# -*- coding: utf-8 -*-
"""
注册任务服务层：
    - 数量计划写入 SQLite，只有并发容量内的任务才进入线程池
    - 注册、登录态保存和2FA收尾共用一个准入名额
    - 暂停只暂停补充，停止只取消未准入任务

使用：
    submit_registration(email_source="outlook", count=5)
    → 记录5项计划，有界准入，立即返回 [job_dict, ...]
"""
import logging
import threading
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from core import codex_retry_service, db
from core.concurrency_limit import ConcurrencyLimit
from config.env_loader import env_int

logger = logging.getLogger(__name__)

# 线程池只提供执行线程；实际并发由可热调整的入口限制控制。
_DEFAULT_MAX_WORKERS = 4
_MIN_MAX_WORKERS = 1
_MAX_MAX_WORKERS = 16
_executor: ThreadPoolExecutor | None = None
_executor_workers = max(1, min(16, env_int("REGISTRATION_WORKERS", _DEFAULT_MAX_WORKERS)))
_EXECUTION_SLOTS = ConcurrencyLimit(_executor_workers)
_executor_generation = 0
_retired_executors: list[ThreadPoolExecutor] = []
_executor_lock = threading.RLock()
_PENDING_TASKS = deque()
_DISPATCHED_TASKS: dict[int, object] = {}
_DISPATCHING = False
_SHUTTING_DOWN = False
REGISTRATION_QUEUE_POLICY = "bounded_intake_pause_drain_stop_pending"

_STOP_EVENTS: dict[int, threading.Event] = {}
_ACTIVE_JOBS: set[int] = set()
_PAUSED_JOBS: set[int] = set()
_STOP_LOCK = threading.Lock()
_THREAD_CTX = threading.local()
_PAUSE_GATE = threading.Event()
_PAUSE_GATE.set()
_PAUSE_LOCK = threading.Lock()
# Set while an explicit 开始 action admits exactly one queued account. The
# batch was already paused, so finishing that account must not start another.
_STARTING_ONE = False
_STARTING_JOBS: set[int] = set()


class StopRequested(RuntimeError):
    """用户手动停止注册任务。"""


def _activate_job(job_id: int) -> None:
    _THREAD_CTX.job_id = int(job_id)
    with _STOP_LOCK:
        _STOP_EVENTS.setdefault(int(job_id), threading.Event())
        _ACTIVE_JOBS.add(int(job_id))


def _deactivate_job(job_id: int) -> None:
    with _STOP_LOCK:
        _STOP_EVENTS.pop(int(job_id), None)
        _ACTIVE_JOBS.discard(int(job_id))
        _PAUSED_JOBS.discard(int(job_id))
    try:
        delattr(_THREAD_CTX, "job_id")
    except Exception:
        pass


def is_stop_requested(job_id: int | None = None) -> bool:
    if job_id is None:
        job_id = getattr(_THREAD_CTX, "job_id", None)
    if not job_id:
        return False
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(int(job_id))
        if ev and ev.is_set():
            return True
    job = db.get_job(int(job_id))
    return bool(job and job.get("status") in ("stopping", "stopped", "cancelled"))


def check_stop_requested() -> None:
    job_id = getattr(_THREAD_CTX, "job_id", None)
    # Global pause affects intake only. An admitted account drains through 2FA.
    # A deliberate per-row force-stop remains a separate operation.
    if is_stop_requested(job_id):
        raise StopRequested(f"任务 #{job_id} 已被用户手动停止")


def registration_pause_status() -> dict:
    with _executor_lock:
        paused = not _PAUSE_GATE.is_set()
        waiting = len(_PENDING_TASKS)
        admitted = len(_DISPATCHED_TASKS)
    with _STOP_LOCK:
        active_ids = sorted(_ACTIVE_JOBS)
        waiting_ids = sorted(_PAUSED_JOBS)
    return {"paused": paused, "active_jobs": len(active_ids), "workers": get_executor_workers(),
            "waiting_jobs": waiting, "admitted_jobs": admitted, "intake_only": True,
            "active_job_ids": active_ids, "paused_job_ids": waiting_ids, "paused_jobs": len(waiting_ids)}


def pause_registration() -> dict:
    with _executor_lock:
        _PAUSE_GATE.clear()
    logger.warning("[Service] 已暂停补充邮箱；已准入任务继续注册和2FA")
    return registration_pause_status()


def resume_registration() -> dict:
    with _executor_lock:
        _PAUSE_GATE.set()
        _dispatch_pending()
    logger.info("[Service] 注册总开关已继续")
    return registration_pause_status()


def _append_job_log(job_id: int, message: str) -> None:
    try:
        job = db.get_job(job_id)
        log_file = job.get("log_file") if job else None
        if not log_file:
            return
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%H:%M:%S")
        with Path(log_file).open("a", encoding="utf-8") as f:
            f.write(f"{ts} [WARNING] [manual-stop] {message}\n")
    except Exception:
        pass


def _random_display_name() -> str:
    """生成符合 OpenAI 限制的英文字母显示名。"""
    from core.name_samples import random_display_name

    return random_display_name()


def _prepare_registration_args(email_override: str | None = None) -> tuple[str | None, str, str]:
    """复用 CLI 的默认规则，为旧 Web 任务入口补齐注册参数。"""
    # 用模块属性读，支持 WebUI 热加载
    from config import register as _r, email as _e
    from core.profile_utils import generate_random_birthday

    manual_email = getattr(_r, "REGISTER_EMAIL", "") if not _e.USE_EMAIL_SERVICE else ""
    email = str(email_override or manual_email or "").strip()
    name = str(getattr(_r, "REGISTER_NAME", "") or "").strip()
    # WebUI/配置里有时会把空值存成 "-"，这不是合法 OpenAI 显示名，按空处理并自动生成
    if name in {"-", "—", "无", "空", "none", "None", "null", "NULL"}:
        name = ""

    if not name:
        # 手动模式也自动生成显示名，减少配置负担
        name = _random_display_name()

    birthday = generate_random_birthday()

    # 自动邮箱不在准备阶段领取：浏览器驱动会等页面找到邮箱输入框后再领取，
    # 协议驱动则在 run_registration 即将开始认证时领取。这样页面打不开/找不到
    # 输入框时不会提前消耗邮箱订单或池中素材。
    if not email and not _e.USE_EMAIL_SERVICE:
        raise RuntimeError(
            "手动模式未配置邮箱。请在 WebUI 配置页设置 REGISTER_EMAIL，"
            "或开启 USE_EMAIL_SERVICE 并从邮箱池领取。"
        )

    return email, name, birthday


def _release_unconsumed_job_email(email: str | None, reason: str) -> None:
    """任务失败兜底：只回收尚未生成账号、仍处于 used 的邮箱领取。"""
    if not email:
        return
    try:
        from core.email_provider import release_email_if_unconsumed

        release_email_if_unconsumed(email, note=f"任务未消耗，已自动回收: {reason[:180]}")
    except Exception:
        logger.exception("[Service] 回收未消耗邮箱失败: %s", email)


def _should_disable_failed_registration_email(error: object) -> bool:
    """仅明确的停用错误允许自动禁用，不由页面落点或会话缺失推断。"""
    text = str(error or "")
    if not text:
        return False
    return (
        "account_deactivated" in text.lower()
        or "account_deleted" in text.lower()
        or "account_banned" in text.lower()
    )


def _disable_job_email(email: str | None, reason: str) -> bool:
    """把本次任务邮箱停用，避免后续再次领取。"""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(email, status="disabled", note=f"自动停用: {reason[:180]}")
        logger.warning("[Service] 已自动停用邮箱: source=%s email=%s reason=%s", source, email, reason[:220])
        return True
    except Exception:
        logger.exception("[Service] 自动停用邮箱失败: %s", email)
        return False


def _normalize_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _DEFAULT_MAX_WORKERS
    try:
        value = int(max_workers)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_WORKERS
    return max(_MIN_MAX_WORKERS, min(_MAX_MAX_WORKERS, value))


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """同一线程池热调准入并发，不让旧池与新池叠加执行。"""
    global _executor, _executor_workers, _executor_generation
    requested_workers = _normalize_workers(max_workers) if max_workers is not None else _executor_workers
    with _executor_lock:
        configure_workers(requested_workers)
        if _executor is None:
            _executor_generation += 1
            _executor = ThreadPoolExecutor(
                max_workers=_MAX_MAX_WORKERS,
                thread_name_prefix=f"reg-worker-{_executor_generation}",
            )
    return _executor


def configure_workers(workers: int) -> None:
    global _executor_workers
    with _executor_lock:
        _executor_workers = _normalize_workers(workers)
        _EXECUTION_SLOTS.set_limit(_executor_workers)
        _dispatch_pending()


def _dispatch_pending() -> None:
    """Called under _executor_lock; never flood the executor with waiting accounts."""
    global _DISPATCHING
    if _DISPATCHING or _SHUTTING_DOWN or _executor is None or not _PAUSE_GATE.is_set():
        return
    from core.workflow_driver import submit_with_driver
    _DISPATCHING = True
    try:
        while _PENDING_TASKS and len(_DISPATCHED_TASKS) < _executor_workers and _PAUSE_GATE.is_set():
            task, args, driver = _PENDING_TASKS.popleft()
            job_id = int(args[0])
            job = db.get_job(job_id)
            if not job or job.get("status") != "pending":
                continue
            _DISPATCHED_TASKS[job_id] = None
            try:
                future = submit_with_driver(_executor, _run_limited, task, *args, _driver=driver)
                _DISPATCHED_TASKS[job_id] = future
                future.add_done_callback(lambda f, jid=job_id: _dispatch_finished(jid, f))
            except Exception as exc:
                _DISPATCHED_TASKS.pop(job_id, None)
                db.update_job(job_id, status="failed", error=f"队列提交失败：{type(exc).__name__}"[:500],
                              completed_at=datetime.now().isoformat(timespec="seconds"))
                logger.exception("[Service] 任务 #%s 提交失败", job_id)
    finally:
        _DISPATCHING = False


def _dispatch_finished(job_id, future):
    global _STARTING_ONE
    with _executor_lock:
        _DISPATCHED_TASKS.pop(job_id, None)
        # A start-one account is the last one to run while paused. If the task
        # finishes before admit_queued() runs its closure, close the gate now
        # instead of refilling a batch the user has not resumed.
        if _STARTING_ONE and job_id in _STARTING_JOBS:
            _STARTING_JOBS.discard(job_id)
            with _PAUSE_LOCK:
                if not _STARTING_JOBS:
                    _STARTING_ONE = False
                    _PAUSE_GATE.clear()
        _dispatch_pending()


def _queue_task(task, *args):
    from core.workflow_driver import resolve_driver
    _PENDING_TASKS.append((task, args, resolve_driver()))


def _run_limited(task, *args, **kwargs):
    from core.account_concurrency import registration_scope
    with _EXECUTION_SLOTS, registration_scope():
        return task(*args, **kwargs)


def get_executor_workers() -> int:
    """当前注册任务的准入并发上限。"""
    with _executor_lock:
        return _executor_workers


def shutdown_executor(wait: bool = True) -> None:
    global _executor, _SHUTTING_DOWN
    with _executor_lock:
        _SHUTTING_DOWN = True
        executors = []
        if _executor is not None:
            executors.append(_executor)
            _executor = None
        executors.extend(_retired_executors)
        _retired_executors.clear()
    for ex in executors:
        ex.shutdown(wait=wait, cancel_futures=False)
    with _executor_lock:
        _SHUTTING_DOWN = False


# ============================================================
# 单任务执行：日志重定向到任务专属文件
# ============================================================

class _JobLogContext:
    """让本线程的根 logger 多一个 FileHandler，结束后移除。"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.handler: logging.FileHandler | None = None

    def __enter__(self):
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(self.log_path, encoding="utf-8")
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        # 仅给本线程过滤 —— 用 thread name 做区分，避免污染其他任务的日志
        thread_name = threading.current_thread().name
        self.handler.addFilter(lambda r: r.threadName == thread_name)
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handler is not None:
            self.handler.close()
            logging.getLogger().removeHandler(self.handler)


def _run_one_job(job_id: int, log_file: str) -> None:
    """单任务入口（线程池里跑这个）。"""
    log_logger = logging.getLogger(__name__)
    _activate_job(job_id)

    # 取消检查：用户可能在任务排队期间点了"取消排队"，把 status 改成了 cancelled。
    # 因为 Future 已经 submit 进线程池无法撤回，只能在真正执行前自检一下，跳过 cancelled 的。
    current = db.get_job(job_id)
    if not current:
        log_logger.info(f"[Job {job_id}] 任务记录已删除，跳过执行")
        _deactivate_job(job_id)
        return
    if current.get("status") == "cancelled":
        log_logger.info(f"[Job {job_id}] 已被用户取消，跳过执行")
        _deactivate_job(job_id)
        return

    if not db.update_job_if_status(job_id, ("pending",), status="running", started_at=datetime.now().isoformat(timespec="seconds")):
        _deactivate_job(job_id)
        return

    email: str | None = None
    try:
        with _JobLogContext(log_file):
            from main import run_registration
            log_logger.info(f"[Job {job_id}] 开始注册任务")
            check_stop_requested()
            email, name, birthday = _prepare_registration_args(str(current.get("email") or "").strip() or None)
            db.update_job(job_id, email=email)
            # 重试/指定邮箱任务可能已经把邮箱放回 available；再次执行前精确领取，
            # 防止成功后邮箱池仍显示可用。
            if email and current.get("email_source"):
                try:
                    db.claim_pool_email(email, str(current.get("email_source")), note="注册任务执行")
                except Exception:
                    pass
            check_stop_requested()
            def _on_email_acquired(acquired_email: str) -> None:
                nonlocal email
                email = str(acquired_email or "").strip() or None
                if email:
                    db.update_job(job_id, email=email)
                    log_logger.info(f"[Job {job_id}] 页面已找到邮箱输入框，已分配邮箱: {email}")

            from core.email_provider import use_email_sources
            with use_email_sources(current.get("email_source")):
                result = run_registration(
                    email=email,
                    name=name,
                    birthday=birthday,
                    on_email_acquired=_on_email_acquired,
                )
            if is_stop_requested(job_id):
                _release_unconsumed_job_email(email, "用户手动停止")
                db.update_job(
                    job_id,
                    status="stopped",
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error="用户手动停止",
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.warning(f"[Job {job_id}] 已按用户请求停止")
                return
            if isinstance(result, dict) and result.get("success"):
                db.update_job(
                    job_id,
                    status=result["status"] if result.get("status") in {"already_registered", "partial_success"} else "success",
                    email=result.get("email"),
                    account_id=result.get("account_id"),
                    network_traffic=result.get("network_traffic"),
                    error=str(result.get("error") or "")[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                label = "部分成功" if result.get("status") == "partial_success" else "成功"
                log_logger.info(f"[Job {job_id}] {label}: {result.get('email')}")
            else:
                # 注意：失败也可能伴随 account_id（如 Codex 失败但账号已注册成功）
                err = (result or {}).get("error") if isinstance(result, dict) else "unknown"
                result_email = (result or {}).get("email") if isinstance(result, dict) else None
                db.update_job(
                    job_id,
                    status=("disabled" if _should_disable_failed_registration_email(err) else
                            "blocked" if isinstance(result, dict) and result.get("status") == "blocked" else "failed"),
                    email=result_email,
                    account_id=(result or {}).get("account_id") if isinstance(result, dict) else None,
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error=str(err)[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                email_to_handle = str(result_email or email or "").strip()
                if _should_disable_failed_registration_email(err):
                    _disable_job_email(email_to_handle, str(err))
                else:
                    _release_unconsumed_job_email(email_to_handle, str(err))
                log_logger.error(f"[Job {job_id}] {'入口受阻' if isinstance(result, dict) and result.get('status') == 'blocked' else '失败'}: {err}")
    except StopRequested as exc:
        _release_unconsumed_job_email(email, str(exc))
        log_logger.warning(f"[Job {job_id}] 已停止: {exc}")
        db.update_job(
            job_id,
            status="stopped",
            error="用户手动停止",
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    except Exception as exc:
        err_text = f"{type(exc).__name__}: {exc}"
        if _should_disable_failed_registration_email(err_text):
            _disable_job_email(email, err_text)
        else:
            _release_unconsumed_job_email(email, err_text)
        if is_stop_requested(job_id):
            log_logger.warning(f"[Job {job_id}] 停止中捕获异常，按停止处理: {type(exc).__name__}: {exc}")
            db.update_job(
                job_id,
                status="stopped",
                error="用户手动停止",
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return
        log_logger.exception(f"[Job {job_id}] 异常")
        db.update_job(
            job_id,
            status="disabled" if _should_disable_failed_registration_email(err_text) else "failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    finally:
        _deactivate_job(job_id)


def _run_codex_retry_job(job_id: int, log_file: str, email: str, account_id: int) -> None:
    """把 Codex 补跑作为标准任务执行，并复用任务状态、日志和停止入口。"""
    _activate_job(job_id)
    current = db.get_job(job_id)
    if not current or current.get("status") == "cancelled":
        codex_retry_service.release(email)
        _deactivate_job(job_id)
        return

    if not db.update_job_if_status(job_id, ("pending",), status="running", started_at=datetime.now().isoformat(timespec="seconds")):
        codex_retry_service.release(email)
        _deactivate_job(job_id)
        return
    try:
        result = codex_retry_service.run_worker(
            email,
            clear_log=False,
            target_log_path=log_file,
        )
        now_iso = datetime.now().isoformat(timespec="seconds")
        if is_stop_requested(job_id) or result.get("status") == "stopped":
            db.update_job(job_id, status="stopped", email=email, account_id=account_id, error=str(result.get("message") or "用户手动停止")[:500], completed_at=now_iso)
        elif result.get("ok"):
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=account_id,
                completed_at=now_iso,
            )
        else:
            db.update_job(
                job_id,
                status="failed",
                email=email,
                account_id=account_id,
                error=str(result.get("message") or "Codex 补跑失败")[:500],
                completed_at=now_iso,
            )
    except Exception as exc:
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        codex_retry_service.release(email)
        logger.exception("[Job %s] Codex 补跑异常", job_id)
    finally:
        _deactivate_job(job_id)


# ============================================================
# 公共接口
# ============================================================

def submit_registration(
    count: int = 1,
    email_source: str | None = None,
    workers: int | None = None,
    selected_emails: list[dict] | None = None,
    selected_checked: bool = False,
) -> list[dict]:
    """
    创建 N 项计划；按保存的并发数准入，余项不领取邮箱、不占执行线程。
    指定邮箱与自动池使用同一准入队列。

    ``selected_checked`` 仅供 Web UI 使用：调用方已完成 claim_pool_emails 校验，
    这里不再重复校验（重复校验会把同批刚创建的排队任务当成占用）。

    Returns:
        N 个新创建的 job dict
    """
    from core.workflow_driver import require_driver_ready
    require_driver_ready()
    if email_source is None:
        from config import email as _email_cfg
        email_source = _email_cfg.EMAIL_SOURCE

    # 创建/切换线程池和提交本批任务必须整体串行化：否则另一请求在本批提交中途
    # 切换 workers 并 shutdown 旧池，会导致后续 submit 报 cannot schedule new futures after shutdown。
    with _executor_lock:
        paused_before = not _PAUSE_GATE.is_set()
        if selected_emails and not selected_checked:
            _, skipped = db.claim_pool_emails(selected_emails, reserve=False)
            if skipped:
                raise ValueError("所选邮箱已不可用，请刷新邮箱池后重试")
        get_executor(max_workers=workers)
        effective_workers = get_executor_workers()
        jobs = []
        batch_id = str(uuid.uuid4())
        chosen = selected_emails if isinstance(selected_emails, list) and selected_emails else [None] * count
        for selected in chosen:
            fixed_email = str((selected or {}).get("email") or "").strip() if isinstance(selected, dict) else None
            fixed_source = str((selected or {}).get("source") or email_source).strip() if isinstance(selected, dict) else email_source
            job = db.create_job(email_source=fixed_source, email=fixed_email or None, batch_id=batch_id)
            _queue_task(_run_one_job, job["id"], job["log_file"])
            jobs.append(job)
        if paused_before:
            logger.info("[Service] 注册队列处于暂停状态：%s 个任务已入队，等待继续注册", len(jobs))
        else:
            _dispatch_pending()
    logger.info(f"[Service] 已提交 {count} 个注册任务，源={email_source}，workers={effective_workers}")
    return jobs


def _account_for_job(job: dict) -> dict | None:
    account_id = job.get("account_id")
    if account_id is not None:
        try:
            account = db.get_account(int(account_id))
            if account is not None:
                return account
        except (TypeError, ValueError):
            pass
    email = str(job.get("email") or "").strip()
    return db.get_account_by_email(email) if email else None


def failure_info(error: object) -> dict:
    """只分类已有证据，不把传输/验证失败推断成账号停用。"""
    text = str(error or "").lower()
    if "mail_otp_freshness_unverified" in text:
        from core.otp_freshness import failure_message
        reason = failure_message(error)
        return {"failure_code": "mail_otp_freshness_unverified", "display_status": "attention_required",
                "status_message": f"验证码时效未确认：{reason}；未提交验证码，需人工核验。",
                "needs_manual_review": True}
    if "wrong_email_otp_code" in text or "emailotpinvaliderror" in text or "邮箱验证码无效或已过期" in text:
        return {"failure_code": "email_otp_rejected", "display_status": "attention_required",
                "status_message": "验证码被拒绝；已停止自动重发和重提，请人工核验本次邮件及登录状态。",
                "needs_manual_review": True}
    if "missingschema" in text or "invalidurl" in text:
        return {"failure_code": "mail_url_invalid", "display_status": "configuration_error",
                "status_message": "取码地址格式不合法，请先检查邮箱素材；请求可能尚未发出。"}
    if "验证码超时" in text or "imapotptimeout" in text or "otp 超时" in text:
        network = any(x in text for x in ("sslerror", "connecttimeout", "readtimeout", "proxyerror", "connectionerror"))
        if "imapotptimeout" in text or ("本地检查" in text and "远端刷新" in text):
            return {"failure_code": "imap_otp_timeout", "display_status": "mail_timeout",
                    "status_message": "IMAP 收码超时：未找到本次目标邮件，请核对转发收件箱。单任务远端刷新为 0 不代表共享收件箱没有刷新；不能据此判定账号停用。"}
        return {"failure_code": "mail_network_timeout" if network else "mail_timeout",
                "display_status": "mail_timeout",
                "status_message": "收码网络连接失败或超时；不代表邮箱无邮件或账号停用。" if network else
                                  "等待期限内未得到可用验证码；需核对收件箱，不能据此判断账号停用。"}
    if any(x in text for x in ("curl: (35)", "curl: (28)", "sslerror", "connecttimeout", "readtimeout", "proxyerror")):
        return {"failure_code": "network_error", "display_status": "network_error",
                "status_message": "网络/TLS 连接失败，未能完成账号状态判断；不是账号停用结论。"}
    if "需 gmail 登录" in text or ("注册尚未到达邮箱验证页" in text and "/v3/signin/identifier" in text):
        return {"failure_code": "gmail_login_required", "display_status": "attention_required",
                "status_message": "需 Gmail 登录：页面跳转到 Google 登录，尚未发送邮箱验证码；请人工完成正常网页登录。",
                "needs_manual_review": True}
    if "注册尚未到达邮箱验证页" in text:
        return {"failure_code": "unexpected_auth_page", "display_status": "attention_required",
                "status_message": "未进入预期的邮箱验证页，已停止；请通过正常网页人工确认登录方式。"}
    if "邮箱提交后进入登录密码页" in text or "/log-in/password" in text:
        return {"failure_code": "existing_login_required", "display_status": "attention_required",
                "status_message": "已进入已有账号的登录密码页，不能据此判断停用；需人工确认，不重复注册。",
                "needs_manual_review": True}
    if "等待 /api/auth/session accesstoken 超时" in text or "未拿到 accesstoken" in text:
        return {"failure_code": "session_incomplete", "display_status": "attention_required",
                "status_message": "登录会话尚未建立完整，不能据此判断账号停用；需人工核验。",
                "needs_manual_review": True}
    return {}


def job_display_info(job: dict, queue: dict | None = None) -> dict:
    queue = registration_pause_status() if queue is None else queue
    status = job.get("status")
    if job.get("display_status", status) != status:
        return {}
    if status == "failed":
        return failure_info(job.get("error_message"))
    jid = int(job.get("id") or 0)
    if status == "running":
        if jid not in queue["active_job_ids"]:
            return {"display_status": "interrupted", "status_message": "没有对应执行线程；该记录并未运行，请停止后人工处理。"}
        if queue["paused"]:
            return {"status_message": "已暂停补充邮箱；本邮箱继续完成注册及2FA。"}
    if status == "pending" and queue["paused"]:
        return {"display_status": "paused_queue", "status_message": "排队已暂停；任务尚未开始。"}
    return {}


def get_retry_info(job: dict) -> dict:
    """返回给 API/UI 的重试能力描述，不依赖前端猜测错误阶段。"""
    status = str(job.get("status") or "")
    info = {
        "retryable": False,
        "retry_action": None,
        "retry_label": None,
        "retry_reason": None,
        "display_status": status,
    }
    account = _account_for_job(job)
    if account and (account.get("live_check_status") == "deactivated" or account.get("codex_status") == "deactivated"):
        info.update(display_status="disabled", retry_reason="账号已停用，已停止后续操作")
        return info
    if account and (status == "partial_success" or account.get("live_check_status") == "action_required"):
        if status not in {"pending", "running", "stopping", "cancelled"}:
            info.update(display_status="partial_success", retry_reason="账号已创建，请到账号页处理查活、套餐或 2FA；不会重新注册或自动补跑 Codex")
            return info
    if status not in ("failed", "blocked", "stopped", "cancelled"):
        return info

    successful_retry = db.get_successful_retry_for_job(int(job.get("id") or 0))
    if successful_retry is not None:
        info["retry_reason"] = f"后续重试任务 #{successful_retry.get('id')} 已成功"
        info["successful_retry_job_id"] = successful_retry.get("id")
        return info

    failure = failure_info(job.get("error_message")) if status == "failed" else {}
    if failure.get("needs_manual_review"):
        info.update(failure, retry_reason=failure["status_message"])
        return info

    if account and job.get("account_id") is not None and status in ("failed", "stopped"):
        info["display_status"] = "success" if (account.get("codex_status") or "") == "success" else "partial_success"

    if account:
        codex_status = str(account.get("codex_status") or "")
        if codex_status == "deactivated":
            info["retry_reason"] = "账号已废号，不能补跑 Codex"
            return info
        if codex_status == "success":
            info["retry_reason"] = "账号和 Codex 授权均已完成"
            return info
        info.update({
            "retryable": True,
            "retry_action": "codex",
            "retry_label": "补跑 Codex",
        })
        return info

    info.update({
        "retryable": True,
        "retry_action": "registration",
        "retry_label": "重试",
    })
    return info


def retry_job(job_id: int, workers: int | None = None) -> dict:
    """智能重试终态任务：未生成账号则重新注册，已有账号则仅补跑 Codex。"""
    from core.workflow_driver import require_driver_ready
    try:
        require_driver_ready()
    except (ValueError, RuntimeError) as exc:
        return {"ok": False, "error": str(exc), "status": 409}
    source = db.get_job(job_id)
    if source is None:
        return {"ok": False, "error": "任务不存在", "status": 404}

    retry_info = get_retry_info(source)
    if not retry_info["retryable"]:
        reason = retry_info.get("retry_reason") or f"当前状态不支持重试：{source.get('status')}"
        return {"ok": False, "error": reason, "status": 409}

    action = str(retry_info["retry_action"])
    account = _account_for_job(source)
    email = str((account or {}).get("email") or source.get("email") or "").strip()
    account_id = int(account["id"]) if account and account.get("id") is not None else None
    reserved_codex = False
    if action == "codex":
        if not email or account_id is None:
            return {"ok": False, "error": "已注册账号信息不完整，无法补跑 Codex", "status": 409}
        if not codex_retry_service.reserve(email):
            return {"ok": False, "error": "该账号正在补跑 Codex，请稍候", "status": 409}
        reserved_codex = True

    try:
        if action == "registration":
            # Keep the original failed row so the UI changes in place from
            # failed -> pending -> running instead of creating a confusing
            # second record.
            job = db.reset_job_for_retry(int(job_id))
            created = True
        else:
            job, created = db.create_retry_job(
                int(job_id),
                job_type="codex_retry",
                email_source=str(source.get("email_source") or "outlook"),
                email=email,
                account_id=account_id,
            )
    except LookupError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 404}
    except ValueError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 409}

    if not created:
        if reserved_codex:
            codex_retry_service.release(email)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "message": f"已有重试任务 #{job['id']} 在排队或运行中",
            "source_job_id": int(job_id),
            "retry_action": action,
            "job": job,
        }

    try:
        if action == "codex":
            db.update_account_codex_status(email, "retrying", None)
        with _executor_lock:
            executor = get_executor(max_workers=workers)
            if action == "codex":
                from core.workflow_driver import submit_with_driver
                _queue_task(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
            else:
                from core.workflow_driver import submit_with_driver
                _queue_task(_run_one_job, job["id"], job["log_file"])
            _dispatch_pending()
    except Exception as exc:
        if reserved_codex:
            codex_retry_service.release(email)
            db.update_account_codex_status(email, "failed", f"队列提交失败：{type(exc).__name__}: {exc}"[:500])
        db.update_job(
            int(job["id"]),
            status="failed",
            error=f"队列提交失败：{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.exception("[Service] 重试任务 #%s 提交线程池失败", job["id"])
        return {"ok": False, "error": "重试任务创建成功，但提交执行失败", "status": 500, "job": db.get_job(int(job["id"]))}

    return {
        "ok": True,
        "created": True,
        "reused": False,
        "message": f"已创建重试任务 #{job['id']}（{'Codex 补跑' if action == 'codex' else '完整注册'}）",
        "source_job_id": int(job_id),
        "retry_action": action,
        "job": job,
    }


def recover_interrupted_queue() -> dict:
    """Re-enqueue pending jobs after a WebUI restart; never replay started work.

    ``pending`` rows never claimed a mailbox (claiming happens inside the
    worker), so they are safe to enqueue again. ``running``/``stopping`` rows
    lost their worker thread and may have partial remote side effects; they
    are marked failed for explicit human review instead of being replayed.
    """
    with _executor_lock:
        jobs = db.list_jobs(limit=100000)
        interrupted = 0
        now_iso = datetime.now().isoformat(timespec="seconds")
        for job in jobs:
            if job.get("status") in ("running", "stopping"):
                if db.update_job_if_status(int(job["id"]), ("running", "stopping"), status="failed",
                                           error="WebUI 重启中断：执行线程已丢失，未自动重放；请人工核验后重试",
                                           completed_at=now_iso):
                    interrupted += 1
        pending = sorted((job for job in jobs if job.get("status") == "pending"), key=lambda item: int(item["id"]))
        queued = 0
        for job in pending:
            job_id = int(job["id"])
            if job_id in _DISPATCHED_TASKS or any(int(item[1][0]) == job_id for item in _PENDING_TASKS):
                continue
            _queue_task(_run_one_job, job_id, job.get("log_file"))
            queued += 1
        if queued:
            # Restored work must not start by itself after a restart. Keep the
            # intake gate closed until the user explicitly clicks 继续注册.
            _PAUSE_GATE.clear()
            get_executor()
        logger.warning("[Service] 重启恢复：待启动任务重新入队 %s 个（保持暂停，需手动继续），运行中断标记失败 %s 个", queued, interrupted)
        return {"queued": queued, "interrupted": interrupted, "paused": queued > 0}


def admit_queued() -> int:
    """Start one queued account for an explicit 开始注册 action.

    A paused batch stays paused after this account starts; releasing its slot
    never refills the queue until the user resumes the batch.
    """
    global _STARTING_ONE
    with _executor_lock:
        if not _PENDING_TASKS:
            return 0
        from core.workflow_driver import submit_with_driver
        while _PENDING_TASKS:
            task, args, driver = _PENDING_TASKS.popleft()
            job_id = int(args[0])
            job = db.get_job(job_id)
            if not job or job.get("status") != "pending":
                continue
            _STARTING_ONE = True
            _STARTING_JOBS.add(job_id)
            _DISPATCHED_TASKS[job_id] = None
            try:
                future = submit_with_driver(_executor, _run_limited, task, *args, _driver=driver)
                _DISPATCHED_TASKS[job_id] = future
                future.add_done_callback(lambda f, jid=job_id: _dispatch_finished(jid, f))
            except Exception as exc:
                _DISPATCHED_TASKS.pop(job_id, None)
                _STARTING_JOBS.discard(job_id)
                _STARTING_ONE = False
                db.update_job(job_id, status="failed", error=f"队列提交失败：{type(exc).__name__}"[:500],
                              completed_at=datetime.now().isoformat(timespec="seconds"))
                logger.exception("[Service] 任务 #%s 提交失败", job_id)
                continue
            return 1
        return 0


def cancel_pending_jobs() -> int:
    with _executor_lock:
        return _cancel_waiting_jobs()


def stop_registration() -> dict:
    with _executor_lock:
        cancelled = _cancel_waiting_jobs()
        # Stopped work cannot be resumed; a later Start is a new batch.
        _PAUSE_GATE.set()
    return {"cancelled": cancelled, **registration_pause_status()}


def _cancel_waiting_jobs() -> int:
    """
    把所有 status=pending 的任务批量改成 cancelled，避免它们被执行。
    已经在 running 的任务不动（线程池中无法中途打断）。
    返回成功取消的数量。

    实际"不执行"的保证在 _run_one_job 开头——它真要跑起来时会先看 status 决定是否跳过。
    """
    jobs = db.list_jobs(limit=100000)
    cancelled = 0
    now_iso = datetime.now().isoformat(timespec="seconds")
    for job in jobs:
        if job.get("status") == "pending" and int(job["id"]) not in _DISPATCHED_TASKS:
            changed = db.update_job_if_status(
                int(job["id"]),
                ("pending",),
                status="cancelled",
                completed_at=now_iso,
                error="用户手动取消",
            )
            cancelled += int(changed)
    logger.info(f"[Service] 已取消 {cancelled} 个排队任务")
    remaining = [item for item in _PENDING_TASKS if int(item[1][0]) in _DISPATCHED_TASKS]
    _PENDING_TASKS.clear()
    _PENDING_TASKS.extend(remaining)
    return cancelled


def request_stop_job(job_id: int) -> dict:
    """手动停止单个注册任务。pending 直接取消；running 设置停止标记，运行线程会在检查点退出。"""
    job = db.get_job(job_id)
    if not job:
        return {"ok": False, "error": "任务不存在", "status": 404}
    status = job.get("status")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if status == "pending":
        if db.update_job_if_status(job_id, ("pending",), status="cancelled", completed_at=now_iso, error="用户手动停止/取消排队"):
            _append_job_log(job_id, "用户手动停止：任务尚未运行，已取消排队。")
            return {"ok": True, "message": "排队任务已取消", "job_id": job_id, "state": "cancelled"}
        job = db.get_job(job_id)
        if not job:
            return {"ok": False, "error": "任务不存在", "status": 404}
        status = job.get("status")
    if status in ("success", "failed", "cancelled", "stopped", "partial_success", "disabled", "blocked", "already_registered"):
        return {"ok": True, "message": f"任务已结束：{status}", "job_id": job_id, "state": status}
    if status in ("running", "stopping"):
        with _STOP_LOCK:
            active = int(job_id) in _ACTIVE_JOBS
            ev = _STOP_EVENTS.get(int(job_id)) if active else None
            if ev is not None:
                ev.set()
        if not active or ev is None:
            # Web 服务重启、线程异常退出、历史残留 stopping，或之前手动停止时只创建了 stop event
            # 但没有真实线程实例：直接落为 stopped，避免永远卡在“停止中”。
            with _STOP_LOCK:
                _STOP_EVENTS.pop(int(job_id), None)
                _ACTIVE_JOBS.discard(int(job_id))
            changed = db.update_job_if_status(
                job_id,
                ("running", "stopping"),
                status="stopped",
                completed_at=now_iso,
                error="用户手动停止（任务实例不存在）",
            )
            if not changed:
                latest = db.get_job(job_id) or {}
                return {"ok": True, "message": "任务状态已变化，请刷新", "job_id": job_id, "state": latest.get("status")}
            _release_unconsumed_job_email(
                str(job.get("email") or "").strip() or None,
                "任务实例不存在，确认未继续执行",
            )
            _append_job_log(job_id, "用户手动停止：未找到运行中的任务实例，已直接标记为已停止。")
            logger.warning("[Service] 用户停止任务 #%s：任务实例不存在，已直接标记 stopped", job_id)
            return {"ok": True, "message": "任务实例不存在，已直接标记为已停止", "job_id": job_id, "state": "stopped"}
        if not db.update_job_if_status(job_id, ("running", "stopping"), status="stopping", error="用户手动停止中"):
            latest = db.get_job(job_id) or {}
            return {"ok": True, "message": "任务状态已变化，请刷新", "job_id": job_id, "state": latest.get("status")}
        _append_job_log(job_id, "用户手动停止：已发送停止信号，任务会在当前步骤检查点退出。")
        logger.warning("[Service] 用户请求停止任务 #%s", job_id)
        return {"ok": True, "message": "已发送停止信号", "job_id": job_id, "state": "stopping"}
    return {"ok": False, "error": f"当前状态不支持停止：{status}", "status": 409}


def read_job_log(job_id: int, max_bytes: int = 50_000) -> str:
    """读取任务日志文件最后 max_bytes 字节，给 Web UI 显示。"""
    job = db.get_job(job_id)
    if not job or not job.get("log_file"):
        return ""
    p = Path(job["log_file"])
    if not p.exists():
        return ""
    size = p.stat().st_size
    with p.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")
