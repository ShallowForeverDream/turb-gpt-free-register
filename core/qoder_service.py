"""Bounded Qoder intake, independent of GPT/Grok jobs and account concurrency."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading

from core import qoder_store as store

_LOCK = threading.RLock()
_EXECUTOR = None
_PENDING = deque()
_RUNNING = {}
_PAUSED = False
_WORKERS = 10
_INITIALIZED = False


class Signals:
    def __init__(self):
        self.stop = threading.Event()
        self.resume = threading.Event()
        self._lock = threading.Lock()
        self._code = ""

    def put_code(self, code):
        with self._lock:
            self._code = code

    def take_code(self):
        with self._lock:
            value, self._code = self._code, ""
            return value


def state():
    with _LOCK:
        return {"paused": _PAUSED, "workers": _WORKERS, "waiting": len(_PENDING), "active": len(_RUNNING),
                "active_ids": list(_RUNNING)}


def control(action, workers=None):
    global _PAUSED, _WORKERS
    ensure_initialized()
    if action not in {"configure", "pause", "resume", "stop"}:
        raise ValueError("队列操作不合法")
    with _LOCK:
        if workers is not None:
            if type(workers) is not int or not 1 <= workers <= 10:
                raise ValueError("Qoder 并发必须为1到10的整数")
            _WORKERS = workers
            store.workers(workers)
        if action == "pause":
            _PAUSED = True
        elif action == "resume":
            _PAUSED = False
        elif action == "stop":
            store.cancel_pending(list(_PENDING)); _PENDING.clear(); _PAUSED = False
        _dispatch()
        return state()


def submit(items, *, driver="browser"):
    global _EXECUTOR
    ensure_initialized()
    if not isinstance(items, list) or not 1 <= len(items) <= 50:
        raise ValueError("请选择1到50个已授权使用的邮箱")
    if driver != "browser":
        raise ValueError("Qoder驱动必须为browser")
    with _LOCK:
        ids = store.create_jobs(items, driver=driver)
        threads = max(10, _WORKERS + 1)
        current_threads = getattr(_EXECUTOR, "_max_workers", threads)
        if _EXECUTOR is None or current_threads != threads:
            old, _EXECUTOR = _EXECUTOR, ThreadPoolExecutor(max_workers=threads, thread_name_prefix="qoder")
            if old is not None:
                old.shutdown(wait=False)
        _PENDING.extend(ids)
        _dispatch()
        return ids


def _dispatch():
    if _PAUSED or _EXECUTOR is None:
        return
    while _PENDING and len(_RUNNING) < _WORKERS:
        job_id = _PENDING.popleft()
        _RUNNING[job_id] = Signals()
        try:
            future = _EXECUTOR.submit(_run, job_id, _RUNNING[job_id])
            future.add_done_callback(lambda f, jid=job_id: _finished(jid))
        except Exception:
            _RUNNING.pop(job_id, None)
            store.update_job(job_id, "failed", "dispatch", "任务未能提交执行，未自动重试")


def _finished(job_id):
    with _LOCK:
        _RUNNING.pop(job_id, None)
        _dispatch()


def _run(job_id, signals):
    record = store.job(job_id, private=True)
    if not record or record["status"] != "pending":
        return
    try:
        from core import qoder_browser
        from core import grok_service

        def update(status, stage, message, **private):
            store.update_job(job_id, status, stage, message, private=private)

        update("running", "starting", "开始 Qoder 注册（driver=browser）；不占用 GPT/Grok 邮箱注册状态")
        relay = None
        attempted = set()
        last_error = None
        for attempt in range(1, 4):
            relay, proxy_target = grok_service._dynamic_pool_route(exclude_targets=attempted)
            attempted.add(str(proxy_target))
            record["private"]["proxy_target"] = proxy_target
            record["private"]["proxy_transport"] = relay.proxy_url if relay else ""
            update("running", "proxy", f"动态家宽出口已固定：{proxy_target}；本任务全程复用（出口 {attempt}/3）")
            try:
                from core.grok_browser import verify_proxy_transport
                verify_proxy_transport(relay.proxy_url)
                record["private"]["proxy_prechecked"] = True
                break
            except Exception as exc:
                last_error = exc
                if attempt >= 3:
                    raise
                update("running", "proxy", f"出口 {attempt}/3 预检失败，换下一个动态家宽出口；尚未打开注册页")
                try:
                    relay.close()
                finally:
                    relay = None
        if relay is None:
            raise last_error or RuntimeError("没有可用的动态家宽出口")
        try:
            result = qoder_browser.run(record, store.mailbox(record["email"], record["source"]), signals, update,
                                       proxy_url=relay.proxy_url)
            if result:
                record = store.job(job_id, private=True)
                if not record["private"].get("profile_submitted"):
                    raise qoder_browser.QoderBrowserError("尚未确认注册完成，未保存 PAT", reason="identity")
                saved = store.save_account(job_id, result)
                update("success", "complete", "Qoder 账号与 PAT 均已保存；不代表 API 套餐或模型调用资格")
                return saved
        finally:
            if relay is not None:
                relay.close()
    except Exception as exc:
        record = store.job(job_id, private=True) or {}
        uncertain = record.get("private", {}).get("profile_submitted")
        http_status = getattr(exc, "http_status", None)
        reason_code = getattr(exc, "reason", "")
        status = "uncertain" if uncertain else "cancelled" if signals.stop.is_set() else "blocked" if (
            http_status in (401, 403, 429) or reason_code in {"captcha", "native_security"}) else "failed"
        reason = {"browser_closed": "注册浏览器已关闭", "third_party": "进入第三方页面，未提交后续信息",
                  "window_unavailable": "无法展开本任务浏览器窗口，未访问官网或发码",
                  "user_stop": "用户停止了此任务", "mail_timeout": "验证码未获取（已读取3次，未重发）",
                  "timeout": "等待页面或人工操作超时",
                  "captcha": "滑块验证码未通过；请人工完成",
                  "pat": "PAT 尚未创建成功",
                  "proxy_unavailable": "动态家宽出口预检未通过（最多试 3 个出口）",
                  "identity": "注册完成但未确认登录态，未保存 PAT"}.get(reason_code, "请查看浏览器阶段")
        if http_status in (401, 403, 429):
            reason = f"服务拒绝请求 HTTP {http_status}，已停止且不换线"
        store.update_job(job_id, status, "stopped", f"Qoder 流程已停止（{type(exc).__name__}）；" +
            reason + "；" + ("注册提交结果未确认，保留候选且不自动重提" if uncertain else "未自动重试"))


def manual_code(job_id, value):
    from core.qoder_mail import validate_code
    code = validate_code(value)
    if not code:
        raise ValueError("请输入当前 Qoder 邮件中的六位数字验证码")
    with _LOCK:
        signals = _RUNNING.get(job_id)
        record = store.job(job_id)
        if not signals or not record or record["status"] != "running":
            raise ValueError("此任务当前不在等待邮箱验证码")
        signals.put_code(code)


def stop_job(job_id):
    with _LOCK:
        if job_id not in _RUNNING:
            raise ValueError("任务不在执行中")
        _RUNNING[job_id].stop.set()


def continue_job(job_id):
    with _LOCK:
        record = store.job(job_id)
        signals = _RUNNING.get(job_id)
        if not signals or not record or record["status"] != "manual_required":
            raise ValueError("此任务当前不在等待人工接管确认")
        signals.resume.set()


def initialize():
    global _WORKERS, _INITIALIZED
    with _LOCK:
        if _INITIALIZED:
            return
        store.recover()
        if not _RUNNING and not _PENDING:
            _WORKERS = store.workers()
            if _WORKERS == 1:
                _WORKERS = 10
                store.workers(_WORKERS)
        _INITIALIZED = True


def ensure_initialized():
    """Recover interrupted Qoder work only when the queue is actually used."""
    if not _INITIALIZED:
        initialize()
