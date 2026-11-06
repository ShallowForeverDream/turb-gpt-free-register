"""Bounded Grok intake, independent of GPT jobs and account concurrency."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading

from core import grok_store as store
from core.grok_mail import validate_code

_LOCK = threading.RLock()
_EXECUTOR = None
_PENDING = deque()
_RUNNING = {}
_PAUSED = False
_WORKERS = 1
_ACTIVE_BROWSER_TARGETS: set[str] = set()


class Signals:
    def __init__(self):
        self.stop = threading.Event()
        self.resume = threading.Event()
        self.native_verify = threading.Event()
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
    if action not in {"configure", "pause", "resume", "stop"}:
        raise ValueError("队列操作不合法")
    with _LOCK:
        if workers is not None:
            if type(workers) is not int or not 1 <= workers <= 10:
                raise ValueError("Grok 并发必须为1到10的整数")
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


def submit(items, *, driver="protocol"):
    global _EXECUTOR
    if not isinstance(items, list) or not 1 <= len(items) <= 50:
        raise ValueError("请选择1到50个已授权使用的邮箱")
    if driver == "browser":
        from core.grok_browser import require_browser
        require_browser()  # fail before claiming or creating work
    elif driver == "protocol":
        from core.grok_protocol import require_protocol
        require_protocol()
    else:
        raise ValueError("Grok驱动必须为protocol或browser")
    _require_dynamic_proxy()
    with _LOCK:
        ids = store.create_jobs(items, driver=driver)
        # A finished future frees its slot even when the next Grok task is
        # still held by its result callback.  Keep capacity above the checked
        # active limit so every configured slot can actually run concurrently.
        threads = max(10, _WORKERS + 1)
        current_threads = getattr(_EXECUTOR, "_max_workers", threads)
        if _EXECUTOR is None or current_threads != threads:
            old, _EXECUTOR = _EXECUTOR, ThreadPoolExecutor(max_workers=threads,
                                                           thread_name_prefix="grok")
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


def _dynamic_pool_route(*, exclude_targets: set[str] | None = None):
    """Pick one dynamic residential proxy and keep it for the whole browser flow.

    Both Grok drivers, browser and HTTP, must use a single fixed dynamic
    residential exit from navigation through SSO/CLI authorization.  If an exit
    is proven broken before the page opens (the caller can pass its previous
    target in ``exclude_targets``), another exit from the same pool is allowed;
    a flow already in progress is never moved to a different exit.
    """
    from config import proxy as proxy_cfg
    from core.proxy_chain import ProxyChainRelay
    from core.proxy_utils import mask_proxy_url, is_loopback_proxy
    excluded = {str(item).strip() for item in (exclude_targets or set()) if str(item).strip()}
    with _LOCK:
        excluded |= set(_ACTIVE_BROWSER_TARGETS)
    # A Grok task must never run on the machine's ambient/direct route or a
    # loopback-only relay.  Entries resolve through the configured upstream
    # route; an entry identical to that local route is not a dynamic exit.
    upstream = (
        str(getattr(proxy_cfg, "PROXY_POOL_UPSTREAM_PROXY", "") or "").strip()
        or str(getattr(proxy_cfg, "PLAN_CHECK_UPSTREAM_PROXY", "") or "").strip()
    )
    if not upstream:
        raise RuntimeError("Grok 动态注册要求经动态家宽代理池出口，但未配置上游链路；已停止，不使用本机代理")
    candidates = []
    for item in (getattr(proxy_cfg, "PROXY_POOL", []) or []):
        item = str(item).strip()
        if not item or is_loopback_proxy(item):
            continue
        candidates.append(item)
    if not candidates:
        raise RuntimeError("Grok 动态注册要求动态家宽代理，但当前只有本机代理或没有可用出口；已停止")
    candidates = [item for item in candidates if item not in excluded]
    if not candidates:
        raise RuntimeError("Grok 动态注册要求动态家宽代理，但当前没有可用出口；已停止")
    target = str(proxy_cfg.pick_proxy() or "").strip()
    if not target or target in excluded or target not in candidates:
        target = candidates[0]
    relay = ProxyChainRelay(target, upstream, timeout=30).start()
    with _LOCK:
        _ACTIVE_BROWSER_TARGETS.add(target)
    return relay, mask_proxy_url(target)


def _require_dynamic_proxy(proxy_cfg=None):
    """Validate the configured egress before any Grok job claims a mailbox."""
    from config import proxy as proxy_cfg
    from core.proxy_utils import is_loopback_proxy
    upstream = (
        str(getattr(proxy_cfg, "PROXY_POOL_UPSTREAM_PROXY", "") or "").strip()
        or str(getattr(proxy_cfg, "PLAN_CHECK_UPSTREAM_PROXY", "") or "").strip()
    )
    if not upstream:
        raise RuntimeError("Grok 动态注册要求经动态家宽代理池出口；当前未配置上游链路，已停止")
    usable = [str(item).strip() for item in (getattr(proxy_cfg, "PROXY_POOL", []) or [])
              if str(item).strip() and not is_loopback_proxy(item)]
    if not usable:
        raise RuntimeError("Grok 动态注册要求动态家宽代理；当前只有本机代理或没有可用出口，已停止")
    return True


def _release_browser_target(target):
    with _LOCK:
        _ACTIVE_BROWSER_TARGETS.discard(str(target or "").strip())


def _run(job_id, signals):
    record = store.job(job_id, private=True)
    if not record or record["status"] != "pending":
        return
    try:
        driver = record["private"].get("driver", "browser")
        if driver == "protocol":
            from core.grok_protocol import run
        else:
            from core.grok_browser import run
        def update(status, stage, message, **private):
            store.update_job(job_id, status, stage, message, private=private)
        update("running", "starting", f"开始 Grok 注册（driver={driver}）；不占用 GPT 邮箱注册状态")
        relay = None
        # Every Grok driver owns exactly one dynamic residential exit.  Both
        # visible Chrome and HTTP use this same relay, never the machine's
        # ambient or loopback proxy.  A dead exit is replaced only before any
        # registration page or request starts.
        from core.grok_browser import GrokBrowserError
        attempted = set()
        last_error = None
        for attempt in range(1, 4):
            relay, proxy_target = _dynamic_pool_route(exclude_targets=attempted)
            attempted.add(str(proxy_target))
            record["private"]["proxy_target"] = proxy_target
            record["private"]["proxy_transport"] = relay.proxy_url if relay else ""
            update("running", "proxy", f"动态家宽出口已固定：{proxy_target}；本任务全程复用（出口 {attempt}/3）")
            try:
                from core.grok_browser import verify_proxy_transport
                verify_proxy_transport(relay.proxy_url)
                record["private"]["proxy_prechecked"] = True
                break
            except GrokBrowserError as exc:
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
            if driver == "protocol":
                result = _run_protocol(record, signals, update, relay.proxy_url)
            else:
                # Visible Chrome must receive the task relay explicitly.  Do not
                # rely on a record field alone: a missing/stale value would let
                # Chrome fall back to the machine's ambient network route.
                result = run(record, store.mailbox(record["email"], record["source"]), signals, update,
                             proxy_url=relay.proxy_url)
            if result:
                saved = store.save_account(job_id, result)
                cli_message = ""
                try:
                    authorize_cli(saved["account_id"], update,
                                  proxy_url=(relay.proxy_url if relay is not None else None))
                    cli_message = "Grok 账号、SSO 与官方 Grok CLI auth.json 均已保存"
                except Exception:
                    # The registration itself is complete. CLI authorization is a
                    # separate, retryable step and must not turn the account into a
                    # failed signup or trigger another OTP/registration attempt.
                    cli_message = "Grok 账号与 SSO 已保存；官方 Grok CLI 授权未完成，可在账号页重试"
                update("success", "complete", cli_message + "；不代表 API 套餐或模型调用资格")
        finally:
            if relay is not None:
                relay.close()
            _release_browser_target(record["private"].get("proxy_target"))
    except Exception as exc:
        record = store.job(job_id, private=True) or {}
        uncertain = record.get("private", {}).get("profile_submitted")
        http_status = getattr(exc, "http_status", None)
        reason_code = getattr(exc, "reason", "")
        status = "uncertain" if uncertain else "cancelled" if signals.stop.is_set() else "blocked" if (
            http_status in (401, 403, 429) or reason_code in {"native_security", "protocol_challenge", "protocol_email_unavailable"}
        ) else "failed"
        reason = {"browser_closed": "注册浏览器已关闭", "third_party": "进入第三方页面，未提交后续信息",
                  "dynamic_proxy": "Grok 要求动态住宅代理池出口；本机代理缺少上游已被拒绝",
                  "window_unavailable": "无法展开本任务浏览器窗口，未访问官网或发码",
                  "user_stop": "用户停止了此任务", "mail_timeout": "验证码未获取（已读取3次，未重发）",
                  "protocol_network": "原生HTTP连接未完成，不重放请求或切换线路",
                  "native_security": "原生SDK安全上下文尚未接通；未打开浏览器或跳过校验",
                  "protocol_challenge": "官网明确要求人机验证；协议任务已停止，未自动打开浏览器或重放请求",
                  "protocol_proxy": "现有网络代理配置无效，未回退直连或使用代理池",
                  "protocol_response": "原生HTTP响应格式未确认，不重放请求",
                  "protocol_rejected": "官网拒绝原生HTTP请求，不自动重试",
                  "protocol_email_unavailable": "官网提示该邮箱当前无法使用邮箱方式注册（Email sign-up isn't available right now）；请改用其他登录方式或更换邮箱，不要对同一邮箱重复发码",
                  "proxy_unavailable": "动态家宽出口预检未通过（最多试 3 个出口），未打开注册页；请检查代理池库存",
                  "protocol_identity": "原生会话归属或验证状态不匹配，未保存SSO",
                  "protocol_security": "发码后需要原生安全上下文，未重开流程或再次发码",
                  "protocol_sso": "官网返回SSO登录方式，需要人工确认，未重复建号",
                  "protocol_redirect": "原生会话跳转不符合允许范围，未继续访问",
                  "protocol_send": "发码接口未确认接收，未读取邮箱",
                  "protocol_verify": "邮箱验证结果未确认，未重复提交",
                  "sdk_config": "官网公开SDK配置缺失或不唯一，未猜测配置",
                  "sdk_proxy": "SDK无法使用当前固定代理，未换线或回退直连",
                  "sdk_unavailable": "未找到普通原生SDK浏览器运行时，未自动安装或替换浏览器",
                  "sdk_isolation": "SDK上下文不符合业务隔离要求，已停止",
                  "sdk_page": "SDK官网上下文未正常加载，未重试或换线",
                  "sdk_runtime": "原生SDK运行或加载失败，未绕过CSP、TLS或重试认证",
                  "sdk_widget": "原生验证组件返回错误或过期，未伪造验证结果",
                  "sdk_token": "原生SDK未返回有效的新上下文，未提交请求",
                  "sdk_security_context": "官网未下发匿名安全上下文；未生成令牌或提交邮箱",
                  "timeout": "等待页面或人工操作超时"}.get(getattr(exc, "reason", ""), "请查看浏览器阶段")
        if http_status in (401, 403, 429):
            reason = f"服务拒绝请求 HTTP {http_status}，已停止且不换线"
        elif type(exc).__name__ not in {"GrokBrowserError", "GrokProtocolError", "ManualVerificationRequired",
                                         "EmailCodeRejected", "TimeoutError", "RuntimeError"}:
            # Fixture seams can replace the runner with an incompatible
            # callable. Keep that internal defect distinguishable from a real
            # signup failure, without logging exception text or credentials.
            reason = f"内部执行异常（{type(exc).__name__}）；未重放注册或改密"
        # Never log browser exception strings, URLs, page HTML, candidate passwords or OTP.
        store.update_job(job_id, status, "stopped", f"Grok 流程已停止（{type(exc).__name__}）；" +
            reason + "；" + ("建号提交结果未确认，保留候选且不自动重提" if uncertain else "未自动重试"))
        _release_browser_target(record["private"].get("proxy_target"))


def _run_protocol(record, signals, update, proxy_url):
    """Run native HTTP on the task's fixed relay, never an ambient proxy."""
    import requests
    from core.grok_browser import verify_proxy_transport
    from core.grok_protocol import run
    # The same transport check gates the HTTP driver.  It proves the relay
    # reaches a public endpoint before any mailbox or account request.
    verify_proxy_transport(proxy_url)
    http = requests.Session()
    http.trust_env = False
    http.proxies = {"http": proxy_url, "https": proxy_url}
    http.headers.update({"Accept": "application/json"})
    update("running", "proxy", "原生HTTP使用本任务固定的动态家宽出口；不读取系统代理、不回退直连")
    try:
        return run(record, store.mailbox(record["email"], record["source"]), signals, update, http=http)
    finally:
        http.close()


def authorize_cli(account_id, update=None, *, proxy_url=None):
    from core import grok_cli_auth
    account = store.account(account_id, private=True)
    if not account:
        raise ValueError("Grok 账号不存在")
    payload = account["payload"]
    if update:
        update("running", "cli_auth", "Grok 注册已完成；开始官方 Grok CLI 设备授权（不重发邮箱验证码）")
    relay = None
    try:
        if proxy_url is None:
            # CLI authorization opens a browser as well. It must use the same
            # kind of fixed dynamic residential exit, never the ambient route.
            relay, _ = _dynamic_pool_route()
            proxy_url = relay.proxy_url if relay else None
        result = grok_cli_auth.authorize_account(account["email"], payload.get("sso", ""), payload.get("sso_rw", ""),
                                                 proxy_url=proxy_url)
    except Exception as exc:
        store.set_cli_auth_error(account_id, f"{type(exc).__name__}: {exc}")
        if update:
            update("running", "cli_auth_failed", "Grok 账号已保存；Grok CLI 授权未完成，可在账号页重试")
        raise
    finally:
        if relay is not None:
            relay.close()
    cli = {"status": "ready", "authorized_at": result["authorized_at"], "expires_at": result.get("expires_at"),
           "auth_json": result["auth_json"], "error": ""}
    store.set_cli_auth(account_id, cli)
    if update:
        update("success", "complete", "Grok 账号、SSO 与官方 Grok CLI auth.json 均已保存")
    return cli


def manual_code(job_id, value):
    code = validate_code(value, allow_numeric=True)
    if not code:
        raise ValueError("请输入当前 Grok 邮件中的六位数字或字母数字验证码")
    with _LOCK:
        signals = _RUNNING.get(job_id)
        record = store.job(job_id)
        if not signals or not record or record["stage"] != "email_code":
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
        if not signals or not record or record["status"] != "manual_required" or record["stage"] != "access_check":
            raise ValueError("此任务当前不在等待人工接管确认")
        signals.resume.set()


def verify_native(job_id):
    with _LOCK:
        record = store.job(job_id)
        signals = _RUNNING.get(job_id)
        if not signals or not record or record['status'] != 'manual_required' or record['stage'] != 'native_challenge':
            raise ValueError('此任务当前不在等待原生SDK人工验证')
        signals.native_verify.set()


def initialize():
    global _WORKERS
    with _LOCK:
        store.recover()
        if not _RUNNING and not _PENDING:
            _WORKERS = store.workers()
