"""所有账号流程共用的驱动选择。外部邮件/CPA/支付服务保留各自的 API 客户端。"""
from contextvars import ContextVar
from contextvars import copy_context
import importlib.util
import logging
import socket
from urllib.parse import urlsplit

_ACTIVE = ContextVar("workflow_driver", default=None)
logger = logging.getLogger(__name__)
ALIASES = {
    "api": "protocol", "http": "protocol", "roxybrowser": "roxy",
    "fingerprint": "roxy", "browser": "roxy", "cloakbrowser": "cloak",
    "browseruse": "browser_use", "browser-use": "browser_use", "bu": "browser_use", "sv": "skyvern",
}
DRIVERS = {"protocol", "roxy", "cloak", "browser_use", "skyvern"}


def resolve_driver():
    if _ACTIVE.get():
        return _ACTIVE.get()
    from config import roxybrowser
    value = str(roxybrowser.REGISTRATION_DRIVER or "").strip().lower()
    value = ALIASES.get(value, value)
    if value not in DRIVERS:
        raise ValueError(f"统一运行驱动无效：{value!r}")
    return value


def require_driver_ready(driver=None):
    """只检查配置/依赖；不启动浏览器、不领取邮箱。"""
    driver = driver or resolve_driver()
    if driver not in DRIVERS:
        raise ValueError(f"统一运行驱动无效：{driver!r}")
    if driver == "protocol":
        return driver
    packages = ["selenium"]
    if driver != "roxy":
        packages.append("playwright")
    if driver == "cloak":
        packages.append("cloakbrowser")
    for package in packages:
        if importlib.util.find_spec(package) is None:
            raise RuntimeError(f"{driver} 缺少依赖 {package}；请先安装项目 requirements.txt")
    if driver == "roxy":
        from config import roxybrowser as cfg
        if not str(cfg.ROXY_API_TOKEN or "").strip():
            raise RuntimeError("Roxy API Token 未配置；在统一运行方式 → RoxyBrowser 中填写")
        if not str(cfg.ROXY_WORKSPACE_ID or "").strip():
            raise RuntimeError("Roxy 工作区未配置；请使用“获取团队”选择自己的工作区")
        if not cfg.ROXY_ONE_PROFILE_PER_ACCOUNT:
            raise RuntimeError("统一账号流程要求开启 Roxy 一号一环境，避免账号共用登录态")
        parsed = urlsplit(str(cfg.ROXY_API_BASE or ""))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("Roxy API 地址无效，请检查 ROXY_API_BASE")
        if parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            try:
                with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=0.8):
                    pass
            except OSError as exc:
                raise RuntimeError(f"Roxy 本地服务未启动：{parsed.hostname}:{parsed.port or 80}") from exc
    elif driver == "cloak":
        from config import cloakbrowser as cfg
        if str(cfg.CLOAK_USER_DATA_DIR or "").strip():
            raise RuntimeError("统一账号流程要求 Cloak 用户数据目录留空，为每次账号任务创建独立环境")
    elif driver == "browser_use":
        from core.browser_use_client import BrowserUseClient
        BrowserUseClient().require_api_key()
        from config import browser_use as cfg
        if str(cfg.BROWSER_USE_PROFILE_ID or "").strip():
            raise RuntimeError("统一账号流程要求 Browser Use Profile ID 留空，避免共用账号环境")
    elif driver == "skyvern":
        from core.skyvern_client import SkyvernClient
        SkyvernClient().require_api_key()
        from config import skyvern as cfg
        if str(cfg.SKYVERN_BROWSER_PROFILE_ID or "").strip():
            raise RuntimeError("统一账号流程要求 Skyvern Profile ID 留空，避免共用账号环境")
    return driver


def driver_status():
    driver = resolve_driver()
    try:
        require_driver_ready(driver)
        ready, error = True, ""
    except Exception as exc:
        ready, error = False, str(exc)
    return {"driver": driver, "ready": ready, "error": error,
            "operations": ["registration", "live_check", "twofa", "email_change", "codex", "plan", "codex_agent"],
            "network_check": "not_performed",
            "external_services": ["IMAP/邮箱 API", "CPA/Sub2", "提链服务"]}


def create_account_session(*, proxy=None, protocol_factory=None, **kwargs):
    driver = require_driver_ready()
    if driver == "protocol":
        if protocol_factory is None:
            from core.session import BrowserSession
            protocol_factory = BrowserSession
        return protocol_factory(proxy=proxy, **kwargs)
    from core.browser_workflows import BrowserAccountSession
    return BrowserAccountSession(driver, proxy=proxy, **kwargs)


def unified_workflow(operation):
    """任务开始后固定驱动，配置热更新只影响后续任务。"""
    from functools import wraps
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            driver = resolve_driver()
            token = _ACTIVE.set(driver)
            logger.info("[统一流程] operation=%s driver=%s", operation, driver)
            try:
                return fn(*args, **kwargs)
            finally:
                _ACTIVE.reset(token)
        return wrapped
    return decorate


def submit_with_driver(executor, fn, *args, **kwargs):
    """提交后台任务时锁定当前统一驱动，避免排队期间热更新配置改变行为。"""
    driver = require_driver_ready()
    token = _ACTIVE.set(driver)
    try:
        context = copy_context()
        return executor.submit(context.run, fn, *args, **kwargs)
    finally:
        _ACTIVE.reset(token)
