"""Add a missing GPT password after successful 2FA, using the settings reauth flow."""
import json
import logging
import time
from urllib.parse import urlencode, urljoin, urlsplit

import pyotp

from core import db

logger = logging.getLogger(__name__)
_AUTH = "https://auth.openai.com"


class PasswordSetupError(RuntimeError):
    pass


def _auth_url(value: str) -> str:
    url = urljoin(_AUTH, str(value or ""))
    parts = urlsplit(url)
    if (not value or parts.scheme != "https" or parts.hostname != "auth.openai.com"
            or parts.port not in (None, 443) or parts.username or parts.password):
        raise PasswordSetupError("密码流程返回了非预期跳转，已停止")
    return url


def _json_response(response) -> dict:
    # Never include a credential-bearing response body or exception URL in logs.
    if response.status_code != 200:
        raise PasswordSetupError(f"密码流程请求失败（HTTP {response.status_code}），不自动重放")
    data = response.json()
    if not isinstance(data, dict) or data.get("error"):
        raise PasswordSetupError("密码流程响应不符合预期，已停止")
    return data


def _eligibility(session, token: str, action: str) -> bool:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {token}"
    data = _json_response(session.get(
        f"https://chatgpt.com/backend-api/accounts/{action}_password/eligibility", headers=headers,
    ))
    if type(data.get("eligible")) is not bool:
        raise PasswordSetupError("未取得明确的密码设置资格，已停止")
    return data["eligible"]


def _start_reauth(session, email: str) -> str:
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    csrf = _json_response(session.get("https://chatgpt.com/api/auth/csrf", headers=headers))
    if not csrf.get("csrfToken"):
        raise PasswordSetupError("密码重认证缺少 CSRF")
    query = {"connection": "password", "login_hint": email, "reauth": "password",
             "max_age": "0", "ext-oai-did": session.device_id, "post_login_add_password": "true"}
    headers.update({"content-type": "application/x-www-form-urlencoded", "origin": "https://chatgpt.com"})
    data = _json_response(session.post(
        "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query), headers=headers,
        data=urlencode({"csrfToken": csrf["csrfToken"], "callbackUrl": "https://chatgpt.com/", "json": "true"}),
    ))
    return _auth_url(data.get("url"))


def _continuation(data: dict) -> str:
    from core.account_liveness import _extract_continue_url
    target = _extract_continue_url(data)
    if not target and (data.get("page") or {}).get("type") == "reset_password_new_password":
        target = "/reset-password/new-password"
    return _auth_url(target)


def _email_otp(session, row: dict, url: str) -> dict:
    from core.email_provider import wait_for_otp
    from core.generic_api_mail_client import create_signature_poll_state, uses_direct_icapi_polling
    from core.openai_auth import initialize_passwordless_email_otp, validate_email_otp, EmailOtpInvalidError
    ready = issued = time.time()
    if initialize_passwordless_email_otp(session, row["email"], url):
        ready = issued = session._registration_otp_ready_at
    logger.info("[密码] 等待邮箱重认证验证码；沿用邮箱来源，不重发")
    state = create_signature_poll_state(row["email"], ready_at=ready)
    options = {"email_source": row.get("email_source"), "first_read_anchor_ts": ready,
               "first_read_delay_seconds": 30 if uses_direct_icapi_polling(row["email"]) else 0}
    if state is not None:
        options["signature_poll_state"] = state
    for _ in range(3 if state is not None else 1):
        code = wait_for_otp(row["email"], after_ts=issued, **options)
        try:
            return validate_email_otp(session, code)
        except EmailOtpInvalidError:
            if state is None or not state.can_retry:
                raise
            state.defer_after_rejection()
    raise PasswordSetupError("验证码未获取")


def _password_page(session, row: dict) -> str:
    from core.openai_auth import follow_authorize
    from core.account_liveness import _mfa_issue_challenge, _mfa_verify
    url = _start_reauth(session, row["email"])
    for _ in range(4):
        from core.registration_service import check_stop_requested
        check_stop_requested()
        url = _auth_url(follow_authorize(session, url))
        path = urlsplit(url).path.rstrip("/")
        if path == "/reset-password/new-password":
            state = getattr(session, "_registration_auth_page_state", None) or {}
            identity = str(state.get("email") or state.get("username_email") or "").strip().lower()
            if (state.get("post_login_add_password") is not True or state.get("is_missing_session") is True
                    or not state.get("session_id") or identity != row["email"].strip().lower()):
                raise PasswordSetupError("未确认同一账号的添加密码页面，不提交密码")
            return url
        if path == "/email-verification":
            url = _continuation(_email_otp(session, row, url))
        elif path.startswith("/mfa-challenge/"):
            if not row.get("totp_secret"):
                raise PasswordSetupError("密码重认证需要已激活的 2FA")
            factor_id = path.rsplit("/", 1)[-1]
            logger.info("[密码] 按官网要求完成现有 TOTP 重认证")
            _mfa_issue_challenge(session, factor_id)
            url = _continuation(_mfa_verify(session, factor_id, pyotp.TOTP(row["totp_secret"]).now()))
        else:
            raise PasswordSetupError("密码重认证未进入预期页面，已停止")
    raise PasswordSetupError("密码重认证超过允许步骤数，已停止")


def _add_password(session, row: dict) -> dict:
    if not _eligibility(session, row["access_token"], "add"):
        if _eligibility(session, row["access_token"], "change"):
            db.update_account_password_setup(row["id"], "already_set")
            logger.info("[密码] 官网确认已有密码，跳过；不覆盖、不猜测原密码")
            return {"ok": True, "status": "skipped", "reason": "already_set"}
        raise PasswordSetupError("官网当前不允许添加密码，未修改账号")
    url = _password_page(session, row)
    from core.openai_auth import generate_registration_password, request_sentinel_token, build_sentinel_header
    bundle = request_sentinel_token(session, "password_reset")
    token, observer = build_sentinel_header(session, bundle, "password_reset")
    headers = session.get_auth_headers(referer=url)
    headers["openai-sentinel-token"] = token
    if observer:
        headers["openai-sentinel-so-token"] = observer
    password = generate_registration_password(length=20)
    # A timeout after POST is ambiguous. Retain the candidate privately, without
    # exporting it as a confirmed password or ever automatically submitting again.
    if not db.update_account_password_setup(row["id"], "running", candidate=password):
        raise PasswordSetupError("账号已不存在，未提交密码")
    try:
        result = _json_response(session.post(_AUTH + "/api/accounts/password/add", headers=headers,
                                             data=json.dumps({"password": password}), allow_redirects=False))
        if (result.get("success") is not True
                and (result.get("page") or {}).get("type") != "reset_password_success"):
            raise PasswordSetupError("密码提交结果未明确确认成功，需人工核验")
    except Exception:
        db.update_account_password_setup(row["id"], "uncertain", error="密码提交结果未确认；不自动重复提交，请人工核验")
        raise
    if not db.update_account_password_setup(row["id"], "success", password=password):
        raise PasswordSetupError("官网已确认添加密码，但本地保存失败")
    logger.info("[密码] 设置完成：官网已确认，GPT 密码已保存（不记录密码）")
    try:
        from core.account_export import fetch_session
        latest = fetch_session(session)
        identity = str((latest.get("user") or {}).get("email") or "").strip().lower()
        if identity and identity != row["email"].strip().lower():
            raise PasswordSetupError("密码设置后的登录态邮箱不一致")
        from core.account_session import session_fields
        db.update_account_liveness(row["id"], {"ok": True, "status": "live", **session_fields(session, latest),
                                              "access_token": latest["accessToken"]})
    except Exception:
        logger.warning("[密码] 密码已保存，Session 刷新未确认；交给收尾复核，不重复设置密码")
    return {"ok": True, "status": "success"}


def set_missing_password(account_id: int, *, session=None) -> dict:
    row = db.get_account(account_id)
    if not row:
        raise ValueError("账号不存在")
    if row.get("live_check_status") == "deactivated" or not row.get("access_token"):
        return {"ok": False, "status": "blocked", "error": "账号不可用或无登录态，不设置密码"}
    if db._extract_registration_password(row):
        logger.info("[密码] 已保存 GPT 密码，跳过；不改动已有密码")
        return {"ok": True, "status": "skipped", "reason": "already_saved"}
    if not row.get("totp_secret"):
        return {"ok": False, "status": "blocked", "error": "2FA 未确认激活，不设置密码"}
    raw = row.get("extra_json")
    extra = json.loads(raw) if isinstance(raw, str) and raw.strip() else dict(raw or {})
    if extra.get("password_setup_candidate"):
        return {"ok": False, "status": "uncertain", "error": "上次密码提交结果未确认，保留候选且不自动重提"}
    owns_session = session is None
    relay = None
    try:
        logger.info("[密码] 开始：2FA 已完成，仅补设缺失的 GPT 密码")
        db.update_account_password_setup(account_id, "running")
        if session is None:
            from core.workflow_driver import create_account_session, resolve_driver
            proxy = row.get("proxy_used")
            if proxy and resolve_driver() == "protocol":
                from core.proxy_chain import open_proxy_pool_proxy
                proxy, relay = open_proxy_pool_proxy(proxy)
            session = create_account_session(proxy=proxy, fingerprint_seed=f"account:{row['email'].lower()}")
        if getattr(session, "is_browser_workflow", False) is True:
            raise PasswordSetupError("当前浏览器驱动尚未支持补设密码，请在官网设置；未切换协议执行")
        return _add_password(session, row)
    except Exception as exc:
        fresh = db.get_account(account_id) or {}
        status = fresh.get("password_setup_status")
        if status not in {"uncertain", "success"}:
            db.update_account_password_setup(account_id, "failed", error="补设密码未完成，请核验官网设置入口")
        logger.warning("[密码] 未完成（%s）；保留账号、登录态及 2FA，不自动改密重试", type(exc).__name__)
        return {"ok": False, "status": status if status in {"uncertain", "success"} else "failed",
                "error": "补设密码未完成，请核验官网设置入口"}
    finally:
        if owns_session and session is not None:
            from core.session import close_browser_session
            close_browser_session(session)
        if relay is not None:
            relay.close()
