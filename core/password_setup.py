"""Add a missing GPT password after successful 2FA, using the settings reauth flow."""
import json
import logging
import time
from urllib.parse import urlencode, urljoin, urlsplit

import pyotp

from core import db
from core.auth_diagnostics import auth_error_diagnostic, redact_error_text

logger = logging.getLogger(__name__)
_AUTH = "https://auth.openai.com"
_ALREADY_SET = "already_set"


class PasswordSetupError(RuntimeError):
    def __init__(self, message: str, *, diagnostic=None):
        super().__init__(message)
        self.diagnostic = diagnostic


def _stage(session, name: str) -> None:
    session._password_setup_stage = name
    logger.info("[密码] 阶段：%s", name)


def _failure_summary(detail: dict) -> str:
    return (f"阶段={detail['stage']} HTTP={detail['http_status']} "
            f"error_code={detail['error_code']} request_id={detail['request_id']} "
            f"exception={detail['exception_type']} "
            f"原因={detail['reason']}；{detail['error_message']}")[:1000]


def _failure(exc, stage: str, *, sensitive_values=()) -> dict:
    """Safe failure detail, never the original request URL or response text."""
    detail = getattr(exc, "diagnostic", None)
    if not isinstance(detail, dict):
        detail = auth_error_diagnostic(getattr(exc, "response", None), stage=stage,
                                       sensitive_values=sensitive_values)
    else:
        detail = dict(detail)
    if detail.get("http_status") in (0, None):
        response = getattr(exc, "response", None)
        if response is not None:
            detail = auth_error_diagnostic(response, stage=stage, sensitive_values=sensitive_values)
    for name in ("status_code", "headers"):
        if not getattr(exc, name, None):
            response = getattr(exc, "response", None)
            if response is not None:
                setattr(exc, name, getattr(response, name, None))
    detail["exception_type"] = type(exc).__name__
    if isinstance(exc, PasswordSetupError):
        detail["reason"] = redact_error_text(str(exc), sensitive_values=sensitive_values)
    else:
        detail["reason"] = type(exc).__name__
    return detail


def _auth_url(value: str) -> str:
    url = urljoin(_AUTH, str(value or ""))
    parts = urlsplit(url)
    if (not value or parts.scheme != "https" or parts.hostname != "auth.openai.com"
            or parts.port not in (None, 443) or parts.username or parts.password):
        raise PasswordSetupError("密码流程返回了非预期跳转，已停止")
    return url


def _json_response(response, *, stage="response", sensitive_values=(), accept_4xx=False) -> dict:
    # Never include a credential-bearing response body or exception URL in logs.
    logger.info("[密码] %s 响应：HTTP %s", stage, response.status_code)
    if not 200 <= response.status_code < 300 and not (accept_4xx and 400 <= response.status_code < 500):
        raise PasswordSetupError("密码流程请求失败，不自动重放", diagnostic=auth_error_diagnostic(
            response, stage=stage, sensitive_values=sensitive_values))
    try:
        data = response.json()
    except ValueError:
        error = PasswordSetupError("密码流程响应不是有效 JSON（不是原始响应正文）",
                                   diagnostic=auth_error_diagnostic(
                                       response, stage=stage, sensitive_values=sensitive_values))
        error.response = response
        raise error from None
    # A 4xx error body is parsed by the add-password rejection branch so its
    # structured diagnostic is retained. Other responses must be a JSON object.
    if not isinstance(data, dict) or (data.get("error") and not 400 <= response.status_code < 500):
        error = PasswordSetupError("密码流程响应不符合预期，已停止（未记录原始响应正文）",
                                   diagnostic=auth_error_diagnostic(
                                       response, stage=stage, sensitive_values=sensitive_values))
        error.response = response
        error.payload = data
        raise error
    return data


def _eligibility(session, token: str, action: str) -> bool:
    _stage(session, "eligibility_" + action)
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {token}"
    data = _json_response(session.get(
        f"https://chatgpt.com/backend-api/accounts/{action}_password/eligibility", headers=headers,
    ), stage="eligibility_" + action, sensitive_values=(token,))
    if type(data.get("eligible")) is not bool:
        raise PasswordSetupError("未取得明确的密码设置资格，已停止")
    return data["eligible"]


def _start_reauth(session, email: str) -> str:
    _stage(session, "reauth_csrf")
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    csrf = _json_response(session.get("https://chatgpt.com/api/auth/csrf", headers=headers), stage="reauth_csrf")
    if not csrf.get("csrfToken"):
        raise PasswordSetupError("密码重认证缺少 CSRF")
    query = {"connection": "password", "login_hint": email, "reauth": "password",
             "max_age": "0", "ext-oai-did": session.device_id, "post_login_add_password": "true"}
    headers.update({"content-type": "application/x-www-form-urlencoded", "origin": "https://chatgpt.com"})
    _stage(session, "reauth_signin")
    data = _json_response(session.post(
        "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query), headers=headers,
        data=urlencode({"csrfToken": csrf["csrfToken"], "callbackUrl": "https://chatgpt.com/", "json": "true"}),
    ), stage="reauth_signin", sensitive_values=(csrf["csrfToken"],))
    return _auth_url(data.get("url"))


def _continuation(data: dict) -> str:
    from core.account_liveness import _extract_continue_url
    target = _extract_continue_url(data)
    if not target and (data.get("page") or {}).get("type") == "reset_password_new_password":
        target = "/reset-password/new-password"
    return _auth_url(target)


def _password_login_page(session, row: dict) -> str:
    """Return a bound add-password page, or ``_ALREADY_SET`` when the account
    already has a password and the current site no longer offers add-password.

    Only the authenticated account identity plus the current email/mail source
    is accepted; the page is never inferred from a reset-password URL.
    """
    url = _password_page(session, row)
    return _existing_password_evidence(session, row, urlsplit(url).path.rstrip("/"))


def _existing_password_evidence(session, row: dict, landing: str) -> str:
    """Distinguish a bound add-password page from the password-login page.

    The current reset-password URL is not accepted as a new-password page
    without the account-bound state.  Missing state is reported as an
    existing/untracked password rather than guessed or overwritten.
    """
    if landing == "/log-in/password":
        return _ALREADY_SET
    state = getattr(session, "_registration_auth_page_state", None) or {}
    identity = str(state.get("email") or state.get("username_email") or "").strip().lower()
    if (state.get("post_login_add_password") is True and state.get("is_missing_session") is not True
            and state.get("session_id") and identity == row["email"].strip().lower()):
        return landing
    return _ALREADY_SET


def _email_otp(session, row: dict, url: str) -> dict:
    _stage(session, "email_otp")
    from core.email_provider import wait_for_otp
    from core.generic_api_mail_client import create_signature_poll_state, uses_direct_icapi_polling
    from core.openai_auth import (
        initialize_passwordless_login_otp,
        validate_email_otp,
        EmailOtpInvalidError,
    )
    ready = issued = time.time()
    if initialize_passwordless_login_otp(session, row["email"], url):
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
        _stage(session, "reauth_navigation")
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
        elif path == "/log-in/password":
            # The site only offers "add password" when the account has none.
            # After a prior attempt the same reauth can land here, which is
            # positive evidence that a password now exists; never overwrite it.
            return _ALREADY_SET
        elif path.startswith("/mfa-challenge/"):
            if not row.get("totp_secret"):
                raise PasswordSetupError("密码重认证需要已激活的 2FA")
            factor_id = path.rsplit("/", 1)[-1]
            _stage(session, "totp_reauth")
            logger.info("[密码] 按官网要求完成现有 TOTP 重认证")
            _mfa_issue_challenge(session, factor_id)
            url = _continuation(_mfa_verify(session, factor_id, pyotp.TOTP(row["totp_secret"]).now()))
        else:
            raise PasswordSetupError("密码重认证未进入预期页面，已停止")
    raise PasswordSetupError("密码重认证超过允许步骤数，已停止")


def _confirmed_add_result(data, status_code: int | None = None, response=None) -> bool:
    """Accept a bound success continuation, or the current site's bare 2xx body.

    The add-password endpoint changes its acknowledgement shape.  A 2xx
    ``reset_password/success`` continuation may omit ``method`` (GET is the
    default), and a successful request can return an empty object.  Neither
    case is a reason to discard a password the server has already accepted.
    A redirect to any other page remains unconfirmed.
    """
    if not isinstance(data, dict):
        raise PasswordSetupError("密码流程响应不符合预期，已停止")
    page = data.get("page")
    page_type = page.get("type") if isinstance(page, dict) else None
    continuation = data.get("continue_url")
    if continuation is None and response is not None:
        location = str(response.headers.get("Location") or "").strip() \
            if getattr(response, "headers", None) is not None else ""
        if location:
            continuation = location
            data.setdefault("method", "GET")
    if continuation is not None:
        if (not isinstance(continuation, str)
                or str(data.get("method", "GET") or "GET").upper() != "GET"):
            return False
        target = _auth_url(continuation)
        if urlsplit(target).path.rstrip("/") != "/reset-password/success":
            return False
        if page_type not in (None, "reset_password_success") or data.get("success") is False:
            return False
        return True
    # A bare success flag is accepted only under the freshly bound add-password
    # page. Here it comes from a 2xx response to this POST, not a saved session.
    if data.get("success") is True and status_code is not None and 200 <= status_code < 300:
        return True
    if data.get("success") is False:
        return False
    if not data:
        if response is not None and 300 <= int(getattr(response, "status_code", 0) or 0) < 400:
            return False
        return status_code is not None and 200 <= status_code < 300
    return page_type == "reset_password_success"


def _explicit_password_rejection(data, status_code: int | None = None) -> bool:
    """A 4xx password error is definitive; a 2xx page is not a rejection."""
    if not isinstance(data, dict) or not data.get("error"):
        return False
    return status_code is not None and 400 <= status_code < 500 and status_code != 408


def _password_already_set(data, status_code: int | None = None) -> bool:
    """The site says this account already has a password; do not overwrite it."""
    if status_code != 400 or not isinstance(data, dict):
        return False
    error = data.get("error")
    detail = error if isinstance(error, dict) else {}
    code = str(detail.get("code") or data.get("code") or "").strip()
    message = str(detail.get("message") or (error if isinstance(error, str) else "")
                  or data.get("message") or "").lower()
    return code == "password_already_set" or "already have a password" in message


def verify_private_candidate(row: dict, proxy: str | None = None) -> bool:
    """Promote a retained password only after the server accepts it at login.

    ``True`` means the candidate is now a confirmed password.  ``False`` means
    this attempt did not prove the candidate (for example the account now asks
    for a password reset page); the caller must not resubmit it and must not
    turn that into a password failure.
    """
    raw = row.get("extra_json")
    extra = json.loads(raw) if isinstance(raw, str) and raw.strip() else dict(raw or {})
    candidate = str(extra.get("password_setup_candidate") or "")
    if row.get("password_setup_status") != "uncertain" or not candidate:
        return False
    session = None
    try:
        from core.account_liveness import (
            _extract_continue_url, _follow_continue_and_fetch,
            _mfa_issue_challenge, _mfa_verify, _network_preflight_with_retry,
            _password_verify, _requires_workspace_selection,
            _select_workspace_and_fetch,
        )
        import pyotp

        session, authorize_url = _network_preflight_with_retry(
            row["email"], proxy, fingerprint_state={},
        )
        from core.account_export import follow_oauth_callback
        landing_url = follow_oauth_callback(session, authorize_url)
        landing = urlsplit(landing_url).path.rstrip("/")
        _stage(session, "candidate_verify")
        if landing != "/log-in/password":
            logger.warning("[密码] 候选密码核验未进入密码页；保留候选，不重复改密")
            return False
        verified = _password_verify(session, candidate)
        continuation = _extract_continue_url(verified)
        if not continuation:
            logger.warning("[密码] 候选密码已验证，但登录继续地址缺失；保留候选")
            return False
        referer = "https://auth.openai.com/log-in/password"
        if "/mfa-challenge/" in continuation:
            if not row.get("totp_secret"):
                logger.warning("[密码] 候选密码登录需要 TOTP，但账号没有 2FA 密钥；保留候选")
                return False
            factor_id = continuation.rstrip("/").rsplit("/", 1)[-1]
            _mfa_issue_challenge(session, factor_id)
            verified = _mfa_verify(session, factor_id, pyotp.TOTP(row["totp_secret"]).now())
            continuation = _extract_continue_url(verified)
            referer = f"https://auth.openai.com/mfa-challenge/{factor_id}"
            if not continuation:
                logger.warning("[密码] 候选密码 TOTP 已通过，但继续地址缺失；保留候选")
                return False
        if "/workspace" in continuation or _requires_workspace_selection(continuation):
            info = _select_workspace_and_fetch(session, row["email"], verified)
        else:
            info = _follow_continue_and_fetch(
                session, continuation, referer=referer,
                email=row["email"], auth_result=verified,
            )
        if not info.get("accessToken"):
            logger.warning("[密码] 候选密码登录后未取得 AT；保留候选")
            return False
        db.update_account_password_setup(row["id"], "success", password=candidate)
        logger.info("[密码] 候选密码已通过登录核验，确认保存；未再次提交改密")
        return True
    except PasswordSetupError:
        raise
    except Exception as exc:
        logger.warning("[密码] 候选密码核验未通过（%s）；保留候选，不重复改密",
                       type(exc).__name__)
        return False
    finally:
        if session is not None:
            from core.session import close_browser_session
            close_browser_session(session)


def _add_password(session, row: dict, *, mutation_allowed: bool = True) -> dict:
    # A retained candidate from an ambiguous earlier POST must be checked by
    # login, not by re-POSTing or by treating "change password" eligibility as
    # proof that the candidate itself is the saved password.
    if not mutation_allowed:
        if _eligibility(session, row["access_token"], "change"):
            db.update_account_password_setup(row["id"], "already_set")
            logger.info("[密码] 官网确认已有密码，停止重提；不覆盖原密码")
            return {"ok": True, "status": "skipped", "reason": "already_set"}
        if not _eligibility(session, row["access_token"], "add"):
            raise PasswordSetupError("官网当前不允许添加密码，未修改账号")
    elif not _eligibility(session, row["access_token"], "add"):
        # A missing add eligibility can be a transient capability answer while
        # a password already exists. Confirm "change" before claiming failure,
        # and never treat an unknown eligibility as absent.
        if _eligibility(session, row["access_token"], "change"):
            db.update_account_password_setup(row["id"], "already_set")
            logger.info("[密码] 官网确认已有密码，跳过；不覆盖、不猜测原密码")
            return {"ok": True, "status": "skipped", "reason": "already_set"}
        raise PasswordSetupError("官网当前不允许添加密码，未修改账号")
    url = _password_page(session, row)
    if url == _ALREADY_SET:
        db.update_account_password_setup(row["id"], "already_set")
        logger.info("[密码] 官网已确认账号有密码但本次没有候选；跳过，不改动原密码")
        return {"ok": True, "status": "skipped", "reason": "already_set"}
    return _submit_password(session, row, url)


def _submit_password(session, row: dict, url: str) -> dict:
    if url is None:
        raise PasswordSetupError("未取得绑定的添加密码页面，未提交密码")
    from core.openai_auth import generate_registration_password, request_sentinel_token, build_sentinel_header
    _stage(session, "password_challenge")
    bundle = request_sentinel_token(session, "password_reset")
    token, observer = build_sentinel_header(session, bundle, "password_reset")
    headers = session.get_auth_headers(referer=url)
    headers["openai-sentinel-token"] = token
    if observer:
        headers["openai-sentinel-so-token"] = observer
    # The current add-password page requires at least 12 characters; the
    # server can still reject weak/reused input with a structured 4xx, which
    # is never treated as success.
    password = generate_registration_password(length=20)
    # A timeout after POST is ambiguous. Retain the candidate privately, without
    # exporting it as a confirmed password or ever automatically submitting again.
    if not db.update_account_password_setup(row["id"], "running", candidate=password):
        raise PasswordSetupError("账号已不存在，未提交密码")
    _stage(session, "password_add")
    try:
        response = session.post(_AUTH + "/api/accounts/password/add", headers=headers,
                                data=json.dumps({"password": password}), allow_redirects=False)
        result = _json_response(response,
                                stage="password_add", sensitive_values=(password, row["access_token"], row["totp_secret"]),
                                accept_4xx=True)
        if _password_already_set(result, response.status_code):
            # Another client may have set the password between eligibility and
            # add. The site is authoritative: retain no candidate and never
            # overwrite the existing credential.
            db.update_account_password_setup(row["id"], "already_set", candidate="")
            logger.info("[密码] 官网返回已有密码，停止覆盖；请在官网使用重置流程")
            return {"ok": True, "status": "already_set", "reason": "password_already_set"}
        if _explicit_password_rejection(result, response.status_code):
            rejection = PasswordSetupError("官网明确拒绝了密码提交", diagnostic=auth_error_diagnostic(
                response, stage="password_add", sensitive_values=(password, row["access_token"], row["totp_secret"])))
            rejection.rejected = True
            raise rejection
        if not _confirmed_add_result(result, response.status_code, response):
            error = PasswordSetupError("密码提交结果未明确确认成功，需人工核验", diagnostic=auth_error_diagnostic(
                response, stage="password_add", sensitive_values=(password, row["access_token"], row["totp_secret"])))
            error.response = response
            raise error
    except PasswordSetupError as exc:
        if getattr(exc, "rejected", False):
            detail = _failure(exc, "password_add", sensitive_values=(password, row["access_token"], row["totp_secret"]))
            status = "blocked" if detail["http_status"] in (403, 429) else "failed"
            db.update_account_password_setup(row["id"], status, error=_failure_summary(detail),
                                             diagnostic=detail, candidate="")
            recorded = PasswordSetupError(_failure_summary(detail), diagnostic=detail)
            recorded.recorded = True
            raise recorded from None
        # The request was accepted. If only the optional confirmation body
        # differs, the candidate is already a saved password at the server.
        # Keep it privately and let the account page test it by logging in;
        # never submit the password again automatically.
        response = getattr(exc, "response", None)
        try:
            body = response.json() if response is not None else None
        except ValueError:
            body = None
        detail = auth_error_diagnostic(response, stage="password_add",
                                       sensitive_values=(password, row["access_token"], row["totp_secret"]))
        if (response is not None and 200 <= response.status_code < 300
                and (not isinstance(body, dict) or (not body.get("error") and not body.get("message")
                                                   and not body.get("detail")))):
            db.update_account_password_setup(row["id"], "uncertain", error="官网已接受密码请求，登录态待核验",
                                             diagnostic={**detail, "stage": "password_add", "http_status": 200,
                                                         "reason": "accepted_pending_login",
                                                         "exception_type": type(exc).__name__},
                                             candidate=password)
            try:
                from core.account_export import fetch_session
                latest = fetch_session(session)
                identity = str((latest.get("user") or {}).get("email") or "").strip().lower()
                if identity and identity != row["email"].strip().lower():
                    raise PasswordSetupError("密码设置后的登录态邮箱不一致")
                from core.account_session import session_fields
                db.update_account_liveness(row["id"], {"ok": True, "status": "live", **session_fields(session, latest),
                                                      "access_token": latest["accessToken"]})
                db.update_account_password_setup(row["id"], "uncertain", candidate=password)
            except Exception:
                logger.warning("[密码] 密码请求已被官网接受；Session 刷新未确认；保留候选且不重复提交")
            logger.warning("[密码] 官网已接受密码请求；未再次提交，待登录核验")
            return {"ok": True, "status": "accepted_unverified", "reason": "password_accepted_pending_login"}
        raise
    except Exception as exc:
        detail = _failure(exc, "password_add", sensitive_values=(password, row["access_token"], row["totp_secret"]))
        # An explicit Auth error is a rejection, not an ambiguous timeout.
        # All other outcomes retain the private candidate and never re-POST.
        definitive = (400 <= detail["http_status"] < 500 and detail["http_status"] != 408
                      and detail["error_code"] != "unavailable")
        status = ("blocked" if detail["http_status"] in (403, 429) else "failed") if definitive else "uncertain"
        # PasswordSetupError carries a safe diagnostic; its generic message
        # doesn't replace the structured attempt we just recorded.
        # The outer handler must not reclassify this already-recorded status.
        db.update_account_password_setup(row["id"], status, error=_failure_summary(detail),
                                         diagnostic=detail, **({"candidate": ""} if definitive else {}))
        error = PasswordSetupError(_failure_summary(detail), diagnostic=detail)
        error.recorded = True
        raise error from None
    if not db.update_account_password_setup(row["id"], "success", password=password):
        # The server already changed the password. Retain the confirmed value
        # privately so a local write retry never sends another password POST.
        db.update_account_password_setup(row["id"], "uncertain", candidate=password,
                                         error="官网已确认密码，但本地保存未完成")
        error = PasswordSetupError("官网已确认添加密码，但本地保存失败")
        error.recorded = True
        raise error
    logger.info("[密码] 设置完成：官网已确认，GPT 密码已保存（不记录密码）")
    try:
        from core.account_export import fetch_session
        _stage(session, "session_refresh")
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


def set_missing_password(account_id: int, *, session=None, proxy: str | None = None) -> dict:
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
    ambiguous_candidate = bool(extra.get("password_setup_candidate"))
    if ambiguous_candidate:
        # Never resubmit the retained candidate. An uncertain candidate may
        # already be the server-side password, so prove it through a normal
        # login before deciding whether any add-password flow is needed.
        logger.info("[密码] 上次候选的提交结果未确认；先独立登录核验，不重复提交原候选")
        verified = False
        try:
            verified = bool(verify_private_candidate(row, row.get("proxy_used")))
        except Exception as exc:
            logger.warning("[密码] 候选密码核验未完成（%s）；保留候选、不重复提交",
                           type(exc).__name__)
        if verified:
            return {"ok": True, "status": "success", "reason": "candidate_verified"}
        fresh = db.get_account(account_id) or row
        if db._extract_registration_password(fresh):
            return {"ok": True, "status": "success", "reason": "candidate_verified"}
        if fresh.get("password_setup_status") == "already_set":
            return {"ok": True, "status": "skipped", "reason": "already_set"}
    owns_session = session is None
    relay = None
    try:
        if ambiguous_candidate:
            # The uncertain candidate is preserved with its diagnostic. A new
            # attempt only runs when the account still has no password, so it
            # can start from a clean state instead of inheriting "running".
            db.update_account_password_setup(account_id, "uncertain", candidate="")
            ambiguous_candidate = False
        if owns_session and not ambiguous_candidate:
            # A fresh login is needed to prove whether an untracked password
            # exists before generating or submitting another one.
            from core.proxy_chain import open_proxy_pool_proxy
            from core.workflow_driver import create_account_session, resolve_driver
            target = str(proxy or row.get("proxy_used") or "").strip()
            if target and resolve_driver() == "protocol":
                target, relay = open_proxy_pool_proxy(target)
            session = create_account_session(proxy=target or None,
                                             fingerprint_seed=f"account:{row['email'].lower()}")
            url = _password_login_page(session, row)
            if url == _ALREADY_SET:
                db.update_account_password_setup(account_id, "already_set")
                return {"ok": True, "status": "skipped", "reason": "already_set"}
        logger.info("[密码] 开始：2FA 已完成，仅补设缺失的 GPT 密码")
        db.update_account_password_setup(account_id, "running")
        _stage(session, "prepare")
        if getattr(session, "is_browser_workflow", False) is True:
            raise PasswordSetupError("当前浏览器驱动尚未支持补设密码，请在官网设置；未切换协议执行")
        if owns_session:
            return _submit_password(session, row, url)
        return _add_password(session, row, mutation_allowed=not ambiguous_candidate)
    except Exception as exc:
        fresh = db.get_account(account_id) or {}
        status = fresh.get("password_setup_status")
        secrets = (row.get("access_token"), row.get("totp_secret"),
                   (json.loads(fresh.get("extra_json") or "{}") or {}).get("password_setup_candidate"))
        detail = _failure(exc, getattr(session, "_password_setup_stage", "prepare"), sensitive_values=secrets)
        if not getattr(exc, "recorded", False) and status not in {"uncertain", "success", "failed", "blocked"}:
            status = "blocked" if detail["http_status"] in (403, 429) else "failed"
            db.update_account_password_setup(account_id, status, error=_failure_summary(detail), diagnostic=detail)
        error = (db.get_account(account_id) or {}).get("password_setup_error") or _failure_summary(detail)
        logger.warning("[密码] 未完成：%s；保留账号、登录态及 2FA，不自动改密重试", error)
        return {"ok": False, "status": status, "error": error}
    finally:
        if owns_session and session is not None:
            from core.session import close_browser_session
            close_browser_session(session)
        if relay is not None:
            relay.close()
