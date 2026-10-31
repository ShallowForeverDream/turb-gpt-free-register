"""Joined registration post-processing: eligibility first, then optional 2FA."""
from contextvars import ContextVar
from functools import wraps
import json
import logging

from core import db

logger = logging.getLogger(__name__)
_MANAGED = ContextVar("registration_completion", default=False)


def completion_managed():
    return _MANAGED.get()


def _wait_plan_check(args: dict, proxy: str | None, *, session=None):
    from core.plan_check_service import enqueue_account_plan_check
    if session is not None:
        # Stay on the registration thread: curl handles and the active proxy
        # tunnel belong to it. Do not wrap the saved proxy a second time.
        queued = enqueue_account_plan_check(
            **args, existing_session=session, return_future=True,
        )
        return queued["future"].result() if queued.get("accepted") else queued
    from core.workflow_driver import resolve_driver
    relay = None
    transport = proxy
    if proxy and resolve_driver() == "protocol":
        from core.proxy_chain import open_proxy_pool_proxy
        transport, relay = open_proxy_pool_proxy(proxy)
        from core.protocol_traffic import current_traffic, is_proxy_pool_target
        meter = current_traffic()
        if meter is not None:
            meter.register_proxy_route(transport, dynamic_ip=is_proxy_pool_target(proxy))
    try:
        # An explicit plan proxy is a complete transport override. Build the
        # saved pool proxy's upstream first, just as the 2FA service does.
        queued = enqueue_account_plan_check(**args, proxy=transport, return_future=True)
        return queued["future"].result() if queued.get("accepted") else queued
    finally:
        if relay is not None:
            relay.close()


def _record_token_check(account_id: int, result: dict) -> str:
    if result.get("ok"):
        db.update_account_liveness(account_id, {
            "ok": True, "status": "live", "checked_at": result.get("checked_at"),
            "stage": "registration_completion",
        })
        return "valid"
    try:
        error = json.loads(result.get("response_preview") or "{}").get("error")
        code = str(error.get("code") or "") if isinstance(error, dict) else ""
    except (TypeError, ValueError, AttributeError):
        code = ""
    if code == "account_deactivated":
        db.update_account_liveness(account_id, {
            "ok": False, "status": "deactivated", "error": code,
            "error_code": code, "stage": "registration_completion",
        })
        return "deactivated"
    if result.get("http_status") == 401 or result.get("needs_live_check"):
        db.update_account_liveness(account_id, {
            "ok": False, "status": "action_required",
            "error": "AT已失效，需要正常登录核验；未确认账号停用。",
            "error_code": code or "invalid_token", "stage": "registration_completion",
        })
        return "invalid"
    return "failed"


def finish_account(account_id: int, *, session=None) -> dict:
    from config import register, twofa
    from core.protocol_traffic import current_traffic

    row = db.get_account(account_id)
    if not row:
        raise ValueError("账号不存在")
    if row.get("live_check_status") == "deactivated":
        outcome = {"plan": "skipped", "twofa": "skipped", "status": "deactivated"}
        db.update_account_flow(account_id, completion=outcome)
        return outcome
    if not row.get("access_token"):
        outcome = {"plan": "skipped", "twofa": "skipped", "status": "login_required"}
        db.update_account_flow(account_id, completion=outcome)
        return outcome
    meter = current_traffic()
    # Only joined children may share this meter. Unrelated queued operations
    # still keep their own counters and cannot mutate a closed registration.
    if meter:
        meter.share_with_workers = True
    outcome = {"plan": "skipped", "twofa": "skipped"}
    args = {"account_id": account_id, "email": row["email"],
            "access_token": row.get("access_token") or "", "trigger": "registration_auto"}
    plan_session = {"session": session} if session is not None else {}
    if register.AUTO_PLAN_CHECK_AFTER_REGISTER:
        logger.info("[收尾] 查询套餐和试用资格：%s", row["email"])
        try:
            result = _wait_plan_check(args, row.get("proxy_used"), **plan_session)
            outcome["plan"] = "success" if result.get("ok") else "failed"
            _record_token_check(account_id, result)
        except Exception:
            logger.exception("[收尾] 套餐查询异常")
            outcome["plan"] = "failed"
    fresh = db.get_account(account_id) or {}
    if fresh.get("live_check_status") == "deactivated":
        outcome["status"] = "deactivated"
        db.update_account_flow(account_id, completion=outcome)
        return outcome
    did_setup_twofa = False
    if twofa.ENABLE_2FA:
        if row.get("totp_secret"):
            outcome["twofa"] = "success"
        else:
            from core.twofa_service import enqueue_account_totp_setup
            logger.info("[收尾] 开启 2FA：%s", row["email"])
            try:
                extra = {"existing_session": session} if session is not None else {}
                queued = enqueue_account_totp_setup(**args, proxy=row.get("proxy_used"), **extra)
                result = queued["future"].result() if queued.get("accepted") else queued
                outcome["twofa"] = "success" if result.get("ok") else "failed"
                did_setup_twofa = bool(result.get("ok"))
            except Exception:
                logger.exception("[收尾] 2FA 设置异常")
                outcome["twofa"] = "failed"
    fresh = db.get_account(account_id) or {}
    if fresh.get("live_check_status") == "deactivated":
        outcome["status"] = "deactivated"
    else:
        if outcome["twofa"] == "success":
            from core.password_setup import set_missing_password
            password_result = set_missing_password(account_id, **plan_session)
            outcome["password"] = (password_result.get("status", "success") if password_result.get("ok")
                                   else "failed")
            fresh = db.get_account(account_id) or fresh
        # Enrollment can invalidate an AT captured during reauthentication.
        # Verify once after activation, without another login or OTP request.
        if did_setup_twofa or outcome.get("password") == "success":
            try:
                result = _wait_plan_check({**args, "access_token": fresh.get("access_token") or args["access_token"],
                                           "trigger": "registration_final"}, row.get("proxy_used"), **plan_session)
                outcome["credential_validation"] = _record_token_check(account_id, result)
                if register.AUTO_PLAN_CHECK_AFTER_REGISTER:
                    outcome["plan"] = "success" if result.get("ok") else "failed"
            except Exception:
                logger.exception("[收尾] 2FA 后 AT 复核失败")
                outcome["credential_validation"] = "failed"
        state = (db.get_account(account_id) or {}).get("live_check_status")
        outcome["status"] = ("deactivated" if state == "deactivated" else
                             "partial" if state == "action_required" or
                             any(v in {"failed", "invalid"} for v in outcome.values()) else "success")
    db.update_account_flow(account_id, completion=outcome)
    logger.info("[收尾] 完成：plan=%s twofa=%s password=%s", outcome["plan"], outcome["twofa"],
                outcome.get("password", "skipped"))
    return outcome


def complete_registration_result(result, *, session=None):
    """Finish before the protocol session closes; browser drivers use fallback."""
    if not isinstance(result, dict) or not result.get("account_id"):
        return result
    if session is not None:
        from core.account_session import save_account_session
        save_account_session(int(result["account_id"]), session)
    if not isinstance(result.get("completion"), dict):
        try:
            extra = {"session": session} if session is not None else {}
            result["completion"] = finish_account(int(result["account_id"]), **extra)
        except Exception:
            logger.exception("[收尾] 后处理异常，保留已经保存的注册结果")
            result["completion"] = {"status": "partial", "error": "后处理异常，请查看日志"}
    if session is not None:
        save_account_session(int(result["account_id"]), session)
    status = result["completion"].get("status")
    if status == "deactivated":
        result.update(success=False, status="disabled", error="account_deactivated：后处理明确返回账号停用，已停止后续操作。")
    elif status in {"partial", "login_required"} and result.get("success"):
        result.update(status="partial_success", error="账号已创建，但后处理或登录态核验未完成；请检查查活、套餐、2FA 和 GPT 密码设置状态。")
    saved = db.get_account(int(result["account_id"])) or {}
    if saved.get("access_token"):
        result["access_token"] = saved["access_token"]
    if saved.get("totp_secret"):
        result["totp_secret"] = saved["totp_secret"]
    # 只有整个账号收尾明确成功才按 status=3 关闭临时 Gmail；partial 仍可能
    # 需要补收邮件码，交给人工/后续流程保留激活。失败路径由驱动 release_email
    # 处理，不能只凭任务成功文案跳过供应商收尾。
    if (str(saved.get("email_source") or "").strip().lower() == "smsbower_mail"
            and status == "success" and result.get("success")
            and "mail_activation" not in result):
        try:
            from core.smsbower_mail_client import mark_success_closed
            result["mail_activation"] = mark_success_closed(saved.get("email") or "")
        except Exception as exc:
            logger.warning("[收尾] SMSBower Gmail 激活关闭失败：%s: %s", type(exc).__name__, str(exc)[:180])
            result["mail_activation"] = "failed"
        if result.get("mail_activation") != "closed":
            result.update(status="partial_success", error="账号已创建，但 SMSBower 激活收尾未确认；请核对供应商订单，不自动重新购买。")
    return result


def complete_registration_flow(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        token = _MANAGED.set(True)
        try:
            return complete_registration_result(fn(*args, **kwargs))
        finally:
            _MANAGED.reset(token)
    return wrapped
