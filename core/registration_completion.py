"""Joined registration post-processing: eligibility first, then optional 2FA."""
from contextvars import ContextVar
from functools import wraps
import logging

from core import db

logger = logging.getLogger(__name__)
_MANAGED = ContextVar("registration_completion", default=False)


def completion_managed():
    return _MANAGED.get()


def finish_account(account_id: int) -> dict:
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
    if register.AUTO_PLAN_CHECK_AFTER_REGISTER:
        from core.plan_check_service import enqueue_account_plan_check
        logger.info("[收尾] 查询套餐和试用资格：%s", row["email"])
        try:
            queued = enqueue_account_plan_check(**args, proxy=row.get("proxy_used"), return_future=True)
            result = queued["future"].result() if queued.get("accepted") else queued
            outcome["plan"] = "success" if result.get("ok") else "failed"
        except Exception:
            logger.exception("[收尾] 套餐查询异常")
            outcome["plan"] = "failed"
    if twofa.ENABLE_2FA:
        if row.get("totp_secret"):
            outcome["twofa"] = "success"
        else:
            from core.twofa_service import enqueue_account_totp_setup
            logger.info("[收尾] 开启 2FA：%s", row["email"])
            try:
                queued = enqueue_account_totp_setup(**args, proxy=row.get("proxy_used"))
                result = queued["future"].result() if queued.get("accepted") else queued
                outcome["twofa"] = "success" if result.get("ok") else "failed"
            except Exception:
                logger.exception("[收尾] 2FA 设置异常")
                outcome["twofa"] = "failed"
    # A successful reauthentication refreshes the saved AT. If the preceding
    # eligibility lookup rejected the old AT, query once with the refreshed one.
    if outcome["plan"] == "failed" and outcome["twofa"] == "success":
        fresh = db.get_account(account_id) or {}
        if fresh.get("access_token") and fresh["access_token"] != args["access_token"]:
            try:
                queued = enqueue_account_plan_check(**{**args, "access_token": fresh["access_token"]}, proxy=row.get("proxy_used"), return_future=True)
                result = queued["future"].result() if queued.get("accepted") else queued
                outcome["plan"] = "success" if result.get("ok") else "failed"
            except Exception:
                logger.exception("[收尾] 刷新 AT 后查询套餐失败")
    outcome["status"] = "partial" if "failed" in outcome.values() else "success"
    db.update_account_flow(account_id, completion=outcome)
    logger.info("[收尾] 完成：plan=%s twofa=%s", outcome["plan"], outcome["twofa"])
    return outcome


def complete_registration_flow(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        token = _MANAGED.set(True)
        try:
            result = fn(*args, **kwargs)
            if isinstance(result, dict) and result.get("account_id"):
                try:
                    result["completion"] = finish_account(int(result["account_id"]))
                except Exception:
                    logger.exception("[收尾] 后处理异常，保留已经保存的注册结果")
                    result["completion"] = {"status": "partial", "error": "后处理异常，请查看日志"}
            return result
        finally:
            _MANAGED.reset(token)
    return wrapped
