"""Authenticated Qoder API; credentials are read only through explicit secret endpoints."""
from datetime import date
import io
import json
import zipfile

from flask import Blueprint, jsonify, request, Response

from core import qoder_service as service, qoder_store as store


def register_qoder_routes(app):
    bp = Blueprint("qoder", __name__, url_prefix="/api/qoder")

    @bp.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @bp.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(ok=False, error=str(exc)), 400

    def paging():
        page = max(1, request.args.get("page", 1, type=int))
        size = max(1, min(1000, request.args.get("page_size", 20, type=int)))
        query = str(request.args.get("q", "")).strip()[:200]
        return {"query": query, "offset": (page - 1) * size, "limit": size}

    @bp.get("/accounts")
    def accounts():
        raw = request.args.get("filters", "")
        try:
            filters = json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            raise ValueError("筛选条件不是有效 JSON") from None
        return jsonify(ok=True, **store.accounts(**paging(), filters=filters))

    @bp.get("/accounts/filter-options")
    def filter_options():
        return jsonify(ok=True, **store.account_filter_options(request.args.get("column", "")))

    @bp.post("/accounts/bulk-auth")
    def bulk_auth():
        data = request.get_json() or {}
        ids = data.get("ids")
        field = str(data.get("field", ""))
        if field not in {"email", "pat", "password"}:
            raise ValueError("不支持的批量导出字段")
        if not isinstance(ids, list) or not 1 <= len(ids) <= 1000:
            raise ValueError("请选择1到1000个 Qoder 账号")
        try:
            ids = list(dict.fromkeys(int(value) for value in ids))
        except (TypeError, ValueError):
            raise ValueError("账号 ID 不合法") from None
        items = []
        for account_id in ids:
            row = store.account(account_id)
            if row is None:
                continue
            value = store.secret(account_id, field)
            if value:
                items.append({"id": account_id, "email": row["email"], "value": value})
        return jsonify(ok=True, items=items, total=len(items), missing=len(ids) - len(items))

    @bp.get("/accounts/<int:account_id>/secret")
    def secret(account_id):
        value = store.secret(account_id, request.args.get("field", "pat"))
        if value is None:
            return jsonify(ok=False, error="Qoder 账号不存在"), 404
        return jsonify(ok=True, value=value)

    @bp.get("/queue")
    def queue():
        return jsonify(ok=True, **service.state())

    @bp.post("/queue")
    def control():
        data = request.get_json() or {}
        return jsonify(ok=True, **service.control(data.get("action"), data.get("workers")))

    @bp.post("/jobs")
    def submit():
        data = request.get_json() or {}
        if data.get("authorized") is not True:
            raise ValueError("请先确认仅使用本人拥有或获授权的邮箱，并在浏览器人工完成必要验证")
        try:
            ids = service.submit(data.get("emails"), driver=data.get("driver", "browser"))
        except (RuntimeError, ImportError):
            return jsonify(ok=False, error="普通浏览器未准备就绪，请检查 Chrome/Edge 或 Playwright 安装"), 503
        return jsonify(ok=True, job_ids=ids, queue=service.state()), 202

    @bp.get("/jobs")
    def jobs():
        status = request.args.get("status", "")
        if status and status not in store.ACTIVE | store.TERMINAL:
            raise ValueError("Qoder 日志状态不合法")
        dates = {key: request.args.get(key, "") for key in ("date_from", "date_to")}
        for value in dates.values():
            if value:
                try:
                    if date.fromisoformat(value).isoformat() != value:
                        raise ValueError()
                except ValueError:
                    raise ValueError("日志日期必须为 YYYY-MM-DD") from None
        if dates["date_from"] and dates["date_to"] and dates["date_from"] > dates["date_to"]:
            raise ValueError("日志起始日期不能晚于结束日期")
        return jsonify(ok=True, queue=service.state(), **store.jobs(status=status, **dates, **paging()))

    @bp.get("/jobs/blocked")
    def blocked_jobs():
        return jsonify(ok=True, **store.unresolved())

    @bp.post("/jobs/<int:job_id>/resolve")
    def resolve_job(job_id):
        if (request.get_json() or {}).get("confirmed") is not True:
            raise ValueError("请确认该邮箱未成功注册 Qoder；只结束旧任务，不自动注册或发码")
        return jsonify(ok=True, **store.resolve_uncertain(job_id))

    @bp.get("/jobs/<int:job_id>")
    def job(job_id):
        record = store.job(job_id)
        if not record:
            return jsonify(ok=False, error="Qoder 任务不存在"), 404
        record["log"] = "\n".join(f"{e['at']} [{e['stage']}] {e['message']}" for e in record["events"])
        return jsonify(ok=True, **record)

    @bp.post("/jobs/<int:job_id>/code")
    def code(job_id):
        service.manual_code(job_id, (request.get_json() or {}).get("code"))
        return jsonify(ok=True)

    @bp.post("/jobs/<int:job_id>/stop")
    def stop(job_id):
        service.stop_job(job_id)
        return jsonify(ok=True)

    @bp.post("/jobs/<int:job_id>/continue")
    def continue_job(job_id):
        if (request.get_json() or {}).get("confirmed") is not True:
            raise ValueError("请先在浏览器人工处理官网提示，再确认继续")
        service.continue_job(job_id)
        return jsonify(ok=True)

    app.register_blueprint(bp)
