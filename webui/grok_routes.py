"""Authenticated Grok API; credentials are read only through explicit secret endpoints."""
from datetime import date
import io
import json
import zipfile

from flask import Blueprint, jsonify, request

from core import grok_service as service, grok_store as store
from core.grok_mail import GrokMailError, read_once


def register_grok_routes(app):
    bp = Blueprint("grok", __name__, url_prefix="/api/grok")

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
        """Return selected, explicitly-requested credentials; response is no-store."""
        data = request.get_json(silent=True) or {}
        ids = data.get("ids")
        field = str(data.get("field", ""))
        if field not in {"email", "auth_json", "sso", "password"}:
            raise ValueError("不支持的批量导出字段")
        if not isinstance(ids, list) or not 1 <= len(ids) <= 1000:
            raise ValueError("请选择1到1000个 Grok 账号")
        try:
            ids = list(dict.fromkeys(int(value) for value in ids))
        except (TypeError, ValueError):
            raise ValueError("账号 ID 不合法") from None
        items = []
        for account_id in ids:
            row = store.account(account_id)
            if row is None:
                continue
            if field == "email":
                items.append({"id": account_id, "email": row["email"], "value": row["email"]})
                continue
            value = store.secret(account_id, "cli_auth" if field == "auth_json" else field)
            if field == "auth_json":
                try:
                    payload = json.loads(value or "{}")
                except ValueError:
                    payload = {}
                if not isinstance(payload, dict) or not payload:
                    continue
                items.append({"id": account_id, "email": row["email"], "value": payload})
            elif value:
                items.append({"id": account_id, "email": row["email"], "value": value})
        return jsonify(ok=True, items=items, total=len(items), missing=len(ids) - len(items))

    @bp.post("/accounts/bulk-auth.zip")
    def bulk_auth_zip():
        data = request.get_json(silent=True) or {}
        ids = data.get("ids")
        if not isinstance(ids, list) or not 1 <= len(ids) <= 1000:
            raise ValueError("请选择1到1000个 Grok 账号")
        try:
            ids = list(dict.fromkeys(int(value) for value in ids))
        except (TypeError, ValueError):
            raise ValueError("账号 ID 不合法") from None
        archive = io.BytesIO()
        used, included = set(), 0
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for account_id in ids:
                row = store.account(account_id)
                value = store.secret(account_id, "cli_auth") if row else None
                try:
                    payload = json.loads(value or "{}")
                except ValueError:
                    payload = {}
                if row is None or not isinstance(payload, dict) or not payload:
                    continue
                name = row["email"].replace("/", "_").replace("\\", "_")
                filename, suffix = name, 2
                while filename in used:
                    filename = f"{name} ({suffix})"; suffix += 1
                used.add(filename); included += 1
                bundle.writestr(f"{filename}/auth.json", json.dumps(payload, ensure_ascii=False, indent=2))
        if not included:
            raise ValueError("选中的账号没有可导出的 Grok CLI auth.json")
        from flask import Response
        return Response(archive.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="grok-auth-json.zip"',
                                 "Cache-Control": "no-store", "Pragma": "no-cache"})

    @bp.get("/accounts/<int:account_id>/secret")
    def secret(account_id):
        value = store.secret(account_id, request.args.get("field", "sso"))
        if value is None:
            return jsonify(ok=False, error="Grok 账号不存在"), 404
        return jsonify(ok=True, value=value)

    @bp.post("/accounts/<int:account_id>/cli-auth")
    def cli_auth(account_id):
        if (request.get_json() or {}).get("confirmed") is not True:
            raise ValueError("请确认使用当前 Grok 账号完成官方 CLI 设备授权")
        try:
            result = service.authorize_cli(account_id)
        except Exception as exc:
            return jsonify(ok=False, error=f"Grok CLI 授权未完成：{exc}"), 502
        return jsonify(ok=True, status=result.get("status"), authorized_at=result.get("authorized_at"),
                       expires_at=result.get("expires_at"))

    @bp.get("/accounts/<int:account_id>/cli-auth/download")
    def cli_auth_download(account_id):
        from flask import Response
        value = store.secret(account_id, "cli_auth")
        if value is None:
            return jsonify(ok=False, error="Grok 账号不存在"), 404
        payload = json.loads(value or "{}")
        if not payload:
            return jsonify(ok=False, error="该账号尚未生成 Grok CLI auth.json"), 404
        return Response(json.dumps(payload, ensure_ascii=False, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="auth.json"',
                                 "Cache-Control": "no-store", "Pragma": "no-cache"})

    @bp.get("/mailboxes")
    def mailboxes():
        source = request.args.get("source", "icloud")
        if source not in {"all", "icloud", "generic_api", "imap", "outlook", "cloudflare_domain"}:
            raise ValueError("邮箱来源不合法")
        return jsonify(ok=True, **store.mailboxes(source=source, **paging()))

    @bp.post("/mailbox-code")
    def mailbox_code():
        data = request.get_json() or {}
        try:
            code = read_once(store.mailbox(str(data.get("email", "")), str(data.get("source", "generic_api"))))
        except GrokMailError as exc:
            return jsonify(ok=False, error=str(exc)), 502
        return jsonify(ok=True, code=code, note="只读现有 API；未触发发码；数字 GPT 码不会作为 Grok 码使用")

    @bp.post("/mailboxes/viewer-links")
    def viewer_links():
        from core import db, generic_api_mail_client
        from core.icapi_mailbox import MailboxError
        import csv
        data = request.get_json() or {}
        text = str(data.get("text") or "")
        if len(text) > 1024 * 1024: raise ValueError("链接文件不能超过1MB")
        records = []
        for line in text.splitlines():
            if not line.strip(): continue
            parts = line.strip().lstrip("\ufeff").split("----", 1) if "----" in line else next(csv.reader([line]))
            if len(parts) != 2: raise ValueError("每行需为 邮箱----邮件页面URL 或两列CSV；未记录原文")
            if parts[0].strip().lower() in {"email", "邮箱"}: continue
            records.append({"email": parts[0], "url": parts[1]})
        try:
            updated = db.configure_icapi_mailboxes(records, imported_at=str(data.get("imported_at") or "2026-10-28T21:08:15"))
        except MailboxError as exc:
            raise ValueError(str(exc)) from None
        for item in records: generic_api_mail_client._CONTEXT_CACHE.pop(item["email"].strip().lower(), None)
        return jsonify(ok=True, updated=updated, note="只替换提供的映射；未访问其他邮箱、发码或注册")

    @bp.get("/mailbox-link")
    def mailbox_link():
        from core.icapi_mailbox import is_viewer_url
        row = store.mailbox(request.args.get("email", ""), request.args.get("source", "generic_api"))
        url = row.get("code_url", "")
        if not is_viewer_url(url): raise ValueError("此邮箱尚未配置邮件页面链接")
        return jsonify(ok=True, url=url)

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
            ids = service.submit(data.get("emails"), driver=data.get("driver", "protocol"))
        except (RuntimeError, ImportError):
            return jsonify(ok=False, error="普通浏览器未准备就绪，请检查 Chrome/Edge 或 Playwright 安装"), 503
        return jsonify(ok=True, job_ids=ids, queue=service.state()), 202

    @bp.get("/jobs")
    def jobs():
        status = request.args.get("status", "")
        if status and status not in store.ACTIVE | store.TERMINAL:
            raise ValueError("Grok 日志状态不合法")
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

    @bp.get("/jobs/<int:job_id>")
    def job(job_id):
        record = store.job(job_id)
        if not record:
            return jsonify(ok=False, error="Grok 任务不存在"), 404
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

    @bp.post("/jobs/<int:job_id>/verify-native")
    def verify_native(job_id):
        if (request.get_json() or {}).get('confirmed') is not True:
            raise ValueError('请明确允许打开仅SDK验证窗口；不会执行页面注册或重发验证码')
        service.verify_native(job_id)
        return jsonify(ok=True)

    service.initialize()
    app.register_blueprint(bp)
