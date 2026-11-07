"""Grok-only records. Never mutate GPT accounts or the shared mailbox's used flag."""
from contextlib import closing
import hashlib
import json
import os
import secrets
import sqlite3
import string

from core import db
from core.import_formats import valid_email

ACTIVE = {"pending", "running", "manual_required"}
TERMINAL = {"success", "failed", "blocked", "cancelled", "uncertain", "already_registered"}
PUBLIC_JOB_FIELDS = ("id", "email", "source", "status", "stage", "created_at", "started_at", "completed_at")


def connect():
    db._ensure_sqlite()
    return db._sqlite_conn()


def mailbox(email, source):
    if source == "icloud":
        source = "generic_api"
    with closing(connect()) as conn:
        row = conn.execute("SELECT payload,source FROM email_pool WHERE email=? COLLATE NOCASE AND source=?",
                           (email, source)).fetchone()
    if not row:
        raise ValueError("邮箱不在所选邮箱池中")
    data = json.loads(row[0])
    if data.get("archived"):
        raise ValueError("邮箱已归档，请先恢复邮箱")
    data.update(email=email.lower(), source=source)
    return data


def mailboxes(*, query="", source="generic_api", offset=0, limit=20):
    where, params = ["ep.archived=0"], []
    if source == "icloud":
        where.extend(["ep.source='generic_api'", "lower(ep.email) LIKE '%@icloud.com'"])
    elif source != "all":
        where.append("ep.source=?"); params.append(source)
    if query:
        where.append("instr(lower(ep.email),lower(?))>0"); params.append(query)
    sql = " AND ".join(where)
    with closing(connect()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM email_pool ep WHERE " + sql, params).fetchone()[0]
        rows = conn.execute("SELECT ep.email,ep.source,ep.created_at, "
            "EXISTS(SELECT 1 FROM accounts a WHERE a.email=ep.email COLLATE NOCASE) AS gpt_registered, "
            "EXISTS(SELECT 1 FROM grok_accounts a WHERE a.email=ep.email COLLATE NOCASE) AS grok_registered, "
            "(SELECT status FROM grok_jobs j WHERE j.email=ep.email COLLATE NOCASE ORDER BY id DESC LIMIT 1) AS job_status "
            "FROM email_pool ep WHERE " + sql + " ORDER BY ep.id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset]).fetchall()
    return {"items": [dict(row) for row in rows], "total": total}


def create_jobs(items, *, driver="protocol"):
    # All-or-nothing validation; no mailbox is consumed by planning a Grok task.
    if driver not in {"protocol", "browser"}:
        raise ValueError("Grok驱动必须为protocol或browser")
    clean, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or not valid_email(str(item.get("email") or "")):
            raise ValueError("邮箱条目不合法")
        email = item["email"].strip().lower()
        source = str(item.get("source") or "generic_api")
        if source == "icloud":
            source = "generic_api"
        if email in seen:
            raise ValueError("所选邮箱重复")
        seen.add(email); mailbox(email, source); clean.append((email, source))
    with db._LOCK, closing(connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        ids = []
        for email, source in clean:
            if conn.execute("SELECT 1 FROM grok_accounts WHERE email=?", (email,)).fetchone():
                raise ValueError("所选邮箱已有 Grok 账号，未重复注册")
            # Protect GPT mailbox challenges already in flight.
            if conn.execute("SELECT 1 FROM registration_jobs WHERE email=? COLLATE NOCASE "
                            "AND status IN ('pending','running','stopping')", (email,)).fetchone():
                raise ValueError("邮箱正在执行 GPT 任务，请稍后再试")
            if conn.execute("SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE AND ("
                "json_extract(payload,'$.totp_setup_status') IN ('queued','running') OR "
                "json_extract(payload,'$.live_check_status') IN ('queued','running') OR "
                "json_extract(payload,'$.email_change_status') IN ('queued','running') OR "
                "json_extract(payload,'$.codex_agent_status') IN ('queued','running') OR "
                "json_extract(payload,'$.password_setup_status')='running' OR "
                "json_extract(payload,'$.codex_status')='retrying')", (email,)).fetchone():
                raise ValueError("邮箱正在执行 GPT 认证操作，请稍后再试")
            password = (secrets.choice(string.ascii_uppercase) + secrets.choice(string.ascii_lowercase)
                        + secrets.choice(string.digits) + "!" + secrets.token_urlsafe(24))
            payload = {"password": password, "profile_submitted": False, "driver": driver}
            try:
                cur = conn.execute("INSERT INTO grok_jobs(email,source,status,stage,created_at,owner_pid,payload) "
                    "VALUES(?,?,'pending','pending',?,?,?)", (email, source, db._now(), os.getpid(), json.dumps(payload)))
            except sqlite3.IntegrityError:
                raise ValueError("邮箱已有 Grok 在途或结果未确认任务，未重复提交") from None
            ids.append(cur.lastrowid)
    return ids


def job(job_id, *, private=False):
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM grok_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return None
    result = {key: row[key] for key in PUBLIC_JOB_FIELDS}
    result["events"] = json.loads(row["events"])
    if private:
        result["private"] = json.loads(row["payload"])
    return result


def update_job(job_id, status, stage, message, *, private=None):
    if status not in ACTIVE | TERMINAL:
        raise ValueError("Grok 任务状态不合法")
    with closing(connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM grok_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return False
        if row["status"] in TERMINAL:
            return False
        events = json.loads(row["events"])
        if not events or events[-1]["stage"] != stage or events[-1]["message"] != message:
            events.append({"at": db._now(), "stage": stage, "message": message})
        payload = json.loads(row["payload"])
        payload.update(private or {})
        started = row["started_at"] or (db._now() if status != "pending" else None)
        ended = db._now() if status in TERMINAL else None
        conn.execute("UPDATE grok_jobs SET status=?,stage=?,started_at=?,completed_at=?,events=?,payload=? WHERE id=?",
            (status, stage, started, ended, json.dumps(events[-150:], ensure_ascii=False), json.dumps(payload), job_id))
    return True


def save_account(job_id, cookies):
    record = job(job_id, private=True)
    if not record or not record["private"].get("profile_submitted"):
        raise ValueError("尚未确认提交资料，不能保存为新账号")
    sso = cookies.get("sso")
    if not isinstance(sso, str) or not sso or any(c in sso for c in "\r\n;"):
        raise ValueError("未取得有效 Grok SSO")
    origin = record["private"].get("registration_origin")
    payload = {"email": record["email"], "source": record["source"],
               "password": record["private"]["password"] if record["private"].get("password_confirmed") else "", "sso": sso,
               "sso_rw": cookies.get("sso-rw", ""),
               "registration_origin": origin if origin in {"protocol", "browser"} else "browser",
               "session_validation_status": "protocol_identity" if record["private"].get("session_validation_status") == "protocol_identity" else "browser_identity",
               "proxy_target": record["private"].get("proxy_target") or "",
               "proxy_transport": record["private"].get("proxy_transport") or ""}
    with closing(connect()) as conn, conn:
        # Unique email and digest make duplicate SSO fail closed, even across processes.
        cur = conn.execute("INSERT INTO grok_accounts(email,source,created_at,payload,sso_digest) VALUES(?,?,?,?,?)",
                     (record["email"], record["source"], db._now(), json.dumps(payload),
                      hashlib.sha256(sso.encode()).hexdigest()))
        account_id = cur.lastrowid
    return {**payload, "account_id": account_id}


def accounts(*, query="", offset=0, limit=20, filters=None):
    filters = filters if isinstance(filters, dict) else {}
    where, params = [], []
    if query:
        where.append("instr(lower(email),lower(?))>0"); params.append(str(query)[:200])
    for column in ("source", "origin", "cli"):
        values = filters.get(column)
        # The UI sends {"cli": {"values": [...]}} so that older saved filter
        # maps stay readable; accept the bare list as well.
        if isinstance(values, dict):
            values = values.get("values")
        values = [str(v)[:80] for v in values] if isinstance(values, list) else []
        if not values:
            continue
        if column == "source":
            where.append(f"source IN ({','.join('?' * len(values))})"); params.extend(values)
        elif column == "origin":
            where.append(f"json_extract(payload,'$.registration_origin') IN ({','.join('?' * len(values))})")
            params.extend(values)
        else:
            where.append("COALESCE(json_extract(payload,'$.cli_auth.status'),'missing') IN "
                         f"({','.join('?' * len(values))})")
            params.extend(values)
    sql = (" WHERE " + " AND ".join(where)) if where else ""
    with closing(connect()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM grok_accounts" + sql, params).fetchone()[0]
        rows = conn.execute("SELECT * FROM grok_accounts" + sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                            [*params, limit, offset]).fetchall()
    items = []
    for row in rows:
        payload = json.loads(row["payload"])
        cli = payload.get("cli_auth") if isinstance(payload.get("cli_auth"), dict) else {}
        items.append({"id": row["id"], "email": row["email"], "source": row["source"],
                      "created_at": row["created_at"], "status": "registered", "has_sso": True,
                      "has_password": bool(payload.get("password")),
                      "has_sso_rw": bool(payload.get("sso_rw")),
                      "has_cli_auth": bool(cli.get("auth_json")),
                      "cli_auth_status": cli.get("status") or ("ready" if cli.get("auth_json") else "missing"),
                      "cli_auth_authorized_at": cli.get("authorized_at") or "",
                      "cli_auth_expires_at": cli.get("expires_at") or "",
                      "cli_auth_error": cli.get("error") or "",
                      "registration_origin": payload.get("registration_origin") if payload.get("registration_origin") in {"manual_capture", "protocol", "browser"} else "browser",
                      "session_validation_status": payload.get("session_validation_status") if payload.get("session_validation_status") in {"capture_only", "protocol_identity", "browser_identity"} else "browser_identity"})
    return {"items": items, "total": total}


def account_filter_options(column):
    """Distinct values for a Grok account table column; no credentials."""
    expressions = {"source": "source", "origin": "json_extract(payload,'$.registration_origin')",
                   "cli": "COALESCE(json_extract(payload,'$.cli_auth.status'),'missing')"}
    if column not in expressions:
        raise ValueError("不支持筛选此列")
    with closing(connect()) as conn:
        rows = conn.execute(f"SELECT DISTINCT {expressions[column]} AS value FROM grok_accounts").fetchall()
    values = sorted({str(row[0]) for row in rows if row[0] not in (None, "")})
    labels = {"protocol": "协议注册", "browser": "普通浏览器", "manual_capture": "人工抓包导入",
              "ready": "CLI 已授权", "failed": "CLI 授权失败", "missing": "未授权 CLI"}
    return {"items": [{"value": value, "label": labels.get(value, value)} for value in values]}


def secret(account_id, field):
    if field not in {"sso", "sso_rw", "password", "cli_auth"}:
        raise ValueError("不支持的 Grok 凭据字段")
    with closing(connect()) as conn:
        row = conn.execute("SELECT payload FROM grok_accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        return None
    payload = json.loads(row[0])
    if field == "cli_auth":
        value = payload.get("cli_auth") or {}
        return json.dumps(value.get("auth_json") or {}, ensure_ascii=False)
    return payload.get(field, "")


def account(account_id, *, private=False):
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM grok_accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        return None
    payload = json.loads(row["payload"])
    result = {"id": row["id"], "email": row["email"], "source": row["source"], "created_at": row["created_at"]}
    if private:
        result["payload"] = payload
    return result


def account_id_for_email(email):
    with closing(connect()) as conn:
        row = conn.execute("SELECT id FROM grok_accounts WHERE email=? COLLATE NOCASE", (str(email or ""),)).fetchone()
    return row["id"] if row else None


def set_cli_auth(account_id, cli_auth):
    with closing(connect()) as conn, conn:
        row = conn.execute("SELECT payload FROM grok_accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise ValueError("Grok 账号不存在")
        payload = json.loads(row["payload"])
        payload["cli_auth"] = cli_auth
        conn.execute("UPDATE grok_accounts SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), account_id))
    return payload


def set_cli_auth_error(account_id, message):
    with closing(connect()) as conn, conn:
        row = conn.execute("SELECT payload FROM grok_accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            return
        payload = json.loads(row["payload"])
        current = payload.get("cli_auth") if isinstance(payload.get("cli_auth"), dict) else {}
        current.update(status="failed", error=str(message or "")[:500])
        payload["cli_auth"] = current
        conn.execute("UPDATE grok_accounts SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), account_id))


def jobs(*, query="", status="", date_from="", date_to="", offset=0, limit=20):
    where, params = ["started_at IS NOT NULL"], []
    if query:
        job_id = query.strip().upper().removeprefix("G").removeprefix("#")
        if job_id.isascii() and job_id.isdigit():
            where.append("id=?"); params.append(job_id)
        else:
            where.append("instr(lower(email),lower(?))>0"); params.append(query)
    if status:
        where.append("status=?"); params.append(status)
    if date_from:
        where.append("substr(created_at,1,10)>=?"); params.append(date_from)
    if date_to:
        where.append("substr(created_at,1,10)<=?"); params.append(date_to)
    with closing(connect()) as conn:
        clause = " AND ".join(where)
        total = conn.execute("SELECT COUNT(*) FROM grok_jobs WHERE " + clause, params).fetchone()[0]
        rows = conn.execute("SELECT " + ",".join(PUBLIC_JOB_FIELDS) + " FROM grok_jobs WHERE " + clause +
                            " ORDER BY id DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total}


def cancel_pending(ids=None):
    if ids is not None and not ids:
        return 0
    with closing(connect()) as conn, conn:
        clause = "" if ids is None else " AND id IN (" + ",".join("?" for _ in ids) + ")"
        return conn.execute("UPDATE grok_jobs SET status='cancelled',stage='cancelled',completed_at=? "
                            "WHERE status='pending'" + clause, [db._now(), *(ids or [])]).rowcount


def recover():
    with closing(connect()) as conn, conn:
        # Never automatically replay a possibly sent OTP or creation request after restart.
        conn.execute("UPDATE grok_jobs SET status='uncertain',stage='interrupted',completed_at=? "
            "WHERE owner_pid!=? AND status IN ('running','manual_required')", (db._now(), os.getpid()))
        conn.execute("UPDATE grok_jobs SET status='cancelled',stage='interrupted',completed_at=? "
            "WHERE owner_pid!=? AND status='pending'", (db._now(), os.getpid()))


def workers(value=None):
    with closing(connect()) as conn, conn:
        if value is not None:
            conn.execute("INSERT INTO storage_meta(key,value) VALUES('grok_workers',?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(value),))
        row = conn.execute("SELECT value FROM storage_meta WHERE key='grok_workers'").fetchone()
    return max(1, min(10, int(row[0]))) if row else 1
