"""Temporary-mail activation journal in the project's SQLite database.

Keep provider write intents before sending them. An interrupted write must not be
replayed merely because the process cache was lost. No API keys or OTPs are stored.
"""
import json
from contextlib import closing

from core import db


def _connection():
    conn = db._sqlite_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS mail_activations (
        local_id TEXT PRIMARY KEY, email TEXT COLLATE NOCASE,
        payload TEXT NOT NULL
    )""")
    conn.commit()
    return conn


def save(record, expected_action=None):
    with closing(_connection()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT payload FROM mail_activations WHERE local_id=?",
                           (record["local_id"],)).fetchone()
        old = json.loads(row[0]) if row else {}
        pending = old.get("uncertain_action")
        if pending and pending != record.get("uncertain_action") and pending != expected_action:
            raise ValueError("SMSBower 操作结果未确认，不能覆盖待核对状态")
        if old.get("closed") and not record.get("closed"):
            raise ValueError("SMSBower 激活已关闭，不能重新打开")
        record = dict(record, creation_confirmed=bool(old.get("creation_confirmed") or record.get("creation_confirmed")),
                      code_digests=sorted(set(old.get("code_digests") or []) | set(record.get("code_digests") or [])))
        conn.execute(
            "INSERT OR REPLACE INTO mail_activations(local_id,email,payload) VALUES(?,?,?)",
            (record["local_id"], record.get("email") or "", json.dumps(record, ensure_ascii=False)),
        )


def by_email(email):
    # Source detection also calls this for non-SMS mailboxes. Reads must not add
    # a table just because another provider is resolving an address.
    with closing(db._sqlite_conn()) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='mail_activations'").fetchone():
            return None
        row = conn.execute(
            "SELECT payload FROM mail_activations WHERE email=? ORDER BY rowid DESC LIMIT 1",
            (email,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def begin_acquisition(record):
    """An unresolved purchase for the same credentials blocks another purchase."""
    with closing(_connection()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("SELECT payload FROM mail_activations WHERE email='' ").fetchall()
        for row in rows:
            other = json.loads(row[0])
            if (other.get("supplier") == record["supplier"]
                    and other.get("uncertain_action")):
                raise ValueError("SMSBower 上次领取结果未确认，请先核对平台订单；不自动重新购买")
        conn.execute("INSERT INTO mail_activations VALUES(?,?,?)",
                     (record["local_id"], "", json.dumps(record, ensure_ascii=False)))


def bind(record):
    """Reject a supplier reissuing an email/ID still owned by another task."""
    with closing(_connection()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in conn.execute("SELECT payload FROM mail_activations WHERE local_id!=?",
                                (record["local_id"],)).fetchall():
            other = json.loads(row[0])
            if other.get("supplier") != record["supplier"]:
                continue
            if (other.get("email", "").casefold() == record["email"].casefold()
                    or (other.get("original_email") and other["original_email"].casefold()
                        == record.get("original_email", "").casefold())
                    or other.get("mail_id") == record["mail_id"]):
                raise ValueError("SMSBower 返回重复邮箱/激活 ID；保留原任务绑定，请核对订单")
        conn.execute("UPDATE mail_activations SET email=?,payload=? WHERE local_id=?",
                     (record["email"], json.dumps(record, ensure_ascii=False), record["local_id"]))


def claim_action(record, action):
    """Atomically refuse closed or unresolved activations, across processes too."""
    with closing(_connection()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT payload FROM mail_activations WHERE local_id=?",
                           (record["local_id"],)).fetchone()
        saved = json.loads(row[0]) if row else record
        if saved.get("closed") or saved.get("uncertain_action"):
            raise ValueError("SMSBower 激活已关闭或操作结果未确认，禁止自动重放")
        pending = dict(record, uncertain_action=action,
                       creation_confirmed=bool(saved.get("creation_confirmed") or record.get("creation_confirmed")),
                       code_digests=sorted(set(saved.get("code_digests") or []) | set(record.get("code_digests") or [])))
        conn.execute("INSERT OR REPLACE INTO mail_activations VALUES(?,?,?)",
                     (record["local_id"], record["email"], json.dumps(pending, ensure_ascii=False)))


def consume_code(record, digest):
    """At most one process may consume a code from an activation."""
    with closing(_connection()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT payload FROM mail_activations WHERE local_id=?",
                           (record["local_id"],)).fetchone()
        saved = json.loads(row[0]) if row else record
        if saved.get("closed") or saved.get("uncertain_action"):
            raise ValueError("SMSBower 激活已关闭或操作结果未确认")
        used = set(saved.get("code_digests") or [])
        if digest in used:
            return False
        saved = dict(saved, code_digests=sorted(used | {digest}))
        conn.execute("INSERT OR REPLACE INTO mail_activations VALUES(?,?,?)",
                     (record["local_id"], record["email"], json.dumps(saved, ensure_ascii=False)))
        return True
