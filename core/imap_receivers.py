"""Imported receiver routes and credentials scoped to that exact receiver."""
import hashlib
import json
from contextlib import closing


def route_from_row(row):
    saved = row.get("imap_imported_route")
    source = saved if isinstance(saved, dict) else row
    ssl = source.get("ssl", source.get("imap_ssl", source.get("use_ssl", True)))
    return {
        "username": str(source.get("username") or source.get("imap_username") or "").strip(),
        "server": str(source.get("server") or source.get("imap_server") or "").strip(),
        "port": int(source.get("port") or source.get("imap_port") or 993),
        "ssl": ssl if isinstance(ssl, bool) else str(ssl).lower() not in {"0", "false", "no", "off"},
        "mailbox": str(source.get("mailbox") or source.get("imap_mailbox") or "INBOX"),
    }


def auth_key(route):
    identity = [route["server"].lower(), route["port"], route["ssl"], route["username"].lower()]
    digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:24]
    return "FORWARDED_IMAP_AUTH_" + digest.upper()


def imported_fields(*, inbox, server, port=993, ssl=True, mailbox="INBOX"):
    route = route_from_row({"username": inbox, "server": server, "port": port, "ssl": ssl, "mailbox": mailbox})
    return {"imap_username": route["username"], "imap_server": route["server"],
            "imap_port": route["port"], "imap_ssl": route["ssl"], "imap_mailbox": route["mailbox"],
            "imap_imported_route": route, "imap_auth_key": auth_key(route), "imap_route_origin": "import"}


def password_for_row(row, route, legacy_password):
    key = row.get("imap_auth_key")
    if not key and isinstance(row.get("imap_imported_route"), dict):
        key = auth_key(route)
    if not key:
        return legacy_password  # Compatibility for old, not-yet-migrated records only.
    if key != auth_key(route):
        raise ValueError("收件箱凭据绑定与导入配置不一致，请重新导入该邮箱的收件配置")
    from config.env_loader import env_str
    return env_str(key, "")  # Never borrow another receiver's authorization.


def credential_fields():
    """Public config metadata; authorization values stay in .env, not pool rows."""
    from core import db
    db._ensure_sqlite()
    profiles = {}
    with closing(db._sqlite_conn()) as conn:
        rows = conn.execute("SELECT payload FROM email_pool WHERE source='imap' AND ("
                            "json_extract(payload,'$.imap_auth_key') IS NOT NULL OR "
                            "json_extract(payload,'$.imap_imported_route') IS NOT NULL)")
        for record in rows:
            row = json.loads(record["payload"])
            if not row.get("imap_forwarded"):
                continue
            route = route_from_row(row)
            key = auth_key(route)
            if row.get("imap_auth_key") in (None, "", key):
                profiles[key] = route
    return [{"key": key, "file": "email.py", "type": "str", "group": "邮箱 / OTP",
             "label": f"{route['username']} 的 IMAP 授权码",
             "help": f"仅用于 {route['server']}:{route['port']} 上这个收件箱。地址和服务器以每条素材的导入记录为准；留空不会借用其他收件箱授权码。",
             "storage": "env", "secret": True}
            for key, route in sorted(profiles.items(), key=lambda item: item[1]["username"].lower())]


def validate_registration_receivers(selected, count, sources):
    """Configuration-only preflight; don't enqueue hundreds of doomed jobs."""
    from core import db
    from core.imap_mail_client import _account_from_row, _missing_forwarded_authorization, ImapConfigurationError
    if selected:
        rows = [db.get_imap_email_by_email(item["email"]) for item in selected if item.get("source") == "imap"]
    elif sources == ["imap"]:
        db._ensure_sqlite()
        with closing(db._sqlite_conn()) as conn:
            rows = [json.loads(record["payload"]) for record in conn.execute(
                "SELECT p.payload FROM email_pool p WHERE p.source='imap' AND p.status='available' "
                "AND NOT EXISTS(SELECT 1 FROM accounts a WHERE a.email=p.email COLLATE NOCASE) "
                "ORDER BY p.id LIMIT ?", (count,))]
    else:
        return
    checked = set()
    for row in rows:
        if not row or not row.get("imap_forwarded"):
            continue
        try:
            route = route_from_row(row)
        except (ValueError, TypeError) as exc:
            raise ImapConfigurationError("转发收件箱配置无效，请重新导入对应邮箱的收件配置") from exc
        key = auth_key(route)
        if key in checked:
            continue
        checked.add(key)
        account = _account_from_row(row)
        if not account.password:
            raise _missing_forwarded_authorization(account)
