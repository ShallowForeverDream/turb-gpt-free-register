"""One-day, recipient-isolated cache of verification mail, without mailbox credentials."""
import hashlib
import json
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path


CACHE_PATH = Path(__file__).resolve().parent.parent / "run" / "imap-message-cache.sqlite3"
TTL_SECONDS = 86400
_LOCK = threading.Lock()


def inbox_id(account):
    # Include the credential generation so changing an inbox cannot expose its
    # previous cached mail. Neither the username nor password is stored on disk.
    values = [account.server.lower(), account.port, account.use_ssl,
              (account.username or account.email).lower(), account.mailbox, account.password]
    return hashlib.sha256(json.dumps(values, ensure_ascii=True).encode()).hexdigest()


def _open():
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_PATH, timeout=0.2)
    try:
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages (
            inbox TEXT NOT NULL, recipient TEXT NOT NULL, mail_key TEXT NOT NULL,
            received_at REAL NOT NULL, stored_at REAL NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(inbox,recipient,mail_key))""")
        conn.execute("CREATE INDEX IF NOT EXISTS messages_expiry ON messages(received_at)")
    except BaseException:
        conn.close()
        raise
    return conn


def _prune(conn, now):
    conn.execute("DELETE FROM messages WHERE received_at < ? OR stored_at < ?",
                 (now - TTL_SECONDS, now - TTL_SECONDS))


def read(account, recipient, after_ts):
    now = time.time()
    with _LOCK, closing(_open()) as conn, conn:
        _prune(conn, now)
        rows = conn.execute("""SELECT payload FROM messages
            WHERE inbox=? AND recipient=? AND received_at>=? AND received_at<=?
            ORDER BY received_at DESC LIMIT 100""",
            (inbox_id(account), recipient.strip().lower(), max(after_ts, now - TTL_SECONDS), now + 30))
        return [json.loads(row[0]) for row in rows]


def write(account, records):
    """records contains only verified recipient/OTP mail, not the full inbox."""
    now = time.time()
    key = inbox_id(account)
    with _LOCK, closing(_open()) as conn, conn:
        _prune(conn, now)
        for recipient, item, stamp in records:
            if not now - TTL_SECONDS <= stamp <= now + 30:
                continue
            payload = json.dumps(item, ensure_ascii=False, sort_keys=True)
            mail_key = hashlib.sha256(payload.encode()).hexdigest()
            conn.execute("INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?,?)",
                         (key, recipient.strip().lower(), mail_key, stamp, now, payload))
        # A busy shared receiver is bounded as well as time-limited.
        conn.execute("""DELETE FROM messages WHERE rowid IN (
            SELECT rowid FROM messages ORDER BY received_at DESC LIMIT -1 OFFSET 10000)""")
