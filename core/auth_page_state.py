"""Read the server's initial Auth route state without executing page scripts."""
import json


def read_auth_page_session(document: str) -> dict | None:
    marker = "window.__reactRouterContext.streamController.enqueue("
    if not isinstance(document, str) or marker not in document:
        return None
    try:
        encoded, _ = json.JSONDecoder().raw_decode(document.split(marker, 1)[1])
        entries = json.loads(encoded)
        if not isinstance(entries, list):
            return None

        def field(ref, name):
            if type(ref) is not int or not 0 <= ref < len(entries):
                return None
            obj = entries[ref]
            if not isinstance(obj, dict):
                return None
            for key, value in obj.items():
                if not key.startswith("_") or not key[1:].isdigit():
                    continue
                index = int(key[1:])
                if index < len(entries) and entries[index] == name:
                    return value
            return None

        loader = field(0, "loaderData")
        layout = field(loader, "routes/layouts/client-auth-session-layout/layout")
        session = field(layout, "session")
        result = {}
        for name in ("session_id", "email", "email_verification_mode",
                     "is_missing_session", "passwordless_email_otp_send_pending",
                     "post_login_add_password", "phone_verification_channel", "set_phone_verification_channel",
                     "multi_channel_allowed"):
            ref = field(session, name)
            if type(ref) is int and 0 <= ref < len(entries):
                result[name] = entries[ref]
        username = field(session, "username")
        value = field(username, "value")
        kind = field(username, "kind")
        if (type(kind) is int and 0 <= kind < len(entries) and entries[kind] == "email"
                and type(value) is int and 0 <= value < len(entries)
                and isinstance(entries[value], str)):
            result["username_email"] = entries[value]
        return result or None
    except (ValueError, TypeError, IndexError, AttributeError, RecursionError):
        return None
