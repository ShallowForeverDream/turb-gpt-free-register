"""Count mail transfer sizes only inside a joined registration context."""
from numbers import Real
from functools import wraps

from core.protocol_traffic import current_traffic


def _length(value):
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(value) if isinstance(value, (bytes, bytearray)) else 0


def _record_mail_http(response):
    meter = current_traffic()
    if meter is None:
        return response
    sizes = [getattr(response, key, None) for key in ("upload_size", "request_size", "download_size", "header_size")]
    if all(isinstance(value, Real) and not isinstance(value, bool) for value in sizes):
        upload, download = int(sizes[0] + sizes[1]), int(sizes[2] + sizes[3])
    else:
        request = getattr(response, "request", None)
        upload = _length(getattr(request, "body", None))
        headers = getattr(request, "headers", {})
        upload += sum(_length(str(k)) + _length(str(v)) + 4 for k, v in headers.items()) + 4
        content = getattr(response, "content", b"")
        try:
            wire = response.raw.tell()
        except (AttributeError, OSError):
            wire = None
        download = int(wire) if isinstance(wire, Real) else _length(content)
        download += sum(_length(str(k)) + _length(str(v)) + 4 for k, v in response.headers.items()) + 4
    meter.record_mail_bytes(upload, download, request=True)
    return response


def record_mail_http(response):
    try:
        return _record_mail_http(response)
    except Exception:
        meter = current_traffic()
        if meter is not None:
            meter.record_mail_bytes(request=True)
        return response


def track_mail_session(session):
    if current_traffic() is None:
        return session
    request = session.request
    @wraps(request)
    def measured(*args, **kwargs):
        return record_mail_http(request(*args, **kwargs))
    session.request = measured
    return session


def track_imap_connection(mail):
    if getattr(mail, "_mail_traffic_tracked", False) is True:
        return mail
    meter = current_traffic()
    if meter is not None:
        meter.record_mail_bytes(request=True)
    mail._mail_traffic_tracked = True
    for name in ("send", "read", "readline"):
        original = getattr(mail, name, None)
        if not callable(original):
            continue
        def measured(*args, _original=original, _name=name, **kwargs):
            result = _original(*args, **kwargs)
            # A persistent inbox is used by different joined tasks over time.
            # Attribute each actual I/O to its caller, never its first creator.
            active = current_traffic()
            if active is not None:
                if _name == "send":
                    active.record_mail_bytes(upload=_length(args[0]) if args else 0)
                else:
                    active.record_mail_bytes(download=_length(result))
            return result
        setattr(mail, name, measured)
    return mail
