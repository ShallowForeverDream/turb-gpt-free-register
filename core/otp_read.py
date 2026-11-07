"""Result of a mailbox-button lookup: best code plus every candidate."""

from core.otp_formats import normalize_otp


class OTPRead(str):
    """A str so existing callers keep working, with the full candidate list.

    ``code`` is the normalized best value, ``candidates`` is de-duplicated and
    ordered most-likely-first, ``subject`` / ``received_at`` describe the mail
    it came from when the source reports them.
    """

    def __new__(cls, code, candidates=None, *, subject="", received_at=None):
        value = str(code or "")
        obj = super().__new__(cls, value)
        best = normalize_otp(value) or value
        cleaned = []
        for item in [best, *(candidates or [])]:
            item = str(item or "").strip()
            if item and item not in cleaned:
                cleaned.append(item)
        obj.code = best
        obj.candidates = cleaned
        obj.subject = str(subject or "")
        obj.received_at = received_at
        return obj

    @classmethod
    def from_text(cls, *parts, subject="", received_at=None):
        from core.otp_formats import extract_candidates
        values = extract_candidates(*parts)
        return cls(values[0] if values else "", values, subject=subject,
                   received_at=received_at)
