"""Code shapes that real senders use for mailbox lookups.

Registration and live-check keep their historic six-digit contract. Only the
pool mailbox button asks for every shape, so this wider rule cannot leak into
an account flow.
"""
import html as _html
import re

_DASHES = "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"
_DASH = f"[{re.escape(_DASHES)}]"
_TOKEN = r"[A-Za-z0-9" + re.escape(_DASHES) + "]"
# A token boundary on either side; a lookbehind cannot hold a variable-width
# character class together with the shape, so the mixed shapes use this.
_START = r"(?<![A-Za-z0-9" + re.escape(_DASHES) + r"])"

# 6/8 digits, optionally grouped 3+3, 4+4 or 3+2+3.
_NUMERIC = rf"\d{{6}}|\d{{8}}|\d{{3}}{_DASH}\d{{3}}|\d{{4}}{_DASH}\d{{4}}|\d{{3}}{_DASH}\d{{2}}{_DASH}\d{{3}}"
_WIDE = rf"\d{{2}}(?:\s*{_DASH}\s*\d{{2}}){{2,3}}"
_SPACED = r"\d{3}\s+\d{3}|\d{4}\s+\d{4}"
# Letters and digits, at least one letter so ordinary words never match.
# Each shape is anchored at a token start so a longer dashed code is never
# truncated ("A1B2-C" out of "A1B2-C3D").
_MIXED = (
    rf"{_START}(?=[A-Za-z0-9]{{0,12}}[A-Za-z])(?:"
    rf"{_TOKEN}{{3}}{_DASH}{_TOKEN}{{2}}{_DASH}{_TOKEN}{{3}}|{_TOKEN}{{3}}{_DASH}{_TOKEN}{{2}}{_DASH}{_TOKEN}{{2}}"
    rf"|{_TOKEN}{{4}}{_DASH}{_TOKEN}{{4}}|{_TOKEN}{{3}}{_DASH}{_TOKEN}{{3}}"
    rf"|{_TOKEN}{{2}}{_DASH}{_TOKEN}{{2}}|{_TOKEN}{{6}}|{_TOKEN}{{8}})"
)
_CANDIDATE = re.compile(
    rf"(?<![A-Za-z0-9_])(?:{_NUMERIC}|{_WIDE}|{_SPACED}|{_MIXED})(?![A-Za-z0-9_])")

_CONTEXT = (
    "temporary verification code", "verification code", "security code", "confirmation code",
    "login code", "sign-in code", "one-time code", "one time code", "verify code", "passcode",
    "verification", "verify", "confirm", "otp", "pin", "code",
    "验证码", "驗證碼", "校验码", "校驗碼", "确认码", "確認碼", "动态码", "安全代码", "验证",
    "認証コード", "確認コード", "検証コード", "인증 코드", "확인 코드", "код",
)
_STRONG_CONTEXT = (
    "temporary verification code", "verification code", "security code", "confirmation code",
    "login code", "sign-in code", "one-time code", "one time code", "verify code", "passcode",
    "验证码", "驗證碼", "确认码", "確認碼", "校验码", "校驗碼", "动态码",
    "認証コード", "確認コード", "検証コード", "인증 코드", "확인 코드",
)
_NOISE = (
    "order", "invoice", "transaction", "reference", "ticket", "tracking", "amount", "price",
    "total", "uuid", "guid", "version", "build", "rgb", "color", "date", "time", "phone", "tel",
    "订单", "单号", "流水", "金额", "价格", "运单", "编号", "电话", "手机", "日期", "时间", "版本",
)
_CONTEXT_RE = re.compile("|".join(re.escape(word) for word in _CONTEXT), re.I)
_STRONG_CONTEXT_RE = re.compile("|".join(re.escape(word) for word in _STRONG_CONTEXT), re.I)
_NOISE_RE = re.compile("|".join(re.escape(word) for word in _NOISE), re.I)
_TEMPLATE_NOISE = {"000000", "202123", "353740"}
_MONEY = re.compile(rf"\d{{1,3}}(?:,\d{{3}})+|\d+{_DASH}0+")
_YEAR = re.compile(r"(?:19|20)\d{2}")
_GROUPED_DATE = re.compile(rf"(\d{{4}}){_DASH}(\d{{4}})$")
_CSS_VALUE_RE = re.compile(r"(?:color|background|border)\s*:\s*$", re.I)
# Transport names and units in a log look mixed-case but are never codes.
_CONFIG_WORDS = {"socks5", "socks4", "https", "http2", "ipv6", "ipv4"}


def normalize_otp(value, *, upper=False) -> str:
    """Trim, unify dash variants and reject anything that is not code shaped."""
    if isinstance(value, bool) or value is None or not isinstance(value, (str, int)):
        return ""
    raw = str(value).strip()
    if len(raw) > 32:
        return ""
    # A 3+3 code sometimes loses its dash in copy/paste: "123 456".
    text = re.sub(r"\s+", "", raw)
    if re.fullmatch(r"\d{3}\s+\d{3}", raw):
        text = re.sub(r"\s+", "", raw)
    text = re.sub(rf"\s*{_DASH}\s*", "-", text)
    compact = text.replace("-", "")
    groups = [len(part) for part in text.split("-")]
    if len(compact) == 8 and compact.isdigit() and groups in ([3, 2, 3], [2, 2, 2, 2]):
        text = compact
    if not re.fullmatch(rf"(?:{_NUMERIC}|{_WIDE}|{_SPACED}|{_MIXED})", text) or not text.isascii():
        return ""
    if not re.fullmatch(r"[0-9A-Za-z]+(?:-[0-9A-Za-z]+){0,3}", text):
        return ""
    if _has_letter(text) and not any(ch.isdigit() for ch in text) and "-" not in text:
        return ""
    return text.upper() if upper else text


def _has_letter(text: str) -> bool:
    return any(ch.isalpha() for ch in text)


def _plain(text: str) -> str:
    text = re.sub(r"<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"#[0-9a-fA-F]{6}\b", " ", text)
    text = re.sub(r"(?:color|background|border|width|height|font-size|line-height|padding|margin)"
                  r"\s*:\s*[^;\"']+", " ", text, flags=re.IGNORECASE)
    return _html.unescape(text)


def _near(text: str, start: int, end: int, distance: int = 40, strong: bool = False) -> bool:
    # Long labels such as "temporary verification code" must reach a code that
    # follows a colon, so look at the whole sentence rather than a fixed window.
    left = text[:start].rsplit("\n", 1)[-1][-160:]
    right = text[end:].split("\n", 1)[0][:160]
    window = left + " " + right
    return bool((_STRONG_CONTEXT_RE if strong else _CONTEXT_RE).search(window))


def _looks_like_label(text: str) -> bool:
    return bool(_CONTEXT_RE.search(text) or _STRONG_CONTEXT_RE.search(text))


def _reject(text: str, match) -> bool:
    # A letter touching either side makes this a word or host rather than a code.
    if match.start() > 0 and re.match(r"[A-Za-z0-9_/\\-]", text[match.start() - 1] or " "):
        if not _near(text, match.start(), match.end(), 32, strong=True):
            return True
    if re.match(r"[A-Za-z0-9_/\\-]", text[match.end(): match.end() + 1] or " "):
        if not _near(text, match.start(), match.end(), 32, strong=True):
            return True
    value = match.group(0)
    plain = re.sub(_DASH, "", value)
    left = text[max(0, match.start() - 64): match.start()]
    right = text[match.end(): match.end() + 64]
    # A dash inside a longer token would split a UUID or phone number.
    if re.match(r"[A-Za-z0-9-]", text[match.end(): match.end() + 1] or " "):
        return True
    if re.search(r"[A-Za-z0-9-]$", text[max(0, match.start() - 1): match.start()] or " "):
        return True
    if re.search(r"#\s*$", left) or re.match(r"^\s*#", right):
        return True
    if not _has_letter(value):
        if not plain[0].isdigit() or not plain[-1].isdigit():
            return True
        if _MONEY.search(text[max(0, match.start() - 2): match.end() + 2]):
            return True
        if _YEAR.fullmatch(plain):
            # A six-digit amount or year range is not a code unless labelled.
            if not _near(text, match.start(), match.end()):
                return True
        grouped_date = _GROUPED_DATE.match(value)
        if grouped_date and not _near(text, match.start(), match.end()):
            return True
    if re.match(r"[A-Za-z]", right[:1]) and not _near(text, match.start(), match.end(), 32,
                                                       strong=True):
        # A code followed immediately by a word ("1000000B") is a token, not an OTP.
        return True
    if not _has_letter(value) and len(plain) == 8:
        # Eight unlabeled digits are usually ids or phone fragments.
        if not _near(text, match.start(), match.end(), 32) and _NOISE_RE.search(left):
            return True
    if _has_letter(value) and "-" in value:
        # "A1B2-C3DX" is an id with a long tail; a labelled code may still be
        # the very token after "code:".
        labelled = re.search(r"(?:code|验证码|驗證碼|認証コード|код)\s*[:：]?\s*$", left, re.I)
        if not labelled and max(len(part) for part in value.split("-")) >= 4:
            return True
    # "order id 123456" / "参考号：123456" must not outrank the real code.
    if _NOISE_RE.search(left) and not _looks_like_label(left[-48:]):
        return True
    if _NOISE_RE.search(right[:32]) and not _looks_like_label(right[:32]):
        return True
    # "color: #353740" is a CSS value, not a code, even when words follow it.
    if _CSS_VALUE_RE.search(left[-24:]):
        return True
    if _CSS_VALUE_RE.match(right[:8]):
        return True
    return False


def _rank(text: str, value: str, start: int, end: int) -> tuple:
    plain = value.replace("-", "")
    return (
        0 if _near(text, start, end) else 1,
        0 if _near(text, start, end, 32, strong=True) else 1,
        0 if len(plain) == 6 else 1,
        0 if "-" in value else 1,
        0 if _has_letter(plain) else 1,
        start,
    )


def extract_candidates(*parts, limit: int = 30) -> list[str]:
    """Return distinct code-shaped values, most likely first.

    A value close to a code/验证码 keyword ranks ahead of a bare one; dates,
    amounts, order ids and template colours are dropped before ranking. Callers
    pass the newest message part first, as the old mailbox lookup did.
    """
    ordered = [str(part) for part in parts if part]
    text = re.sub(r"[ \t\u00a0]+", " ", _plain("\n".join(reversed(ordered))))
    if not text:
        return []
    found = []
    annotated = []
    for match in _CANDIDATE.finditer(text):
        if _reject(text, match):
            continue
        raw_value = match.group(0)
        # A "123 456" split is only a code when it sits next to a code label.
        # Empty body fields must not be turned into a candidate by stripping.
        value = normalize_otp(raw_value) if raw_value.strip() else ""
        if not value:
            # "queue-2v" / "49-level" are mailbox names in a log, not codes.
            continue
        if value.lower() in _CONFIG_WORDS:
            continue
        if re.fullmatch(_SPACED, raw_value) and not _near(text, match.start(), match.end()):
            continue
        if not value or value.replace("-", "") in _TEMPLATE_NOISE:
            continue
        entry = {"value": value, "context": _near(text, match.start(), match.end()),
                 "grouped": "-" in value, "letters": _has_letter(value)}
        found.append((_rank(text, value, match.start(), match.end()), entry))
        annotated.append(entry)
    # The same code repeated as "123456" and "123-456" is one candidate; keep
    # the grouped form that was shown next to the code label.
    grouped_values = {entry["value"].replace("-", ""): entry["value"]
                      for entry in annotated if entry["grouped"] and not entry["letters"]}
    for entry in annotated:
        plain = entry["value"].replace("-", "")
        if entry["letters"] or entry["grouped"] or plain not in grouped_values:
            continue
        if entry["context"]:
            entry["value"] = grouped_values[plain]
    ordered = {}
    for _key, entry in sorted(found, key=lambda item: item[0]):
        ordered.setdefault(entry["value"].upper(), entry["value"])
    return list(ordered.values())[: max(1, limit)]


def best_candidate(*parts) -> str:
    values = extract_candidates(*parts, limit=1)
    return values[0] if values else ""


def split_grouped(value: str) -> tuple[str, str]:
    """Split ``123-456`` into its parts; a bare value yields ("", value)."""
    text = normalize_otp(value)
    for dash in _DASHES:
        if dash in text:
            head, _, tail = text.partition(dash)
            return head, tail
    return "", text


