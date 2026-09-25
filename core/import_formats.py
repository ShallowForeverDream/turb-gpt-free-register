"""Parse pasted GPT account rows without logging their credentials."""
from __future__ import annotations

import csv
import re
from urllib.parse import parse_qs, urlparse


_EMAIL = re.compile(r"^[^\s@|,]+@[^\s@|,]+\.[^\s@|,]+$")
_SEPARATOR = re.compile(r"^:?-+:?$")


def valid_email(value: str) -> bool:
    return bool(_EMAIL.fullmatch(str(value or "").strip()))


def parse_registered_accounts(text: str) -> tuple[list[dict], int]:
    """Accept Markdown tables, TSV/CSV, pipes and ``----`` separated rows."""
    records: list[dict] = []
    invalid = 0
    for raw in str(text or "").splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = [part.strip() for part in line.strip("|").split("|")]
        elif "\t" in line:
            parts = [part.strip() for part in line.split("\t")]
        elif "----" in line:
            parts = [part.strip() for part in line.split("----", 3)]
        else:
            parts = [part.strip() for part in next(csv.reader([line]))]
        if len(parts) >= 4 and (
            parts[0].lower() in {"邮箱", "email", "e-mail"}
            or all(_SEPARATOR.fullmatch(part) for part in parts[:4])
        ):
            continue
        if len(parts) < 4 or not valid_email(parts[0]):
            invalid += 1
            continue
        secret = re.sub(r"^\s*2fa\s*[:：]\s*", "", parts[2], flags=re.IGNORECASE).strip()
        if secret.startswith("otpauth://"):
            secret = (parse_qs(urlparse(secret).query).get("secret") or [""])[0].strip()
        if re.fullmatch(r"[A-Z2-7= ]+", secret, flags=re.IGNORECASE):
            secret = secret.replace(" ", "")
        if secret.isdigit() and len(secret) == 6:
            invalid += 1
            continue
        records.append({
            "email": parts[0],
            "registration_password": parts[1],
            "totp_secret": secret,
            "access_token": parts[3],
        })
    return records, invalid
