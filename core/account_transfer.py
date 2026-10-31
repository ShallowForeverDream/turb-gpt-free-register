"""Local account import/export schemas. No authentication or background jobs."""
import csv
import json
import re
from io import BytesIO, StringIO
from zipfile import BadZipFile, ZipFile

from core.import_formats import valid_email


FIELDS = [
    ("email", "邮箱", True),
    ("registration_password", "GPT密码", True),
    ("mail_password", "邮箱密码", True),
    ("totp_secret", "2FA密钥", True),
    ("access_token", "Access Token", True),
    ("user_name", "账号名称", True),
    ("email_source", "来源", True),
    ("account_group", "分组", True),
    ("note", "备注", True),
    ("id", "ID", False),
    ("archived", "归档状态", False),
    ("plan_type", "套餐", False),
    ("codex_status", "Codex状态", False),
    ("registered_at", "注册时间", False),
]
DEFAULT_IMPORT_FIELDS = ["email", "registration_password", "totp_secret", "access_token"]
LABELS = {key: label for key, label, _ in FIELDS}
IMPORTABLE = {key for key, _, allowed in FIELDS if allowed}
_ALIASES = {
    "email": {"email", "emailaddress", "邮箱", "邮箱地址"},
    "registration_password": {"registrationpassword", "gptpassword", "password", "密码", "gpt密码", "chatgpt密码"},
    "mail_password": {"mailpassword", "emailpassword", "邮箱密码"},
    "totp_secret": {"totpsecret", "totp", "2fa", "2fa密钥", "2fa秘钥"},
    "access_token": {"accesstoken", "token", "at"},
    "user_name": {"username", "name", "账号名称", "名称"},
    "email_source": {"emailsource", "source", "来源", "邮箱来源"},
    "account_group": {"accountgroup", "group", "分组"},
    "note": {"note", "notes", "备注"},
}


def transfer_schema():
    return {"fields": [{"key": key, "label": label, "importable": allowed} for key, label, allowed in FIELDS],
            "default_import_fields": DEFAULT_IMPORT_FIELDS}


def validate_fields(value, *, importing=False):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            raise ValueError("字段选择格式无效") from None
    allowed = IMPORTABLE if importing else set(LABELS)
    if not isinstance(value, list) or not value or len(value) > len(FIELDS):
        raise ValueError("请至少选择一个有效字段")
    if any(not isinstance(key, str) or key not in allowed for key in value) or len(set(value)) != len(value):
        raise ValueError("包含无效、只读或重复字段")
    if importing and "email" not in value:
        raise ValueError("导入必须选择邮箱字段")
    return list(value)


def _header_key(value):
    text = re.sub(r"[\s_\-/]+", "", str(value or "").strip()).lower()
    return next((key for key, aliases in _ALIASES.items() if text in aliases), None)


def _record(values, fields):
    if any(value is not None and not isinstance(value, str) for value in values):
        return None
    row = {key: str(value or "").strip() for key, value in zip(fields, values)}
    if not valid_email(row.get("email", "")):
        return None
    secret = row.get("totp_secret", "")
    if secret:
        from core.import_formats import _registered_account_from_parts
        parsed = _registered_account_from_parts([row["email"], "", secret, ""])
        if parsed is None:
            return None
        row["totp_secret"] = parsed["totp_secret"]
    if len(row.get("account_group", "")) > 100 or len(row.get("note", "")) > 10000:
        return None
    return row


def _parse_rows(rows, fields):
    records, invalid, columns = [], 0, None
    for index, values in enumerate(rows):
        if index >= 50000:
            raise ValueError("单次最多导入 50000 行")
        values = list(values)
        if not any(value is not None and str(value).strip() for value in values):
            continue
        if len(values) == 1 and str(values[0] or "").lstrip().startswith("#"):
            continue
        keys = [_header_key(value) for value in values]
        if "email" in keys:
            if any(keys.count(key) > 1 for key in fields):
                raise ValueError("表头包含重复的所选字段，请保留唯一列名")
            if any(key not in keys for key in fields):
                raise ValueError("表头缺少所选字段：" + "、".join(LABELS[key] for key in fields if key not in keys))
            columns = [keys.index(key) for key in fields]
            continue
        if values and all(re.fullmatch(r"\s*:?-+:?\s*", str(value or "")) for value in values):
            continue
        if columns is None:
            while len(values) > len(fields) and values[-1] in (None, ""):
                values.pop()
            if len(values) != len(fields):
                invalid += 1
                continue
            selected = values
        else:
            if max(columns) >= len(values):
                invalid += 1
                continue
            selected = [values[col] for col in columns]
        record = _record(selected, fields)
        if record is None:
            invalid += 1
        else:
            records.append(record)
    return records, invalid


def parse_selected_text(text, fields):
    fields = validate_fields(fields, importing=True)
    text = str(text or "").lstrip("\ufeff")
    first = next((line for line in text.splitlines() if line.strip()), "")
    if "----" in first or "====" in first:
        delimiter = "----" if "----" in first else "===="
        rows = ([cell.strip() for cell in line.split(delimiter)] for line in text.splitlines())
    elif first.strip().startswith("|"):
        rows = ([cell.strip() for cell in line.strip().strip("|").split("|")] for line in text.splitlines())
    else:
        rows = csv.reader(StringIO(text), delimiter="\t" if "\t" in first else ",", strict=True)
    try:
        return _parse_rows(rows, fields)
    except csv.Error:
        raise ValueError("文本分隔或引号格式无效") from None


def parse_selected_xlsx(content, fields):
    fields = validate_fields(fields, importing=True)
    if not content or len(content) > 8_000_000:
        raise ValueError("Excel 文件不能为空或超过 8 MB")
    try:
        with ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > 500 or sum(item.file_size for item in members) > 80_000_000:
                raise ValueError("Excel 文件内容过大")
    except BadZipFile:
        raise ValueError("文件不是有效的 .xlsx") from None
    from openpyxl import load_workbook
    try:
        book = load_workbook(BytesIO(content), read_only=True, data_only=False, keep_links=False)
    except Exception:
        raise ValueError("无法读取 Excel 文件") from None
    records, invalid = [], 0
    try:
        for sheet in book.worksheets:
            if (sheet.max_row or 0) > 50000:
                raise ValueError("Excel 工作表超过 50000 行")
            def rows():
                for cells in sheet.iter_rows(max_col=min(sheet.max_column or len(fields), 64)):
                    yield [object() if cell.data_type == "f" else cell.value for cell in cells]
            parsed, bad = _parse_rows(rows(), fields)
            records.extend(parsed); invalid += bad
            if len(records) + invalid > 50000:
                raise ValueError("单次最多导入 50000 行")
    finally:
        book.close()
    return records, invalid


def export_text(rows, fields, secret_value):
    fields = validate_fields(fields)
    output = StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow([LABELS[key] for key in fields])
    secret_fields = {"registration_password": "password", "mail_password": "mail_password",
                     "access_token": "access_token", "totp_secret": "totp_secret"}
    for row in rows:
        values = []
        for key in fields:
            if key in secret_fields:
                value = secret_value(row, secret_fields[key])
                if key == "registration_password" and value == "未设置":
                    value = ""
            elif key == "archived":
                value = "已归档" if row.get("archived") else "未归档"
            elif key == "plan_type":
                value = row.get("current_plan_type") or row.get("plan_type") or ""
            else:
                value = row.get(key) if row.get(key) is not None else ""
            values.append(str(value))
        writer.writerow(values)
    return output.getvalue()
