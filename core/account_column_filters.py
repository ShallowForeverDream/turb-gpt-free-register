"""Validated account-column filters and parameterized SQLite predicates."""
import json
import math
from datetime import date, datetime, timedelta, timezone


PRESENT = [("present", "已保存"), ("missing", "未保存")]
COLUMNS = {
    "id": ("ID", "values", None),
    "status": ("状态", "values", [("unarchived", "未归档"), ("archived", "归档")]),
    "email": ("邮箱", "values", None),
    "group": ("分组", "values", None),
    "source": ("来源", "values", None),
    "email_otp": ("邮箱验证码", "values", [("supported", "支持查询"), ("unsupported", "不支持查询")]),
    "token": ("Token", "values", PRESENT),
    "gpt_password": ("GPT密码", "values", PRESENT),
    "mail_password": ("邮箱密码", "values", PRESENT),
    "plan": ("套餐", "values", [("free", "free"), ("plus", "已开通 Plus"), ("go", "已开通 Go"),
        ("team", "Team"), ("business", "Business"), ("pro", "Pro"),
        ("plus_trial", "free(可Plus试用)"), ("free_no_trial", "free不可试用Plus")] +
        [(f"{product}_{kind}_{months}m", f"{product}{label}-{months}月") for product in ("plus", "go")
         for kind, months, label in (("half",1,"半价"),("half",2,"半价"),("half",3,"半价"),("trial",1,"试用"))]),
    "note": ("备注", "values", [("present", "有备注"), ("missing", "无备注")]),
    "twofa": ("2FA", "values", [("enabled", "已开启"), ("disabled", "未开启"), ("pending", "设置中"),
        ("failed", "设置失败"), ("stopped", "已停止"), ("blocked", "受阻")]),
    "codex": ("CODEX", "values", [("success", "成功"), ("failed", "失败"), ("retrying", "补跑中"),
        ("stopped", "已停止"), ("skipped", "已跳过"), ("__empty__", "未执行")]),
    "registered_at": ("注册时间", "date", [("known", "已查询注册时间"), ("missing", "注册时间未知")]),
    "traffic": ("总/动态IP", "traffic", [("known", "已统计总流量"), ("missing", "总流量未知")]),
    "actions": ("操作", "values", [("live", "可查活"), ("plan", "可查套餐"), ("twofa", "可开2FA"),
        ("codex", "可补跑CODEX"), ("email_otp", "可查询邮箱验证码"), ("cancel", "可取消排队")]),
}
TEXT_COLUMNS = {"id", "email", "group", "source", "note"}


def normalize_filters(raw):
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        if len(raw) > 32000:
            raise ValueError("筛选条件过长")
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise ValueError("筛选条件不是有效 JSON") from exc
    if not isinstance(raw, dict) or any(key not in COLUMNS for key in raw):
        raise ValueError("账号列筛选条件无效")
    result = {}
    for key, item in raw.items():
        if isinstance(item, list):
            item = {"values": item}
        if not isinstance(item, dict):
            raise ValueError("列筛选必须为对象")
        allowed = {"values"}
        if key in TEXT_COLUMNS:
            allowed.add("text")
        if key == "registered_at":
            allowed.update(("from", "to"))
        if key == "traffic":
            allowed.update(("min", "max", "dynamic_min", "dynamic_max"))
        if set(item) - allowed:
            raise ValueError("列筛选字段无效")
        values = item.get("values", [])
        if not isinstance(values, list) or len(values) > 200:
            raise ValueError("每列最多选择 200 个值")
        normalized = {}
        choices = COLUMNS[key][2]
        valid = {value for value, _ in choices} if choices else None
        cleaned = []
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise ValueError("筛选选项无效")
            value = str(value)
            if not value or len(value) > 320 or (valid is not None and value not in valid):
                raise ValueError("筛选选项无效")
            if key == "id" and (not value.isascii() or not value.isdigit() or int(value) < 1):
                raise ValueError("ID 筛选必须为正整数")
            if value not in cleaned:
                cleaned.append(value)
        if cleaned:
            normalized["values"] = cleaned
        text = item.get("text", "")
        if not isinstance(text, str) or len(text) > 200:
            raise ValueError("筛选关键词最多 200 字符")
        if text.strip():
            normalized["text"] = text.strip()
        if key == "registered_at":
            for bound in ("from", "to"):
                value = item.get(bound)
                if value not in (None, ""):
                    try:
                        parsed = date.fromisoformat(value)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("日期格式应为 YYYY-MM-DD") from exc
                    if parsed.year >= 9999:
                        raise ValueError("日期年份不能超过9998")
                    normalized[bound] = parsed.isoformat()
            if normalized.get("from", "") > normalized.get("to", "9999-12-31"):
                raise ValueError("开始日期不能晚于结束日期")
        if key == "traffic":
            for bound in ("min", "max", "dynamic_min", "dynamic_max"):
                value = item.get(bound)
                if value not in (None, ""):
                    if isinstance(value, bool):
                        raise ValueError("流量范围无效")
                    try:
                        number = float(value)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("流量范围无效") from exc
                    if not math.isfinite(number) or number < 0:
                        raise ValueError("流量范围必须为非负数")
                    normalized[bound] = number
            for low, high in (("min", "max"), ("dynamic_min", "dynamic_max")):
                if normalized.get(low, 0) > normalized.get(high, float("inf")):
                    raise ValueError("最小流量不能大于最大流量")
        if normalized:
            result[key] = normalized
    return result


def field_sql(key):
    return f"json_extract(accounts.payload, '$.{key}')"


EXTRA = f"(CASE WHEN json_valid({field_sql('extra_json')}) THEN {field_sql('extra_json')} ELSE '{{}}' END)"
SOURCE = f"lower(COALESCE({field_sql('email_source')}, ''))"
GPT_PASSWORD = f"COALESCE(NULLIF(json_extract({EXTRA}, '$.registration_password'), ''), {field_sql('registration_password')}, '')"
MAIL_PASSWORD = (
    f"CASE WHEN {SOURCE} = 'outlook' THEN COALESCE(NULLIF((SELECT json_extract(ep.payload, '$.password') "
    "FROM email_pool ep WHERE ep.source='outlook' AND ep.email=accounts.email COLLATE NOCASE LIMIT 1), ''), "
    f"{field_sql('mail_password')}, '') WHEN {SOURCE} = 'imap' THEN COALESCE({field_sql('mail_password')}, '') ELSE '' END"
)
OTP_SUPPORTED = f"{SOURCE} IN ('imap', 'outlook', 'generic_api')"
TOKEN_PRESENT = f"length(trim(COALESCE({field_sql('access_token')}, ''))) > 0"
SECRET_PRESENT = f"length(trim(COALESCE({field_sql('totp_secret')}, ''))) > 0"
TOTAL_BYTES = f"CASE WHEN {field_sql('flow_traffic.available')}=1 THEN {field_sql('flow_traffic.total_bytes')} ELSE NULL END"
DYNAMIC_BYTES = f"CASE WHEN {field_sql('flow_traffic.available')}=1 THEN {field_sql('flow_traffic.dynamic_ip_bytes')} ELSE NULL END"
RAW_REGISTERED = f"json_extract({EXTRA}, '$.account.createdTime')"
REGISTERED_EPOCH = (
    f"CASE WHEN (CASE WHEN json_valid({RAW_REGISTERED}) THEN "
    f"json_type({RAW_REGISTERED}) IN ('integer','real') ELSE 0 END) THEN CASE WHEN CAST({RAW_REGISTERED} AS REAL)>1000000000000 "
    f"THEN CAST({RAW_REGISTERED} AS REAL)/1000.0 ELSE CAST({RAW_REGISTERED} AS REAL) END ELSE NULL END"
)
VALUE_EXPRESSIONS = {
    "id": "CAST(accounts.id AS TEXT)", "email": "accounts.email",
    "status": "CASE WHEN accounts.archived=1 THEN 'archived' ELSE 'unarchived' END",
    "group": f"COALESCE(NULLIF({field_sql('account_group')}, ''), '__ungrouped__')",
    "source": f"COALESCE(NULLIF({SOURCE}, ''), '__unknown__')",
}


def compile_filters(filters, legacy_filters):
    filters = normalize_filters(filters)
    # A confirmed disabled account stays out of the account page, including
    # when the archive column is cleared or both archive states are selected.
    where = [f"lower(COALESCE({field_sql(key)}, '')) != 'deactivated'"
             for key in ("live_check_status", "codex_status")]
    params = []
    for key, item in filters.items():
        values = item.get("values", [])
        if values and key in VALUE_EXPRESSIONS:
            expression = VALUE_EXPRESSIONS[key]
            if key == "status":
                expression = "accounts.archived"
                values = [int(value == "archived") for value in values]
            elif key == "email":
                expression = "accounts.email COLLATE NOCASE"
            elif key == "source":
                expression = f"lower({expression})"
                values = [value.lower() for value in values]
            where.append(f"{expression} IN ({','.join('?' for _ in values)})")
            params.extend(values)
        elif values:
            clauses, args = [], []
            for value in values:
                if key in ("plan", "twofa", "codex"):
                    if key == "codex" and value == "__empty__":
                        clause, bound = [f"COALESCE({field_sql('codex_status')}, '') = ''"], []
                    else:
                        name = {"plan": "plan_filter", "twofa": "totp_filter", "codex": "codex_filter"}[key]
                        clause, bound = legacy_filters(**{name: value})
                    clauses.append('('+' AND '.join(clause)+')'); args.extend(bound)
                elif key in ("token", "gpt_password", "mail_password", "note"):
                    expression = {"token": TOKEN_PRESENT,
                        "gpt_password": f"length(trim({GPT_PASSWORD})) > 0",
                        "mail_password": f"length({MAIL_PASSWORD}) > 0",
                        "note": f"length(COALESCE({field_sql('note')}, '')) > 0"}[key]
                    clauses.append(f"({expression})" if value == "present" else f"NOT ({expression})")
                elif key == "email_otp":
                    clauses.append(f"({OTP_SUPPORTED})" if value == "supported" else f"NOT ({OTP_SUPPORTED})")
                elif key in ("registered_at", "traffic"):
                    expression = REGISTERED_EPOCH if key == "registered_at" else TOTAL_BYTES
                    clauses.append(f"({expression}) IS {'NOT ' if value == 'known' else ''}NULL")
                elif key == "actions":
                    pending = lambda field: f"COALESCE({field_sql(field)}, '') IN ('queued','running')"
                    actions = {
                        "live": f"NOT ({pending('live_check_status')})",
                        "plan": f"({TOKEN_PRESENT}) AND NOT ({pending('plan_check_status')})",
                        "twofa": f"({TOKEN_PRESENT}) AND NOT ({SECRET_PRESENT}) AND NOT ({pending('totp_setup_status')})",
                        "codex": f"COALESCE({field_sql('codex_status')}, '') NOT IN ('retrying','deactivated')",
                        "email_otp": OTP_SUPPORTED,
                        "cancel": ' OR '.join(f"COALESCE({field_sql(field)}, '')='queued'" for field in
                            ('live_check_status','plan_check_status','totp_setup_status','email_change_status','codex_agent_status')),
                    }
                    clauses.append(f"({actions[value]})")
            where.append('('+' OR '.join(clauses)+')'); params.extend(args)
        if item.get("text"):
            expression = VALUE_EXPRESSIONS.get(key, field_sql(key))
            if key == "group":
                expression = f"CASE WHEN {expression}='__ungrouped__' THEN '未分组' ELSE {expression} END"
            elif key == "source":
                expression = f"CASE WHEN {expression}='__unknown__' THEN '未知来源' ELSE {expression} END"
            elif key == "id":
                expression = f"'#' || {expression}"
            where.append(f"instr(lower(COALESCE({expression}, '')), lower(?)) > 0")
            params.append(item["text"])
        if key == "registered_at":
            for bound, operator in (("from", ">="), ("to", "<")):
                if item.get(bound):
                    stamp = datetime.combine(date.fromisoformat(item[bound]), datetime.min.time(), timezone(timedelta(hours=8)))
                    if bound == "to":
                        stamp += timedelta(days=1)
                    where.append(f"({REGISTERED_EPOCH}) {operator} ?"); params.append(stamp.timestamp())
        if key == "traffic":
            for bound, expression, operator in (("min", TOTAL_BYTES, ">="), ("max", TOTAL_BYTES, "<="),
                    ("dynamic_min", DYNAMIC_BYTES, ">="), ("dynamic_max", DYNAMIC_BYTES, "<=")):
                if bound in item:
                    where.append(f"({expression}) {operator} ?"); params.append(item[bound]*1024*1024)
    return where, params
