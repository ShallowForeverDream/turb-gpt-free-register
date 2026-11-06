"""Official Grok CLI device authorization and auth.json generation.

The registration flow already holds a confirmed grok.com SSO session.  The
official CLI uses a separate OIDC device flow; this module reuses that SSO
session only to approve the device code, then stores the resulting OIDC tokens
in the official auth.json registry shape understood by my-cockpit-tools.
"""
import base64
import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests

OIDC_ISSUER = "https://auth.x.ai"
OIDC_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_SCOPE = ("openid profile email offline_access grok-cli:access api:access "
              "conversations:read conversations:write workspaces:read workspaces:write")
AUTH_REGISTRY_KEY = f"{OIDC_ISSUER}::{OIDC_CLIENT_ID}"
DEVICE_ENDPOINT = "https://auth.x.ai/oauth2/device/code"
TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class GrokCliAuthError(RuntimeError):
    pass


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _session(proxy_url=None):
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"Accept": "application/json"})
    proxy = str(proxy_url or "").strip()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def _json(response):
    try:
        payload = response.json()
    except Exception:
        raise GrokCliAuthError("Grok CLI 授权接口返回了非 JSON 响应") from None
    if not isinstance(payload, dict):
        raise GrokCliAuthError("Grok CLI 授权接口响应格式不合法")
    return payload


def start_device_flow(http=None):
    owned = http is None
    if owned:
        http = _session()
    try:
        response = http.post(DEVICE_ENDPOINT, data={"client_id": OIDC_CLIENT_ID, "scope": OIDC_SCOPE},
                             headers={"Accept": "application/json"}, timeout=25)
        if response.status_code != 200:
            raise GrokCliAuthError(f"Grok CLI 设备授权 HTTP {response.status_code}")
        payload = _json(response)
        for field in ("device_code", "user_code", "verification_uri"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise GrokCliAuthError("Grok CLI 设备授权响应缺少必要字段")
        return payload
    except requests.RequestException:
        raise GrokCliAuthError("Grok CLI 设备授权网络请求失败") from None
    finally:
        if owned:
            http.close()


def _decode_jwt_claims(token):
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return {}
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _claims(tokens):
    result = {}
    for token in (tokens.get("id_token"), tokens.get("access_token")):
        result.update(_decode_jwt_claims(token))
    return result


def _claim_text(claims, *keys):
    for key in keys:
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_auth_json(email, tokens):
    if not isinstance(tokens, dict):
        raise GrokCliAuthError("Grok CLI token 响应格式不合法")
    access_token = str(tokens.get("access_token") or "").strip()
    if not access_token:
        raise GrokCliAuthError("Grok CLI 授权未返回 access_token")
    claims = _claims(tokens)
    now = datetime.now(timezone.utc)
    try:
        expires_in = max(60, int(tokens.get("expires_in") or 21600))
    except (TypeError, ValueError):
        expires_in = 21600
    expires_at = now + timedelta(seconds=expires_in)
    principal_id = _claim_text(claims, "principal_id", "sub")
    user_id = _claim_text(claims, "user_id", "uid") or principal_id
    auth = {
        "key": access_token,
        "auth_mode": "oidc",
        "create_time": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "user_id": user_id,
        "email": _claim_text(claims, "email", "preferred_username") or str(email or "").strip(),
        "first_name": _claim_text(claims, "first_name", "given_name"),
        "last_name": _claim_text(claims, "last_name", "family_name"),
        "profile_image_asset_id": _claim_text(claims, "profile_image_asset_id", "picture"),
        "principal_type": _claim_text(claims, "principal_type") or "User",
        "principal_id": principal_id,
        "team_id": _claim_text(claims, "team_id"),
        "coding_data_retention_opt_out": True,
        "refresh_token": str(tokens.get("refresh_token") or "").strip() or None,
        "expires_at": expires_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": OIDC_CLIENT_ID,
    }
    auth = {key: value for key, value in auth.items() if value is not None}
    return {AUTH_REGISTRY_KEY: auth}


def poll_token(device_code, *, http=None, timeout=180, interval=None):
    owned = http is None
    if owned:
        http = _session()
    wait = max(2, int(interval or 5))
    deadline = time.monotonic() + max(10, int(timeout))
    try:
        while time.monotonic() < deadline:
            response = http.post(TOKEN_ENDPOINT, data={
                "grant_type": DEVICE_GRANT_TYPE,
                "device_code": device_code,
                "client_id": OIDC_CLIENT_ID,
            }, headers={"Accept": "application/json"}, timeout=25)
            if response.status_code == 200:
                return _json(response)
            payload = _json(response)
            error = str(payload.get("error") or "")
            if error == "authorization_pending":
                time.sleep(wait)
                continue
            if error == "slow_down":
                wait += 5
                time.sleep(wait)
                continue
            if error == "access_denied":
                raise GrokCliAuthError("Grok CLI 授权被拒绝")
            if error == "expired_token":
                raise GrokCliAuthError("Grok CLI 设备码已过期")
            raise GrokCliAuthError(f"Grok CLI token 获取失败：{error or 'unknown'}")
        raise GrokCliAuthError("Grok CLI 授权等待超时")
    except requests.RequestException:
        raise GrokCliAuthError("Grok CLI token 网络请求失败") from None
    finally:
        if owned:
            http.close()


def _verification_url(device):
    complete = device.get("verification_uri_complete")
    if isinstance(complete, str) and complete.startswith("https://"):
        return complete
    uri = str(device.get("verification_uri") or "")
    if not uri.startswith("https://"):
        raise GrokCliAuthError("Grok CLI 验证地址不合法")
    separator = "&" if "?" in uri else "?"
    return f"{uri}{separator}user_code={device.get('user_code', '')}"


def authorize_with_browser(verification_url, sso, sso_rw, *, browser_launcher=None, timeout=90, proxy_url=None):
    from playwright.sync_api import sync_playwright

    if not isinstance(sso, str) or not sso:
        raise GrokCliAuthError("Grok 账号缺少 SSO，无法完成 CLI 授权")
    launcher = browser_launcher
    if launcher is None:
        from core.grok_browser import launch_ordinary_browser as launcher
    try:
        process, port = launcher(proxy_url=proxy_url)
    except TypeError:
        process, port = launcher()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            context = browser.new_context()
            for domain in (".x.ai", ".grok.com"):
                cookies = [{"name": "sso", "value": sso, "domain": domain, "path": "/"}]
                if isinstance(sso_rw, str) and sso_rw:
                    cookies.append({"name": "sso-rw", "value": sso_rw, "domain": domain, "path": "/"})
                context.add_cookies(cookies)
            page = context.new_page()
            page.goto(verification_url, wait_until="domcontentloaded", timeout=45000)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            deadline = time.monotonic() + max(10, int(timeout))
            def click(node):
                try:
                    node.click(timeout=4000)
                except Exception:
                    node.evaluate("el => el.click()")
            while time.monotonic() < deadline:
                if "/oauth2/device/done" in page.url:
                    return True
                if page.is_closed():
                    raise GrokCliAuthError("Grok CLI 授权浏览器已关闭")
                clicked = False
                button = page.get_by_role("button", name=re.compile(r"^(?:继续|Continue)$", re.I))
                if button.count():
                    try:
                        if button.first.is_visible() and button.first.is_enabled():
                            click(button.first)
                            try:
                                page.wait_for_url("**/oauth2/device/consent**", timeout=12000)
                            except Exception:
                                page.wait_for_timeout(1800)
                            clicked = True
                    except Exception:
                        pass
                if clicked:
                    continue
                button = page.get_by_role("button", name=re.compile(r"^(?:允许|Allow)$", re.I))
                if button.count() and button.first.is_visible() and button.first.is_enabled():
                    click(button.first)
                    try:
                        page.wait_for_url("**/oauth2/device/done", timeout=8000)
                        return True
                    except Exception:
                        page.wait_for_timeout(1200)
                        continue
                page.wait_for_timeout(1200)
            raise GrokCliAuthError("Grok CLI 授权页面未完成（可能需要人工处理）")
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            pass


def authorize_account(email, sso, sso_rw, *, http=None, browser_launcher=None, proxy_url=None):
    owned = http is None
    if owned:
        http = _session(proxy_url)
    device = start_device_flow(http=http)
    authorize_with_browser(_verification_url(device), sso, sso_rw, browser_launcher=browser_launcher,
                           proxy_url=proxy_url)
    try:
        tokens = poll_token(device["device_code"], http=http)
    finally:
        if owned:
            http.close()
    auth_json = build_auth_json(email, tokens)
    claims = _claims(tokens)
    auth = auth_json[AUTH_REGISTRY_KEY]
    return {
        "status": "success",
        "authorized_at": auth["create_time"],
        "expires_at": auth.get("expires_at"),
        "email": auth.get("email") or email,
        "user_id": auth.get("user_id"),
        "principal_id": auth.get("principal_id"),
        "principal_type": auth.get("principal_type"),
        "team_id": auth.get("team_id"),
        "auth_json": auth_json,
        "scope": tokens.get("scope"),
        "token_type": tokens.get("token_type"),
    }
