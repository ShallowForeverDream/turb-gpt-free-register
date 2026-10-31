"""Opt-in, offline soak test of the real job and post-processing queues.

Run: python -m tests.stability_registration --seconds 600 --workers 5
All identities, responses and traffic counters are fixtures. Production storage
and external registration endpoints are never used by the worker process.
"""
import argparse
from collections import Counter
from contextlib import ExitStack, closing
import ctypes
from datetime import datetime
import json
import logging
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from core import db, plan_check_service, protocol_traffic, registration_service as svc, twofa_service
from core.registration_completion import complete_registration_flow
from core.workflow_driver import submit_with_driver
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app
import main


TERMINAL = {"success", "partial_success", "failed", "disabled", "blocked", "cancelled", "stopped", "already_registered"}
CASES = ("success", "revoked", "deactivated", "tls", "otp_timeout", "twofa_error", "blocked", "success")


def resources():
    class Memory(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [
            (name, ctypes.c_size_t) for name in ("peak_rss", "rss", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")]
    memory = Memory()
    memory.cb = ctypes.sizeof(memory)
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Memory), ctypes.c_ulong]
    ctypes.windll.kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb)
    handles = ctypes.c_ulong()
    ctypes.windll.kernel32.GetProcessHandleCount(handle, ctypes.byref(handles))
    return {"rss_bytes": memory.rss, "handles": handles.value,
            "threads": threading.active_count(), "root_log_handlers": len(logging.getLogger().handlers)}


def production_counts(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
        return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("accounts", "registration_jobs", "email_pool")}


def run(seconds, workers, folder):
    production = db._active_sqlite_path().resolve()
    before = production_counts(production)
    errors, samples, completed = [], [], []
    cases, pending = {}, {}
    peak_active = submitted = cancellations = pauses = stops = 0
    fixture_root = folder / "storage"
    fixture_root.mkdir()
    logging.basicConfig(filename=folder / "soak.log", level=logging.INFO, force=True,
                        format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s")
    response = SimpleNamespace(upload_size=5, request_size=0, download_size=15, header_size=0,
                               content=b"fixture", redirect_count=0)

    def record(stage):
        meter = protocol_traffic.current_traffic()
        if meter:
            meter.record("https://fixture.invalid/" + stage, response)

    @protocol_traffic.capture_protocol_registration
    @complete_registration_flow
    def register(email=None, **kwargs):
        kind = cases[email]
        for _ in range(8):
            svc.check_stop_requested()
            time.sleep(0.10)
        record("register")
        if kind == "tls":
            raise RuntimeError("fixture TLS connection closed before account creation")
        if kind == "otp_timeout":
            return {"success": False, "email": email, "error": "fixture OTP timeout"}
        if kind == "blocked":
            return {"success": False, "status": "blocked", "email": email, "error": "fixture HTTP 403"}
        token = "initial|" + kind + "|" + email
        aid = db.insert_account(email=email, access_token=token, email_source="outlook")
        return {"success": True, "email": email, "account_id": aid}

    def plan(token, **kwargs):
        time.sleep(0.06)
        record("plan")
        phase, kind, email = token.split("|", 2)
        if phase == "fresh" and kind == "revoked":
            return {"ok": False, "http_status": 401, "needs_live_check": True,
                    "response_preview": '{"error":{"code":"token_revoked"}}'}
        return {"ok": True, "http_status": 200, "current_plan_type": "free", "plus_trial_eligible": False}

    def session(**kwargs):
        return SimpleNamespace(proxy="", proxy_target="", device_id="fixture-device", kind="protocol",
                               is_browser_workflow=False, fingerprint_summary_text=lambda: "fixture")

    def setup(env, email, access_token=None):
        time.sleep(0.08)
        record("twofa")
        kind = cases[email]
        if kind == "deactivated":
            raise RuntimeError("account_deactivated fixture")
        if kind == "twofa_error":
            raise RuntimeError("fixture reauthentication timeout")
        env._twofa_session_info = {"accessToken": "fresh|" + kind + "|" + email}
        return "JBSWY3DPEHPK3PXP"

    with ExitStack() as stack:
        stack.enter_context(patch.multiple(db, **storage(fixture_root), _LOG_DIR=folder / "jobs"))
        assert db._active_sqlite_path().resolve() != production
        stack.enter_context(patch.object(twofa_service, "_LOG_DIR", folder / "twofa"))
        stack.enter_context(patch("config.roxybrowser.REGISTRATION_DRIVER", "protocol"))
        stack.enter_context(patch("config.email.USE_EMAIL_SERVICE", True))
        stack.enter_context(patch("config.register.AUTO_PLAN_CHECK_AFTER_REGISTER", True))
        stack.enter_context(patch("config.twofa.ENABLE_2FA", True))
        stack.enter_context(patch("config.proxy.PLAN_CHECK_MIN_INTERVAL", 0.02))
        stack.enter_context(patch("config.proxy.PLAN_CHECK_JITTER", 0.0))
        stack.enter_context(patch("config.proxy.PLAN_CHECK_REGISTRATION_RECHECK_DELAY", 0.0))
        stack.enter_context(patch.object(main, "run_registration", register))
        stack.enter_context(patch.object(plan_check_service, "check_account_plan", plan))
        stack.enter_context(patch.object(twofa_service, "setup_2fa", setup))
        stack.enter_context(patch.object(twofa_service, "_resolve_twofa_proxy", return_value=(None, None, "fixture")))
        stack.enter_context(patch.object(twofa_service, "close_browser_session"))
        stack.enter_context(patch("core.workflow_driver.create_account_session", session))
        stack.enter_context(patch("core.proxy_chain.open_proxy_pool_proxy", side_effect=AssertionError("Fixture must not open a proxy")))
        stack.enter_context(patch("curl_cffi.requests.Session.request", side_effect=AssertionError("External requests disabled in soak test")))
        client = create_app(local_no_auth=True).test_client()
        executor = svc.get_executor(workers)
        start = time.monotonic()
        next_sample = next_pause = 0.0
        next_stop = 60.0
        last_progress = start

        def submit():
            nonlocal submitted
            submitted += 1
            email = f"soak-{submitted:05d}@fixture.invalid"
            cases[email] = CASES[(submitted - 1) % len(CASES)]
            db.import_outlook_accounts([{"email": email, "password": "fixture", "client_id": "fixture", "refresh_token": "fixture"}])
            job = svc.submit_registration(count=1, email_source="outlook", workers=workers,
                                          selected_emails=[{"email": email, "source": "outlook"}])[0]
            pending[job["id"]] = email

        try:
            while True:
                now = time.monotonic()
                elapsed = now - start
                for jid, email in list(pending.items()):
                    job = db.get_job(jid)
                    if job["status"] not in TERMINAL:
                        continue
                    if job["status"] not in {"stopped", "cancelled"}:
                        expected = {"success": "success", "revoked": "partial_success", "deactivated": "disabled",
                                    "tls": "failed", "otp_timeout": "failed", "twofa_error": "partial_success", "blocked": "blocked"}[cases[email]]
                        if job["status"] != expected:
                            errors.append({"job_id": jid, "expected": expected, "actual": job["status"]})
                        account = db.get_account(job["account_id"]) if job.get("account_id") else None
                        if expected == "disabled" and not (account or {}).get("archived"):
                            errors.append({"job_id": jid, "error": "deactivated account not archived"})
                        if account and (account.get("flow_traffic") or {}).get("total_bytes") != (job.get("network_traffic") or {}).get("total_bytes"):
                            errors.append({"job_id": jid, "error": "traffic not synchronized"})
                    completed.append({"job_id": jid, "case": cases[email], "status": job["status"]})
                    pending.pop(jid)
                    last_progress = now
                while elapsed < seconds and len(pending) < workers:
                    submit()
                with svc._STOP_LOCK:
                    peak_active = max(peak_active, len(svc._ACTIVE_JOBS))
                if elapsed >= next_sample:
                    api = client.get("/api/jobs?paged=1&page_size=20")
                    if api.status_code != 200:
                        errors.append({"error": "job listing failed", "http_status": api.status_code})
                    samples.append({"elapsed_seconds": round(elapsed, 2), "submitted": submitted,
                                    "completed": len(completed), "pending": len(pending), **resources()})
                    with (folder / "samples.jsonl").open("a", encoding="utf8") as f:
                        f.write(json.dumps(samples[-1]) + "\n")
                    print(json.dumps(samples[-1]), flush=True)
                    next_sample = elapsed + 15
                if elapsed < seconds and elapsed >= next_pause:
                    svc.pause_registration()
                    time.sleep(0.15)
                    svc.resume_registration()
                    pauses += 1
                    cancelled = db.create_job("outlook", "cancelled@fixture.invalid")
                    svc.request_stop_job(cancelled["id"])
                    submit_with_driver(executor, svc._run_one_job, cancelled["id"], cancelled["log_file"])
                    cancellations += 1
                    next_pause = elapsed + 60
                if elapsed < seconds and elapsed >= next_stop:
                    for jid in pending:
                        if db.get_job(jid)["status"] == "running":
                            svc.request_stop_job(jid)
                            stops += 1
                            break
                    next_stop = elapsed + 60
                if not pending and elapsed >= seconds:
                    break
                if now - last_progress > 90:
                    errors.append({"error": "no completions for 90 seconds"})
                    break
                time.sleep(0.06)
        finally:
            svc.resume_registration()
            svc.shutdown_executor(wait=True)
            plan_check_service._EXECUTOR.shutdown(wait=True)
            twofa_service._EXECUTOR.shutdown(wait=True)
        after_resources = resources()
        with closing(db._sqlite_conn()) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if svc._ACTIVE_JOBS or svc._STOP_EVENTS:
            errors.append({"error": "job bookkeeping leaked after drain"})
        if db.job_status_counts()["active"]:
            errors.append({"error": "active rows remain after drain"})
        if peak_active != workers:
            errors.append({"error": "did not reach requested concurrency", "actual": peak_active})
        if integrity != "ok":
            errors.append({"error": "sqlite integrity failure"})
        if after_resources["root_log_handlers"] != 1:
            errors.append({"error": "task log handlers leaked"})
        elapsed_total = time.monotonic() - start
    after = production_counts(production)
    if before != after:
        errors.append({"error": "production row counts changed during test", "before": before, "after": after})
    result = {"mode": "isolated_fixture_not_live_registration", "target_seconds": seconds,
              "elapsed_seconds": round(elapsed_total, 3), "workers": workers, "peak_active": peak_active,
              "submitted": submitted, "completed": len(completed), "cancelled_queued_jobs": cancellations,
              "pause_resume_cycles": pauses, "stop_requests": stops,
              "statuses": dict(Counter(x["status"] for x in completed)), "integrity_check": integrity,
              "production_counts_unchanged": before == after, "errors": errors,
              "resources_first": samples[0], "resources_last_loaded": samples[-1], "resources_after_drain": after_resources,
              "no_real_mailboxes_or_proxy_traffic": True}
    (folder / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf8")
    print("RESULT " + json.dumps(result, ensure_ascii=False), flush=True)
    return not errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 16 or not 1 <= args.seconds <= 3600:
        parser.error("workers must be 1..16, seconds must be 1..3600")
    root = Path(__file__).resolve().parents[1] / "run" / "diagnostics"
    output = (args.output or root / ("soak5-" + datetime.now().strftime("%Y%m%d-%H%M%S"))).resolve()
    if not output.is_relative_to(root.resolve()):
        parser.error("output must stay inside run/diagnostics")
    output.mkdir(parents=True, exist_ok=False)
    print("OUTPUT " + str(output), flush=True)
    raise SystemExit(0 if run(args.seconds, args.workers, output) else 1)
