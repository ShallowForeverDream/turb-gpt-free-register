"""Run unit tests in a disposable source copy, never beside real account data.

Usage: python tools/run_offline_tests.py [--suite all|python|node]
Logs: .local.offline-python.log and .local.offline-node.log (git-ignored).
The protocol fixture is an offline test setting, not a deployment change.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
_NETWORK_GUARD = '''
import socket
from urllib.parse import urlsplit
original_connect = socket.socket.connect
def guarded_connect(self, address):
    if isinstance(address, tuple) and address[0] not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError("OFFLINE_TEST: external network blocked")
    return original_connect(self, address)
socket.socket.connect = guarded_connect
def guard_request(fn):
    def request(self, method, url, *args, **kwargs):
        if urlsplit(str(url)).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("OFFLINE_TEST: external HTTP blocked")
        return fn(self, method, url, *args, **kwargs)
    return request
for name in ("requests.sessions", "curl_cffi.requests.session"):
    module = __import__(name, fromlist=["Session"])
    module.Session.request = guard_request(module.Session.request)
'''


def copy_source(destination):
    paths = subprocess.check_output(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT,
    ).decode("utf-8").split("\0")
    for name in set(filter(None, paths)):
        relative = Path(name)
        # Only code, fixtures and docs; never copy captures, runtime data or a .env.
        if (relative.parts[0] not in {"config", "core", "tests", "webui", "sentinel", "static", "tools", "docs"}
                and name not in {"main.py", "web.py", "webui.ps1", "webui.cmd", "webui.sh",
                                 "requirements.txt", "README.md", ".gitignore", ".env.example"}):
            continue
        source = (ROOT / relative).resolve()
        target = (destination / relative).resolve()
        if not source.is_relative_to(ROOT) or not target.is_relative_to(destination):
            raise ValueError("Source path escaped the project")
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    (destination / "sitecustomize.py").write_text(_NETWORK_GUARD, encoding="utf-8")
    (destination / ".env").write_text(
        "REGISTRATION_DRIVER=protocol\nPROXY_POOL=[]\nPLAN_CHECK_PROXY=[]\n"
        "REGISTRATION_WORKERS=4\nWEBUI_LOCAL_NO_AUTH=false\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", "python", "node"), default="all")
    parser.add_argument("--pattern", default="test_*.py", help="unittest discovery pattern")
    args = parser.parse_args()
    # Tests can reload .env. All paths and config reads therefore belong in the copy.
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
                              "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME", "LANG"}}
    env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    failed = False
    with tempfile.TemporaryDirectory(prefix="any-register-offline-") as folder:
        snapshot = Path(folder).resolve()
        if not snapshot.is_relative_to(Path(tempfile.gettempdir()).resolve()):
            raise ValueError("Unexpected temporary directory")
        copy_source(snapshot)
        env["PYTHONPATH"] = str(snapshot)
        for suite in ("python", "node"):
            if args.suite not in {"all", suite}:
                continue
            if suite == "python":
                command = [sys.executable, "-c",
                           "import sitecustomize; import runpy; runpy.run_module('unittest', run_name='__main__')",
                           "discover", "-s", "tests", "-p", args.pattern]
            else:
                command = [shutil.which("node") or "node", "--test"]
                command.extend(str(path.relative_to(snapshot)) for path in sorted((snapshot / "tests").glob("test_*.cjs")))
            log = ROOT / f".local.offline-{suite}.log"
            with log.open("w", encoding="utf-8") as output:
                result = subprocess.run(command, cwd=snapshot, env=env, stdout=output, stderr=subprocess.STDOUT)
            failed |= result.returncode != 0
            print(f"{suite}: exit={result.returncode}; log={log}", flush=True)
            for line in log.read_text(encoding="utf-8").splitlines():
                if line.startswith(("ERROR:", "FAIL:", "Ran ", "FAILED", "OK", "# tests", "# pass", "# fail")):
                    print(line, flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
