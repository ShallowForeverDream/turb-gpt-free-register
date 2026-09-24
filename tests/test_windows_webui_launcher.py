"""Exercise the Windows manager against an offline dummy server, not the application."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import venv


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")
DUMMY_SERVER = """
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
parser = argparse.ArgumentParser()
parser.add_argument('--host')
parser.add_argument('--port', type=int)
args = parser.parse_args()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
HTTPServer((args.host, args.port), Handler).serve_forever()
"""


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell required")
class WindowsWebUiLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="webui test 中文 ")
        self.root = Path(self.temp.name)
        shutil.copyfile(ROOT / "webui.ps1", self.root / "webui.ps1")
        (self.root / "web.py").write_text(DUMMY_SERVER, encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.state = self.root / "run" / f"webui-{self.port}.json"

    def command(self, action, *extra, check=True, python_exe=None):
        # File handles avoid waiting for pipe EOF inherited by a detached Windows child.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                 str(self.root / "webui.ps1"), action, "-Python", python_exe or sys.executable,
                 "-Port", str(self.port), "-StartupTimeout", "8", *extra],
                stdout=stdout, stderr=stderr, timeout=45,
            )
            stdout.seek(0)
            stderr.seek(0)
            result.stdout, result.stderr = stdout.read(), stderr.read()
        if check:
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))
        return result

    def tearDown(self):
        try:
            self.command("stop")
        finally:
            self.temp.cleanup()

    def test_start_status_idempotence_restart_and_stop(self):
        self.command("start")
        initial = json.loads(self.state.read_text(encoding="utf-8-sig"))
        self.command("start")
        self.assertEqual(json.loads(self.state.read_text(encoding="utf-8-sig"))["ProcessId"], initial["ProcessId"])
        self.assertIn(b"running: PID=", self.command("status").stdout)
        with socket.create_connection(("127.0.0.1", self.port), timeout=3):
            pass
        self.command("restart")
        current = json.loads(self.state.read_text(encoding="utf-8-sig"))
        self.assertNotEqual((current["ProcessId"], current["StartedTicks"]), (initial["ProcessId"], initial["StartedTicks"]))
        self.command("stop")
        self.assertFalse(self.state.exists())
        self.assertIn(b"not running", self.command("status").stdout)

    def test_windows_venv_redirector_starts_and_stops_worker(self):
        venv_dir = self.root / "env"
        venv.EnvBuilder(with_pip=False).create(venv_dir)
        venv_python = str(venv_dir / "Scripts" / "python.exe")
        self.command("start", python_exe=venv_python)
        self.assertIn(b"running: PID=", self.command("status").stdout)
        with socket.create_connection(("127.0.0.1", self.port), timeout=3):
            pass
        self.command("stop")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1)

    def test_occupied_port_is_not_stopped(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            result = self.command("start", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"occupied", result.stderr)
            self.assertFalse(self.state.exists())
            with socket.create_connection(("127.0.0.1", self.port), timeout=3):
                pass

    def test_reused_pid_is_rejected_without_touching_unrelated_process(self):
        self.state.parent.mkdir()
        self.state.write_text(json.dumps({"ProcessId": os.getpid(), "StartedTicks": "0", "Python": sys.executable}), encoding="utf-8")
        try:
            result = self.command("stop", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"identity", result.stderr)
            self.assertTrue(self.state.exists())
        finally:
            self.state.unlink()

    def test_failed_start_removes_pid_state(self):
        (self.root / "web.py").write_text("raise SystemExit(7)\n", encoding="utf-8")
        result = self.command("start", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
