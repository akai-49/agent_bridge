"""End-to-end tests for bi-directional bridge (Task 8).

Verifies:
- Both roles can ask questions and have them answered by the peer's responder.
- A can opt in to serve via bridge_serve(confirm_folder).
- bridge_serve requires matching confirm_folder and is idempotent.
- bridge_serve and bridge_join refuse home directory or parent of home.
- bridge_status reports serving (bool) and serving_folder.
- bridge_net_revoke stops responders on both sides.
- No real claude CLI is invoked (mock/fake runners only).
"""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from relay.relay import make_server
import server.bridge as bridge
from server.responder import Cfg, main as responder_main
import server.wire as wire


class FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestBidirEndToEnd(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name).resolve()

        # Machine A directories
        self.home_a = self.base_dir / "home_a"
        self.home_a.mkdir(parents=True, exist_ok=True)
        self.repo_a = self.base_dir / "repo_a"
        self.repo_a.mkdir(parents=True, exist_ok=True)
        (self.repo_a / "index.js").write_text("console.log('frontend app');\n")

        # Machine B directories
        self.home_b = self.base_dir / "home_b"
        self.home_b.mkdir(parents=True, exist_ok=True)
        self.repo_b = self.base_dir / "repo_b"
        self.repo_b.mkdir(parents=True, exist_ok=True)
        (self.repo_b / "server.py").write_text("def run():\n    return 'jwt_token'\n")

        # Save environment
        self.orig_bridge_home = os.environ.get("BRIDGE_HOME")
        self.orig_bridge_path = os.environ.get("BRIDGE_PATH")

        # Start real relay on port 0
        self.relay_db = str(self.base_dir / "relay.db")
        self.relay_server = make_server(self.relay_db, "127.0.0.1", 0)
        self.relay_port = self.relay_server.server_address[1]
        self.relay_url = f"http://127.0.0.1:{self.relay_port}"
        self.relay_thread = threading.Thread(
            target=lambda: self.relay_server.serve_forever(poll_interval=0.05),
            daemon=True,
        )
        self.relay_thread.start()

        self.stop_events: list[threading.Event] = []
        self.subprocesses: list[subprocess.Popen] = []
        self.responder_threads: list[threading.Thread] = []

    def tearDown(self):
        for stop_evt in self.stop_events:
            stop_evt.set()

        for proc in self.subprocesses:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                pass

        self.relay_server.shutdown()
        self.relay_server.server_close()

        for t in self.responder_threads:
            if t.is_alive():
                t.join(timeout=2.0)

        if self.orig_bridge_home is not None:
            os.environ["BRIDGE_HOME"] = self.orig_bridge_home
        else:
            os.environ.pop("BRIDGE_HOME", None)

        if self.orig_bridge_path is not None:
            os.environ["BRIDGE_PATH"] = self.orig_bridge_path
        else:
            os.environ.pop("BRIDGE_PATH", None)

        self.temp_dir.cleanup()

    @contextmanager
    def on_machine_a(self):
        prev_home = os.environ.get("BRIDGE_HOME")
        prev_path = os.environ.get("BRIDGE_PATH")
        os.environ["BRIDGE_HOME"] = str(self.home_a)
        os.environ["BRIDGE_PATH"] = str(self.repo_a)
        try:
            yield
        finally:
            if prev_home is not None:
                os.environ["BRIDGE_HOME"] = prev_home
            else:
                os.environ.pop("BRIDGE_HOME", None)
            if prev_path is not None:
                os.environ["BRIDGE_PATH"] = prev_path
            else:
                os.environ.pop("BRIDGE_PATH", None)

    @contextmanager
    def on_machine_b(self):
        prev_home = os.environ.get("BRIDGE_HOME")
        prev_path = os.environ.get("BRIDGE_PATH")
        os.environ["BRIDGE_HOME"] = str(self.home_b)
        os.environ["BRIDGE_PATH"] = str(self.repo_b)
        try:
            yield
        finally:
            if prev_home is not None:
                os.environ["BRIDGE_HOME"] = prev_home
            else:
                os.environ.pop("BRIDGE_HOME", None)
            if prev_path is not None:
                os.environ["BRIDGE_PATH"] = prev_path
            else:
                os.environ.pop("BRIDGE_PATH", None)

    def _spawn_dummy_proc(self) -> int:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.subprocesses.append(proc)
        return proc.pid

    def _start_responder_thread(self, config_path: str, runner) -> threading.Thread:
        stop_evt = threading.Event()
        self.stop_events.append(stop_evt)
        t = threading.Thread(
            target=lambda: responder_main(config_path, once=False, stop_event=stop_evt, runner=runner),
            daemon=True,
        )
        self.responder_threads.append(t)
        t.start()
        return t

    def test_a_serve_requires_matching_confirm_folder(self):
        """bridge_serve refuses unless confirm_folder matches the current repo root."""
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)

        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", return_value=self._spawn_dummy_proc()):
                bridge.bridge_join(token, confirm_relay=self.relay_url)

        with self.on_machine_a():
            # Mismatched folder must raise BridgeError
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.bridge_serve(confirm_folder="/some/other/folder")
            self.assertIn("Folder confirmation failed", str(ctx.exception))

            # Matching folder succeeds
            with patch.object(bridge, "spawn_responder", return_value=self._spawn_dummy_proc()):
                res = bridge.bridge_serve(confirm_folder=str(self.repo_a))
                self.assertIn("serving", res.lower())

    def test_serve_refuses_home_dir(self):
        """bridge_serve refuses to serve user's home dir or any parent of it."""
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)

        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", return_value=self._spawn_dummy_proc()):
                bridge.bridge_join(token, confirm_relay=self.relay_url)

        user_home = Path.home().resolve()
        parent_home = user_home.parent

        with self.on_machine_a():
            # Test user home
            os.environ["BRIDGE_PATH"] = str(user_home)
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.bridge_serve(confirm_folder=str(user_home))
            self.assertIn(str(user_home), str(ctx.exception))

            # Test parent of home
            os.environ["BRIDGE_PATH"] = str(parent_home)
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.bridge_serve(confirm_folder=str(parent_home))
            self.assertIn(str(parent_home), str(ctx.exception))

    def test_join_refuses_home_dir(self):
        """bridge_join refuses to join from user's home dir or any parent of it."""
        user_home = Path.home().resolve()
        parent_home = user_home.parent

        with self.on_machine_a():
            token1 = bridge.bridge_invite(self.relay_url)
            token2 = bridge.bridge_invite(self.relay_url)

        with self.on_machine_b():
            os.environ["BRIDGE_PATH"] = str(user_home)
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.bridge_join(token1, confirm_relay=self.relay_url)
            self.assertIn(str(user_home), str(ctx.exception))

            os.environ["BRIDGE_PATH"] = str(parent_home)
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.bridge_join(token2, confirm_relay=self.relay_url)
            self.assertIn(str(parent_home), str(ctx.exception))

    def test_serve_is_idempotent(self):
        """Calling bridge_serve when already serving returns 'already serving <folder>'."""
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)

        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", return_value=self._spawn_dummy_proc()):
                bridge.bridge_join(token, confirm_relay=self.relay_url)

        dummy_pid = self._spawn_dummy_proc()
        with self.on_machine_a():
            with patch.object(bridge, "spawn_responder", return_value=dummy_pid):
                res1 = bridge.bridge_serve(confirm_folder=str(self.repo_a))
                self.assertIn("serving", res1.lower())

            # Second call when dummy_pid is alive returns "already serving <folder>"
            res2 = bridge.bridge_serve(confirm_folder=str(self.repo_a))
            self.assertEqual(res2, f"already serving {self.repo_a}")

    def test_e2e_both_directions(self):
        """Relay in thread, A and B in separate BRIDGE_HOME, both responders with fake runners:

        A asks B and B asks A; each receives the other's answer.
        """
        # Step 1: Machine A invites
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)

        # Step 2: Machine B joins
        cfg_b_paths = []
        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", side_effect=lambda p: cfg_b_paths.append(p) or self._spawn_dummy_proc()):
                res_join = bridge.bridge_join(token, confirm_relay=self.relay_url)
                self.assertIn("Joined bridge", res_join)
        self.assertEqual(len(cfg_b_paths), 1)

        # Start B's responder thread with fake_runner_b
        def fake_runner_b(cmd, cwd=None, timeout=None, env=None, **kwargs):
            return FakeCompletedProcess(stdout="Answer from B: login returns JWT token.")

        self._start_responder_thread(cfg_b_paths[0], fake_runner_b)

        # Step 3: Machine A serves
        cfg_a_paths = []
        with self.on_machine_a():
            with patch.object(bridge, "spawn_responder", side_effect=lambda p: cfg_a_paths.append(p) or self._spawn_dummy_proc()):
                res_serve = bridge.bridge_serve(confirm_folder=str(self.repo_a))
                self.assertIn("serving", res_serve.lower())
        self.assertEqual(len(cfg_a_paths), 1)

        # Start A's responder thread with fake_runner_a
        def fake_runner_a(cmd, cwd=None, timeout=None, env=None, **kwargs):
            return FakeCompletedProcess(stdout="Answer from A: frontend button component in index.js.")

        self._start_responder_thread(cfg_a_paths[0], fake_runner_a)

        # Step 4: A asks B
        with self.on_machine_a():
            ans_from_b = bridge.bridge_ask("How does authentication work in backend?")
            self.assertEqual(ans_from_b, "Answer from B: login returns JWT token.")

        # Step 5: B asks A
        with self.on_machine_b():
            ans_from_a = bridge.bridge_ask("What frontend components are in index.js?")
            self.assertEqual(ans_from_a, "Answer from A: frontend button component in index.js.")

        # Step 6: Verify audit logs
        audit_b = (self.home_b / "audit.jsonl").read_text().strip().splitlines()
        self.assertTrue(len(audit_b) >= 1)
        rec_b = json.loads(audit_b[0])
        self.assertEqual(rec_b["q"], "How does authentication work in backend?")
        self.assertEqual(rec_b["a"], "Answer from B: login returns JWT token.")

        audit_a = (self.home_a / "audit.jsonl").read_text().strip().splitlines()
        self.assertTrue(len(audit_a) >= 1)
        rec_a = json.loads(audit_a[0])
        self.assertEqual(rec_a["q"], "What frontend components are in index.js?")
        self.assertEqual(rec_a["a"], "Answer from A: frontend button component in index.js.")

    def test_status_reports_serving(self):
        """bridge_status reports serving (bool) and serving_folder."""
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)
            # Before peer joins and before serve
            status_a_init = bridge.bridge_status()
            self.assertFalse(status_a_init["serving"])
            self.assertIsNone(status_a_init["serving_folder"])

        # B joins
        dummy_pid_b = self._spawn_dummy_proc()
        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", return_value=dummy_pid_b):
                bridge.bridge_join(token, confirm_relay=self.relay_url)
            status_b = bridge.bridge_status()
            self.assertTrue(status_b["serving"])
            self.assertEqual(status_b["serving_folder"], str(self.repo_b))

        # A before serving
        with self.on_machine_a():
            status_a_pre = bridge.bridge_status()
            self.assertFalse(status_a_pre["serving"])
            self.assertIsNone(status_a_pre["serving_folder"])

            # A serves
            dummy_pid_a = self._spawn_dummy_proc()
            with patch.object(bridge, "spawn_responder", return_value=dummy_pid_a):
                bridge.bridge_serve(confirm_folder=str(self.repo_a))

            status_a_post = bridge.bridge_status()
            self.assertTrue(status_a_post["serving"])
            self.assertEqual(status_a_post["serving_folder"], str(self.repo_a))

    def test_revoke_stops_both_responders(self):
        """bridge_net_revoke stops this side's responder and peer responder exits on 401."""
        with self.on_machine_a():
            token = bridge.bridge_invite(self.relay_url)

        cfg_b_paths = []
        dummy_proc_b = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.subprocesses.append(dummy_proc_b)

        with self.on_machine_b():
            with patch.object(bridge, "spawn_responder", side_effect=lambda p: cfg_b_paths.append(p) or dummy_proc_b.pid):
                bridge.bridge_join(token, confirm_relay=self.relay_url)

        thread_b = self._start_responder_thread(cfg_b_paths[0], lambda cmd, **kw: FakeCompletedProcess(stdout="ok"))

        cfg_a_paths = []
        dummy_proc_a = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.subprocesses.append(dummy_proc_a)

        with self.on_machine_a():
            with patch.object(bridge, "spawn_responder", side_effect=lambda p: cfg_a_paths.append(p) or dummy_proc_a.pid):
                bridge.bridge_serve(confirm_folder=str(self.repo_a))

        thread_a = self._start_responder_thread(cfg_a_paths[0], lambda cmd, **kw: FakeCompletedProcess(stdout="ok"))

        self.assertTrue(thread_a.is_alive())
        self.assertTrue(thread_b.is_alive())

        # Machine A revokes
        with self.on_machine_a():
            res = bridge.bridge_net_revoke()
            self.assertIn("revoked", res.lower())

        # Machine A's dummy responder process was terminated via SIGTERM
        dummy_proc_a.wait(timeout=3.0)
        self.assertIsNotNone(dummy_proc_a.poll())

        # B's polling thread receives 401 on next poll and exits
        thread_b.join(timeout=3.0)
        self.assertFalse(thread_b.is_alive())


if __name__ == "__main__":
    unittest.main()
