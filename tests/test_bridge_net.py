"""Tests for server/bridge.py network tools (Task 5)."""
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from relay.relay import make_server
import server.bridge as bridge
from server.responder import Cfg, handle as responder_handle, main as responder_main
from server.wire import parse_token, sign, verify


class FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestBridgeNet(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name).resolve()

        # Set up BRIDGE_HOME for machine A
        self.home_a = self.base_dir / "home_a"
        self.home_a.mkdir(parents=True, exist_ok=True)
        self.orig_bridge_home = os.environ.get("BRIDGE_HOME")
        os.environ["BRIDGE_HOME"] = str(self.home_a)

        # Start real in-thread relay on port 0
        self.relay_db = str(self.base_dir / "relay.db")
        self.server = make_server(self.relay_db, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.relay_url = f"http://127.0.0.1:{self.port}"
        self.server_thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05),
            daemon=True,
        )
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        if self.orig_bridge_home is not None:
            os.environ["BRIDGE_HOME"] = self.orig_bridge_home
        else:
            os.environ.pop("BRIDGE_HOME", None)
        self.temp_dir.cleanup()

    def test_status_unpaired(self):
        """bridge_status returns paired=False when no net.json exists."""
        status = bridge.bridge_status()
        self.assertIsInstance(status, dict)
        self.assertFalse(status["paired"])
        self.assertIsNone(status.get("role"))
        self.assertIsNone(status.get("relay_url"))
        self.assertIsNone(status.get("session_age"))

    def test_invite_returns_parseable_token(self):
        """bridge_invite generates e2e_key, calls /invite, saves net.json with 0600 perms, returns token."""
        token = bridge.bridge_invite(self.relay_url)
        self.assertIsInstance(token, str)
        self.assertTrue(token.startswith("brg1."))

        parsed = parse_token(token)
        self.assertEqual(parsed["relay_url"], self.relay_url)
        self.assertTrue(parsed["invite_id"])
        self.assertTrue(parsed["join_secret"])
        self.assertTrue(parsed["e2e_key"])

        # Check net.json in BRIDGE_HOME
        net_path = self.home_a / "net.json"
        self.assertTrue(net_path.is_file())

        # Check 0600 permissions
        mode = stat.S_IMODE(net_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

        net_data = json.loads(net_path.read_text())
        self.assertEqual(net_data["role"], "A")
        self.assertEqual(net_data["relay_url"], self.relay_url)
        self.assertEqual(net_data["invite_id"], parsed["invite_id"])
        self.assertEqual(net_data["e2e_key"], parsed["e2e_key"])
        self.assertTrue(net_data.get("poll_secret"))

    def test_join_requires_matching_confirm_relay(self):
        """bridge_join refuses with BridgeError unless confirm_relay matches token's relay."""
        token = bridge.bridge_invite(self.relay_url)

        # Mismatched confirm_relay must raise BridgeError
        with self.assertRaises(bridge.BridgeError):
            bridge.bridge_join(token, confirm_relay="http://evil-relay.com:8080")

        # Invalid token must raise BridgeError
        with self.assertRaises(bridge.BridgeError):
            bridge.bridge_join("not_a_valid_token", confirm_relay=self.relay_url)

    def test_join_success_writes_config_and_spawns_responder(self):
        """bridge_join writes responder config with 0600 perms and spawns responder daemon."""
        token = bridge.bridge_invite(self.relay_url)

        # Switch to machine B's BRIDGE_HOME
        home_b = self.base_dir / "home_b"
        home_b.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b)

        spawn_mock = MagicMock(return_value=12345)
        with patch.object(bridge, "spawn_responder", spawn_mock):
            res = bridge.bridge_join(token, confirm_relay=self.relay_url)
            self.assertIn("Joined", res)

            # Responder spawn was called
            spawn_mock.assert_called_once()
            cfg_path_str = spawn_mock.call_args[0][0]
            cfg_path = Path(cfg_path_str)
            self.assertTrue(cfg_path.is_file())

            # Config file has 0600 permissions
            mode = stat.S_IMODE(cfg_path.stat().st_mode)
            self.assertEqual(mode, 0o600)

            # Config has valid fields for responder Cfg
            cfg_data = json.loads(cfg_path.read_text())
            self.assertEqual(cfg_data["relay_url"], self.relay_url)
            self.assertTrue(cfg_data["session_b"])
            self.assertTrue(cfg_data["e2e_key"])
            self.assertTrue(cfg_data["repo_root"])

            # net.json on B has 0600 permissions and records PID
            net_b_path = home_b / "net.json"
            self.assertTrue(net_b_path.is_file())
            self.assertEqual(stat.S_IMODE(net_b_path.stat().st_mode), 0o600)
            net_b = json.loads(net_b_path.read_text())
            self.assertEqual(net_b["role"], "B")
            self.assertEqual(net_b["responder_pid"], 12345)

    def test_ask_lazy_session_fetch_and_answer_roundtrip(self):
        """bridge_ask lazily fetches session_a, signs question, polls result, and verifies answer."""
        token = bridge.bridge_invite(self.relay_url)

        # Before B joins, asking must fail because session_a is not ready
        with self.assertRaises(bridge.BridgeError):
            bridge.bridge_ask("Premature question?")

        # Now B joins in home_b
        home_b = self.base_dir / "home_b"
        home_b.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b)

        spawn_mock = MagicMock(return_value=54321)
        with patch.object(bridge, "spawn_responder", spawn_mock):
            bridge.bridge_join(token, confirm_relay=self.relay_url)
            cfg_path_str = spawn_mock.call_args[0][0]

        # Switch back to machine A
        os.environ["BRIDGE_HOME"] = str(self.home_a)

        # Status on A should now reflect paired (via lazy fetch)
        status_a = bridge.bridge_status()
        self.assertTrue(status_a["paired"])
        self.assertEqual(status_a["role"], "A")
        self.assertGreaterEqual(status_a["session_age"], 0)

        # Start responder in a background thread to answer incoming question
        def fake_runner(cmd, **kwargs):
            return FakeCompletedProcess(stdout="42 is the answer.")

        stop_evt = threading.Event()
        resp_thread = threading.Thread(
            target=lambda: responder_main(cfg_path_str, once=True, stop_event=stop_evt, runner=fake_runner),
            daemon=True,
        )
        resp_thread.start()

        # Machine A asks question
        answer = bridge.bridge_ask("What is the meaning of life?")
        self.assertEqual(answer, "42 is the answer.")

        # Check status shows question count
        status_after = bridge.bridge_status()
        self.assertGreaterEqual(status_after.get("questions_used", 0), 1)

    def test_ask_rejects_bad_answer_signature(self):
        """bridge_ask raises BridgeError if the relay returns an answer with an invalid signature."""
        token = bridge.bridge_invite(self.relay_url)

        home_b = self.base_dir / "home_b"
        home_b.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b)

        spawn_mock = MagicMock(return_value=11111)
        with patch.object(bridge, "spawn_responder", spawn_mock):
            bridge.bridge_join(token, confirm_relay=self.relay_url)
            cfg_path_str = spawn_mock.call_args[0][0]

        with open(cfg_path_str) as f:
            cfg_dict = json.load(f)

        # Switch back to A
        os.environ["BRIDGE_HOME"] = str(self.home_a)

        # Answering responder that produces a bad signature
        def bad_sig_responder():
            import http.client
            # Poll for question
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/poll?wait=5", headers={"Authorization": f"Bearer {cfg_dict['session_b']}"})
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                qid = data["qid"]
                # Post answer with tampered signature
                body = json.dumps({"qid": qid, "a": "tampered answer", "sig": "bad_signature_deadbeef"}).encode()
                conn2 = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn2.request("POST", "/answer", body=body, headers={
                    "Authorization": f"Bearer {cfg_dict['session_b']}",
                    "Content-Type": "application/json",
                })
                conn2.getresponse().read()
                conn2.close()
            conn.close()

        resp_thread = threading.Thread(target=bad_sig_responder, daemon=True)
        resp_thread.start()

        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.bridge_ask("Is this safe?")
        self.assertIn("signature", str(ctx.exception).lower())

    def test_net_revoke_kills_process_and_cleans_up(self):
        """bridge_net_revoke sends /revoke to relay, kills responder pid, and deletes net.json."""
        token = bridge.bridge_invite(self.relay_url)

        home_b = self.base_dir / "home_b"
        home_b.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b)

        spawn_mock = MagicMock(return_value=99999)
        with patch.object(bridge, "spawn_responder", spawn_mock):
            bridge.bridge_join(token, confirm_relay=self.relay_url)

        net_b_path = home_b / "net.json"
        self.assertTrue(net_b_path.is_file())

        kill_mock = MagicMock()
        with patch("os.kill", kill_mock):
            res = bridge.bridge_net_revoke()
            self.assertIn("revoked", res.lower())
            kill_mock.assert_called_with(99999, signal.SIGTERM)

        # net.json must be deleted
        self.assertFalse(net_b_path.exists())

        # bridge_status is now unpaired
        status = bridge.bridge_status()
        self.assertFalse(status["paired"])

    def test_tools_registered_with_descriptions(self):
        """Ensure all 5 new network tools are in TOOLS with correct descriptions."""
        expected = ["bridge_invite", "bridge_join", "bridge_ask", "bridge_status", "bridge_net_revoke"]
        for tool_name in expected:
            self.assertIn(tool_name, bridge.TOOLS)
            func, desc, schema, req = bridge.TOOLS[tool_name]
            self.assertTrue(callable(func))
            self.assertIsInstance(desc, str)
            self.assertGreater(len(desc), 10)

        # bridge_join description must instruct Claude to show the user the relay host and get a yes
        join_desc = bridge.TOOLS["bridge_join"][1].lower()
        self.assertIn("relay", join_desc)
        self.assertTrue("yes" in join_desc or "confirm" in join_desc)

    def test_ask_oversized_question(self):
        """bridge_ask refuses questions larger than 4096 bytes."""
        token = bridge.bridge_invite(self.relay_url)
        big_q = "x" * 4097
        with self.assertRaises(bridge.BridgeError):
            bridge.bridge_ask(big_q)

    def test_join_already_used_token_raises(self):
        """Replaying a used invite token on bridge_join raises BridgeError."""
        token = bridge.bridge_invite(self.relay_url)

        home_b1 = self.base_dir / "home_b1"
        home_b1.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b1)

        with patch.object(bridge, "spawn_responder", return_value=101):
            bridge.bridge_join(token, confirm_relay=self.relay_url)

        # Second join attempt must fail
        home_b2 = self.base_dir / "home_b2"
        home_b2.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b2)

        with patch.object(bridge, "spawn_responder", return_value=102):
            with self.assertRaises(bridge.BridgeError):
                bridge.bridge_join(token, confirm_relay=self.relay_url)

    def test_bridge_path_env_used_for_repo_root(self):
        """bridge_join uses BRIDGE_PATH environment variable for repo_root if set."""
        token = bridge.bridge_invite(self.relay_url)

        custom_repo = self.base_dir / "custom_repo"
        custom_repo.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_PATH"] = str(custom_repo)

        home_b = self.base_dir / "home_b_custom"
        home_b.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(home_b)

        try:
            with patch.object(bridge, "spawn_responder", return_value=123) as mock_spawn:
                bridge.bridge_join(token, confirm_relay=self.relay_url)
                cfg_path_str = mock_spawn.call_args[0][0]
                with open(cfg_path_str) as f:
                    cfg_data = json.load(f)
                self.assertEqual(cfg_data["repo_root"], str(custom_repo.resolve()))
        finally:
            os.environ.pop("BRIDGE_PATH", None)

    def test_default_spawn_responder_calls_popen_with_session(self):
        """spawn_responder calls subprocess.Popen with start_new_session=True."""
        dummy_cfg = str(self.base_dir / "dummy.json")
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.pid = 77777
            mock_popen.return_value = mock_proc
            pid = bridge.spawn_responder(dummy_cfg)
            self.assertEqual(pid, 77777)
            mock_popen.assert_called_once()
            _, kwargs = mock_popen.call_args
            self.assertTrue(kwargs.get("start_new_session"))

    def test_mcp_handle_bridge_tools(self):
        """MCP handle executes bridge network tools via tools/call."""
        import io
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            req = {
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "tools/call",
                "params": {
                    "name": "bridge_status",
                    "arguments": {},
                },
            }
            bridge.handle(req)

        output = stdout_buf.getvalue()
        resp = json.loads(output)
        self.assertEqual(resp["id"], "req-1")
        self.assertIn("content", resp["result"])
        text = resp["result"]["content"][0]["text"]
        status_dict = json.loads(text)
        self.assertFalse(status_dict["paired"])


if __name__ == "__main__":
    unittest.main()
