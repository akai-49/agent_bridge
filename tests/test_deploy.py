from __future__ import annotations
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

from relay.relay import RelayServer, make_server, main as relay_main
from server import bridge
from server.bridge import BridgeError
from server.http_client import relay_urlopen
from server import responder
from server.responder import Cfg
from server.wire import q_tag, sign


class TestDeploy(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = str(self.temp_path / "test_deploy.db")
        self.home_dir = self.temp_path / "home"
        self.home_dir.mkdir(parents=True, exist_ok=True)
        os.environ["BRIDGE_HOME"] = str(self.home_dir)
        self.orig_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        self.temp_dir.cleanup()

    def test_relay_main_env_defaults(self):
        """Relay main() defaults come from env: RELAY_HOST, PORT, RELAY_DB."""
        with patch.dict(os.environ, {
            "RELAY_HOST": "127.0.0.1",
            "PORT": "9123",
            "RELAY_DB": "/custom/path/relay.db",
        }, clear=True):
            with patch("relay.relay.make_server") as mock_make_server, \
                 patch("sys.argv", ["relay.py"]):
                mock_server = MagicMock()
                mock_make_server.return_value = mock_server
                mock_server.serve_forever.side_effect = KeyboardInterrupt
                try:
                    relay_main()
                except SystemExit:
                    pass

                mock_make_server.assert_called_once_with(
                    "/custom/path/relay.db", "127.0.0.1", 9123, relay_key=None
                )

        # Fallback defaults when env unset
        with patch.dict(os.environ, {}, clear=True):
            with patch("relay.relay.make_server") as mock_make_server, \
                 patch("sys.argv", ["relay.py"]):
                mock_server = MagicMock()
                mock_make_server.return_value = mock_server
                mock_server.serve_forever.side_effect = KeyboardInterrupt
                try:
                    relay_main()
                except SystemExit:
                    pass

                mock_make_server.assert_called_once_with(
                    "relay.db", "127.0.0.1", 8080, relay_key=None
                )

    def test_refuse_public_bind_without_relay_key(self):
        """Refuse public bind (e.g. 0.0.0.0 or 192.168.1.1) when RELAY_KEY is unset."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("sys.argv", ["relay.py", "--host", "0.0.0.0"]):
                with self.assertRaises(SystemExit) as cm:
                    relay_main()
                self.assertNotEqual(cm.exception.code, 0)

        # Loopback hosts must be allowed without RELAY_KEY
        for loopback in ("127.0.0.1", "localhost", "::1"):
            with patch.dict(os.environ, {}, clear=True):
                with patch("relay.relay.make_server") as mock_make_server, \
                     patch("sys.argv", ["relay.py", "--host", loopback]):
                    mock_server = MagicMock()
                    mock_make_server.return_value = mock_server
                    mock_server.serve_forever.side_effect = KeyboardInterrupt
                    try:
                        relay_main()
                    except SystemExit:
                        pass
                    self.assertTrue(mock_make_server.called)

        # Non-loopback host is allowed if RELAY_KEY is set
        with patch.dict(os.environ, {"RELAY_KEY": "some-secret"}, clear=True):
            with patch("relay.relay.make_server") as mock_make_server, \
                 patch("sys.argv", ["relay.py", "--host", "0.0.0.0"]):
                mock_server = MagicMock()
                mock_make_server.return_value = mock_server
                mock_server.serve_forever.side_effect = KeyboardInterrupt
                try:
                    relay_main()
                except SystemExit:
                    pass
                self.assertTrue(mock_make_server.called)

    def test_healthz_endpoint(self):
        """GET /healthz returns 200 plain 'ok' without auth or db setup beyond opening."""
        server = make_server(self.db_path, "127.0.0.1", 0)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read().decode("utf-8").strip(), "ok")
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_relay_key_invite_auth_and_join_unaffected(self):
        """POST /invite requires X-Relay-Key equal to RELAY_KEY, but /join is unaffected."""
        server = make_server(self.db_path, "127.0.0.1", 0)
        server.relay_key = "test-relay-key-secret"
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # 1. /invite without key -> 401 {"error":"unauthorized"}
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/invite", body=b"{}", headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("error"), "unauthorized")
            conn.close()

            # 2. /invite with wrong key -> 401
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/invite", body=b"{}", headers={
                "Content-Type": "application/json",
                "X-Relay-Key": "wrong-key",
            })
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            conn.close()

            # 3. /invite with right key -> 200
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/invite", body=b"{}", headers={
                "Content-Type": "application/json",
                "X-Relay-Key": "test-relay-key-secret",
            })
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            invite_data = json.loads(resp.read().decode("utf-8"))
            invite_id = invite_data["invite_id"]
            join_secret = invite_data["join_secret"]
            conn.close()

            # 4. /join unaffected by key -> succeeds without X-Relay-Key
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            join_body = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
            conn.request("POST", "/join", body=join_body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            join_data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("session_b", join_data)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_bridge_invite_sends_relay_key_and_raises_specific_401(self):
        """bridge_invite sends BRIDGE_RELAY_KEY header and raises clear error on 401."""
        server = make_server(self.db_path, "127.0.0.1", 0)
        server.relay_key = "secure-key-abc"
        port = server.server_address[1]
        relay_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # 1. When BRIDGE_RELAY_KEY is unset, 401 raises BridgeError with exact instruction
            with patch.dict(os.environ, {}, clear=True):
                os.environ["BRIDGE_HOME"] = str(self.home_dir)
                with self.assertRaises(BridgeError) as cm:
                    bridge.bridge_invite(relay_url)
                self.assertIn(
                    "Relay requires a relay key: set BRIDGE_RELAY_KEY in the environment you start claude from.",
                    str(cm.exception),
                )

            # 2. When BRIDGE_RELAY_KEY is set, bridge_invite succeeds
            with patch.dict(os.environ, {"BRIDGE_RELAY_KEY": "secure-key-abc"}):
                token = bridge.bridge_invite(relay_url)
                self.assertTrue(token.startswith("brg1."))
        finally:
            server.shutdown()
            server.server_close()

    def test_retry_helper_retries_503_and_fails_fast_on_400(self):
        """Shared retry helper retries 502/503/504 and connection errors up to 3 times, never 4xx."""
        attempts = 0

        class FlakyHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                nonlocal attempts
                attempts += 1
                if self.path == "/flaky":
                    if attempts < 3:
                        self.send_response(503)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        body = b"success"
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                elif self.path == "/bad-request":
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        flaky_server = HTTPServer(("127.0.0.1", 0), FlakyHandler)
        f_port = flaky_server.server_address[1]
        t = threading.Thread(target=flaky_server.serve_forever, daemon=True)
        t.start()

        try:
            # 1. 503 twice then 200 on 3rd attempt
            sleeps = []
            req = urllib.request.Request(f"http://127.0.0.1:{f_port}/flaky")
            with relay_urlopen(req, backoffs=(0.01, 0.02, 0.04), sleep_fn=sleeps.append) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read(), b"success")
            self.assertEqual(attempts, 3)
            self.assertEqual(sleeps, [0.01, 0.02])

            # 2. 400 is never retried
            req_400 = urllib.request.Request(f"http://127.0.0.1:{f_port}/bad-request")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                relay_urlopen(req_400, backoffs=(0.01, 0.02, 0.04))
            self.assertEqual(cm.exception.code, 400)
            cm.exception.close()
        finally:
            flaky_server.shutdown()
            flaky_server.server_close()

    def test_responder_loop_survives_connection_error_then_exits_on_401(self):
        """Responder loop keeps retrying on connection errors/5xx and exits only on 401 after audit log."""
        poll_count = 0

        class FlakyPollHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                nonlocal poll_count
                poll_count += 1
                if poll_count == 1:
                    # Return 503 to simulate waking render service
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    # Return 401 session gone
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        poll_server = HTTPServer(("127.0.0.1", 0), FlakyPollHandler)
        p_port = poll_server.server_address[1]
        t = threading.Thread(target=poll_server.serve_forever, daemon=True)
        t.start()

        audit_path = str(self.home_dir / "audit.jsonl")
        cfg = Cfg(
            repo_root=str(self.temp_path),
            relay_url=f"http://127.0.0.1:{p_port}",
            session_b="test-session-b",
            e2e_key="test-key",
            audit_path=audit_path,
        )

        try:
            # Run responder loop; it should retry on 503, then exit on 401
            with patch("time.sleep", return_value=None):
                responder.main(cfg, once=False)

            self.assertGreaterEqual(poll_count, 2)
            self.assertTrue(os.path.exists(audit_path))
            with open(audit_path, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]
            self.assertTrue(len(lines) >= 1)
            self.assertTrue(any(
                entry.get("status") in ("session_terminated", "session_gone") or
                "401" in str(entry.get("reason", ""))
                for entry in lines
            ))
        finally:
            poll_server.shutdown()
            poll_server.server_close()

    def test_established_session_401_friendlier_message(self):
        """Friendly message when established session is rejected (401) in bridge_ask/bridge_status."""
        server = make_server(self.db_path, "127.0.0.1", 0)
        port = server.server_address[1]
        relay_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        expected_msg = (
            "The relay no longer accepts this session (revoked, expired, "
            "or the relay restarted and lost its data). Run a fresh bridge_invite and join again."
        )

        try:
            # Create net.json with expired/unknown session
            net_data = {
                "role": "A",
                "relay_url": relay_url,
                "invite_id": "nonexistent-invite",
                "poll_secret": "nonexistent-poll",
                "session_a": "invalid-session-token",
                "e2e_key": "dummy-e2e-key",
            }
            bridge.secure_jwrite(bridge.get_net_path(), net_data)

            # bridge_ask should raise the friendly message on 401
            with self.assertRaises(BridgeError) as cm_ask:
                bridge.bridge_ask("Hello?")
            self.assertEqual(str(cm_ask.exception), expected_msg)

            # bridge_status should also raise the friendly message on 401
            with self.assertRaises(BridgeError) as cm_status:
                bridge.bridge_status()
            self.assertEqual(str(cm_status.exception), expected_msg)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
