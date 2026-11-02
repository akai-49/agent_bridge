from __future__ import annotations
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from relay.relay import make_server


class TestRelayPairing(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_relay.db")
        self.current_time = 1_700_000_000.0

        def fake_clock():
            return self.current_time

        self.clock = fake_clock
        self.server = make_server(self.db_path, "127.0.0.1", 0, clock=self.clock)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05),
            daemon=True,
        )
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.temp_dir.cleanup()

    def _request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        req_headers = headers.copy() if headers else {}
        if body is not None and "Content-Length" not in req_headers:
            req_headers["Content-Length"] = str(len(body))
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        conn.close()
        return resp.status, resp.headers, resp_body

    def test_join_ok_then_replay_409(self):
        # 1. Invite
        status, _, body = self._request("POST", "/invite", body=b"{}", headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        invite_data = json.loads(body.decode("utf-8"))
        invite_id = invite_data["invite_id"]
        join_secret = invite_data["join_secret"]
        self.assertIn("poll_secret", invite_data)

        # 2. Join (first time -> 200 with session_b)
        join_payload = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
        status, _, body = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        join_data = json.loads(body.decode("utf-8"))
        self.assertIn("session_b", join_data)
        self.assertTrue(isinstance(join_data["session_b"], str))
        self.assertGreater(len(join_data["session_b"]), 20)

        # 3. Join again (replay -> 409 Conflict)
        status, _, _ = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 409)

    def test_join_expired_401_after_15min(self):
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite_data = json.loads(body.decode("utf-8"))
        invite_id = invite_data["invite_id"]
        join_secret = invite_data["join_secret"]

        # Advance time by 15 min + 1 second (901 seconds)
        self.current_time += 901.0

        join_payload = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
        status, _, _ = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)

    def test_join_wrong_secret_401_same_body_as_expired(self):
        # 1. Trigger expired join
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite1 = json.loads(body.decode("utf-8"))
        self.current_time += 901.0
        join_expired_payload = json.dumps({
            "invite_id": invite1["invite_id"],
            "join_secret": invite1["join_secret"],
        }).encode("utf-8")
        status_expired, _, body_expired = self._request(
            "POST", "/join", body=join_expired_payload, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status_expired, 401)

        # 2. Trigger wrong secret join (on fresh invite)
        self.current_time += 10.0
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite2 = json.loads(body.decode("utf-8"))
        join_wrong_payload = json.dumps({
            "invite_id": invite2["invite_id"],
            "join_secret": "wrong_secret_value",
        }).encode("utf-8")
        status_wrong, _, body_wrong = self._request(
            "POST", "/join", body=join_wrong_payload, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status_wrong, 401)

        # 3. Trigger unknown invite join
        join_unknown_payload = json.dumps({
            "invite_id": "inv_non_existent_id",
            "join_secret": invite2["join_secret"],
        }).encode("utf-8")
        status_unknown, _, body_unknown = self._request(
            "POST", "/join", body=join_unknown_payload, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status_unknown, 401)

        # Failure bodies must be byte-identical
        self.assertEqual(body_expired, body_wrong)
        self.assertEqual(body_wrong, body_unknown)

    def test_session_requires_poll_secret(self):
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite = json.loads(body.decode("utf-8"))
        invite_id = invite["invite_id"]
        join_secret = invite["join_secret"]
        poll_secret = invite["poll_secret"]

        # Missing header -> 401
        status, _, _ = self._request("GET", f"/session?invite_id={invite_id}")
        self.assertEqual(status, 401)

        # Wrong header -> 401
        status, _, _ = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": "wrong_secret"}
        )
        self.assertEqual(status, 401)

        # Correct header before join -> 204 No Content
        status, _, body = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": poll_secret}
        )
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

        # Join occurs
        join_payload = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
        status, _, _ = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)

        # Correct header after join -> 200 OK with session_a
        status, _, body = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": poll_secret}
        )
        self.assertEqual(status, 200)
        sess_data = json.loads(body.decode("utf-8"))
        self.assertIn("session_a", sess_data)
        self.assertTrue(isinstance(sess_data["session_a"], str))
        self.assertGreater(len(sess_data["session_a"]), 20)

    def test_db_holds_only_hashes(self):
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite = json.loads(body.decode("utf-8"))
        invite_id = invite["invite_id"]
        join_secret = invite["join_secret"]
        poll_secret = invite["poll_secret"]

        # Perform join to mint session_b
        join_payload = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
        status, _, body = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        session_b = json.loads(body.decode("utf-8"))["session_b"]

        # Fetch session_a
        status, _, body = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": poll_secret}
        )
        self.assertEqual(status, 200)

        # Read db bytes (including wal file if present)
        db_bytes = Path(self.db_path).read_bytes()
        wal_path = Path(self.db_path + "-wal")
        if wal_path.exists():
            db_bytes += wal_path.read_bytes()

        # Plaintext secrets must not be in the database bytes
        self.assertNotIn(join_secret.encode("utf-8"), db_bytes)
        self.assertNotIn(poll_secret.encode("utf-8"), db_bytes)
        self.assertNotIn(session_b.encode("utf-8"), db_bytes)

        # Hashes MUST be present in the database bytes
        expected_join_hash = hashlib.sha256(join_secret.encode("utf-8")).hexdigest().encode("utf-8")
        expected_poll_hash = hashlib.sha256(poll_secret.encode("utf-8")).hexdigest().encode("utf-8")
        expected_session_b_hash = hashlib.sha256(session_b.encode("utf-8")).hexdigest().encode("utf-8")

        self.assertIn(expected_join_hash, db_bytes)
        self.assertIn(expected_poll_hash, db_bytes)
        self.assertIn(expected_session_b_hash, db_bytes)

    def test_revoke_kills_both(self):
        # Case 1: session_a revokes -> kills both session_a and session_b
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite = json.loads(body.decode("utf-8"))
        invite_id = invite["invite_id"]
        join_secret = invite["join_secret"]
        poll_secret = invite["poll_secret"]

        join_payload = json.dumps({"invite_id": invite_id, "join_secret": join_secret}).encode("utf-8")
        status, _, body = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        session_b = json.loads(body.decode("utf-8"))["session_b"]

        status, _, body = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": poll_secret}
        )
        self.assertEqual(status, 200)
        session_a = json.loads(body.decode("utf-8"))["session_a"]

        # Revoke using session_a
        status, _, body = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"ok": True})

        # session_a calling revoke again -> 401
        status, _, _ = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 401)

        # session_b calling revoke -> 401 (killed as well)
        status, _, _ = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 401)

        # GET /session after revocation -> 401
        status, _, _ = self._request(
            "GET", f"/session?invite_id={invite_id}", headers={"X-Poll-Secret": poll_secret}
        )
        self.assertEqual(status, 401)

        # Case 2: fresh pair, revoke using session_b -> kills session_a too
        status, _, body = self._request("POST", "/invite", body=b"{}")
        invite2 = json.loads(body.decode("utf-8"))
        join_payload2 = json.dumps({"invite_id": invite2["invite_id"], "join_secret": invite2["join_secret"]}).encode("utf-8")
        status, _, body = self._request("POST", "/join", body=join_payload2, headers={"Content-Type": "application/json"})
        session_b2 = json.loads(body.decode("utf-8"))["session_b"]
        status, _, body = self._request(
            "GET", f"/session?invite_id={invite2['invite_id']}", headers={"X-Poll-Secret": invite2["poll_secret"]}
        )
        session_a2 = json.loads(body.decode("utf-8"))["session_a"]

        # Revoke using session_b2
        status, _, body = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_b2}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"ok": True})

        # session_a2 calling revoke -> 401
        status, _, _ = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_a2}"}
        )
        self.assertEqual(status, 401)

    def test_session_expiry_after_8h(self):
        status, _, body = self._request("POST", "/invite", body=b"{}")
        invite = json.loads(body.decode("utf-8"))
        join_payload = json.dumps({"invite_id": invite["invite_id"], "join_secret": invite["join_secret"]}).encode("utf-8")
        status, _, body = self._request("POST", "/join", body=join_payload, headers={"Content-Type": "application/json"})
        session_b = json.loads(body.decode("utf-8"))["session_b"]
        status, _, body = self._request(
            "GET", f"/session?invite_id={invite['invite_id']}", headers={"X-Poll-Secret": invite["poll_secret"]}
        )
        session_a = json.loads(body.decode("utf-8"))["session_a"]

        # Advance clock by 8 hours + 1 second (28801 seconds)
        self.current_time += 28801.0

        # /session -> 401 expired
        status, _, _ = self._request(
            "GET", f"/session?invite_id={invite['invite_id']}", headers={"X-Poll-Secret": invite["poll_secret"]}
        )
        self.assertEqual(status, 401)

        # /revoke -> 401 expired
        status, _, _ = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
