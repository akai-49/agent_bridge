from __future__ import annotations
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from relay.relay import make_server, validate_bind


class OpenRelayBase(unittest.TestCase):
    key = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "r.db")
        self.now = 1_700_000_000.0
        self.server = make_server(self.db, "127.0.0.1", 0, clock=lambda: self.now, relay_key=self.key)
        self.port = self.server.server_address[1]
        threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def req(self, method, path, body=b"{}", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        h["Content-Length"] = str(len(body))
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def invite(self, headers=None):
        st, data = self.req("POST", "/invite", headers=headers)
        return st, (json.loads(data) if st == 200 else {})

    def join(self, inv, headers=None):
        body = json.dumps({"invite_id": inv["invite_id"], "join_secret": inv["join_secret"]}).encode()
        return self.req("POST", "/join", body, headers)


class TestOpenMode(OpenRelayBase):
    def test_invite_without_key_when_none_configured(self):
        self.assertEqual(self.invite()[0], 200)

    def test_validate_bind(self):
        self.assertIsNotNone(validate_bind("0.0.0.0", None, False))
        self.assertIsNone(validate_bind("0.0.0.0", None, True))
        self.assertIsNone(validate_bind("0.0.0.0", "k", False))
        self.assertIsNone(validate_bind("127.0.0.1", None, False))

    def test_invite_per_ip_limit_slides(self):
        self.server.invites_per_ip_hour = 3
        for _ in range(3):
            self.assertEqual(self.invite()[0], 200)
        self.assertEqual(self.invite()[0], 429)
        self.now += 3601
        self.assertEqual(self.invite()[0], 200)

    def test_proxy_header_rightmost_only_when_trusted(self):
        self.server.invites_per_ip_hour = 1
        # not trusted: header ignored, same peer ip -> second is limited even with different XFF
        self.assertEqual(self.invite({"X-Forwarded-For": "1.1.1.1"})[0], 200)
        self.assertEqual(self.invite({"X-Forwarded-For": "2.2.2.2"})[0], 429)
        self.now += 3601
        self.server.trust_proxy = True
        self.assertEqual(self.invite({"X-Forwarded-For": "6.6.6.6, 9.9.9.9"})[0], 200)
        # spoofed leftmost differs but rightmost (proxy-added) is the same -> limited
        self.assertEqual(self.invite({"X-Forwarded-For": "7.7.7.7, 9.9.9.9"})[0], 429)
        self.assertEqual(self.invite({"X-Forwarded-For": "7.7.7.7, 8.8.8.8"})[0], 200)

    def test_join_fail_limit(self):
        self.server.join_fails_per_ip_hour = 3
        bad = json.dumps({"invite_id": "nope", "join_secret": "x"}).encode()
        for _ in range(3):
            self.assertEqual(self.req("POST", "/join", bad)[0], 401)
        self.assertEqual(self.req("POST", "/join", bad)[0], 429)

    def test_pending_invite_cap(self):
        self.server.max_pending_invites = 2
        self.server.invites_per_ip_hour = 100
        self.assertEqual(self.invite()[0], 200)
        self.assertEqual(self.invite()[0], 200)
        self.assertEqual(self.invite()[0], 503)

    def test_session_cap(self):
        self.server.max_sessions = 1
        self.server.invites_per_ip_hour = 100
        _, inv = self.invite()
        self.assertEqual(self.join(inv)[0], 200)
        self.assertEqual(self.invite()[0], 503)

    def test_purge_removes_expired_keeps_live(self):
        self.server.invites_per_ip_hour = 100
        _, old = self.invite()
        _, old2 = self.invite()
        self.join(old2)
        self.now += 9 * 3600
        _, live = self.invite()
        self.server.purge()
        conn = sqlite3.connect(self.db)
        ids = [r[0] for r in conn.execute("SELECT invite_id FROM invites")]
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        conn.close()
        self.assertEqual(ids, [live["invite_id"]])
        self.assertEqual(sessions, 0)

    def test_oversize_body_413(self):
        st, _ = self.req("POST", "/invite", b"x" * (300 * 1024))
        self.assertEqual(st, 413)


class TestKeyStillEnforced(OpenRelayBase):
    key = "sekret"

    def test_wrong_key_401_right_key_200(self):
        self.assertEqual(self.invite()[0], 401)
        self.assertEqual(self.invite({"X-Relay-Key": "wrong"})[0], 401)
        self.assertEqual(self.invite({"X-Relay-Key": "sekret"})[0], 200)


if __name__ == "__main__":
    unittest.main()
