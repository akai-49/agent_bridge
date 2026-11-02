from __future__ import annotations
import http.client
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest

from relay.relay import make_server
from server.responder import Cfg, handle
from server.wire import a_tag, other, q_tag, sign, verify


class FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestBidirProtocol(unittest.TestCase):
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
        self.e2e_key = "test_shared_e2e_key_12345"

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

    def _pair(self) -> tuple[str, str]:
        status, _, body = self._request("POST", "/invite", body=b"{}")
        self.assertEqual(status, 200)
        invite = json.loads(body.decode("utf-8"))
        join_payload = json.dumps({
            "invite_id": invite["invite_id"],
            "join_secret": invite["join_secret"],
        }).encode("utf-8")
        status, _, body = self._request(
            "POST", "/join", body=join_payload, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        session_b = json.loads(body.decode("utf-8"))["session_b"]
        status, _, body = self._request(
            "GET",
            f"/session?invite_id={invite['invite_id']}",
            headers={"X-Poll-Secret": invite["poll_secret"]},
        )
        self.assertEqual(status, 200)
        session_a = json.loads(body.decode("utf-8"))["session_a"]
        return session_a, session_b

    def test_b_can_ask_a_can_answer(self):
        """B can ask a question and A can answer it over the relay."""
        session_a, session_b = self._pair()

        # B asks question signed with q_tag("B")
        q_text = "What is function bar() doing?"
        q_sig = sign(self.e2e_key, q_tag("B"), q_text)
        ask_payload = json.dumps({"q": q_text, "sig": q_sig}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        ask_data = json.loads(body.decode("utf-8"))
        self.assertIn("qid", ask_data)
        qid = ask_data["qid"]

        # A polls and receives the question with asker="B"
        status, _, body = self._request(
            "GET", "/poll?wait=1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        poll_data = json.loads(body.decode("utf-8"))
        self.assertEqual(poll_data["qid"], qid)
        self.assertEqual(poll_data["asker"], "B")
        self.assertEqual(poll_data["q"], q_text)
        self.assertEqual(poll_data["sig"], q_sig)
        self.assertTrue(verify(self.e2e_key, q_tag("B"), poll_data["q"], poll_data["sig"]))

        # A answers question signed with a_tag("B", qid)
        ans_text = "It performs bar operations."
        ans_sig = sign(self.e2e_key, a_tag("B", qid), ans_text)
        ans_payload = json.dumps({"qid": qid, "a": ans_text, "sig": ans_sig}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)

        # B retrieves result and verifies with a_tag("B", qid)
        status, _, body = self._request(
            "GET", f"/result/{qid}?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        res_data = json.loads(body.decode("utf-8"))
        self.assertEqual(res_data["a"], ans_text)
        self.assertEqual(res_data["sig"], ans_sig)
        self.assertTrue(verify(self.e2e_key, a_tag("B", qid), res_data["a"], res_data["sig"]))

    def test_both_directions_concurrently_do_not_block_each_other(self):
        """A and B each have one in-flight question concurrently without blocking."""
        session_a, session_b = self._pair()

        # A asks Q1
        q1_text = "Q1 from A"
        q1_sig = sign(self.e2e_key, q_tag("A"), q1_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q1_text, "sig": q1_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)
        qid1 = json.loads(body.decode("utf-8"))["qid"]

        # B asks Q2 concurrently
        q2_text = "Q2 from B"
        q2_sig = sign(self.e2e_key, q_tag("B"), q2_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q2_text, "sig": q2_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)
        qid2 = json.loads(body.decode("utf-8"))["qid"]

        # Second question from A while Q1 is unanswered -> 409
        status, _, _ = self._request(
            "POST", "/ask", body=json.dumps({"q": "A another", "sig": "sig"}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 409)

        # Second question from B while Q2 is unanswered -> 409
        status, _, _ = self._request(
            "POST", "/ask", body=json.dumps({"q": "B another", "sig": "sig"}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 409)

        # B polls and receives Q1 (from A)
        status, _, body = self._request(
            "GET", "/poll?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        poll_b = json.loads(body.decode("utf-8"))
        self.assertEqual(poll_b["qid"], qid1)
        self.assertEqual(poll_b["asker"], "A")

        # A polls and receives Q2 (from B)
        status, _, body = self._request(
            "GET", "/poll?wait=1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        poll_a = json.loads(body.decode("utf-8"))
        self.assertEqual(poll_a["qid"], qid2)
        self.assertEqual(poll_a["asker"], "B")

        # B answers Q1
        ans1_text = "Ans to Q1"
        ans1_sig = sign(self.e2e_key, a_tag("A", qid1), ans1_text)
        status, _, _ = self._request(
            "POST", "/answer", body=json.dumps({"qid": qid1, "a": ans1_text, "sig": ans1_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)

        # A answers Q2
        ans2_text = "Ans to Q2"
        ans2_sig = sign(self.e2e_key, a_tag("B", qid2), ans2_text)
        status, _, _ = self._request(
            "POST", "/answer", body=json.dumps({"qid": qid2, "a": ans2_text, "sig": ans2_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)

        # A gets Q1 result
        status, _, body = self._request(
            "GET", f"/result/{qid1}?wait=1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8"))["a"], ans1_text)

        # B gets Q2 result
        status, _, body = self._request(
            "GET", f"/result/{qid2}?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8"))["a"], ans2_text)

    def test_poll_never_returns_own_question(self):
        """GET /poll never returns a question asked by the caller's role."""
        session_a, session_b = self._pair()

        # A asks a question
        q1_text = "Question from A"
        q1_sig = sign(self.e2e_key, q_tag("A"), q1_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q1_text, "sig": q1_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)
        qid1 = json.loads(body.decode("utf-8"))["qid"]

        # A polls -> 204 No Content (must not get its own question)
        status, _, body = self._request(
            "GET", "/poll?wait=0.1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 204)

        # B polls -> gets Q1
        status, _, body = self._request(
            "GET", "/poll?wait=0.1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8"))["qid"], qid1)

        # Answer Q1 so queue is clear
        self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid1, "a": "A1", "sig": sign(self.e2e_key, a_tag("A", qid1), "A1")}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )

        # B asks a question
        q2_text = "Question from B"
        q2_sig = sign(self.e2e_key, q_tag("B"), q2_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q2_text, "sig": q2_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)
        qid2 = json.loads(body.decode("utf-8"))["qid"]

        # B polls -> 204 No Content (must not get its own question)
        status, _, body = self._request(
            "GET", "/poll?wait=0.1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 204)

        # A polls -> gets Q2
        status, _, body = self._request(
            "GET", "/poll?wait=0.1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8"))["qid"], qid2)

    def test_cannot_answer_own_question_403(self):
        """Role R attempting to answer a question with asker == R receives 403."""
        session_a, session_b = self._pair()

        # A asks a question
        q1_text = "A's question"
        q1_sig = sign(self.e2e_key, q_tag("A"), q1_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q1_text, "sig": q1_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)
        qid1 = json.loads(body.decode("utf-8"))["qid"]

        # A attempts to answer its own question -> 403
        status, _, _ = self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid1, "a": "self ans", "sig": "sig"}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 403)

        # B answers A's question -> 200
        status, _, _ = self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid1, "a": "B ans", "sig": sign(self.e2e_key, a_tag("A", qid1), "B ans")}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)

        # B asks a question
        q2_text = "B's question"
        q2_sig = sign(self.e2e_key, q_tag("B"), q2_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q2_text, "sig": q2_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)
        qid2 = json.loads(body.decode("utf-8"))["qid"]

        # B attempts to answer its own question -> 403
        status, _, _ = self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid2, "a": "self ans", "sig": "sig"}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 403)

    def test_only_asker_can_read_result_403(self):
        """GET /result/<qid> returns 403 if requested by a role other than the asker."""
        session_a, session_b = self._pair()

        # A asks a question
        q1_text = "A's question"
        q1_sig = sign(self.e2e_key, q_tag("A"), q1_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q1_text, "sig": q1_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)
        qid1 = json.loads(body.decode("utf-8"))["qid"]

        # B attempts to read result -> 403
        status, _, _ = self._request(
            "GET", f"/result/{qid1}", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 403)

        # B answers A's question
        self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid1, "a": "ans", "sig": sign(self.e2e_key, a_tag("A", qid1), "ans")}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )

        # B still gets 403
        status, _, _ = self._request(
            "GET", f"/result/{qid1}", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 403)

        # A gets 200
        status, _, body = self._request(
            "GET", f"/result/{qid1}", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)

        # B asks a question
        q2_text = "B's question"
        q2_sig = sign(self.e2e_key, q_tag("B"), q2_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": q2_text, "sig": q2_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)
        qid2 = json.loads(body.decode("utf-8"))["qid"]

        # A attempts to read result of B's question -> 403
        status, _, _ = self._request(
            "GET", f"/result/{qid2}", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 403)

    def test_limits_are_per_asker(self):
        """Hourly rate limit (20/hour) is per asker; A maxed out doesn't block B from asking/being answered."""
        session_a, session_b = self._pair()

        # A asks and B answers 20 questions
        for i in range(20):
            q_text = f"q_{i}"
            q_sig = sign(self.e2e_key, q_tag("A"), q_text)
            status, _, body = self._request(
                "POST", "/ask", body=json.dumps({"q": q_text, "sig": q_sig}).encode("utf-8"),
                headers={"Authorization": f"Bearer {session_a}"},
            )
            self.assertEqual(status, 200)
            qid = json.loads(body.decode("utf-8"))["qid"]

            ans_sig = sign(self.e2e_key, a_tag("A", qid), f"a_{i}")
            status, _, _ = self._request(
                "POST", "/answer",
                body=json.dumps({"qid": qid, "a": f"a_{i}", "sig": ans_sig}).encode("utf-8"),
                headers={"Authorization": f"Bearer {session_b}"},
            )
            self.assertEqual(status, 200)

        # A's 21st question fails with 429
        q_text_21 = "q_21"
        q_sig_21 = sign(self.e2e_key, q_tag("A"), q_text_21)
        status, _, _ = self._request(
            "POST", "/ask", body=json.dumps({"q": q_text_21, "sig": q_sig_21}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 429)

        # B has independent limit: B asks a question -> 200 OK
        qb_text = "qb_1"
        qb_sig = sign(self.e2e_key, q_tag("B"), qb_text)
        status, _, body = self._request(
            "POST", "/ask", body=json.dumps({"q": qb_text, "sig": qb_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_b}"},
        )
        self.assertEqual(status, 200)
        qid_b = json.loads(body.decode("utf-8"))["qid"]

        # A can answer B's question
        ans_b_sig = sign(self.e2e_key, a_tag("B", qid_b), "ans_from_a")
        status, _, _ = self._request(
            "POST", "/answer",
            body=json.dumps({"qid": qid_b, "a": "ans_from_a", "sig": ans_b_sig}).encode("utf-8"),
            headers={"Authorization": f"Bearer {session_a}"},
        )
        self.assertEqual(status, 200)

        # B can read result
        status, _, body = self._request(
            "GET", f"/result/{qid_b}", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8"))["a"], "ans_from_a")

    def test_reflected_question_rejected_by_responder(self):
        """Question signed with the responder's own role's q_tag is dropped and audit-logged."""
        audit_path = str(Path(self.temp_dir.name) / "audit_reflect.jsonl")
        repo_dir = str(Path(self.temp_dir.name) / "repo")
        Path(repo_dir).mkdir(parents=True, exist_ok=True)

        # Responder has role B; peer is A
        cfg = Cfg(
            repo_root=repo_dir,
            relay_url=f"http://127.0.0.1:{self.port}",
            session="token_b",
            e2e_key=self.e2e_key,
            audit_path=audit_path,
            role="B",
        )

        runner_called = False

        def fake_runner(cmd, **kwargs):
            nonlocal runner_called
            runner_called = True
            return FakeCompletedProcess(stdout="should not run")

        # Reflected question: signed with q_tag("B") (responder's own role) instead of q_tag("A")
        q_refl = "reflected question text"
        refl_sig = sign(self.e2e_key, q_tag("B"), q_refl)
        msg = {
            "qid": "q_reflect_1",
            "asker": "B",
            "q": q_refl,
            "sig": refl_sig,
        }

        result = handle(msg, cfg, runner=fake_runner)
        self.assertIsNone(result)
        self.assertFalse(runner_called)

        # Check audit log for rejection
        with open(audit_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event"], "rejected")
        self.assertEqual(lines[0]["reason"], "invalid_signature")

    def test_question_echoed_as_answer_rejected(self):
        """Verify with a_tag fails if a question signature is echoed as an answer."""
        qid = "qid_echo_1"
        q_text = "Echo me"
        q_sig = sign(self.e2e_key, q_tag("A"), q_text)

        # Attempting to verify the question as an answer to A fails
        self.assertFalse(verify(self.e2e_key, a_tag("A", qid), q_text, q_sig))

        # Attempting to verify an answer for B when expecting answer for A fails
        ans_for_b = sign(self.e2e_key, a_tag("B", qid), "answer text")
        self.assertFalse(verify(self.e2e_key, a_tag("A", qid), "answer text", ans_for_b))

        # Valid answer for A verifies correctly
        ans_for_a = sign(self.e2e_key, a_tag("A", qid), "answer text")
        self.assertTrue(verify(self.e2e_key, a_tag("A", qid), "answer text", ans_for_a))

    def test_old_db_migrates(self):
        """Starting relay on a DB with the old schema (no asker column) migrates idempotently and allows asking."""
        old_db_path = str(Path(self.temp_dir.name) / "old_relay.db")
        conn = sqlite3.connect(old_db_path)
        conn.execute("""
            CREATE TABLE invites (
                invite_id TEXT PRIMARY KEY,
                join_secret_hash TEXT NOT NULL,
                poll_secret_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            );
        """)
        conn.execute("""
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_id TEXT NOT NULL,
                session_a TEXT NOT NULL,
                session_a_hash TEXT NOT NULL,
                session_b_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
        """)
        # Old questions table without 'asker' column
        conn.execute("""
            CREATE TABLE questions (
                qid TEXT PRIMARY KEY,
                session_id INTEGER NOT NULL,
                q TEXT NOT NULL,
                q_sig TEXT NOT NULL,
                a TEXT,
                a_sig TEXT,
                created_at REAL NOT NULL,
                answered_at REAL
            );
        """)
        # Insert a pre-existing question under old schema
        conn.execute(
            "INSERT INTO questions (qid, session_id, q, q_sig, created_at) VALUES ('old_q', 1, 'old', 'sig', 1.0)"
        )
        conn.commit()
        conn.close()

        # Start relay server using old_db_path -> triggers init_db and migration
        server2 = make_server(old_db_path, "127.0.0.1", 0)
        port2 = server2.server_address[1]
        t2 = threading.Thread(target=lambda: server2.serve_forever(poll_interval=0.05), daemon=True)
        t2.start()

        try:
            # Check DB schema: asker column should exist, and pre-existing row defaulted to 'A'
            c2 = sqlite3.connect(old_db_path)
            c2.row_factory = sqlite3.Row
            row = c2.execute("SELECT * FROM questions WHERE qid = 'old_q'").fetchone()
            self.assertEqual(row["asker"], "A")
            c2.close()

            # Pair and ask a question on this server
            conn_http = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
            conn_http.request("POST", "/invite", body=b"{}")
            invite = json.loads(conn_http.getresponse().read().decode("utf-8"))
            conn_http.close()

            conn_http = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
            join_body = json.dumps({"invite_id": invite["invite_id"], "join_secret": invite["join_secret"]}).encode()
            conn_http.request("POST", "/join", body=join_body, headers={"Content-Type": "application/json"})
            sess_b = json.loads(conn_http.getresponse().read().decode("utf-8"))["session_b"]
            conn_http.close()

            conn_http = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
            conn_http.request("GET", f"/session?invite_id={invite['invite_id']}", headers={"X-Poll-Secret": invite["poll_secret"]})
            sess_a = json.loads(conn_http.getresponse().read().decode("utf-8"))["session_a"]
            conn_http.close()

            # B asks on migrated DB
            conn_http = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
            ask_body = json.dumps({"q": "new question on migrated db", "sig": "sig_new"}).encode()
            conn_http.request("POST", "/ask", body=ask_body, headers={"Authorization": f"Bearer {sess_b}"})
            resp = conn_http.getresponse()
            self.assertEqual(resp.status, 200)
            qid_new = json.loads(resp.read().decode("utf-8"))["qid"]
            conn_http.close()

            # Verify in DB that asker is 'B'
            c2 = sqlite3.connect(old_db_path)
            c2.row_factory = sqlite3.Row
            row_new = c2.execute("SELECT * FROM questions WHERE qid = ?", (qid_new,)).fetchone()
            self.assertEqual(row_new["asker"], "B")
            c2.close()
        finally:
            server2.shutdown()
            server2.server_close()


if __name__ == "__main__":
    unittest.main()
