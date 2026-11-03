from __future__ import annotations
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from relay.relay import make_server


class TestRelayQueue(unittest.TestCase):
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

    def _pair(self):
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

    def test_ask_poll_answer_result_roundtrip(self):
        session_a, session_b = self._pair()

        # Poll when empty returns 204
        status, _, body = self._request(
            "GET", "/poll?wait=0.1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

        # A asks
        ask_payload = json.dumps({"q": "What is the capital of France?", "sig": "sig_q"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        ask_data = json.loads(body.decode("utf-8"))
        self.assertIn("qid", ask_data)
        qid = ask_data["qid"]
        self.assertTrue(isinstance(qid, str))
        self.assertGreater(len(qid), 8)

        # Result before answered returns 204
        status, _, body = self._request(
            "GET", f"/result/{qid}?wait=0.1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 204)

        # B polls and gets question
        status, _, body = self._request(
            "GET", "/poll?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        poll_data = json.loads(body.decode("utf-8"))
        self.assertEqual(poll_data["qid"], qid)
        self.assertEqual(poll_data["q"], "What is the capital of France?")
        self.assertEqual(poll_data["sig"], "sig_q")

        # B answers
        ans_payload = json.dumps({"qid": qid, "a": "Paris", "sig": "sig_a"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)
        ans_data = json.loads(body.decode("utf-8"))
        self.assertEqual(ans_data, {"ok": True})

        # A gets result
        status, _, body = self._request(
            "GET", f"/result/{qid}?wait=1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        res_data = json.loads(body.decode("utf-8"))
        self.assertEqual(res_data["a"], "Paris")
        self.assertEqual(res_data["sig"], "sig_a")

    def test_413_oversize(self):
        session_a, session_b = self._pair()

        # Exactly 8192 bytes (sealed cap) is allowed
        q_4096 = "a" * 8192
        payload_ok = json.dumps({"q": q_4096, "sig": "sig"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=payload_ok, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        qid = data["qid"]

        # Answer it so session is not blocked by in-flight limit
        ans_payload = json.dumps({"qid": qid, "a": "done", "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)

        # 8193 bytes exceeds limit -> 413
        q_4097 = "a" * 8193
        payload_too_big = json.dumps({"q": q_4097, "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/ask", body=payload_too_big, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 413)

    def test_429_21st_question(self):
        session_a, session_b = self._pair()

        # Send 20 questions, answering each so in-flight check passes
        for i in range(20):
            ask_payload = json.dumps({"q": f"question {i}", "sig": f"sig_{i}"}).encode("utf-8")
            status, _, body = self._request(
                "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
            )
            self.assertEqual(status, 200, f"Question {i+1} failed with status {status}")
            qid = json.loads(body.decode("utf-8"))["qid"]

            ans_payload = json.dumps({"qid": qid, "a": f"answer {i}", "sig": f"asig_{i}"}).encode("utf-8")
            status, _, _ = self._request(
                "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
            )
            self.assertEqual(status, 200)

        # 21st question in the rolling hour -> 429
        ask_payload_21 = json.dumps({"q": "question 21", "sig": "sig_21"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/ask", body=ask_payload_21, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 429)

        # Advance clock by 1 hour + 1 second
        self.current_time += 3601.0
        # Now asking should succeed again
        status, _, _ = self._request(
            "POST", "/ask", body=ask_payload_21, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)

    def test_409_second_inflight(self):
        session_a, session_b = self._pair()

        # First question
        ask_payload_1 = json.dumps({"q": "first question", "sig": "sig1"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload_1, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        qid_1 = json.loads(body.decode("utf-8"))["qid"]

        # Second question while first is unanswered -> 409
        ask_payload_2 = json.dumps({"q": "second question", "sig": "sig2"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/ask", body=ask_payload_2, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 409)

        # Answer first question
        ans_payload = json.dumps({"qid": qid_1, "a": "answer 1", "sig": "asig1"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)

        # Now second question succeeds -> 200
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload_2, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)

    def test_wrong_role_403(self):
        session_a, session_b = self._pair()

        # A asks a question
        ask_a = json.dumps({"q": "from A", "sig": "sig"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_a, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        qid_a = json.loads(body.decode("utf-8"))["qid"]

        # A cannot call /answer on its own question -> 403
        ans_a = json.dumps({"qid": qid_a, "a": "ans", "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_a, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 403)

        # B cannot call /result on A's question -> 403
        status, _, _ = self._request(
            "GET", f"/result/{qid_a}?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 403)

    def test_revoke_during_waiting_poll_returns_401(self):
        session_a, session_b = self._pair()
        poll_result = {}

        def do_poll():
            t0 = time.time()
            status, headers, body = self._request(
                "GET", "/poll?wait=2", headers={"Authorization": f"Bearer {session_b}"}
            )
            elapsed = time.time() - t0
            poll_result["status"] = status
            poll_result["elapsed"] = elapsed
            poll_result["body"] = body

        thread = threading.Thread(target=do_poll)
        thread.start()

        # Give thread a moment to enter wait
        time.sleep(0.1)

        # Revoke from A
        status, _, body = self._request(
            "POST", "/revoke", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)

        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(poll_result.get("status"), 401)
        self.assertLess(poll_result.get("elapsed", 999), 1.5)

    def test_session_expires_after_8h(self):
        session_a, session_b = self._pair()
        # Advance clock by 8 hours + 1 second
        self.current_time += 8 * 3600.0 + 1.0

        # Ask fails with 401
        ask_payload = json.dumps({"q": "hi", "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 401)

        # Poll fails with 401
        status, _, _ = self._request(
            "GET", "/poll?wait=1", headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 401)

        # Answer fails with 401
        ans_payload = json.dumps({"qid": "test_qid", "a": "hi", "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 401)

        # Result fails with 401
        status, _, _ = self._request(
            "GET", "/result/test_qid?wait=1", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 401)

    def test_poll_waits_and_unblocks_on_ask(self):
        session_a, session_b = self._pair()
        poll_res = {}

        def do_poll():
            t0 = time.time()
            status, _, body = self._request(
                "GET", "/poll?wait=2", headers={"Authorization": f"Bearer {session_b}"}
            )
            poll_res["status"] = status
            poll_res["body"] = body
            poll_res["elapsed"] = time.time() - t0

        t = threading.Thread(target=do_poll)
        t.start()
        time.sleep(0.1)

        ask_payload = json.dumps({"q": "delayed q", "sig": "sig_delayed"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        qid = json.loads(body.decode("utf-8"))["qid"]

        t.join(timeout=3.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(poll_res.get("status"), 200)
        data = json.loads(poll_res["body"].decode("utf-8"))
        self.assertEqual(data["qid"], qid)
        self.assertLess(poll_res.get("elapsed", 999), 1.5)

    def test_result_waits_and_unblocks_on_answer(self):
        session_a, session_b = self._pair()
        ask_payload = json.dumps({"q": "delayed q", "sig": "sig_delayed"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        qid = json.loads(body.decode("utf-8"))["qid"]

        result_res = {}

        def do_result():
            t0 = time.time()
            status, _, body = self._request(
                "GET", f"/result/{qid}?wait=2", headers={"Authorization": f"Bearer {session_a}"}
            )
            result_res["status"] = status
            result_res["body"] = body
            result_res["elapsed"] = time.time() - t0

        t = threading.Thread(target=do_result)
        t.start()
        time.sleep(0.1)

        ans_payload = json.dumps({"qid": qid, "a": "delayed answer", "sig": "sig_ans"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)

        t.join(timeout=3.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(result_res.get("status"), 200)
        data = json.loads(result_res["body"].decode("utf-8"))
        self.assertEqual(data["a"], "delayed answer")
        self.assertEqual(data["sig"], "sig_ans")
        self.assertLess(result_res.get("elapsed", 999), 1.5)

    def test_nonexistent_and_duplicate_answer(self):
        session_a, session_b = self._pair()

        # Answering non-existent question -> 404
        ans_payload = json.dumps({"qid": "nonexistent_qid", "a": "answer", "sig": "sig"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 404)

        # Getting result for non-existent question -> 404
        status, _, _ = self._request(
            "GET", "/result/nonexistent_qid", headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 404)

        # Ask a real question
        ask_payload = json.dumps({"q": "test q", "sig": "sig"}).encode("utf-8")
        status, _, body = self._request(
            "POST", "/ask", body=ask_payload, headers={"Authorization": f"Bearer {session_a}"}
        )
        self.assertEqual(status, 200)
        qid = json.loads(body.decode("utf-8"))["qid"]

        # First answer -> 200
        ans_payload = json.dumps({"qid": qid, "a": "ans1", "sig": "sig1"}).encode("utf-8")
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 200)

        # Duplicate answer -> 409
        status, _, _ = self._request(
            "POST", "/answer", body=ans_payload, headers={"Authorization": f"Bearer {session_b}"}
        )
        self.assertEqual(status, 409)

    def test_unauthenticated_requests(self):
        # Missing Authorization
        status, _, _ = self._request("POST", "/ask", body=b'{"q": "hi", "sig": "s"}')
        self.assertEqual(status, 401)

        status, _, _ = self._request("GET", "/poll")
        self.assertEqual(status, 401)

        status, _, _ = self._request("POST", "/answer", body=b'{"qid": "1", "a": "hi", "sig": "s"}')
        self.assertEqual(status, 401)

        status, _, _ = self._request("GET", "/result/some_qid")
        self.assertEqual(status, 401)

        # Bogus Bearer token
        status, _, _ = self._request(
            "POST", "/ask", body=b'{"q": "hi", "sig": "s"}', headers={"Authorization": "Bearer bogus_token"}
        )
        self.assertEqual(status, 401)
