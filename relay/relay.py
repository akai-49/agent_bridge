"""claude-bridge relay server.

Handles pairing flow (/invite, /join, /session, /revoke) and routing.
Uses stdlib ThreadingHTTPServer, sqlite3 (WAL mode, per-request connection),
and SHA-256 hashed secrets.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from typing import Any, Callable
import urllib.parse

# Join failure responses for unknown-invite, wrong-secret, and expired must be byte-identical.
JOIN_FAILED_BODY = b'{"error": "invalid_or_expired_invite"}\n'

INVITE_TTL_SECONDS = 15 * 60.0  # 15 minutes
SESSION_TTL_SECONDS = 8 * 3600.0  # 8 hours


def hash_secret(secret: str) -> str:
    """Return SHA-256 hex digest of secret string."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a new per-request SQLite connection with WAL mode and row factory."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Initialize SQLite database tables for invites and sessions."""
    conn = get_db_connection(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS invites (
                invite_id TEXT PRIMARY KEY,
                join_secret_hash TEXT NOT NULL,
                poll_secret_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_id TEXT NOT NULL,
                session_a TEXT NOT NULL,
                session_a_hash TEXT NOT NULL,
                session_b_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (invite_id) REFERENCES invites (invite_id)
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_a ON sessions(session_a_hash);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_b ON sessions(session_b_hash);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                qid TEXT PRIMARY KEY,
                session_id INTEGER NOT NULL,
                asker TEXT NOT NULL DEFAULT 'A',
                q TEXT NOT NULL,
                q_sig TEXT NOT NULL,
                a TEXT,
                a_sig TEXT,
                created_at REAL NOT NULL,
                answered_at REAL,
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            );
        """)
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(questions);").fetchall()]
        if "asker" not in cols:
            conn.execute("ALTER TABLE questions ADD COLUMN asker TEXT NOT NULL DEFAULT 'A';")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_questions_session ON questions(session_id);")
        conn.commit()
    finally:
        conn.close()


class RelayServer(ThreadingHTTPServer):
    """Threaded HTTP server holding relay database configuration and clock."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        db_path: str,
        clock: Callable[[], float] = time.time,
        relay_key: str | None = None,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.db_path = db_path
        self.clock = clock
        self.relay_key = relay_key if relay_key is not None else os.environ.get("RELAY_KEY")
        self.conditions: dict[int, threading.Condition] = {}
        self.conditions_lock = threading.Lock()
        self.shutting_down = False

    def get_condition(self, session_id: int) -> threading.Condition:
        with self.conditions_lock:
            if session_id not in self.conditions:
                self.conditions[session_id] = threading.Condition()
            return self.conditions[session_id]

    def shutdown(self) -> None:
        self.shutting_down = True
        with self.conditions_lock:
            for cond in self.conditions.values():
                with cond:
                    cond.notify_all()
        super().shutdown()


class RelayHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for relay pairing endpoints."""

    server: RelayServer

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr logging."""
        pass

    def send_json_response(self, status: int, data: dict) -> None:
        """Send JSON response with Content-Type and Content-Length headers."""
        body = json.dumps(data).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_join_failed(self) -> None:
        """Send 401 Unauthorized with byte-identical body for join failures."""
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(JOIN_FAILED_BODY)))
        self.end_headers()
        self.wfile.write(JOIN_FAILED_BODY)

    def read_json_body(self) -> dict | None:
        """Read and parse JSON request body; return {} if empty, None if malformed."""
        length_header = self.headers.get("Content-Length")
        if not length_header:
            return {}
        try:
            length = int(length_header)
        except ValueError:
            return None
        raw = self.rfile.read(length)
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            return None
        except Exception:
            return None

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/invite":
            self.handle_invite()
        elif parsed.path == "/join":
            self.handle_join()
        elif parsed.path == "/revoke":
            self.handle_revoke()
        # Extension point for Task 3 POST endpoints (/ask, /answer)
        elif self.handle_task3_post(parsed):
            return
        elif parsed.path == "/session":
            self.send_json_response(405, {"error": "method_not_allowed"})
        else:
            self.send_json_response(404, {"error": "not_found"})

    def handle_healthz(self) -> None:
        """GET /healthz -> 200 plain 'ok' without auth or db access."""
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self.handle_healthz()
        elif parsed.path == "/session":
            self.handle_session(parsed)
        # Extension point for Task 3 GET endpoints (/poll, /result/<qid>)
        elif self.handle_task3_get(parsed):
            return
        elif parsed.path in ("/invite", "/join", "/revoke"):
            self.send_json_response(405, {"error": "method_not_allowed"})
        else:
            self.send_json_response(404, {"error": "not_found"})

    # --- Authentication & Authorization Helper ---

    def authenticate_session(self, required_role: str | None = None) -> tuple[sqlite3.Row | None, str | None]:
        """Authenticate session token from Authorization: Bearer <token>.

        Enforces token validity, revocation check, expiry check, and optional role check.
        Returns (session_row, role) on success, or (None, None) after sending an error response.
        """
        auth = self.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            self.send_json_response(401, {"error": "unauthorized"})
            return None, None

        token = auth[7:].strip()
        if not token:
            self.send_json_response(401, {"error": "unauthorized"})
            return None, None

        token_hash = hash_secret(token)
        conn = get_db_connection(self.server.db_path)
        try:
            session = conn.execute(
                "SELECT * FROM sessions WHERE session_a_hash = ? OR session_b_hash = ?",
                (token_hash, token_hash),
            ).fetchone()

            if not session:
                self.send_json_response(401, {"error": "unauthorized"})
                return None, None

            if session["revoked"] == 1:
                self.send_json_response(401, {"error": "session_revoked"})
                return None, None

            now = self.server.clock()
            if now > session["expires_at"]:
                self.send_json_response(401, {"error": "session_expired"})
                return None, None

            role = "A" if token_hash == session["session_a_hash"] else "B"

            if required_role is not None and role != required_role:
                self.send_json_response(403, {"error": "forbidden"})
                return None, None

            return session, role
        finally:
            conn.close()

    # --- Task 3 Extension Points ---

    def handle_task3_post(self, parsed: urllib.parse.ParseResult) -> bool:
        """Extension point for Task 3 POST endpoints (e.g. /ask, /answer)."""
        if parsed.path == "/ask":
            self.handle_ask()
            return True
        elif parsed.path == "/answer":
            self.handle_answer()
            return True
        elif parsed.path == "/poll" or parsed.path == "/result" or parsed.path.startswith("/result/"):
            self.send_json_response(405, {"error": "method_not_allowed"})
            return True
        return False

    def handle_task3_get(self, parsed: urllib.parse.ParseResult) -> bool:
        """Extension point for Task 3 GET endpoints (e.g. /poll, /result/<qid>)."""
        if parsed.path == "/poll":
            self.handle_poll(parsed)
            return True
        elif parsed.path == "/result" or parsed.path.startswith("/result/"):
            self.handle_result(parsed)
            return True
        elif parsed.path in ("/ask", "/answer"):
            self.send_json_response(405, {"error": "method_not_allowed"})
            return True
        return False

    def handle_ask(self) -> None:
        """POST /ask Bearer session {q, sig} -> {qid}."""
        body = self.read_json_body()
        if body is None:
            self.send_json_response(400, {"error": "invalid_json"})
            return

        session, role = self.authenticate_session()
        if not session or not role:
            return

        q = body.get("q")
        sig = body.get("sig")
        if not isinstance(q, str) or not isinstance(sig, str):
            self.send_json_response(400, {"error": "missing_required_fields"})
            return

        if len(q.encode("utf-8")) > 4096:
            self.send_json_response(413, {"error": "payload_too_large"})
            return

        now = self.server.clock()
        one_hour_ago = now - 3600.0

        cond = self.server.get_condition(session["id"])
        with cond:
            conn = get_db_connection(self.server.db_path)
            try:
                cnt_row = conn.execute(
                    "SELECT COUNT(*) as count FROM questions WHERE session_id = ? AND asker = ? AND created_at >= ?",
                    (session["id"], role, one_hour_ago),
                ).fetchone()
                if cnt_row and cnt_row["count"] >= 20:
                    self.send_json_response(429, {"error": "rate_limit_exceeded"})
                    return

                inflight_row = conn.execute(
                    "SELECT COUNT(*) as count FROM questions WHERE session_id = ? AND asker = ? AND answered_at IS NULL",
                    (session["id"], role),
                ).fetchone()
                if inflight_row and inflight_row["count"] > 0:
                    self.send_json_response(409, {"error": "question_in_flight"})
                    return

                qid = secrets.token_urlsafe(12)
                conn.execute(
                    "INSERT INTO questions (qid, session_id, asker, q, q_sig, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (qid, session["id"], role, q, sig, now),
                )
                conn.commit()
            finally:
                conn.close()

            cond.notify_all()

        self.send_json_response(200, {"qid": qid})

    def handle_poll(self, parsed: urllib.parse.ParseResult) -> None:
        """GET /poll?wait=25 Bearer session -> {qid, asker, q, sig} or 204."""
        session, role = self.authenticate_session()
        if not session or not role:
            return

        query = urllib.parse.parse_qs(parsed.query)
        if "wait" in query:
            raw_wait = query["wait"][0]
            if raw_wait == "":
                wait_seconds = 25.0
            else:
                try:
                    wait_seconds = float(raw_wait)
                except ValueError:
                    wait_seconds = 0.0
        else:
            wait_seconds = 0.0

        wait_seconds = min(max(0.0, wait_seconds), 25.0)

        cond = self.server.get_condition(session["id"])
        deadline = time.time() + wait_seconds

        with cond:
            while True:
                if getattr(self.server, "shutting_down", False):
                    self.send_response(204)
                    self.end_headers()
                    return

                conn = get_db_connection(self.server.db_path)
                try:
                    sess_row = conn.execute(
                        "SELECT revoked, expires_at FROM sessions WHERE id = ?",
                        (session["id"],),
                    ).fetchone()

                    if not sess_row or sess_row["revoked"] == 1:
                        self.send_json_response(401, {"error": "session_revoked"})
                        return

                    now = self.server.clock()
                    if now > sess_row["expires_at"]:
                        self.send_json_response(401, {"error": "session_expired"})
                        return

                    q_row = conn.execute(
                        "SELECT qid, asker, q, q_sig FROM questions WHERE session_id = ? AND asker != ? AND answered_at IS NULL ORDER BY created_at ASC LIMIT 1",
                        (session["id"], role),
                    ).fetchone()

                    if q_row:
                        self.send_json_response(200, {
                            "qid": q_row["qid"],
                            "asker": q_row["asker"],
                            "q": q_row["q"],
                            "sig": q_row["q_sig"],
                        })
                        return
                finally:
                    conn.close()

                remaining = deadline - time.time()
                if remaining <= 0:
                    self.send_response(204)
                    self.end_headers()
                    return

                cond.wait(timeout=min(remaining, 0.5))

    def handle_answer(self) -> None:
        """POST /answer Bearer session {qid, a, sig} -> {ok: true}."""
        body = self.read_json_body()
        if body is None:
            self.send_json_response(400, {"error": "invalid_json"})
            return

        session, role = self.authenticate_session()
        if not session or not role:
            return

        qid = body.get("qid")
        a = body.get("a")
        sig = body.get("sig")
        if not isinstance(qid, str) or not isinstance(a, str) or not isinstance(sig, str):
            self.send_json_response(400, {"error": "missing_required_fields"})
            return

        now = self.server.clock()
        cond = self.server.get_condition(session["id"])
        with cond:
            conn = get_db_connection(self.server.db_path)
            try:
                q_row = conn.execute(
                    "SELECT * FROM questions WHERE qid = ? AND session_id = ?",
                    (qid, session["id"]),
                ).fetchone()

                if not q_row:
                    self.send_json_response(404, {"error": "question_not_found"})
                    return

                if q_row["asker"] == role:
                    self.send_json_response(403, {"error": "cannot_answer_own_question"})
                    return

                if q_row["answered_at"] is not None:
                    self.send_json_response(409, {"error": "already_answered"})
                    return

                conn.execute(
                    "UPDATE questions SET a = ?, a_sig = ?, answered_at = ? WHERE qid = ? AND session_id = ?",
                    (a, sig, now, qid, session["id"]),
                )
                conn.commit()
            finally:
                conn.close()

            cond.notify_all()

        self.send_json_response(200, {"ok": True})

    def handle_result(self, parsed: urllib.parse.ParseResult) -> None:
        """GET /result/<qid>?wait=25 Bearer session -> {a, sig} or 204."""
        qid = parsed.path[len("/result/"):].strip() if parsed.path.startswith("/result/") else ""
        if not qid:
            self.send_json_response(400, {"error": "missing_qid"})
            return

        session, role = self.authenticate_session()
        if not session or not role:
            return

        query = urllib.parse.parse_qs(parsed.query)
        if "wait" in query:
            raw_wait = query["wait"][0]
            if raw_wait == "":
                wait_seconds = 25.0
            else:
                try:
                    wait_seconds = float(raw_wait)
                except ValueError:
                    wait_seconds = 0.0
        else:
            wait_seconds = 0.0

        wait_seconds = min(max(0.0, wait_seconds), 25.0)

        cond = self.server.get_condition(session["id"])
        deadline = time.time() + wait_seconds

        with cond:
            while True:
                if getattr(self.server, "shutting_down", False):
                    self.send_response(204)
                    self.end_headers()
                    return

                conn = get_db_connection(self.server.db_path)
                try:
                    sess_row = conn.execute(
                        "SELECT revoked, expires_at FROM sessions WHERE id = ?",
                        (session["id"],),
                    ).fetchone()

                    if not sess_row or sess_row["revoked"] == 1:
                        self.send_json_response(401, {"error": "session_revoked"})
                        return

                    now = self.server.clock()
                    if now > sess_row["expires_at"]:
                        self.send_json_response(401, {"error": "session_expired"})
                        return

                    q_row = conn.execute(
                        "SELECT asker, a, a_sig, answered_at FROM questions WHERE qid = ? AND session_id = ?",
                        (qid, session["id"]),
                    ).fetchone()

                    if not q_row:
                        self.send_json_response(404, {"error": "question_not_found"})
                        return

                    if q_row["asker"] != role:
                        self.send_json_response(403, {"error": "forbidden"})
                        return

                    if q_row["answered_at"] is not None:
                        self.send_json_response(200, {
                            "a": q_row["a"],
                            "sig": q_row["a_sig"],
                        })
                        return
                finally:
                    conn.close()

                remaining = deadline - time.time()
                if remaining <= 0:
                    self.send_response(204)
                    self.end_headers()
                    return

                cond.wait(timeout=min(remaining, 0.5))

    # --- Task 2 Pairing Handlers ---

    def handle_invite(self) -> None:
        """POST /invite {} -> {invite_id, join_secret, poll_secret}."""
        relay_key = getattr(self.server, "relay_key", None)
        if relay_key is None:
            relay_key = os.environ.get("RELAY_KEY")
        if relay_key:
            client_key = self.headers.get("X-Relay-Key") or ""
            if not hmac.compare_digest(client_key, relay_key):
                self.send_json_response(401, {"error": "unauthorized"})
                return

        body = self.read_json_body()
        if body is None:
            self.send_json_response(400, {"error": "invalid_json"})
            return

        now = self.server.clock()
        expires_at = now + INVITE_TTL_SECONDS
        invite_id = secrets.token_urlsafe(16)
        join_secret = secrets.token_urlsafe(32)
        poll_secret = secrets.token_urlsafe(32)

        join_secret_hash = hash_secret(join_secret)
        poll_secret_hash = hash_secret(poll_secret)

        conn = get_db_connection(self.server.db_path)
        try:
            conn.execute(
                "INSERT INTO invites (invite_id, join_secret_hash, poll_secret_hash, created_at, expires_at, status) "
                "VALUES (?, ?, ?, ?, ?, 'pending')",
                (invite_id, join_secret_hash, poll_secret_hash, now, expires_at),
            )
            conn.commit()
        finally:
            conn.close()

        self.send_json_response(200, {
            "invite_id": invite_id,
            "join_secret": join_secret,
            "poll_secret": poll_secret,
        })

    def handle_join(self) -> None:
        """POST /join {invite_id, join_secret} -> {session_b}.

        Returns 409 if already used, 401 if wrong secret, unknown invite, or expired.
        """
        body = self.read_json_body()
        if body is None:
            self.send_json_response(400, {"error": "invalid_json"})
            return

        invite_id = body.get("invite_id")
        join_secret = body.get("join_secret")
        if not invite_id or not join_secret or not isinstance(invite_id, str) or not isinstance(join_secret, str):
            self.send_json_response(400, {"error": "missing_required_fields"})
            return

        conn = get_db_connection(self.server.db_path)
        try:
            invite = conn.execute("SELECT * FROM invites WHERE invite_id = ?", (invite_id,)).fetchone()
            if not invite:
                # Timing defense: dummy hash comparison
                dummy_hash = hashlib.sha256(b"dummy_salt_not_found").hexdigest()
                cand_hash = hash_secret(join_secret)
                hmac.compare_digest(cand_hash, dummy_hash)
                self.send_join_failed()
                return

            cand_hash = hash_secret(join_secret)
            if not hmac.compare_digest(cand_hash, invite["join_secret_hash"]):
                self.send_join_failed()
                return

            if invite["status"] == "used":
                self.send_json_response(409, {"error": "invite_already_used"})
                return

            now = self.server.clock()
            if now > invite["expires_at"]:
                self.send_join_failed()
                return

            session_a = secrets.token_urlsafe(32)
            session_b = secrets.token_urlsafe(32)
            session_a_hash = hash_secret(session_a)
            session_b_hash = hash_secret(session_b)
            session_expires_at = now + SESSION_TTL_SECONDS

            # Atomically mark invite as used
            cursor = conn.execute(
                "UPDATE invites SET status = 'used' WHERE invite_id = ? AND status = 'pending'",
                (invite_id,),
            )
            if cursor.rowcount == 0:
                self.send_json_response(409, {"error": "invite_already_used"})
                return

            conn.execute(
                "INSERT INTO sessions (invite_id, session_a, session_a_hash, session_b_hash, created_at, expires_at, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, 0)",
                (invite_id, session_a, session_a_hash, session_b_hash, now, session_expires_at),
            )
            conn.commit()

            self.send_json_response(200, {"session_b": session_b})
        finally:
            conn.close()

    def handle_session(self, parsed: urllib.parse.ParseResult) -> None:
        """GET /session?invite_id=... with header X-Poll-Secret -> {session_a} once joined, else 204."""
        query = urllib.parse.parse_qs(parsed.query)
        invite_id_list = query.get("invite_id")
        if not invite_id_list or not invite_id_list[0]:
            self.send_json_response(400, {"error": "missing_invite_id"})
            return
        invite_id = invite_id_list[0]

        poll_secret = self.headers.get("X-Poll-Secret")
        if not poll_secret:
            self.send_json_response(401, {"error": "missing_poll_secret"})
            return

        conn = get_db_connection(self.server.db_path)
        try:
            invite = conn.execute("SELECT * FROM invites WHERE invite_id = ?", (invite_id,)).fetchone()
            if not invite:
                dummy_hash = hashlib.sha256(b"dummy_salt_not_found").hexdigest()
                cand_hash = hash_secret(poll_secret)
                hmac.compare_digest(cand_hash, dummy_hash)
                self.send_json_response(401, {"error": "invalid_poll_secret"})
                return

            cand_hash = hash_secret(poll_secret)
            if not hmac.compare_digest(cand_hash, invite["poll_secret_hash"]):
                self.send_json_response(401, {"error": "invalid_poll_secret"})
                return

            session = conn.execute(
                "SELECT * FROM sessions WHERE invite_id = ? ORDER BY id DESC LIMIT 1",
                (invite_id,),
            ).fetchone()

            if not session:
                # Not joined yet
                self.send_response(204)
                self.end_headers()
                return

            if session["revoked"] == 1:
                self.send_json_response(401, {"error": "session_revoked"})
                return

            now = self.server.clock()
            if now > session["expires_at"]:
                self.send_json_response(401, {"error": "session_expired"})
                return

            self.send_json_response(200, {"session_a": session["session_a"]})
        finally:
            conn.close()

    def handle_revoke(self) -> None:
        """POST /revoke Bearer either session -> {ok: true}; kills both sessions."""
        # Read request body if present to keep connection clean
        _ = self.read_json_body()

        auth = self.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            self.send_json_response(401, {"error": "unauthorized"})
            return

        token = auth[7:].strip()
        if not token:
            self.send_json_response(401, {"error": "unauthorized"})
            return

        token_hash = hash_secret(token)
        conn = get_db_connection(self.server.db_path)
        try:
            session = conn.execute(
                "SELECT * FROM sessions WHERE (session_a_hash = ? OR session_b_hash = ?) AND revoked = 0",
                (token_hash, token_hash),
            ).fetchone()

            if not session:
                self.send_json_response(401, {"error": "unauthorized"})
                return

            now = self.server.clock()
            if now > session["expires_at"]:
                self.send_json_response(401, {"error": "session_expired"})
                return

            conn.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (session["id"],))
            conn.commit()

            cond = self.server.get_condition(session["id"])
            with cond:
                cond.notify_all()

            self.send_json_response(200, {"ok": True})
        finally:
            conn.close()


def make_server(
    db_path: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    clock: Callable[[], float] = time.time,
    relay_key: str | None = None,
) -> ThreadingHTTPServer:
    """Create and return a configured ThreadingHTTPServer instance."""
    init_db(db_path)
    return RelayServer((host, port), RelayHandler, db_path=db_path, clock=clock, relay_key=relay_key)


def main() -> None:
    """CLI entrypoint with --port, --host, and --db arguments."""
    default_host = os.environ.get("RELAY_HOST", "127.0.0.1")
    default_port_str = os.environ.get("PORT", "8080")
    try:
        default_port = int(default_port_str)
    except ValueError:
        default_port = 8080
    default_db = os.environ.get("RELAY_DB", "relay.db")

    parser = argparse.ArgumentParser(description="claude-bridge relay server")
    parser.add_argument("--host", default=default_host, help=f"Host to bind to (default: {default_host})")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to bind to (default: {default_port})")
    parser.add_argument("--db", default=default_db, help=f"Path to SQLite database (default: {default_db})")
    args = parser.parse_args()

    relay_key = os.environ.get("RELAY_KEY")
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if args.host not in loopback_hosts and not relay_key:
        sys.exit(f"Error: RELAY_KEY environment variable is required when binding to non-loopback host '{args.host}'.")

    server = make_server(args.db, args.host, args.port, relay_key=relay_key)
    print(f"Relay serving on http://{args.host}:{args.port} (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down relay...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
