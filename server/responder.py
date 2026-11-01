"""Responder daemon for B's machine.

Long-polls relay for questions, enforces path confinement, verifies HMAC signatures,
runs claude -p with read-only tools, redacts secrets from output, and audit-logs.
"""
from dataclasses import dataclass
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.request

from server.wire import sign, verify

ALLOW_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".rs",
    ".c", ".h", ".cpp", ".md", ".json", ".yaml", ".yml", ".toml",
    ".sql", ".html", ".css", ".txt",
})


@dataclass
class Cfg:
    repo_root: str
    relay_url: str
    session_b: str
    e2e_key: str
    audit_path: str
    max_per_hour: int = 30
    daily_budget: int = 200


def confine(repo_root: str, rel: str) -> str:
    """Confine a relative path to repo_root.

    Raises PermissionError if:
    - Path traversal with '..' is attempted.
    - Path resolves outside repo_root.
    - Symlink escapes repo_root.
    - Path is or contains a dotfile or .git component.
    - File extension is not in the ALLOW_EXTENSIONS list.
    """
    if not isinstance(repo_root, str) or not isinstance(rel, str):
        raise TypeError("repo_root and rel must be strings")
    if not rel.strip():
        raise PermissionError("Path cannot be empty")
    if "\0" in rel:
        raise PermissionError("Null byte in path is forbidden")

    rel_norm = rel.replace("\\", "/")
    rel_path = Path(rel_norm)
    if ".." in rel_path.parts:
        raise PermissionError(f"Path traversal ('..') is forbidden: {rel}")

    root = Path(repo_root).resolve()

    if rel_norm.startswith("~"):
        candidate = Path(os.path.expanduser(rel_norm))
    elif os.path.isabs(rel_norm):
        candidate = Path(rel_norm)
    else:
        candidate = root / rel_norm

    try:
        resolved = candidate.resolve()
    except Exception as e:
        raise PermissionError(f"Cannot resolve path '{rel}': {e}") from e

    try:
        cand_rel = resolved.relative_to(root)
    except ValueError as e:
        raise PermissionError(f"Path '{rel}' escapes repo root: {resolved}") from e

    if not cand_rel.parts:
        raise PermissionError("Repo root itself cannot be accessed as a file")

    for part in cand_rel.parts:
        if part.startswith("."):
            raise PermissionError(f"Hidden or dotfile component '{part}' is forbidden in {rel}")

    for part in rel_path.parts:
        if part.startswith(".") and part != ".":
            raise PermissionError(f"Hidden or dotfile component '{part}' is forbidden in {rel}")

    suffix = resolved.suffix.lower()
    if not suffix or suffix not in ALLOW_EXTENSIONS:
        raise PermissionError(f"Extension '{suffix}' is not in the allowed list for {rel}")

    return str(resolved)


def redact(text: str) -> str:
    """Mask sensitive patterns in text (AWS keys, private keys, sk-/ghp_/xox tokens, KEY= assignments)."""
    if not isinstance(text, str):
        return text

    # 1. Private key blocks (PEM / OpenSSH / RSA / etc.)
    text = re.sub(
        r"-----BEGIN [A-Z0-9_\s-]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\s-]+PRIVATE KEY-----",
        "[REDACTED]",
        text,
    )

    # 2. AWS Access Key IDs (AKIA, ASIA, ACCA, ABIA + 16 alphanumeric)
    text = re.sub(r"\b(AKIA|ASIA|ACCA|ABIA)[0-9A-Z]{16}\b", "[REDACTED]", text)

    # 3. sk- tokens (Anthropic / OpenAI API keys, etc.)
    text = re.sub(r"\bsk-[a-zA-Z0-9_\-]{16,}\b", "[REDACTED]", text)

    # 4. ghp_ tokens (GitHub personal access tokens)
    text = re.sub(r"\bgh[pousr]_[a-zA-Z0-9]{16,}\b", "[REDACTED]", text)

    # 5. xox tokens (Slack tokens)
    text = re.sub(r"\bxox[baprs]-[a-zA-Z0-9\-]+\b", "[REDACTED]", text)

    # 6. KEY=... style assignments (quoted or unquoted values)
    text = re.sub(
        r'(?i)\b([a-z0-9_]*(?:key|secret|password|token|auth|passwd|pwd)[a-z0-9_]*\s*=\s*)(?:(["\'])(.*?)\2|(\S+))',
        lambda m: f"{m.group(1)}{m.group(2) or ''}[REDACTED]{m.group(2) or ''}",
        text,
    )

    return text


def build_cmd(question: str) -> list[str]:
    """Build the claude -p command with strict read-only toolset and security prompt."""
    prompt = (
        "You are an assistant answering questions about the repository in the current working directory.\n"
        "Guidelines:\n"
        "- Provide only the direct answer to the question.\n"
        "- Do NOT output base64, hex, rot13, or any other encoded or obfuscated text.\n"
        "- Never quote, reveal, or output secrets, tokens, passwords, private keys, or credentials.\n"
        "- You may only consult source and documentation files inside the repository.\n\n"
        f"Question: {question}"
    )
    return [
        "claude",
        "-p",
        prompt,
        "--allowedTools",
        "Read,Grep,Glob",
        "--disallowedTools",
        "Read(~/**),Read(/etc/**)",
        "--max-turns",
        "8",
    ]


def extract_paths(text: str) -> list[str]:
    """Extract candidate path strings mentioned in question text."""
    tokens: list[str] = []

    # 1. Quoted strings: '...', "...", `...`
    for match in re.finditer(r'["\'`]([^"\'`\n]+)["\'`]', text):
        val = match.group(1).strip()
        if val:
            tokens.append(val)

    # 2. Whitespace-separated tokens
    for raw in text.split():
        tok = raw.strip()
        tok = re.sub(r'[\s\'"`\)\]\}\>\:\;\,\?\!]+$', '', tok)
        tok = re.sub(r'^[\s\'"`\(\[\{\<]+', '', tok)
        if tok.endswith(".") and tok != "..":
            tok = tok[:-1]
        if tok:
            tokens.append(tok)

    candidates: list[str] = []
    seen: set[str] = set()

    for tok in tokens:
        if tok in seen:
            continue
        if tok.startswith(("http://", "https://", "ftp://")):
            continue
        if re.match(r'^v?\d+(\.\d+)+$', tok):
            continue
        if tok.lower() in ("e.g.", "i.e.", "etc.", "etc"):
            continue

        is_path = False
        if tok.startswith(("~", "/", ".")):
            is_path = True
        elif re.search(r'\.[a-zA-Z0-9_-]+$', tok):
            is_path = True

        if is_path:
            seen.add(tok)
            candidates.append(tok)

    return candidates


def _log_audit(audit_path: str, record: dict[str, Any]) -> None:
    """Append a JSONL record to the audit log."""
    try:
        p = Path(audit_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record) + "\n"
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
    except Exception as e:
        sys.stderr.write(f"Warning: failed to write audit log: {e}\n")


def _get_history(cfg: Cfg) -> list[float]:
    """Retrieve history of successfully answered questions for rate limiting."""
    if hasattr(cfg, "_history"):
        return getattr(cfg, "_history")

    history: list[float] = []
    if os.path.exists(cfg.audit_path):
        try:
            with open(cfg.audit_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if rec.get("status") in ("answered", "timeout"):
                            ts = float(rec.get("timestamp", 0.0))
                            if ts > 0:
                                history.append(ts)
                    except Exception:
                        continue
        except Exception:
            pass

    setattr(cfg, "_history", history)
    return history


def handle(
    msg: dict[str, Any],
    cfg: Cfg,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any] | None:
    """Handle an incoming question message.

    Verifies signature with cfg.e2e_key. If unsigned or forged, returns None and logs 'rejected'.
    Enforces hourly and daily budgets.
    Confines paths mentioned in question text; refuses if blocked.
    Calls runner with cwd=cfg.repo_root, timeout=120, scrubbed env (PATH, HOME only).
    Redacts answer, signs with wire.sign, logs JSONL to cfg.audit_path, and returns {qid, a, sig}.
    """
    if not isinstance(msg, dict):
        return None

    qid = msg.get("qid")
    q = msg.get("q")
    sig = msg.get("sig")

    # 1. Validate signature
    if (
        not isinstance(qid, str)
        or not isinstance(q, str)
        or not isinstance(sig, str)
        or not verify(cfg.e2e_key, qid, q, sig)
    ):
        _log_audit(cfg.audit_path, {
            "timestamp": time.time(),
            "event": "rejected",
            "status": "rejected",
            "qid": qid if isinstance(qid, str) else None,
            "q": q if isinstance(q, str) else None,
            "reason": "invalid_signature",
        })
        return None

    now = time.time()

    # 2. Enforce budgets
    history = _get_history(cfg)
    hour_ago = now - 3600.0
    day_ago = now - 86400.0
    recent_hour = [t for t in history if t >= hour_ago]
    recent_day = [t for t in history if t >= day_ago]

    if len(recent_hour) >= cfg.max_per_hour or len(recent_day) >= cfg.daily_budget:
        ans_text = "Error: budget exceeded (rate limit or daily budget reached)"
        ans_sig = sign(cfg.e2e_key, qid, ans_text)
        _log_audit(cfg.audit_path, {
            "timestamp": now,
            "event": "refused",
            "status": "refused",
            "qid": qid,
            "q": q,
            "a": ans_text,
            "reason": "budget_exceeded",
        })
        return {"qid": qid, "a": ans_text, "sig": ans_sig}

    # 3. Check paths mentioned in question text
    paths = extract_paths(q)
    for p in paths:
        try:
            confine(cfg.repo_root, p)
        except PermissionError as e:
            ans_text = f"Error: access denied: {e}"
            ans_sig = sign(cfg.e2e_key, qid, ans_text)
            _log_audit(cfg.audit_path, {
                "timestamp": now,
                "event": "refused",
                "status": "refused",
                "qid": qid,
                "q": q,
                "a": ans_text,
                "reason": str(e),
            })
            return {"qid": qid, "a": ans_text, "sig": ans_sig}

    # 4. Prepare scrubbed environment (only PATH and HOME)
    clean_env: dict[str, str] = {}
    if "PATH" in os.environ:
        clean_env["PATH"] = os.environ["PATH"]
    if "HOME" in os.environ:
        clean_env["HOME"] = os.environ["HOME"]

    cmd = build_cmd(q)
    runner_kwargs: dict[str, Any] = {
        "cwd": cfg.repo_root,
        "timeout": 120,
        "env": clean_env,
    }

    try:
        sig_params = inspect.signature(runner).parameters
        if "capture_output" in sig_params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig_params.values()):
            runner_kwargs["capture_output"] = True
            runner_kwargs["text"] = True
    except (ValueError, TypeError):
        runner_kwargs["capture_output"] = True
        runner_kwargs["text"] = True

    try:
        proc = runner(cmd, **runner_kwargs)
        raw = getattr(proc, "stdout", "")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        raw_answer = str(raw or "")
        retcode = getattr(proc, "returncode", 0)
        if retcode != 0 and not raw_answer.strip():
            err = getattr(proc, "stderr", "")
            if isinstance(err, bytes):
                err = err.decode("utf-8", errors="replace")
            raw_answer = f"Error: process exited with code {retcode}: {err}"
        answer = redact(raw_answer)
        status = "answered"
    except subprocess.TimeoutExpired:
        answer = "Error: command timed out (timeout after 120s)"
        status = "timeout"
    except Exception as e:
        answer = f"Error: {e}"
        status = "error"

    ans_sig = sign(cfg.e2e_key, qid, answer)

    _log_audit(cfg.audit_path, {
        "timestamp": now,
        "event": status,
        "status": status,
        "qid": qid,
        "q": q,
        "a": answer,
    })

    history.append(now)

    return {"qid": qid, "a": answer, "sig": ans_sig}


def load_config(config_path: str) -> Cfg:
    """Load Cfg from a JSON configuration file."""
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Cfg(
        repo_root=data["repo_root"],
        relay_url=data["relay_url"],
        session_b=data["session_b"],
        e2e_key=data["e2e_key"],
        audit_path=data["audit_path"],
        max_per_hour=data.get("max_per_hour", 30),
        daily_budget=data.get("daily_budget", 200),
    )


def main(
    config_path: str | Cfg,
    once: bool = False,
    stop_event: Any = None,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    """Long-polls relay GET /poll with Bearer session_b using urllib and posts /answer."""
    if isinstance(config_path, Cfg):
        cfg = config_path
    else:
        cfg = load_config(str(config_path))

    poll_url = f"{cfg.relay_url.rstrip('/')}/poll?wait=25"
    answer_url = f"{cfg.relay_url.rstrip('/')}/answer"

    while True:
        if stop_event is not None and stop_event.is_set():
            break

        req = urllib.request.Request(
            poll_url,
            headers={"Authorization": f"Bearer {cfg.session_b}"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    msg = json.loads(body)
                    result = handle(msg, cfg, runner=runner)
                    if result is not None:
                        post_data = json.dumps(result).encode("utf-8")
                        ans_req = urllib.request.Request(
                            answer_url,
                            data=post_data,
                            headers={
                                "Authorization": f"Bearer {cfg.session_b}",
                                "Content-Type": "application/json",
                            },
                            method="POST",
                        )
                        with urllib.request.urlopen(ans_req, timeout=30):
                            pass
                elif resp.status == 204:
                    pass
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Session revoked or expired
                break
            time.sleep(1.0)
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(1.0)

        if once:
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 server/responder.py <config.json>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
