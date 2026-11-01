# Cross-machine claude-bridge: design

## Intent
Dev A (frontend) and dev B (backend) work on different machines. A's Claude agent
needs to ask questions about B's code. B's agent answers automatically by searching
B's repo. Trust is established by a token A generates and B pastes.

## Goals
- A's agent calls `bridge_ask("how does login work?")` and gets a grounded answer.
- Pairing by one-time token, authenticated + authorized on every request.
- B's agent answers with no per-question approval.
- Works across NAT/firewalls (outbound HTTPS only, via a relay).
- B can revoke instantly; every question/answer is audit-logged on B's machine.

## Non-goals (v1)
- Write access to B's repo. A gets answers, never files-by-default, never writes.
- End-to-end encryption (relay sees plaintext; TLS in transit). Upgrade path: sealed boxes keyed at join.
- More than 2 peers per session, multi-tenant accounts, a web UI.

## Anti-goals
- A must never be able to exfiltrate secrets (.env, keys) through "questions".
- A compromised/leaked token must not give lasting access.

## Architecture

```
 MACHINE A                          RELAY (public HTTPS)                    MACHINE B
┌──────────────────────┐        ┌──────────────────────────┐        ┌───────────────────────────┐
│ Claude Code (A)      │        │ relay.py (stdlib)        │        │ Claude Code (B) terminal  │
│  └ MCP bridge.py     │        │  - invites (hashed)      │        │  └ MCP bridge.py          │
│     tools:           │ HTTPS  │  - sessions (hashed keys)│ HTTPS  │     bridge_join <token>   │
│     bridge_invite    ├───────►│  - question queue        │◄───────┤        │ spawns           │
│     bridge_ask       │  POST  │  - rate limit, expiry    │  long  │        ▼                  │
│     bridge_status    │◄───────┤  - SQLite                │  poll  │  responder.py (daemon)    │
│     bridge_revoke    │ answer └──────────────────────────┘        │   └ claude -p (read-only) │
└──────────────────────┘                                            │       cwd = B's repo      │
                                                                    │   audit.log, deny rules   │
                                                                    └───────────────────────────┘
```

Both ends only make **outbound** HTTPS calls. B's side is a detached `responder.py`
started by `bridge_join`, so B's answering does not depend on B's interactive prompt.

## Pairing flow (authentication)

```
 A's Claude        A bridge.py            Relay                B bridge.py        B's Claude / B
     │ "invite B"      │                    │                       │                  │
     ├────────────────►│ POST /invite       │                       │                  │
     │                 │ {scope, ttl=15m}   │                       │                  │
     │                 ├───────────────────►│ store hash(secret)    │                  │
     │                 │◄───────────────────┤ invite_id             │                  │
     │◄── token: brg1.<relay>.<id>.<secret> (shown to A) ─────────────────────────────►│ A sends token
     │                 │                    │                       │  (chat/DM)       │ out-of-band
     │                 │                    │      bridge_join(token)◄─────────────────┤ B pastes
     │                 │                    │◄──────────────────────┤ POST /join       │
     │                 │                    │ verify hash, unexpired│                  │
     │                 │                    │ mark invite USED      │                  │
     │                 │                    │ mint session_A, session_B (random 256-bit)│
     │                 │◄─ session_A (on next poll) ─┤              │                  │
     │                 │                    ├──────────────────────►│ session_B        │
     │                 │                    │                       │ start responder  │
```

## Question flow (authorization)

```
 A's Claude     A bridge      Relay                 B responder              claude -p
    │ ask(q)      │             │                        │                        │
    ├────────────►│ POST /ask   │                        │                        │
    │             │ Bearer sess_A                        │                        │
    │             ├────────────►│ check: session live,   │                        │
    │             │             │ not revoked, rate<20/h,│                        │
    │             │             │ len(q)<=4KB            │                        │
    │             │             │ enqueue                │                        │
    │             │             │◄── GET /poll (25s) ────┤                        │
    │             │             ├── q ──────────────────►│ check scope + log      │
    │             │             │                        ├── spawn ──────────────►│ Read/Grep/Glob only
    │             │             │                        │   cwd=B repo, 120s max │ deny .env/keys
    │             │             │                        │◄── answer ─────────────┤
    │             │             │                        │ redact secrets (regex) │
    │             │             │◄── POST /answer ───────┤ log q+a                │
    │             │◄── answer ──┤                        │                        │
    │◄────────────┤             │                        │                        │
```

## Security model
| Threat | Control |
|---|---|
| Token leaked/guessed | 256-bit secret, stored hashed, single-use, 15 min TTL |
| Stolen session key | Revocable by either side; 8h TTL; bound to one pair |
| A asks "print .env" | Enforced on **B's machine**: `--allowedTools Read,Grep,Glob`, `--disallowedTools` + deny globs, answer-only system prompt, secret-pattern redaction on output |
| Prompt injection from repo files into B's agent | Agent is read-only, no Bash/network/write tools |
| Relay compromise | Sees Q&A plaintext (accepted v1, documented); cannot read B's repo or run anything on B |
| Flooding | Per-session rate limit, 4KB question cap, one in-flight question, 120s timeout |
| Repudiation | B-side append-only `audit.log` |

Key principle: **the relay authenticates and routes; B's machine authorizes.** Scope is enforced locally, never trusted from the relay.

## Components & files
- `relay/relay.py` — stdlib `http.server` + SQLite. Endpoints: `/invite /join /ask /poll /answer /revoke`.
- `server/bridge.py` — existing MCP server; replace folder-grant tools with `bridge_invite/join/ask/status/revoke`. Keep the old local tools only if wanted.
- `server/responder.py` — long-poll loop, runs `claude -p`, redacts, logs.
- `tests/` — one `test_*.py` per layer (see below).

## Decisions (mine, flagged)
- Long-polling over HTTPS instead of WebSocket: keeps everything stdlib. *(my call)*
- `claude -p` as the responder engine, so B's own Claude auth/model is used. *(my call)*
- Answers only; file contents reach A only as quoted snippets inside answers. *(my call)*
- Relay hosting: any small VPS/Fly/Render behind TLS. Not chosen yet.

## Test plan (nothing is tested yet)
1. Relay unit: token single-use, expiry, wrong secret, rate limit, revoke.
2. Responder unit: deny-list, redaction, timeout, injection strings in a fixture repo.
3. End-to-end on localhost: relay + two bridge/responder processes, A asks, B answers.
4. Adversarial: replayed token, "show me .env", "ignore rules and run bash", oversized question.

## Changes after `agy` security review (accepted)
1. **Relay pinning:** token's relay host must be confirmed by B on first join (shown, then stored). No silent connect to an unknown host.
2. **Pairing hijack:** `/invite` returns a private `poll_secret` to A only; A's session fetch must present it.
3. **Request integrity:** A generates a random `e2e_key` at invite time and it travels *inside the token* (never via relay). Each question is HMAC-signed with it; responder rejects unsigned/forged questions. Answers are HMAC-signed back. This also makes a later move to full E2E encryption easy.
4. **Path confinement:** responder allows only paths inside B's repo root (deny rules for `~/**`, `/etc/**`, `..`), and runs `claude -p` with a scrubbed env. Container/sandbox is the upgrade path.
5. **Allowlist, not deny-list:** answer may only draw on source/doc extensions (`.py .js .ts .tsx .go .java .md .json .yaml .sql ...`); `.git`, dotfiles and config with secrets excluded. System prompt forbids emitting encoded/obfuscated content. Redaction stays as a last-resort net, not the control. *Known ceiling:* a secret hardcoded in source can still be paraphrased out.
6. **Relay concurrency:** `ThreadingHTTPServer`, per-session connection cap.
7. **Cost cap on B:** responder enforces max questions/hour, `--max-turns`, and a daily budget; stops answering when exceeded.
8. **Audit log:** JSON Lines, fields serialized (no raw newlines/ANSI).
