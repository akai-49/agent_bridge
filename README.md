# agent-bridge
Local plugin: Claude sessions in different project folders share files/messages via explicit grants.

Install (Claude Code): `claude plugin marketplace add akai-49/agent_bridge` then `claude plugin install agent-bridge@agent-bridge`. Full two-machine walkthrough: `docs/TWO-MACHINE-TEST.md`.
Requires python3 (stdlib only). State: ~/.claude-bridge (override with BRIDGE_HOME).

Use: in project A: "bridge whoami" -> "grant read to <B>". In project B: "list files in <A>", "read notes.md from <A>", "send <A> a message".

## Cross-machine mode

Cross-machine mode allows an agent on Machine A to ask questions about code on Machine B through an authenticated relay. Machine B answers automatically using a detached read-only responder daemon.

### 1. Start the Relay
One machine runs the relay server and exposes it over public HTTPS:
```bash
python3 relay/relay.py --port 8080
ngrok http 8080
```
> **Note:** Free ngrok URLs change per restart. If the relay or ngrok tunnel restarts, generate a fresh invite token. Alternatively, deploy to Render free tier using `render.yaml` (set `BRIDGE_RELAY_KEY` from dashboard; see `docs/TWO-MACHINE-TEST.md`).

### 2. Pairing & Question Flow
1. **Invite (Machine A):** Call `bridge_invite(relay_url="https://<ngrok-host>")`. Returns a single-use pairing token containing the relay URL, invite ID, join secret, and end-to-end signing key: `brg1.<relay>.<invite_id>.<join_secret>.<e2e_key>`.
2. **Join (Machine B):** Show the user the relay host from the token to confirm. Once confirmed with 'yes', call `bridge_join(token=..., confirm_relay="https://<ngrok-host>")`. B exchanges the token for `session_b` and spawns a background `responder.py` daemon rooted at B's repository.
3. **Ask (Machine A):** Call `bridge_ask(question="...")`. The question is HMAC-signed with `e2e_key`, routed through the relay, verified and answered on B, signed back, and verified on A.
4. **Revoke:** Call `bridge_net_revoke()` from either side to instantly terminate the session on the relay and stop responder daemons.

### Both directions
By default, Machine B answers questions asked by Machine A. Answering on Machine A is opt-in:
1. **Serve (Machine A):** In Claude on Machine A:
   `"Serve this folder to the bridge."`
   Claude shows the folder path and confirms that the peer's agent will be able to read files inside it. When confirmed with "yes", Claude calls `bridge_serve(confirm_folder="<path>")` and spawns a read-only responder daemon for Machine A.
2. **Ask (Machine B):** In Claude on Machine B:
   `"Ask the frontend bridge: how is the user profile page structured?"`
   Claude calls `bridge_ask(question="...")`, signed with `q_tag("B")` and verified with `a_tag("B", qid)`.

> **Note:**
> - Both sides need the same plugin version (0.1.2 or higher).
> - Only the newest invite works: generating a new invite token invalidates previous invites and sessions.

### 3. Read-Only Responder Security
- B's responder runs `claude -p` with strictly `--allowedTools Read,Grep,Glob` and `--disallowedTools Read(~/**),Read(/etc/**)`. No bash, network, or write tools are permitted.
- Working directory is confined to B's repository root; references to `.env`, hidden dotfiles, `.git`, or paths outside the repo root are rejected.
- Execution environment is scrubbed (passes only `PATH` and `HOME`).
- Output is scrubbed with automated regex redaction (AWS keys, private keys, API tokens, passwords).
- All requests, questions, answers, and rejections are logged to `~/.claude-bridge/audit.jsonl` on Machine B.

### 4. Operational Limits
- **Question size:** Maximum 4096 bytes per question.
- **In-flight limit:** Exactly 1 in-flight question per session (subsequent asks return 409 until answered).
- **Rate limits:** Maximum 20 questions/hour per session on the relay; responder enforces a local budget of 30/hour and 200/day.
- **Timeouts:** 120-second execution timeout on B; 130-second poll wait on A.
- **Lifetimes:** 15-minute single-use token TTL; 8-hour maximum session TTL.

### 5. Known Limits
- **Relay visibility:** While questions and answers are HMAC-signed end-to-end to guarantee authenticity and integrity, the relay sees plaintext Q&A in transit (transport security relies on HTTPS/TLS).
- **Source secret leakage:** Redaction filters known credentials, but hardcoded secrets in source code files can potentially leak if paraphrased by the language model. Never commit plain secrets to source repositories.
