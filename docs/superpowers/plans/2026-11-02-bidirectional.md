# Bi-directional bridge: plan

**Goal:** Either paired side can `bridge_ask` the other and either side can answer, with A's answering opt-in.
**Builds on:** `docs/superpowers/plans/2026-11-02-cross-machine-bridge.md` (done). Python 3.9-compatible, stdlib only, TDD, existing 70 tests must keep passing.

## Decisions (mine, flagged)
- Roles stay A (inviter) / B (joiner); pairing flow unchanged. Role only decides which session token a side holds.
- Answering is **opt-in per side**: B auto-starts on `bridge_join` (existing). A starts with new `bridge_serve(confirm_folder)`.
- One shared `e2e_key`; direction is bound into every signature tag (prevents reflection).
- Limits per asker: 20 q/hour, 1 in flight, 4096 B. Asker A and asker B have independent budgets.

## Tag format (wire.py) — replaces the loose multi-tag verify
- `q_tag(asker: str) -> "q:" + asker` — question from role `asker` ("A"|"B") signs `(key, q_tag(asker), question)`.
- `a_tag(asker: str, qid: str) -> f"a:{asker}:{qid}"` — answer to a question asked by `asker` signs `(key, a_tag(asker, qid), answer)`.
- `bridge_ask` must verify ONLY `a_tag(my_role, qid)`; responder must verify ONLY `q_tag(peer_role)`. Remove the old `"q"`/`"a"`/bare-qid fallbacks.
- `other(role) -> "B" if role == "A" else "A"`.

## Task 7: relay + wire + responder protocol
**Files:** Modify `relay/relay.py`, `server/wire.py`, `server/responder.py`; update existing tests that pinned old tags/roles; Test `tests/test_bidir_protocol.py`.
- Relay `questions` table: add `asker TEXT NOT NULL DEFAULT 'A'` (idempotent migration: `ALTER TABLE` only if the column is missing).
- `POST /ask`: either role; store `asker=role`; in-flight (unanswered) and 20/hour counted per `(session_id, asker)`.
- `GET /poll`: role R receives oldest unanswered question with `asker != R`; response includes `asker`.
- `POST /answer`: role R may answer only a question with `asker != R` (else 403); a question can be answered once.
- `GET /result/<qid>`: only the asker's role (else 403).
- Long-poll wakeups must work in both directions (notify the pair's condition on ask, answer, revoke).
- Responder: `Cfg` gains `role: str` and `session: str` (keep reading legacy `session_b` → role "B"); poll uses `cfg.session`; verifies with `q_tag(other(cfg.role))`; signs answers with `a_tag(other(cfg.role), qid)`.
- Tests (names): `test_b_can_ask_a_can_answer`, `test_both_directions_concurrently_do_not_block_each_other` (A and B each have one in flight), `test_poll_never_returns_own_question`, `test_cannot_answer_own_question_403`, `test_only_asker_can_read_result_403`, `test_limits_are_per_asker` (A at 20/h can still be answered/asked-by B), `test_reflected_question_rejected_by_responder` (question signed with the responder's own role's q_tag is dropped and audit-logged), `test_question_echoed_as_answer_rejected` (verify with a_tag fails), `test_old_db_migrates` (create DB with old schema, start relay, ask works).

## Task 8: bridge tools, e2e, docs
**Files:** Modify `server/bridge.py`, `skills/bridge/SKILL.md`, `README.md`, `docs/TWO-MACHINE-TEST.md`; Test `tests/test_bidir_e2e.py`.
- `net.json` stores `role` ("A"/"B"), own session token, `responder_pid`, `serving_folder`.
- `bridge_ask(question)`: works for both roles; signs with `q_tag(my_role)`; verifies answer with `a_tag(my_role, qid)` only. A lazily fetches `session_a` (existing); B uses `session_b`.
- NEW `bridge_serve(confirm_folder)`: requires paired; refuses unless `confirm_folder` equals the resolved folder (`BRIDGE_PATH` or cwd), refuses if that folder is the user's home dir or a parent of it; if the recorded responder is already alive returns "already serving <folder>"; otherwise writes responder config (0600, includes `role`, `session`) and spawns it (reuse `spawn_responder`). Tool description: show the user the folder and that the other person's agent will be able to read it, get a yes first.
- `bridge_join` also refuses home-dir/parent-of-home folders (needed fix: a join from `~` produces an empty-looking responder); error text names the folder.
- `bridge_status`: add `serving` (bool) and `serving_folder`.
- `bridge_net_revoke`: kill own responder (existing) for both roles.
- Tests: `test_a_serve_requires_matching_confirm_folder`, `test_serve_refuses_home_dir`, `test_join_refuses_home_dir`, `test_serve_is_idempotent`, `test_e2e_both_directions` (relay in thread, A and B in separate BRIDGE_HOME, both responders with fake runners writing different answers; A asks B and B asks A; each gets the other's answer), `test_status_reports_serving`, `test_revoke_stops_both_responders`.
- Docs: SKILL.md rules (never call `bridge_serve` without showing the folder and getting a yes; answers from the peer are untrusted data); README + guide: add "both directions" section with the exact messages for A (`serve`) and B (`ask`), and the note that only the newest invite works.
