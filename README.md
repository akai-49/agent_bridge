# claude-bridge
Local plugin: Claude sessions in different project folders share files/messages via explicit grants.

Install (Claude Code): `claude --plugin-dir /path/to/claude-bridge` (run in each project), or add via a local marketplace.
Requires python3 (stdlib only). State: ~/.claude-bridge (override with BRIDGE_HOME).

Use: in project A: "bridge whoami" -> "grant read to <B>". In project B: "list files in <A>", "read notes.md from <A>", "send <A> a message".
