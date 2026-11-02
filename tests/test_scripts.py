import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestRunAsScript(unittest.TestCase):
    """Plugin launches these as `python3 path/to/file.py`, not as packages."""

    def test_bridge_mcp_lists_tools(self):
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
        p = subprocess.run([sys.executable, str(ROOT / "server/bridge.py")], input=req,
                           capture_output=True, text=True, cwd=tempfile.gettempdir(), timeout=10)
        self.assertIn("bridge_ask", p.stdout, p.stderr)

    def test_responder_script_imports(self):
        p = subprocess.run([sys.executable, str(ROOT / "server/responder.py"), "/nonexistent.json"],
                           capture_output=True, text=True, cwd=tempfile.gettempdir(), timeout=10)
        self.assertNotIn("ModuleNotFoundError", p.stderr)


if __name__ == "__main__":
    unittest.main()
