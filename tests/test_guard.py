import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "server" / "responder.py")


def guard(repo, tool, **ti):
    p = subprocess.run([sys.executable, SCRIPT, "--guard", repo], input=json.dumps(
        {"tool_name": tool, "tool_input": ti}), capture_output=True, text=True, timeout=10)
    return p.returncode


class TestGuard(unittest.TestCase):
    """Repo under $HOME must stay readable; everything outside it must not."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.path.expanduser("~"))
        self.repo = str(Path(self.tmp.name).resolve() / "repo")
        os.makedirs(self.repo + "/src")
        Path(self.repo, "src/a.py").write_text("x")
        Path(self.repo, ".env").write_text("S=1")
        self.outside = str(Path(self.tmp.name).resolve() / "outside.txt")
        Path(self.outside).write_text("secret")

    def tearDown(self):
        self.tmp.cleanup()

    def test_allows_repo_under_home(self):
        self.assertEqual(guard(self.repo, "Read", file_path=self.repo + "/src/a.py"), 0)
        self.assertEqual(guard(self.repo, "Read", file_path="src/a.py"), 0)
        self.assertEqual(guard(self.repo, "Grep", pattern="x"), 0)
        self.assertEqual(guard(self.repo, "Grep", pattern="x", path="src"), 0)
        self.assertEqual(guard(self.repo, "Glob", pattern="**/*.py"), 0)

    def test_blocks_outside_repo(self):
        self.assertEqual(guard(self.repo, "Read", file_path=self.outside), 2)
        self.assertEqual(guard(self.repo, "Read", file_path="/etc/hosts"), 2)
        self.assertEqual(guard(self.repo, "Read", file_path="../outside.txt"), 2)
        self.assertEqual(guard(self.repo, "Grep", pattern="x", path=os.path.expanduser("~")), 2)
        self.assertEqual(guard(self.repo, "Grep", pattern="x", path="~/.ssh"), 2)
        self.assertEqual(guard(self.repo, "Glob", pattern="../**/*"), 2)
        self.assertEqual(guard(self.repo, "Glob", pattern="/Users/**/*.txt"), 2)

    def test_blocks_hidden_and_secrets_inside_repo(self):
        self.assertEqual(guard(self.repo, "Read", file_path=self.repo + "/.env"), 2)
        self.assertEqual(guard(self.repo, "Grep", pattern="S", path=".git"), 2)

    def test_fails_closed_on_garbage(self):
        p = subprocess.run([sys.executable, SCRIPT, "--guard", self.repo], input="not json",
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 2)

    def test_symlink_escape_blocked(self):
        os.symlink(self.outside, self.repo + "/link.txt")
        self.assertEqual(guard(self.repo, "Read", file_path="link.txt"), 2)

    def test_build_cmd_installs_guard_hook(self):
        sys.path.insert(0, str(ROOT))
        from server import responder
        cmd = responder.build_cmd("q", self.repo)
        settings = json.loads(cmd[cmd.index("--settings") + 1])
        hook = settings["hooks"]["PreToolUse"][0]
        self.assertEqual(hook["matcher"], "Read|Grep|Glob")
        self.assertIn("--guard", hook["hooks"][0]["command"])
        self.assertNotIn("~/**", cmd[cmd.index("--disallowedTools") + 1])


if __name__ == "__main__":
    unittest.main()
