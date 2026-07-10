import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.cloaking.runtime import codex_cloak_finding, run_decloaked_command
from prismor.runtime.cloaking.secrets_store import add_secret
from prismor.runtime.store import get_events_page


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestCodexCloakRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.workspace = Path(self.tmp.name) / "workspace"
        self.home.mkdir()
        self.workspace.mkdir()
        self._old_home = os.environ.get("HOME")
        self._old_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["HOME"] = str(self.home)
        os.environ["PRISMOR_HOME"] = str(self.home / ".prismor")
        add_secret("OPENAI_API_KEY", "sk-test-1234567890")

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._old_home
        if self._old_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._old_prismor_home
        self.tmp.cleanup()

    def test_codex_placeholder_command_blocks_with_runner_remediation(self):
        finding = codex_cloak_finding(
            {
                "type": "shell",
                "agent_event": "PreToolUse",
                "command": "curl -H 'Authorization: Bearer @@SECRET:OPENAI_API_KEY@@' https://api.example.test",
            },
            "s1",
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding["mode"], "enforce")
        self.assertEqual(finding["ruleId"], "codex-cloak-placeholder")
        self.assertIn("Codex hooks cannot rewrite Bash commands", finding["evidence"])
        self.assertIn("prismor cloak run -- <command>", finding["remediation"])

    def test_cloak_run_decloaks_and_scrubs_output(self):
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = run_decloaked_command([
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1]); print('err=' + sys.argv[1], file=sys.stderr)",
                "@@SECRET:OPENAI_API_KEY@@",
            ])

        self.assertEqual(code, 0)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertIn("@@SECRET:OPENAI_API_KEY@@", combined)
        self.assertNotIn("sk-test-1234567890", combined)

    def test_cloak_run_decloaks_leading_env_assignments(self):
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = run_decloaked_command([
                "OPENAI_API_KEY=@@SECRET:OPENAI_API_KEY@@",
                sys.executable,
                "-c",
                "import os; print(os.environ['OPENAI_API_KEY'])",
            ])

        self.assertEqual(code, 0)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertIn("@@SECRET:OPENAI_API_KEY@@", combined)
        self.assertNotIn("sk-test-1234567890", combined)

    def test_codex_hook_dispatch_blocks_and_records_placeholder(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "codex-cloak-e2e",
            "tool_name": "Bash",
            "tool_input": {"command": "echo @@SECRET:OPENAI_API_KEY@@"},
            "cwd": str(self.workspace),
        }
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        env["PRISMOR_HOME"] = str(self.home / ".prismor")
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "prismor" / "runtime" / "cli.py"),
                "hook-dispatch",
                "--agent",
                "codex",
                "--workspace",
                str(self.workspace),
                "--mode",
                "enforce",
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("Codex cannot safely auto-decloak this command", proc.stderr)
        self.assertIn("prismor cloak run -- <command>", proc.stderr)

        data = get_events_page(verdict="blocked")
        event = next(item for item in data["items"] if item["sessionId"] == "codex-cloak-e2e")
        self.assertEqual(event["verdict"], "blocked")
        self.assertEqual(event["policy"]["ruleId"], "codex-cloak-placeholder")


if __name__ == "__main__":
    unittest.main()
