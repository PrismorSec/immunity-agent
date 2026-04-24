"""Tests for the Warden CLI entry points."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = str(REPO_ROOT / "warden" / "cli.py")
SAMPLE = str(REPO_ROOT / "warden" / "examples" / "sample-session.jsonl")


def run_cli(*args, stdin=None):
    result = subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True,
        text=True,
        stdin=stdin,
        timeout=30,
    )
    return result


class TestCliExitCodes(unittest.TestCase):
    """Test CLI exits cleanly for help/version/bare invocation."""

    def test_help_exits_zero(self):
        r = run_cli("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Warden", r.stdout)

    def test_version_exits_zero(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("prismor-warden", r.stdout)

    def test_bare_invocation_exits_zero(self):
        r = run_cli()
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Warden", r.stdout)

    def test_analyze_help(self):
        r = run_cli("analyze", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--input", r.stdout)

    def test_install_hooks_help(self):
        r = run_cli("install-hooks", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--agent", r.stdout)

    def test_uninstall_hooks_help(self):
        r = run_cli("uninstall-hooks", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--agent", r.stdout)


class TestCliAnalyze(unittest.TestCase):
    """Test the analyze command against the sample session."""

    def test_analyze_text_output(self):
        r = run_cli("analyze", "--input", SAMPLE)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Warden Report", r.stdout)
        self.assertIn("Findings:", r.stdout)
        self.assertIn("CRITICAL", r.stdout)

    def test_analyze_json_output(self):
        r = run_cli("analyze", "--input", SAMPLE, "--json")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertGreater(data["summary"]["totalFindings"], 0)
        self.assertEqual(data["summary"]["totalEvents"], 8)

    def test_analyze_finds_expected_categories(self):
        r = run_cli("analyze", "--input", SAMPLE, "--json")
        data = json.loads(r.stdout)
        categories = {f["category"] for f in data["findings"]}
        self.assertIn("prompt_injection", categories)
        self.assertIn("remote_execution", categories)
        self.assertIn("secret_exfiltration", categories)
        self.assertIn("secret_access", categories)
        self.assertIn("risky_write", categories)

    def test_analyze_risk_score_maxed(self):
        r = run_cli("analyze", "--input", SAMPLE, "--json")
        data = json.loads(r.stdout)
        self.assertEqual(data["summary"]["riskScore"], 100)

    def test_analyze_missing_input(self):
        # Use an empty workspace so no stored session is available.
        import tempfile
        with tempfile.TemporaryDirectory() as empty_ws:
            r = run_cli("analyze", "--workspace", empty_ws)
        self.assertNotEqual(r.returncode, 0)


class TestCliAnalyzeCleanSession(unittest.TestCase):
    """Test analyze with a clean session produces no findings."""

    def test_clean_session(self):
        import tempfile
        clean = '{"type":"shell","command":"ls -la"}\n{"type":"prompt","prompt":"Help me refactor"}\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(clean)
            f.flush()
            try:
                r = run_cli("analyze", "--input", f.name, "--json")
                self.assertEqual(r.returncode, 0)
                data = json.loads(r.stdout)
                self.assertEqual(data["summary"]["totalFindings"], 0)
                self.assertEqual(data["summary"]["totalEvents"], 2)
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
