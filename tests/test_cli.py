"""Tests for the Warden CLI entry points."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = str(REPO_ROOT / "warden" / "cli.py")
IMMUNITY_CLI = str(REPO_ROOT / "immunity")
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


def run_immunity(*args, stdin=None):
    result = subprocess.run(
        [sys.executable, IMMUNITY_CLI, *args],
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
        self.assertIn("Prismor Immunity", r.stdout)

    def test_version_exits_zero(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("prismor-warden", r.stdout)

    def test_bare_invocation_exits_zero(self):
        r = run_cli()
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Immunity", r.stdout)

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

    def test_sandbox_help(self):
        r = run_cli("sandbox", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Docker-backed sandbox", r.stdout)


class TestCliAnalyze(unittest.TestCase):
    """Test the analyze command against the sample session."""

    def test_analyze_text_output(self):
        r = run_cli("analyze", "--input", SAMPLE)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Immunity Report", r.stdout)
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


class TestImmunityUmbrella(unittest.TestCase):
    """Test the unified `immunity` CLI dispatches to the right engine."""

    def test_help_lists_all_domains(self):
        r = run_immunity("--help")
        self.assertEqual(r.returncode, 0)
        # Every advertised domain must appear in the top-level help.
        for domain in (
            "warden", "cloak", "policy", "sweep",
            "iam", "sandbox", "canary", "scope", "learn", "supplychain",
        ):
            self.assertIn(domain, r.stdout, f"domain '{domain}' missing from --help")
        # Quick-start shortcuts must appear too.
        for shortcut in ("setup", "status", "audit", "info"):
            self.assertIn(shortcut, r.stdout)

    def test_bare_invocation_prints_help(self):
        r = run_immunity()
        self.assertEqual(r.returncode, 0)
        self.assertIn("immunity", r.stdout)
        self.assertIn("Quick start", r.stdout)

    def test_version_flag(self):
        r = run_immunity("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("immunity "))

    def test_unknown_command_exits_nonzero(self):
        r = run_immunity("not-a-real-command")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown command", r.stderr)

    def test_domain_help_dispatches_to_warden(self):
        # `immunity cloak --help` should reach warden.cli's cloak subparser.
        r = run_immunity("cloak", "--help")
        self.assertEqual(r.returncode, 0)
        for action in ("install", "uninstall", "add", "list", "remove", "status"):
            self.assertIn(action, r.stdout)

    def test_top_level_shortcut_dispatches(self):
        # `immunity analyze` should reach the warden analyze command.
        r = run_immunity("analyze", "--input", SAMPLE, "--json")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertIn("summary", data)
        self.assertGreater(data["summary"]["totalFindings"], 0)

    def test_check_shortcut(self):
        r = run_immunity("check", "rm -rf /")
        # Critical finding -> warden exits non-zero by design; just verify
        # the output reached the policy engine.
        self.assertIn("CRITICAL", r.stdout)

    def test_supplychain_help(self):
        r = run_immunity("supplychain", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("supplychain", r.stdout)
        self.assertIn("harden", r.stdout)
        for pm in ("npm", "pip", "pnpm", "uv", "cargo", "go"):
            self.assertIn(pm, r.stdout)

    def test_supplychain_harden_dry_run(self):
        # Harden should run in dry-run mode without writing anything.
        r = run_immunity("supplychain", "harden", "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("dry run", r.stdout)

    def test_old_supply_name_is_unknown(self):
        # `immunity supply` (without -chain) should fail — confirms the rename.
        r = run_immunity("supply", "--help")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown command", r.stderr)


if __name__ == "__main__":
    unittest.main()
