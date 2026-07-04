"""Tests for the Prismor CLI entry points."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = str(REPO_ROOT / "prismor" / "runtime" / "cli.py")
IMMUNITY_CLI = str(REPO_ROOT / "bin" / "immunity")
SAMPLE = str(REPO_ROOT / "prismor" / "runtime" / "examples" / "sample-session.jsonl")


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
        self.assertIn("Prismor", r.stdout)

    def test_version_exits_zero(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("prismor", r.stdout)

    def test_bare_invocation_exits_zero(self):
        r = run_cli()
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor", r.stdout)

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


class TestCliCommandConsolidation(unittest.TestCase):
    """info→status, dashboard/serve, and status --all consolidation."""

    def test_info_is_alias_of_status(self):
        # `info` warns it's deprecated and renders the `status` overview.
        r = run_cli("info")
        self.assertEqual(r.returncode, 0)
        self.assertIn("deprecated alias", r.stderr)
        self.assertIn("status", r.stdout)
        # The old separate "workspace info" renderer is gone.
        self.assertNotIn("workspace info", r.stdout)

    def test_status_all_flag_exists(self):
        r = run_cli("status", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--all", r.stdout)
        self.assertIn("--days", r.stdout)

    def test_dashboard_serves_web_dashboard(self):
        # `dashboard` is now the web server, so it exposes --port/--host/--no-open.
        r = run_cli("dashboard", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--port", r.stdout)
        self.assertIn("--no-open", r.stdout)

    def test_serve_is_deprecated_alias(self):
        r = run_cli("serve", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--no-open", r.stdout)


class TestCliAnalyze(unittest.TestCase):
    """Test the analyze command against the sample session."""

    def test_analyze_text_output(self):
        r = run_cli("analyze", "--input", SAMPLE)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Prismor Report", r.stdout)
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
    """Test the unified `prismor` CLI dispatches to the right engine."""

    def test_help_lists_all_domains(self):
        r = run_immunity("--help")
        self.assertEqual(r.returncode, 0)
        # Every advertised domain must appear in the top-level help.
        for domain in (
            "prismor", "cloak", "policy", "sweep",
            "iam", "sandbox", "canary", "scope", "learn", "supplychain",
        ):
            self.assertIn(domain, r.stdout, f"domain '{domain}' missing from --help")
        # Quick-start shortcuts must appear too.
        for shortcut in ("setup", "status", "audit", "info"):
            self.assertIn(shortcut, r.stdout)

    def test_help_lists_every_command(self):
        # Help is introspection-driven: every non-internal top-level command
        # from the real parser must show up, so nothing can silently drop out.
        import argparse
        from prismor.runtime.cli import build_parser
        r = run_immunity("--help")
        self.assertEqual(r.returncode, 0)
        hidden = {"hook-dispatch"}  # internal, intentionally not listed
        parser = build_parser()
        commands = []
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                commands = list(action.choices.keys())
                break
        for cmd in commands:
            if cmd in hidden:
                continue
            self.assertIn(cmd, r.stdout, f"command '{cmd}' missing from --help")

    def test_help_shows_subactions_and_modes(self):
        # Sub-actions of domains and a command's "internal" mode flags must be
        # discoverable straight from `prismor --help`.
        r = run_immunity("--help")
        self.assertEqual(r.returncode, 0)
        for token in ("install", "show", "plant", "--redact", "--all", "--no-open"):
            self.assertIn(token, r.stdout, f"'{token}' missing from --help")

    def test_bare_invocation_prints_help(self):
        r = run_immunity()
        self.assertEqual(r.returncode, 0)
        self.assertIn("immunity", r.stdout)
        self.assertIn("Quick start", r.stdout)

    def test_version_flag(self):
        r = run_immunity("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("prismor "))

    def test_unknown_command_exits_nonzero(self):
        r = run_immunity("not-a-real-command")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown command", r.stderr)

    def test_domain_help_dispatches_to_prismor(self):
        # `prismor cloak --help` should reach prismor.runtime.cli's cloak subparser.
        r = run_immunity("cloak", "--help")
        self.assertEqual(r.returncode, 0)
        for action in ("install", "uninstall", "add", "list", "remove", "status"):
            self.assertIn(action, r.stdout)


class TestSkillInstall(unittest.TestCase):
    """`prismor setup` bundles + installs the immunity-agent Claude skill."""

    def test_install_skill_copies_manifest_and_docs(self):
        import tempfile
        from prismor.runtime.setup_wizard import _install_skill
        with tempfile.TemporaryDirectory() as ws:
            ok, detail = _install_skill(Path(ws))
            self.assertTrue(ok, detail)
            skill = Path(ws) / ".claude" / "skills" / "immunity-agent"
            self.assertTrue((skill / "SKILL.md").exists())
            # Docs the SKILL.md links to come along, the heavy gif does not.
            self.assertTrue((skill / "docs" / "prismor-runtime.md").exists())
            self.assertFalse((skill / "docs" / "demo.gif").exists())

    def test_install_skill_is_idempotent(self):
        import tempfile
        from prismor.runtime.setup_wizard import _install_skill
        with tempfile.TemporaryDirectory() as ws:
            _install_skill(Path(ws))
            ok, detail = _install_skill(Path(ws))
            self.assertTrue(ok)
            self.assertEqual(detail, "already present")


    def test_install_skill_runs_without_claude_agent(self):
        """SKILL.md must be installed regardless of which agents are selected."""
        import tempfile
        from prismor.runtime.setup_wizard import _install_skill
        with tempfile.TemporaryDirectory() as ws:
            ok, detail = _install_skill(Path(ws))
            self.assertTrue(ok, detail)
            self.assertTrue((Path(ws) / ".claude" / "skills" / "immunity-agent" / "SKILL.md").exists())


class TestWriteAgentContext(unittest.TestCase):
    """_write_agent_context writes command reference to agent-specific files."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp()
        self.ws = Path(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_cursor_writes_cursorrules(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["cursor"])
        content = (self.ws / ".cursorrules").read_text()
        self.assertIn("prismor status", content)
        self.assertIn("prismor supplychain", content)

    def test_windsurf_writes_windsurfrules(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["windsurf"])
        content = (self.ws / ".windsurfrules").read_text()
        self.assertIn("prismor status", content)

    def test_agents_md_written_for_codex(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["codex"])
        content = (self.ws / "AGENTS.md").read_text()
        self.assertIn("prismor status", content)

    def test_agents_md_written_for_copilot_and_hermes(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["copilot", "hermes"])
        self.assertTrue((self.ws / "AGENTS.md").exists())

    def test_idempotent_does_not_duplicate(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["cursor"])
        first = (self.ws / ".cursorrules").read_text()
        _write_agent_context(self.ws, ["cursor"])
        second = (self.ws / ".cursorrules").read_text()
        self.assertEqual(first, second, "second call must not append again")

    def test_appends_to_existing_file(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        (self.ws / ".cursorrules").write_text("# My existing rules\n")
        _write_agent_context(self.ws, ["cursor"])
        content = (self.ws / ".cursorrules").read_text()
        self.assertIn("# My existing rules", content)
        self.assertIn("prismor status", content)

    def test_claude_only_skips_cursor_and_windsurf(self):
        from prismor.runtime.setup_wizard import _write_agent_context
        _write_agent_context(self.ws, ["claude"])
        self.assertFalse((self.ws / ".cursorrules").exists())
        self.assertFalse((self.ws / ".windsurfrules").exists())
        self.assertFalse((self.ws / "AGENTS.md").exists())

    def test_skill_is_bundled_in_resolver(self):
        # The resolver must find the manifest in a git checkout (and, by the
        # same suffix, an installed wheel).
        from prismor.runtime.paths import skill_manifest_path
        self.assertTrue(skill_manifest_path().exists())

    def test_top_level_shortcut_dispatches(self):
        # `prismor analyze` should reach the prismor analyze command.
        r = run_immunity("analyze", "--input", SAMPLE, "--json")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertIn("summary", data)
        self.assertGreater(data["summary"]["totalFindings"], 0)

    def test_check_shortcut(self):
        r = run_immunity("check", "rm -rf /")
        # Critical finding -> prismor exits non-zero by design; just verify
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
        # `prismor supply` (without -chain) should fail — confirms the rename.
        r = run_immunity("supply", "--help")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown command", r.stderr)


if __name__ == "__main__":
    unittest.main()
