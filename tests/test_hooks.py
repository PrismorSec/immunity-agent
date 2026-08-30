"""Tests for the Prismor hooks module."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import _is_pre_action, should_block, legacy_should_block


class TestIsPreAction(unittest.TestCase):
    """Test pre-action event name detection across all agents."""

    # Claude Code events
    def test_claude_pre_tool_use(self):
        self.assertTrue(_is_pre_action("PreToolUse"))

    def test_claude_user_prompt_submit(self):
        self.assertTrue(_is_pre_action("UserPromptSubmit"))

    def test_claude_post_tool_use(self):
        self.assertFalse(_is_pre_action("PostToolUse"))

    def test_claude_stop(self):
        self.assertFalse(_is_pre_action("Stop"))

    # Cursor events
    def test_cursor_before_shell_command(self):
        self.assertTrue(_is_pre_action("beforeShellCommand"))

    def test_cursor_before_submit_prompt(self):
        self.assertTrue(_is_pre_action("beforeSubmitPrompt"))

    def test_cursor_before_file_write(self):
        self.assertTrue(_is_pre_action("beforeFileWrite"))

    def test_cursor_after_shell_command(self):
        self.assertFalse(_is_pre_action("afterShellCommand"))

    def test_cursor_after_file_write(self):
        self.assertFalse(_is_pre_action("afterFileWrite"))

    # Windsurf events
    def test_windsurf_pre_run_command(self):
        self.assertTrue(_is_pre_action("pre_run_command"))

    def test_windsurf_pre_write_code(self):
        self.assertTrue(_is_pre_action("pre_write_code"))

    def test_windsurf_pre_user_prompt(self):
        self.assertTrue(_is_pre_action("pre_user_prompt"))

    def test_windsurf_post_run_command(self):
        self.assertFalse(_is_pre_action("post_run_command"))

    def test_windsurf_post_cascade_response(self):
        self.assertFalse(_is_pre_action("post_cascade_response"))

    # Edge cases
    def test_empty_string(self):
        self.assertFalse(_is_pre_action(""))

    def test_unknown_event(self):
        self.assertFalse(_is_pre_action("somethingElse"))


class TestShouldBlock(unittest.TestCase):
    """Test the blocking decision logic."""

    def test_blocks_enforce_rule_on_pre_action(self):
        # Enforcement is per-rule via `mode`: only mode=enforce findings block.
        findings = [{"category": "destructive_command", "severity": "CRITICAL", "mode": "enforce"}]
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNotNone(should_block(findings, event))

    def test_blocks_enforce_rule_alt_event(self):
        findings = [{"category": "secret_exfiltration", "severity": "CRITICAL", "mode": "enforce"}]
        event = {"agent_event": "beforeShellCommand", "type": "shell"}
        self.assertIsNotNone(should_block(findings, event))

    def test_observe_finding_does_not_block(self):
        # Default is observe — even a destructive finding only logs, never blocks.
        findings = [{"category": "destructive_command", "severity": "CRITICAL", "mode": "observe"}]
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNone(should_block(findings, event))
        # A finding with no mode key defaults to observe too.
        self.assertIsNone(should_block([{"category": "destructive_command"}], event))

    def test_no_block_on_post_action(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL", "mode": "enforce"}]
        event = {"agent_event": "PostToolUse", "type": "shell"}
        self.assertIsNone(should_block(findings, event))

    def test_no_block_on_empty_findings(self):
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNone(should_block([], event))

    def test_file_read_only_blocked_for_secret_access(self):
        # An enforce finding on a file_read is still skipped unless it's a
        # secret_access/iam category (reads are otherwise safe).
        findings = [{"category": "destructive_command", "severity": "CRITICAL", "mode": "enforce"}]
        event = {"agent_event": "PreToolUse", "type": "file_read"}
        self.assertIsNone(should_block(findings, event))

        findings = [{"category": "secret_access", "severity": "HIGH", "mode": "enforce"}]
        event = {"agent_event": "PreToolUse", "type": "file_read"}
        self.assertIsNotNone(should_block(findings, event))


class TestLegacyEnforceBridge(unittest.TestCase):
    """The backward-compat bridge: a policy that predates per-rule observe/enforce
    (block_categories set, no default_mode/mode) keeps blocking its categories
    when installed --mode enforce, so upgrading installs don't silently stop
    blocking. cli.py only calls this when engine.is_legacy_policy and --mode enforce.
    """

    CATS = {"destructive_command", "secret_exfiltration", "secret_access"}

    def test_blocks_block_category_on_pre_action(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]  # no mode
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNotNone(legacy_should_block(findings, event, self.CATS))

    def test_does_not_block_uncovered_category(self):
        findings = [{"category": "reconnaissance", "severity": "LOW"}]
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNone(legacy_should_block(findings, event, self.CATS))

    def test_no_block_on_post_action(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]
        event = {"agent_event": "PostToolUse", "type": "shell"}
        self.assertIsNone(legacy_should_block(findings, event, self.CATS))

    def test_empty_block_categories_never_blocks(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNone(legacy_should_block(findings, event, set()))

    def test_file_read_carveout_matches_modern_path(self):
        event = {"agent_event": "PreToolUse", "type": "file_read"}
        # destructive on a read is skipped (reads are safe)...
        self.assertIsNone(legacy_should_block(
            [{"category": "destructive_command"}], event, self.CATS))
        # ...but secret_access on a read still blocks.
        self.assertIsNotNone(legacy_should_block(
            [{"category": "secret_access"}], event, self.CATS))

    def test_reporting_action_is_not_blocked(self):
        """warn/log are reports, not verdicts — even inside a block category."""
        event = {"agent_event": "PreToolUse", "type": "shell"}
        for action in ("warn", "log"):
            self.assertIsNone(legacy_should_block(
                [{"category": "destructive_command", "action": action}], event, self.CATS),
                f"action: {action} should not block")

    def test_verdict_actions_still_block(self):
        """Every real verdict keeps blocking; absent action still defaults to block."""
        event = {"agent_event": "PreToolUse", "type": "shell"}
        for action in ("block", "step_up", "defer", "modify"):
            self.assertIsNotNone(legacy_should_block(
                [{"category": "destructive_command", "action": action}], event, self.CATS),
                f"action: {action} must still block")
        self.assertIsNotNone(legacy_should_block(
            [{"category": "destructive_command"}], event, self.CATS))

    def test_warn_finding_does_not_mask_a_later_block(self):
        """A warn finding is skipped, not treated as the decision for the event."""
        event = {"agent_event": "PreToolUse", "type": "shell"}
        findings = [
            {"category": "destructive_command", "action": "warn"},
            {"category": "secret_exfiltration", "action": "block"},
        ]
        blocking = legacy_should_block(findings, event, self.CATS)
        self.assertIsNotNone(blocking)
        self.assertEqual(blocking["category"], "secret_exfiltration")

    def test_shipped_warn_rule_does_not_block_under_the_bridge(self):
        """End-to-end: the bundled policy is legacy, and its action: warn rules
        must not hard-block when installed --mode enforce."""
        from prismor.runtime.policy_engine import PolicyEngine
        engine = PolicyEngine()
        self.assertTrue(engine.is_legacy_policy)
        event = {"agent_event": "PreToolUse", "type": "shell",
                 "command": "npm install -g typescript", "tool": "Bash"}
        findings = engine.evaluate(event, 0)
        self.assertTrue(any(f.get("ruleId") == "pkg-install-global" for f in findings))
        self.assertIsNone(legacy_should_block(findings, event, engine.block_categories))


class TestIsLegacyPolicy(unittest.TestCase):
    """PolicyEngine.is_legacy_policy gates the enforce bridge."""

    def _engine(self, body):
        import tempfile, pathlib
        from prismor.runtime.policy_engine import PolicyEngine
        d = tempfile.mkdtemp()
        p = pathlib.Path(d) / "policy.yaml"
        p.write_text(body)
        return PolicyEngine(policy_path=p)

    def test_shipped_policy_is_legacy(self):
        # The bundled default policy: block_categories, no default_mode, no rule modes.
        from prismor.runtime.policy_engine import PolicyEngine
        self.assertTrue(PolicyEngine().is_legacy_policy)

    def test_default_mode_opts_out_of_legacy(self):
        eng = self._engine(
            "settings:\n  default_mode: observe\n  block_categories: [destructive_command]\nrules: []\n")
        self.assertFalse(eng.is_legacy_policy)

    def test_rule_level_mode_opts_out_of_legacy(self):
        # A single rule declaring its own mode means the operator has adopted the
        # per-rule model — even with block_categories inherited from the default.
        eng = self._engine(
            "rules:\n"
            "  - id: r1\n"
            "    severity: HIGH\n"
            "    category: destructive_command\n"
            "    title: test rule\n"
            "    event_types: [shell]\n"
            "    patterns: ['rm -rf']\n"
            "    mode: enforce\n")
        self.assertTrue(any(r.mode for r in eng.rules))
        self.assertFalse(eng.is_legacy_policy)


if __name__ == "__main__":
    unittest.main()
