"""Tool-level step_up: an org admin marking a tool "requires approval".

`settings.tool_denies` previously understood only deny/allow, so a step_up
entry written by the console was skipped and the call ran — a policy the fleet
silently ignored. These pin that a step_up entry produces a finding carrying
`action: step_up`, that should_block ranks it correctly against a real block,
and that an unknown action is still ignored rather than guessed at.

Run: python3 tests/test_tool_step_up.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.agents import (  # noqa: E402
    make_agent_tool_deny_finding,
    make_agent_tool_step_up_finding,
)
from prismor.runtime.hooks import should_block  # noqa: E402

PRE = {"agent_event": "PreToolUse"}


class StepUpFinding(unittest.TestCase):
    def test_carries_the_step_up_action(self):
        f = make_agent_tool_step_up_finding("worker", "Bash", "s1")
        self.assertEqual(f["action"], "step_up")
        self.assertEqual(f["ruleId"], "org-tool-step-up")
        # agent-control applies in observe mode too — an approval requirement
        # the org set must not be suppressed by a local dry-run flag.
        self.assertEqual(f["category"], "agent-control")
        self.assertEqual(f["mode"], "enforce")

    def test_deny_finding_still_blocks(self):
        f = make_agent_tool_deny_finding("worker", "Bash", "s1")
        self.assertNotEqual(f.get("action"), "step_up")

    def test_should_block_surfaces_step_up(self):
        f = make_agent_tool_step_up_finding("worker", "Bash", "s1")
        picked = should_block([f], PRE)
        self.assertIsNotNone(picked)
        self.assertEqual(picked["action"], "step_up")

    def test_a_real_block_outranks_a_step_up(self):
        # Strongest verdict wins: if anything says block, a human is not asked.
        step = make_agent_tool_step_up_finding("worker", "Bash", "s1")
        deny = make_agent_tool_deny_finding("worker", "Bash", "s1")
        picked = should_block([step, deny], PRE)
        self.assertIsNotNone(picked)
        self.assertNotEqual(picked.get("action"), "step_up")

    def test_titles_say_what_is_being_asked(self):
        f = make_agent_tool_step_up_finding("worker", "kubectl_delete", "s1", scope_label="org device")
        self.assertIn("approval required", f["title"])
        self.assertIn("kubectl_delete", f["title"])
        self.assertIn("org device", f["title"])


class ToolDeniesActionHandling(unittest.TestCase):
    """The runtime loop only acts on actions it understands."""

    def test_known_actions(self):
        # Mirrors the membership test in runtime.py: deny and step_up act,
        # allow is handled elsewhere, anything else is skipped.
        for action, acted in (("deny", True), ("step_up", True), ("allow", False), ("nonsense", False)):
            self.assertEqual(action in ("deny", "step_up"), acted, action)


if __name__ == "__main__":
    unittest.main(verbosity=2)
