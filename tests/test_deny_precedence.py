"""DENY-wins precedence in should_block.

When several enforce findings fire on one event with mixed actions, the strongest
verdict must win (block > step_up > defer > modify), not whichever the engine
surfaced first — otherwise a rule ordering accident could downgrade a hard block
to a step-up/modify. Run:  python3 tests/test_deny_precedence.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.hooks import should_block  # noqa: E402

EVENT = {"agent_event": "PreToolUse", "type": "shell"}


def _f(action, fid, mode="enforce"):
    return {"mode": mode, "action": action, "id": fid, "category": "test"}


class DenyPrecedence(unittest.TestCase):
    def test_block_wins_over_step_up_even_when_second(self):
        picked = should_block([_f("step_up", "a"), _f("block", "b")], EVENT)
        self.assertEqual(picked["id"], "b")

    def test_block_wins_over_modify_and_defer(self):
        picked = should_block([_f("modify", "a"), _f("defer", "b"), _f("block", "c")], EVENT)
        self.assertEqual(picked["id"], "c")

    def test_step_up_wins_over_modify_when_no_block(self):
        picked = should_block([_f("modify", "a"), _f("step_up", "b")], EVENT)
        self.assertEqual(picked["id"], "b")

    def test_defer_beats_modify(self):
        picked = should_block([_f("modify", "a"), _f("defer", "b")], EVENT)
        self.assertEqual(picked["id"], "b")

    def test_enforce_warn_ranks_as_deny(self):
        # An enforce finding with action=warn/unset still means "stop" → outranks modify.
        picked = should_block([_f("modify", "a"), _f("warn", "b")], EVENT)
        self.assertEqual(picked["id"], "b")

    def test_ties_keep_first_surfaced(self):
        picked = should_block([_f("step_up", "first"), _f("step_up", "second")], EVENT)
        self.assertEqual(picked["id"], "first")

    def test_single_finding_unchanged(self):
        self.assertEqual(should_block([_f("step_up", "only")], EVENT)["id"], "only")

    def test_observe_findings_never_block(self):
        self.assertIsNone(should_block([_f("block", "a", mode="observe")], EVENT))

    def test_no_findings(self):
        self.assertIsNone(should_block([], EVENT))

    def test_not_pre_action(self):
        self.assertIsNone(should_block([_f("block", "a")], {"agent_event": "PostToolUse", "type": "shell"}))

    def test_file_read_carveout_still_applies(self):
        # A non-secret file_read enforce finding is not eligible → no block.
        read_ev = {"agent_event": "PreToolUse", "type": "file_read"}
        self.assertIsNone(should_block([{"mode": "enforce", "action": "block", "id": "r", "category": "test"}], read_ev))
        # …but a secret_access read still blocks.
        secret = {"mode": "enforce", "action": "block", "id": "s", "category": "secret_access"}
        self.assertEqual(should_block([secret], read_ev)["id"], "s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
