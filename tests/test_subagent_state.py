"""Subagent attribution and hook-matcher migration.

Every hook invocation is a separate process and Claude runs subagents
concurrently, so a session's tag ledger is written by several processes at
once. A lost update silently un-taints a session, so the forbidden tool
combination is never blocked — that failure mode is fail-*open*.

This file also pins down subagent_id/subagent_type attribution: Claude tags
tool calls made inside a spawned subagent with agent_id/agent_type, and the
normalizer/telemetry layer must promote those into metadata.subagent_id /
subagent_type (and the Task/Agent tool itself into a subagent_spawn event) so
the control plane can attribute an action to the subagent that took it.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from multiprocessing import Process
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prismor.runtime.enterprise.telemetry import build_record  # noqa: E402
from prismor.runtime.hooks import _merge_claude_entries, _normalize_claude  # noqa: E402
from prismor.runtime.trifecta import (  # noqa: E402
    CRITICAL,
    UNTRUSTED,
    TagLedger,
    normalize_incompatible,
)

SESSION = "sess"
INCOMPATIBLE = normalize_incompatible(None)  # the default red/blue pair


def _record_worker(home: str, tag: str, index: int, tool: str, barrier: str) -> None:
    """Runs in a child process, mimicking one hook invocation."""
    os.environ["PRISMOR_HOME"] = home
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from prismor.runtime.trifecta import TagLedger as Ledger

    while not Path(barrier).exists():  # collide the writes as hard as possible
        pass
    Ledger(Path(home), SESSION).record({tag}, index, tool)


def _run_concurrently(home: Path, specs) -> None:
    barrier = home / "GO"
    procs = [
        Process(target=_record_worker, args=(str(home), tag, idx, tool, str(barrier)))
        for tag, idx, tool in specs
    ]
    for p in procs:
        p.start()
    barrier.write_text("go")
    for p in procs:
        p.join()


class ConcurrentLedgerWrites(unittest.TestCase):
    """Parallel subagents must not drop each other's ledger records."""

    def setUp(self) -> None:
        import tempfile

        self.home = Path(tempfile.mkdtemp(prefix="prismor-test-"))
        self._prior_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.home)

    def tearDown(self) -> None:
        import shutil

        if self._prior_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._prior_home
        shutil.rmtree(self.home, ignore_errors=True)

    def test_no_lost_updates_under_concurrent_writers(self):
        n = 12
        _run_concurrently(self.home, [(f"tag{i}", i, f"tool{i}") for i in range(n)])
        ledger = TagLedger(self.home, SESSION)
        missing = {f"tag{i}" for i in range(n)} - set(ledger.seen)
        self.assertEqual(missing, set(), f"lost {len(missing)} concurrent records")

    def test_ledger_file_never_tears(self):
        _run_concurrently(self.home, [(f"tag{i}", i, f"tool{i}") for i in range(12)])
        path = self.home / "trifecta" / f"{SESSION}.json"
        # A torn file is swallowed by the loader's except-and-continue, which
        # resets the session to clean state — so it must be impossible, not rare.
        json.loads(path.read_text(encoding="utf-8"))

    def test_concurrent_writers_do_not_open_the_trifecta_gate(self):
        """The security consequence of a lost update: one subagent fetches
        untrusted content while others write concurrently; a later critical
        action must still be blocked."""
        specs = [(UNTRUSTED, 0, "WebFetch")]
        specs += [(f"noise{i}", i + 1, f"tool{i}") for i in range(11)]
        _run_concurrently(self.home, specs)
        done = TagLedger(self.home, SESSION).completes(
            {CRITICAL}, INCOMPATIBLE, current_index=99
        )
        self.assertIsNotNone(done, "forbidden combination was not detected")


class HookMatcherMigration(unittest.TestCase):
    """Re-running install-hooks must widen an existing entry's matcher rather
    than appending a second one."""

    COMMAND = 'PYTHONPATH="/x" "/py" -m prismor.runtime.immunity_cli hook-dispatch --agent claude'
    NEW_MATCHER = "Task|Agent|Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*"

    def _new_entry(self):
        return {
            "matcher": self.NEW_MATCHER,
            "hooks": [{"type": "command", "command": self.COMMAND}],
        }

    def _stale(self):
        return [
            {
                "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*",
                "hooks": [{"type": "command", "command": "some-other-tool"}],
            },
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*",
                "hooks": [{"type": "command", "command": self.COMMAND}],
            },
        ]

    def test_stale_matcher_is_widened_in_place(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        ours = [e for e in merged if any(h.get("command") == self.COMMAND for h in e["hooks"])]
        self.assertEqual(len(ours), 1, "dispatcher would fire twice per tool call")
        self.assertEqual(ours[0]["matcher"], self.NEW_MATCHER)

    def test_subagent_spawn_tools_are_matched_after_migration(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        ours = [e for e in merged if any(h.get("command") == self.COMMAND for h in e["hooks"])]
        for tool in ("Task", "Agent"):
            self.assertTrue(
                any(re.fullmatch(e["matcher"], tool) for e in ours),
                f"{tool} spawn would not be screened",
            )

    def test_migration_is_idempotent(self):
        once = _merge_claude_entries(self._stale(), self._new_entry())
        twice = _merge_claude_entries(once, self._new_entry())
        self.assertEqual(once, twice)

    def test_another_tools_entry_is_never_hijacked(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        foreign = [e for e in merged if e["matcher"] == "Bash|Write|Edit|MultiEdit|mcp__.*"]
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0]["hooks"][0]["command"], "some-other-tool")

    def test_fresh_install_still_appends_new_entry(self):
        """No prior install at all: nothing to migrate, so a plain append."""
        merged = _merge_claude_entries([], self._new_entry())
        self.assertEqual(merged, [self._new_entry()])


class SubagentAttribution(unittest.TestCase):
    """Task/Agent tool calls are classified as subagent_spawn, and inner tool
    calls made inside a spawned subagent carry subagent_id/subagent_type
    through the normalizer into the telemetry record."""

    WORKSPACE = Path("/tmp/workspace")

    def test_task_tool_call_is_classified_as_subagent_spawn(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "description": "research something",
                "prompt": "go find X",
            },
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertEqual(event["type"], "subagent_spawn")
        self.assertEqual(event["subagent_type"], "general-purpose")
        self.assertEqual(event["description"], "research something")

    def test_inner_tool_call_promotes_agent_id_to_subagent_id(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "agent_id": "sub-42",
            "agent_type": "general-purpose",
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertEqual(event["metadata"]["subagent_id"], "sub-42")
        self.assertEqual(event["metadata"]["subagent_type"], "general-purpose")

    def test_main_agent_tool_call_has_no_subagent_id(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertIsNone(event["metadata"]["subagent_id"])
        self.assertIsNone(event["metadata"]["subagent_type"])

    def test_telemetry_record_carries_subagent_id_for_inner_call(self):
        event = {
            "type": "shell",
            "metadata": {"tool_name": "Bash", "subagent_id": "sub-42", "subagent_type": "general-purpose"},
        }
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertEqual(record["subagent_id"], "sub-42")
        self.assertEqual(record["subagent_type"], "general-purpose")

    def test_telemetry_record_carries_subagent_type_for_spawn_event(self):
        event = {"type": "subagent_spawn", "subagent_type": "general-purpose", "metadata": {}}
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertIsNone(record["subagent_id"])
        self.assertEqual(record["subagent_type"], "general-purpose")

    def test_telemetry_record_subagent_id_null_on_main_agent_call(self):
        event = {"type": "shell", "metadata": {"tool_name": "Bash"}}
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertIsNone(record["subagent_id"])
        self.assertIsNone(record["subagent_type"])


if __name__ == "__main__":
    unittest.main()
