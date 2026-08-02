"""Claude Code transcript adapter.

Claude Code writes one JSONL file per session under
``$CLAUDE_CONFIG_DIR/projects/<encoded-workspace>/<session-uuid>.jsonl``.
Records are line-delimited objects discriminated by ``type``; the ones that
matter here are:

``assistant``
    Carries ``message.content[]``. Blocks with ``{"type": "tool_use", "name":
    ..., "input": {...}}`` are the agent's tool calls — ``name``/``input`` map
    directly onto a hook payload's ``tool_name``/``tool_input``.

``user``
    When ``message.content`` is a plain string it is genuine user input, which
    replays as ``UserPromptSubmit``. When it carries ``toolUseResult`` it is a
    tool *result* — post-action, and deliberately skipped (see below).

Only pre-action payloads are emitted. `hooks._is_pre_action` gates
`should_block`, so replaying a tool result as if it were a tool call would both
misreport what the agent did and inflate the would-block count with actions the
agent had already completed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from prismor.runtime.transcripts.base import (
    DiscoveredSession,
    JsonlAdapter,
    env_root,
    home,
)


class ClaudeAdapter(JsonlAdapter):
    agent = "claude"
    label = "Claude Code"
    pattern = "**/*.jsonl"

    def roots(self) -> List[Path]:
        base = env_root("CLAUDE_CONFIG_DIR", home() / ".claude")
        return [base / "projects"]

    def workspace_for(self, path: Path) -> Optional[Path]:
        """Best-effort workspace from the encoded project directory name.

        Claude encodes the workspace path by replacing separators with dashes
        (``/Users/a/dev`` -> ``-Users-a-dev``), which is lossy: a directory
        whose own name contains a dash is indistinguishable from a separator.
        This is therefore only a hint — `record_to_payloads` prefers the
        authoritative ``cwd`` recorded on each event.
        """
        encoded = path.parent.name
        if not encoded.startswith("-"):
            return None
        return Path("/" + encoded[1:].replace("-", "/"))

    def record_to_payloads(
        self, record: Dict[str, Any], session: DiscoveredSession
    ) -> Iterator[Dict[str, Any]]:
        record_type = record.get("type")
        if record_type not in ("assistant", "user"):
            return

        session_id = str(record.get("sessionId") or session.session_id)
        base: Dict[str, Any] = {
            "session_id": session_id,
            "timestamp": record.get("timestamp"),
            "cwd": record.get("cwd"),
        }
        # A sidechain record is a tool call made inside a spawned subagent.
        # The transcript records that it *is* one but not which id/persona, so
        # only the fact is promoted — inventing an id would corrupt the
        # subagent attribution that live telemetry populates properly.
        if record.get("isSidechain"):
            base["agent_type"] = "sidechain"

        message = record.get("message")
        if not isinstance(message, dict):
            return
        content = message.get("content")

        if record_type == "user":
            # Tool results arrive as user records; they are post-action.
            if record.get("toolUseResult") is not None:
                return
            if isinstance(content, str) and content.strip():
                yield {
                    **base,
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": content,
                }
            return

        if not isinstance(content, list):
            return
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            tool_input = block.get("input")
            yield {
                **base,
                "hook_event_name": "PreToolUse",
                "tool_name": block.get("name") or "",
                "tool_input": tool_input if isinstance(tool_input, dict) else {},
            }
