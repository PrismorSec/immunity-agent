"""Best-effort token-usage accounting, fed by data already in the hook payload.

Two independent signals, since neither alone answers "where are my tokens
going":

- Real per-turn usage (input/output/cache tokens) is only available for
  Claude Code, via the ``transcript_path`` every hook payload carries — the
  transcript JSONL records the Anthropic API's ``usage`` object per assistant
  turn. This gives exact totals and a cache-hit rate. Other agents' hook
  payloads carry no pointer to their transcript, so no real usage for them.
- Tool-output size is a proxy for context cost that works for every agent
  (claude, codex, copilot, cursor, ...), because the tool result is already
  sitting in the normalized event with no extra data source needed. This
  answers "which tool call / file / command is actually bloating the
  conversation." Recorded on post events only — pre events carry the same
  content (e.g. the text of a Write) and would double-count it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime import store
from prismor.runtime.hooks import _is_pre_action

_TAIL_BYTES = 32_000
_LABEL_MAX = 200


def _tail_lines(path: str, tail_bytes: int = _TAIL_BYTES) -> List[str]:
    """Read the last ``tail_bytes`` of a file as lines.

    Transcripts grow unbounded over a long session; the usage entry we want
    is always near the end, so tailing avoids re-reading the whole file on
    every tool call.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            chunk = fh.read()
    except OSError:
        return []
    return chunk.decode("utf-8", errors="ignore").splitlines()


def _last_usage(transcript_path: str) -> Optional[Dict[str, Any]]:
    """Return the most recent assistant turn's real token usage, or None."""
    for line in reversed(_tail_lines(transcript_path)):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("message") if isinstance(entry, dict) else None
        if not isinstance(message, dict):
            continue
        usage = message.get("usage")
        if not usage:
            continue
        return {
            "message_id": message.get("id") or "",
            "model": message.get("model") or "",
            "input_tokens": usage.get("input_tokens") or 0,
            "output_tokens": usage.get("output_tokens") or 0,
            "cache_read_tokens": usage.get("cache_read_input_tokens") or 0,
            "cache_creation_tokens": usage.get("cache_creation_input_tokens") or 0,
        }
    return None


def _output_size(event: Dict[str, Any]) -> int:
    raw = (event.get("metadata") or {}).get("raw") or {}
    # Response key varies by agent: claude/codex use tool_response, copilot
    # toolResult, cursor output/stdout. Typed-event fields are the fallback.
    payload = (
        raw.get("tool_response") or raw.get("toolResult") or raw.get("tool_result")
        or raw.get("response") or raw.get("output") or raw.get("stdout")
        or event.get("response") or event.get("stdout") or event.get("content") or ""
    )
    if not isinstance(payload, str):
        try:
            payload = json.dumps(payload)
        except (TypeError, ValueError):
            payload = str(payload)
    return len(payload)


def record_from_event(*, workspace: Path, session_id: str, agent: str, event: Dict[str, Any]) -> None:
    """Called on every hook dispatch. Never raises — callers treat this as
    best-effort."""
    agent_event = str(event.get("agent_event", ""))
    metadata = event.get("metadata") or {}
    ts = event.get("ts") or ""

    if agent == "claude" and agent_event == "PostToolUse":
        transcript_path = (metadata.get("raw") or {}).get("transcript_path")
        if transcript_path:
            usage = _last_usage(transcript_path)
            if usage:
                store.record_token_usage(workspace=workspace, session_id=session_id, ts=ts, **usage)

    if _is_pre_action(agent_event):
        return
    # Cursor's normalizer has no tool_name; its event type (shell/file_write/…)
    # is the closest equivalent. Prompt and memory events aren't tool output.
    tool_name = metadata.get("tool_name") or event.get("type") or ""
    if tool_name in ("", "prompt", "memory"):
        return
    size = _output_size(event)
    if size > 0:
        store.record_tool_output_size(
            workspace=workspace,
            session_id=session_id,
            ts=ts,
            agent=agent,
            tool_name=tool_name,
            label=str(event.get("path") or event.get("command") or event.get("url") or "")[:_LABEL_MAX],
            size_chars=size,
        )
