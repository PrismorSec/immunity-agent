"""Prismor adapter for BeeAI Framework (IBM Research / Linux Foundation).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

BeeAI's real hook point is a tool's own ``Emitter``: ``Tool.run()`` awaits
``context.emitter.emit("start", ToolStartEvent(input=..., options=...))``
*before* calling ``self._run(...)``. Verified against source
(``beeai_framework.emitter.Emitter._invoke``): listener callbacks run as
tasks inside an ``asyncio.TaskGroup``, which always awaits every task
before the surrounding ``async with`` block exits and re-raises if any
task failed — so a listener that raises genuinely prevents the tool body
from ever running, not just an after-the-fact observation. (This was
checked carefully rather than assumed, after finding a *different*
framework's documented "before execution" hook did NOT actually block in
practice — see the Mastra adapter's notes.)

RESULT REDACTION: not available here. The other adapters wrap the tool's
entrypoint and so hold its return value; this one attaches a listener to a
"start" event and never sees the output, so a credential in an allowed tool's
result is out of reach on this surface (see contract.SURFACES["sdk-adapter"]).

Easy path::

    from prismor.beeai import guard_tool

    tool = guard_tool(RunShellTool(), subject="user:alice", mode="enforce")
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from beeai_framework.emitter.types import EmitterOptions

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["guard_tool", "guard_tools", "PrismorBlocked"]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


class PrismorBlocked(Exception):
    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _payload(tool_input: Any) -> str:
    try:
        data = tool_input.model_dump() if hasattr(tool_input, "model_dump") else dict(tool_input)
    except Exception:
        return str(tool_input)
    return " ".join(str(v) for v in data.values()).strip()


def guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "beeai",
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
) -> Any:
    """Attach a Prismor policy check to a BeeAI tool's "start" event.

    A denied call raises inside the listener, which the tool's Retryable
    executor surfaces as a tool error (visible to the agent/model) --
    self._run() is never reached. Returns the same tool object.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"beeai-{os.getpid()}"
    tool_name = getattr(tool, "name", tool.__class__.__name__)

    async def on_start(data: Any, event: Any) -> None:
        field = _TYPE_FIELD.get(event_type, "command")
        payload_event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(data.input),
            "metadata": {
                "tool_name": tool_name,
                "framework": "beeai",
                "raw_input": str(data.input),
            },
        }
        decision: Decision = evaluate_tool_call(
            event=payload_event, workspace=ws, agent=agent, mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            raise RuntimeError(f"⛔ Prismor blocked this tool call: {reason}")

    tool.emitter.on("start", on_start, EmitterOptions(is_blocking=True))
    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Any, **kwargs: Any) -> Any:
    """Guard a list of BeeAI tools in one call. Returns the same list."""
    return [guard_tool(t, **kwargs) for t in tools]
