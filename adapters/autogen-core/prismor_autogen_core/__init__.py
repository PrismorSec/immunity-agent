"""Prismor adapter for AutoGen (Microsoft) — Core runtime.

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

CAVEAT (kept from the roadmap entry): this hooks the low-level
``autogen-core`` runtime, specifically the path used by
``autogen_core.tool_agent.tool_agent_caller_loop`` /
``autogen_core.tool_agent.ToolAgent``. Tool calls reach the ``ToolAgent``
as individual ``runtime.send_message(FunctionCall, recipient=tool_agent_id)``
calls, which is exactly the point an ``InterventionHandler.on_send`` sees.
The high-level ``AgentChat`` ``AssistantAgent`` (what most AutoGen users
actually build with) does not route tool execution through this same path,
so this adapter does not cover ``AssistantAgent`` usage.

Easy path::

    from autogen_core import SingleThreadedAgentRuntime
    from prismor.autogen_core import PrismorInterventionHandler

    runtime = SingleThreadedAgentRuntime(
        intervention_handlers=[PrismorInterventionHandler(subject="user:alice", mode="enforce")],
    )
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from autogen_core import DefaultInterventionHandler, DropMessage, FunctionCall
from autogen_core.tool_agent import ToolException

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["PrismorInterventionHandler", "PrismorBlocked"]

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


def _payload(arguments: str) -> str:
    try:
        parsed = json.loads(arguments)
        if isinstance(parsed, dict):
            return " ".join(str(v) for v in parsed.values()).strip()
    except (json.JSONDecodeError, TypeError):
        pass
    return str(arguments)


class PrismorInterventionHandler(DefaultInterventionHandler):
    """InterventionHandler that policy-checks every FunctionCall on_send()
    before it reaches the ToolAgent. This is autogen-core's real hook: any
    message sent through the runtime passes through on_send() first, and
    returning DropMessage or raising cancels delivery."""

    def __init__(
        self,
        *,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "autogen-core",
        mode: str = "enforce",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        drop_instead_of_raise: bool = False,
    ) -> None:
        self._subject = subject
        self._ws = Path(workspace) if workspace else Path.cwd()
        self._agent = agent
        self._mode = mode
        self._sid = session_id or f"autogen-core-{os.getpid()}"
        self._event_type = event_type
        self._drop = drop_instead_of_raise

    async def on_send(self, message: Any, *, message_context: Any, recipient: Any) -> Any:
        if not isinstance(message, FunctionCall):
            return message  # not a tool call -- pass through untouched

        field = _TYPE_FIELD.get(self._event_type, "command")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": self._sid,
            "agent": self._agent,
            "agent_event": "PreToolUse",
            "type": self._event_type,
            field: _payload(message.arguments),
            "metadata": {
                "tool_name": message.name,
                "framework": "autogen-core",
                "call_id": message.id,
                "recipient": str(recipient),
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event,
            workspace=self._ws,
            agent=self._agent,
            mode=self._mode,
            session_id=self._sid,
            subject=resolve_subject(self._subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if self._drop:
                return DropMessage
            # ToolException is caught specifically by tool_agent_caller_loop
            # and converted into a failed FunctionExecutionResult fed back to
            # the model -- the conversation continues with the denial visible
            # to the model, same UX as the other adapters' default behavior.
            raise ToolException(
                call_id=message.id,
                content=f"⛔ Prismor blocked this tool call: {reason}",
                name=message.name,
            )
        return message
