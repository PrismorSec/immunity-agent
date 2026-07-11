"""Session-intent capture for framework SDK adapters (R2/R3).

The hook path synthesizes intent-scoped rules from the user's prompt at
``UserPromptSubmit`` (cli.py); enforcement then lives in ``evaluate_tool_call``,
which loads the session's scoped rules and blocks tool calls the stated goal
doesn't need. A deployed framework agent (OpenAI Agents / LangChain / CrewAI /
browser-use) never emits a prompt event, so it captured **no** intent — its tool
calls were checked against static policy only, never against "does this serve
what the user actually asked for?".

:func:`capture_intent` closes that gap: an adapter passes the agent's task/goal
(and its real tool names), and we synthesize + persist the *same* scoped ruleset
keyed to the session, so the identical intent-alignment enforcement applies to
headless agents. Idempotent per session (synthesized once), a no-op without a
goal, and never raises — intent capture must never break an agent's startup.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Fallback toolset (the Claude coding-agent tools) when an adapter doesn't supply
# its own tool names — keeps the synthesizer's scoping meaningful.
_DEFAULT_TOOLS = ["Bash", "Read", "Edit", "MultiEdit", "Write", "WebFetch", "WebSearch"]


def capture_intent(
    goal: Optional[str],
    *,
    workspace: Optional[Union[str, Path]],
    session_id: str,
    available_tools: Optional[List[str]] = None,
    agent: str = "",
) -> Optional[Dict[str, Any]]:
    """Synthesize + persist intent-scoped rules for a session from its goal.

    Returns the rules dict on success; None when there is no goal, rules were
    already captured for this session, or synthesis produced nothing. Never
    raises.
    """
    if not goal or not str(goal).strip():
        return None
    try:
        from prismor.runtime.scoped_agent import (
            load_scoped_rules,
            synthesize_scoped_rules,
            save_scoped_rules,
        )

        ws = Path(workspace) if workspace else Path.cwd()
        if load_scoped_rules(ws, session_id) is not None:
            return None  # already synthesized for this session — don't re-scope
        tools = [t for t in (available_tools or []) if t] or _DEFAULT_TOOLS
        rules = synthesize_scoped_rules(goal=str(goal), available_tools=tools, workspace=ws)
        if rules:
            save_scoped_rules(ws, session_id, rules)
        return rules
    except Exception:
        return None
