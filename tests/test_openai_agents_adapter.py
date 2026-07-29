"""Tests for the OpenAI Agents SDK adapter (adapters/openai-agents).

Exercises the adapter end to end against the real Prismor policy pipeline with no
live LLM: allow / observe / enforce, and per-user IAM scoping. The adapter wraps
a plain callable, so we drive it by calling the wrapped function directly.
"""
import sys
from pathlib import Path

import pytest

# The adapter ships as a separate distribution under adapters/; make it
# importable for the in-repo test without an editable install.
_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "openai-agents"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from prismor.openai import PrismorBlocked, prismor_guard  # noqa: E402

# The legacy flat module must stay importable and share the same objects, so
# isinstance checks work across old- and new-style imports.
import prismor_openai as _legacy  # noqa: E402
assert _legacy.PrismorBlocked is PrismorBlocked


def _make_tool():
    """A tool that records whether it actually ran."""
    calls = {"ran": 0, "last": None}

    def run_shell(command: str) -> str:
        calls["ran"] += 1
        calls["last"] = command
        return f"ran: {command}"

    return run_shell, calls


def test_safe_call_runs(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce")
    assert guarded(command="echo hello") == "ran: echo hello"
    assert calls["ran"] == 1


def test_enforce_blocks_destructive(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce")
    with pytest.raises(PrismorBlocked) as exc:
        guarded(command="rm -rf /")
    # Tool must NOT have executed.
    assert calls["ran"] == 0
    assert exc.value.decision is not None
    assert exc.value.decision.blocking is not None


def test_observe_never_blocks_but_records(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="observe")
    # Same dangerous input, but observe mode is log-only: the call proceeds.
    assert guarded(command="rm -rf /") == "ran: rm -rf /"
    assert calls["ran"] == 1


def test_no_raise_returns_decision(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)
    decision = guarded(command="rm -rf /")
    assert decision.allow is False
    assert decision.blocking is not None
    assert calls["ran"] == 0


def test_subject_tagged_on_findings(tmp_path):
    tool, _ = _make_tool()
    guarded = prismor_guard(
        tool, workspace=tmp_path, mode="enforce", subject="user:alice", raise_on_block=False
    )
    decision = guarded(command="rm -rf /")
    assert decision.subject is not None
    assert decision.subject.user_id == "alice"
    assert decision.blocking.get("subject", {}).get("user_id") == "alice"


def test_per_request_subject_context(tmp_path):
    # Guard with NO bound subject (the multi-tenant pattern): the per-request
    # context decides who the call is attributed to.
    from prismor.runtime.principal import use_subject

    tool, _ = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)

    with use_subject("user:dave"):
        decision = guarded(command="rm -rf /")
    assert decision.subject.user_id == "dave"
    assert decision.blocking.get("subject", {}).get("user_id") == "dave"

    with use_subject("user=erin;team=sre"):
        decision2 = guarded(command="rm -rf /")
    assert decision2.subject.user_id == "erin"
    assert decision2.subject.team_id == "sre"


def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    # bob is denied shell tools (Bash); other users have no profile → unrestricted.
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_per_user_iam_scoping(tmp_path, monkeypatch):
    # Ensure no ambient named-agent identity overrides subject-based selection.
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)

    tool, calls = _make_tool()

    # bob: has a deny-Bash IAM profile → a safe shell call is still blocked.
    bob = prismor_guard(tool, workspace=tmp_path, mode="enforce", subject="user:bob")
    with pytest.raises(PrismorBlocked):
        bob(command="echo hi")
    assert calls["ran"] == 0

    # alice: no IAM profile → same safe call is allowed.
    alice = prismor_guard(tool, workspace=tmp_path, mode="enforce", subject="user:alice")
    assert alice(command="echo hi") == "ran: echo hi"
    assert calls["ran"] == 1


try:
    import agents as _agents_sdk  # noqa: F401
    _HAS_AGENTS_SDK = True
except ImportError:
    _HAS_AGENTS_SDK = False


@pytest.mark.skipif(not _HAS_AGENTS_SDK, reason="openai-agents not installed")
class TestRealAgentSDK:
    """guard_agent's actual job is wrapping a real Agent's FunctionTool
    (on_invoke_tool) — the tests above only exercise prismor_guard's plain-
    callable fallback path, which is a different code path entirely. See
    PrismorSec/prismor#138."""

    def _make_ctx(self, tool_name="run_shell", agent=None):
        from agents.tool_context import ToolContext
        return ToolContext(context=None, tool_name=tool_name, tool_call_id="call_1", tool_arguments="{}", agent=agent)

    def test_guard_agent_wraps_real_function_tool(self, tmp_path):
        import asyncio
        import json
        from agents import Agent, function_tool
        from prismor.openai import guard_agent

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        agent = Agent(name="ops", tools=[run_shell])
        guard_agent(agent, workspace=tmp_path, mode="enforce", raise_on_block=True)
        tool = agent.tools[0]
        assert getattr(tool, "__prismor_guarded__", False)

        result = asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))
        assert result == "ran: echo hi"

        with pytest.raises(PrismorBlocked):
            asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "rm -rf /"})))

    def test_guard_agent_per_user_iam(self, tmp_path, monkeypatch):
        import asyncio
        import json
        from agents import Agent, function_tool
        from prismor.openai import guard_agent, use_subject

        monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
        _write_iam(tmp_path)

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        agent = Agent(name="ops", tools=[run_shell])
        guard_agent(agent, workspace=tmp_path, mode="enforce", raise_on_block=True)
        tool = agent.tools[0]

        with use_subject("user:alice"):
            result = asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))
        assert result == "ran: echo hi"

        with use_subject("user:bob"), pytest.raises(PrismorBlocked):
            asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))

    def test_handoff_call_carries_subagent_attribution(self, tmp_path, monkeypatch):
        """ctx.agent identifies the SDK's active agent for this call. When it
        differs from the top-level agent the tool was guarded under — a
        handoff or an agent-as-tool nested run — the event must carry
        subagent_id/subagent_type so telemetry attributes the action to the
        subagent that actually took it, not the primary agent."""
        import asyncio
        import json
        from agents import Agent, function_tool
        import prismor_openai as po

        captured = []
        real_evaluate = po.evaluate_tool_call

        def spy(*, event, **kwargs):
            captured.append(event)
            return real_evaluate(event=event, **kwargs)

        monkeypatch.setattr(po, "evaluate_tool_call", spy)

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        primary = Agent(name="primary", tools=[run_shell])
        po.guard_agent(primary, workspace=tmp_path, name="primary", mode="observe", raise_on_block=True)
        tool = primary.tools[0]

        # Call from the primary agent itself: no subagent.
        asyncio.run(tool.on_invoke_tool(self._make_ctx(agent=primary), json.dumps({"command": "echo hi"})))
        # Call from a handed-off-to / nested subagent: attributed.
        researcher = Agent(name="researcher")
        asyncio.run(tool.on_invoke_tool(self._make_ctx(agent=researcher), json.dumps({"command": "echo hi"})))

        assert len(captured) == 2
        primary_meta = captured[0]["metadata"]
        sub_meta = captured[1]["metadata"]
        assert primary_meta["subagent_id"] is None
        assert primary_meta["subagent_type"] is None
        assert sub_meta["subagent_type"] == "researcher"
        assert sub_meta["subagent_id"] is not None
