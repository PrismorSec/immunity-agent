"""SDK adapters must redact the tool RESULT, not only screen the call.

PrismorSec/prismor#309: every adapter wrapped the call and none of them
touched the return value, so a tool that read a file with a hardcoded
credential in it handed that credential straight to the model — the exact
leak the mirror exists to stop, on the surface with no developer watching the
transcript.

Only the adapters whose framework is not needed at import time are driven
here (fake tool objects, real policy pipeline, no live LLM), which is enough
to prove the shared helper is wired at each return site. The two adapters that
structurally cannot redact — BeeAI's "start" listener, the Claude Agent SDK
PreToolUse hook — are asserted to have said so.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# conftest.py puts every adapters/<fw> dir on the path and extends
# prismor.__path__ with its shim, so these import from a bare checkout.
from prismor.runtime.redaction import redact_text, redact_tool_result

#: A token the data-boundary classifier recognises on its own, so the test
#: does not depend on a cloak store being registered in this workspace.
SECRET = "ghp_" + "A" * 36
LEAKY_OUTPUT = f"config.yaml:\n  github_token: {SECRET}\n"


def _is_masked(text: str) -> bool:
    return SECRET not in str(text)


def test_the_specimen_is_actually_redactable():
    """Guard the guard: if the classifier stops matching, every case below
    would pass vacuously by never having had anything to mask."""
    masked, changed = redact_text(LEAKY_OUTPUT)
    assert changed and _is_masked(masked)


# ── the shared helper ───────────────────────────────────────────────────────

def test_helper_walks_containers_and_objects():
    class Result:  # a framework result wrapper (browser-use ActionResult &c.)
        def __init__(self):
            self.extracted_content = LEAKY_OUTPUT
            self.error = None

    out = redact_tool_result({"content": [LEAKY_OUTPUT], "n": 1})
    assert _is_masked(out["content"][0]) and out["n"] == 1

    obj = Result()
    redact_tool_result(obj)  # objects are repaired in place
    assert _is_masked(obj.extracted_content) and obj.error is None


def test_helper_never_raises_and_never_fails_closed():
    """Best-effort by contract: a masking failure must not become an outage."""
    class Hostile:
        @property
        def __dict__(self):  # type: ignore[override]
            raise RuntimeError("boom")

    sentinel = Hostile()
    assert redact_tool_result(sentinel) is sentinel
    assert redact_tool_result(None) is None


def test_helper_terminates_on_a_self_referencing_result():
    class Node:
        def __init__(self):
            self.text = LEAKY_OUTPUT
            self.parent = None

    node = Node()
    node.parent = node  # a result that points back at its own container
    redact_tool_result(node)
    assert _is_masked(node.text)


# ── wrapper-style adapters ──────────────────────────────────────────────────

class _Tool:
    """A structured tool with .name + .func — the shape LangChain and CrewAI
    both wrap (and the shape their own test doubles already use)."""

    def __init__(self, fn):
        self.name = "read_config"
        self.func = fn


def _leaky(**kwargs):
    return LEAKY_OUTPUT


def test_langchain_redacts_the_result(tmp_path):
    from prismor.langchain import prismor_guard_tool

    tool = _Tool(_leaky)
    prismor_guard_tool(tool, workspace=tmp_path, mode="enforce")
    assert _is_masked(tool.func(path="config.yaml"))


def test_langchain_redacts_an_async_result(tmp_path):
    from prismor.langchain import prismor_guard_tool

    async def leaky(**kwargs):
        return LEAKY_OUTPUT

    tool = _Tool(None)
    tool.func = None
    tool.coroutine = leaky
    prismor_guard_tool(tool, workspace=tmp_path, mode="enforce")
    assert _is_masked(asyncio.run(tool.coroutine(path="config.yaml")))


def test_crewai_redacts_the_result(tmp_path):
    from prismor.crewai import prismor_guard_tool

    tool = _Tool(_leaky)
    prismor_guard_tool(tool, workspace=tmp_path, mode="enforce")
    assert _is_masked(tool.func(path="config.yaml"))


def test_openai_agents_redacts_a_plain_callable(tmp_path):
    from prismor.openai import prismor_guard

    def read_config(path: str) -> str:
        return LEAKY_OUTPUT

    guarded = prismor_guard(read_config, workspace=tmp_path, mode="enforce")
    assert _is_masked(guarded(path="config.yaml"))


def test_openai_agents_redacts_a_function_tool(tmp_path):
    from prismor.openai import prismor_guard

    async def on_invoke_tool(ctx, input_str):
        return LEAKY_OUTPUT

    tool = MagicMock()
    tool.name = "read_config"
    tool.on_invoke_tool = on_invoke_tool
    tool.__prismor_guarded__ = False

    prismor_guard(tool, workspace=tmp_path, mode="enforce")
    assert _is_masked(asyncio.run(tool.on_invoke_tool(None, '{"path": "config.yaml"}')))


def test_agno_redacts_the_result(tmp_path):
    from prismor.agno import make_tool_hook

    hook = make_tool_hook(workspace=tmp_path, mode="enforce")
    out = hook("read_config", lambda **kw: LEAKY_OUTPUT, {"path": "config.yaml"})
    assert _is_masked(out)


def test_browser_use_redacts_the_action_result(tmp_path):
    from prismor.browser_use import guard_controller

    ctrl = MagicMock()
    ctrl.registry = MagicMock()
    ctrl.registry.__prismor_guarded__ = False
    ctrl.registry.execute_action = AsyncMock(return_value=LEAKY_OUTPUT)

    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    out = asyncio.run(ctrl.registry.execute_action("extract_content", {"goal": "read it"}))
    assert _is_masked(out)


def test_google_adk_after_callback_substitutes_a_masked_response(tmp_path):
    from prismor.google_adk import make_after_tool_callback

    cb = make_after_tool_callback(workspace=tmp_path)
    replaced = cb(MagicMock(), {"path": "config.yaml"}, None, {"result": LEAKY_OUTPUT})
    # A dict return REPLACES the response; None would leave the leak in place.
    assert replaced is not None and _is_masked(replaced["result"])

    clean = {"result": "nothing to see"}
    assert cb(MagicMock(), {}, None, clean) is None


def test_redaction_does_not_disturb_a_clean_result(tmp_path):
    from prismor.langchain import prismor_guard_tool

    tool = _Tool(lambda **kw: "ran: ls -la")
    prismor_guard_tool(tool, workspace=tmp_path, mode="enforce")
    assert tool.func(path="x") == "ran: ls -la"


def test_a_denied_call_still_returns_the_denial_not_a_result(tmp_path):
    """Redaction sits on the allow path only — it must not swallow a block."""
    from prismor.langchain import prismor_guard_tool

    ran = []
    tool = _Tool(lambda **kw: ran.append(1) or LEAKY_OUTPUT)
    tool.name = "run_shell"
    prismor_guard_tool(tool, workspace=tmp_path, mode="enforce", approvals=False)
    out = tool.func(command="rm -rf /")
    assert "Prismor blocked" in str(out) and ran == []


# ── the surfaces that cannot ────────────────────────────────────────────────

@pytest.mark.parametrize("rel", [
    "adapters/beeai/prismor_beeai/__init__.py",
    "adapters/claude-agent-sdk/prismor_claude_agent_sdk/__init__.py",
])
def test_pre_action_only_adapters_say_so(rel):
    """These two hook a pre-action event and never see the output. Silently
    shipping them under a can_redact=True surface is how a capability ends up
    in the docs but not in the code."""
    text = (Path(__file__).resolve().parent.parent / rel).read_text()
    assert "RESULT REDACTION: not available here" in text
