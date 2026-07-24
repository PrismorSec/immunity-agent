# prismor-autogen-core

Prismor adapter for **AutoGen (Microsoft) Core runtime**. Every tool call is
routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: autogen-core`.

## Why this hook point (and its scope)

`autogen_core.tool_agent.tool_agent_caller_loop` / `ToolAgent` send each
model-requested tool call to the runtime as an individual
`runtime.send_message(FunctionCall, recipient=tool_agent_id)` call. Every
message sent through an `autogen-core` `AgentRuntime` passes through its
registered `InterventionHandler.on_send()` first — that's the real,
genuine pre-execution gate this adapter hooks.

**Scope caveat:** this only covers the low-level `autogen-core` runtime.
The high-level `AgentChat` `AssistantAgent` (what most AutoGen users
actually build with) does not route tool execution through this same
`send_message`/`ToolAgent` path, so this adapter does not cover
`AssistantAgent` usage — only code built directly on `autogen-core`
primitives (`SingleThreadedAgentRuntime`, `ToolAgent`,
`tool_agent_caller_loop`).

## Install

```bash
pip install "prismor[autogen-core]"      # Prismor runtime + adapter + autogen-core
```

## Use

```python
from autogen_core import SingleThreadedAgentRuntime, AgentId
from autogen_core.tool_agent import ToolAgent
from prismor.autogen_core import PrismorInterventionHandler

runtime = SingleThreadedAgentRuntime(
    intervention_handlers=[
        PrismorInterventionHandler(subject="user:alice", mode="enforce"),
    ],
)
await ToolAgent.register(runtime, "tool_agent", lambda: ToolAgent("tools", [run_shell_tool]))
runtime.start()
```

A denied call raises `autogen_core.tool_agent.ToolException` by default —
`tool_agent_caller_loop` specifically catches this exception type and
converts it into a failed `FunctionExecutionResult` fed back to the model,
so the conversation continues with the denial visible to the model (same
UX as the other adapters' default behavior). Pass
`drop_instead_of_raise=True` to return `DropMessage` instead (silently
cancels delivery with no result fed back). `mode="observe"` is log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user.

## Verified

Live-tested against a real `SingleThreadedAgentRuntime` + `ToolAgent` +
`tool_agent_caller_loop`, calling `openai:gpt-4o-mini` with a genuine
OpenAI API key: a shell tool call matching a destructive-command policy
rule was denied before the tool's Python implementation ever ran (the
model received a `ToolException`-derived failure result and reported the
denial), while a benign command executed normally.
