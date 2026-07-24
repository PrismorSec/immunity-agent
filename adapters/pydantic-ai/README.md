# prismor-pydantic-ai

Prismor adapter for **Pydantic AI**. Every tool call is routed through
Prismor's shared policy pipeline (`prismor.runtime.runtime.evaluate_tool_call`)
before the tool runs — same engine, observe/enforce model, and per-user
attribution as the other adapters. Registry entry: `id: pydantic-ai`.

## Why this hook point

Pydantic AI's real interception point is a `WrapperToolset` subclass:
`call_tool(name, tool_args, ctx, tool)` is the single choke point every tool
call passes through — plain Python functions, MCP-server tools, or any
composed toolset. Not calling `super().call_tool(...)` means the wrapped tool
never runs; this is a genuine pre-execution deny gate, not an
observe-only callback.

## Install

```bash
pip install "prismor-pydantic-ai[pydantic-ai]"
```

## Use

```python
from pydantic_ai import Agent
from pydantic_ai.toolsets import FunctionToolset
from prismor_pydantic_ai import guard_toolsets

toolset = FunctionToolset([run_shell, read_file])
agent = Agent(
    "openai:gpt-4o-mini",
    toolsets=guard_toolsets([toolset], subject="user:alice", mode="enforce"),
)
```

A denied call raises `pydantic_ai.exceptions.ToolFailed` by default — the
model sees a definitive failure and adapts, without consuming the tool's
retry budget the way `ModelRetry` would (this is a policy denial, not a
transient/correctable error). Pass `raise_on_block=True` to raise
`PrismorBlocked` instead for a hard Python-level stop. `mode="observe"` is
log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user.

## Verified

Live-tested against a real `pydantic-ai` `Agent` running `openai:gpt-4o-mini`
with a genuine OpenAI API key: a shell tool call matching a `block_categories`
rule (e.g. `rm -rf /`) was denied before execution — the tool's Python
implementation never ran — while a harmless command executed normally.
