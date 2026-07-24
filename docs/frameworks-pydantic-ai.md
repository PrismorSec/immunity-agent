# Pydantic AI integration

Prismor adapter for Pydantic AI. Source lives at
[`adapters/pydantic-ai/`](../adapters/pydantic-ai/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: pydantic-ai` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[pydantic-ai]"
```

## Why this hook point

Pydantic AI's real interception point is a `WrapperToolset` subclass:
`call_tool(name, tool_args, ctx, tool)` is the single choke point every tool
call passes through — plain Python functions, MCP-server tools, or any
composed toolset. Not calling `super().call_tool(...)` means the wrapped tool
never runs — a genuine pre-execution deny gate, not an observe-only callback.

## Use

```python
from pydantic_ai import Agent
from pydantic_ai.toolsets import FunctionToolset
from prismor.pydantic_ai import guard_toolsets

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

## Per-user control

`subject` accepts a `Subject`, a `"user:alice"`-style string, or `None`
(resolved from `PRISMOR_SUBJECT` / the enrolled device at call time). It is
threaded into policy evaluation, IAM profile selection (`user:<id>` /
`team:<id>`), and telemetry — the same generic `Subject`/`resolve_subject`
plumbing every adapter uses, so per-user IAM profiles (`.prismor/iam.yaml`)
apply identically to LangChain, CrewAI, or any other adapter.

## Verified

Live-tested against a real `pydantic-ai` `Agent` running `openai:gpt-4o-mini`
with a genuine OpenAI API key: a shell tool call matching a `block_categories`
rule (e.g. `rm -rf /`) was denied before execution — the tool's Python
implementation never ran — while a harmless command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
