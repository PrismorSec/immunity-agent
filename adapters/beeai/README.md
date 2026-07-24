# prismor-beeai

Prismor adapter for **BeeAI Framework** (IBM Research / Linux Foundation).
Every tool call is routed through Prismor's policy engine before the tool
body runs — same observe/enforce model and per-user attribution as the
other adapters.

## Why this hook point

BeeAI tools are built around an `Emitter`. `Tool.run()` awaits
`context.emitter.emit("start", ToolStartEvent(input=..., options=...))`
*before* calling `self._run(...)`. Verified against source
(`beeai_framework.emitter.Emitter._invoke`): listener callbacks run as
tasks inside an `asyncio.TaskGroup`, which always awaits every task before
the surrounding `async with` block exits, and re-raises if any task
failed. A listener that raises therefore genuinely prevents the tool body
from ever running — this was checked directly against source rather than
assumed, after a different framework's documented "before execution" hook
turned out not to actually block (see the Mastra adapter's notes).

## Install

```bash
pip install "prismor[beeai]"      # Prismor runtime + adapter + beeai-framework
```

## Use

```python
from beeai_framework.tools.search.duckduckgo import DuckDuckGoSearchTool
from prismor.beeai import guard_tool

tool = guard_tool(DuckDuckGoSearchTool(), subject="user:alice", mode="enforce")
```

A denied call raises inside the `"start"` listener (a plain `RuntimeError`
by default, or `PrismorBlocked` if `raise_on_block=True`); BeeAI's tool
executor surfaces this as a tool error visible to the agent, and
`self._run(...)` is never reached. `guard_tools([...])` wraps a list of
tools in one call.

## Verified

Live-tested against a real BeeAI `ReActAgent` running `gpt-4o-mini` via
`beeai_framework.backend.chat.ChatModel` with a genuine OpenAI API key: a
destructive shell command was denied before the wrapped tool's `_run`
ever executed; a benign command executed normally.
