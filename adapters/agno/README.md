# prismor-agno

Prismor adapter for **Agno**. Every tool call is routed through Prismor's
shared policy pipeline (`prismor.runtime.runtime.evaluate_tool_call`) before
the tool runs — same engine, observe/enforce model, and per-user
attribution as the other adapters. Registry entry: `id: agno`.

## Why this hook point

Agno's real hook point is the `tool_hooks` list on `Agent`/`Team` — distinct
from the singular `pre_hook`/`post_hook`. Each hook is threaded into a
nested execution chain around the tool's entrypoint; Agno introspects the
hook's own signature and injects whichever of `function_name` /
`function_call` / `args` (or `arguments`) it declares. `function_call` is
the callable that continues the chain — not calling it means the real tool
never runs, and any exception raised propagates normally (confirmed against
source: the `try/finally` wrapper around hook calls only isolates
message-list state, it does not swallow exceptions).

## Install

```bash
pip install "prismor-agno[agno]"
```

## Use

```python
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from prismor_agno import prismor_tool_hook

agent = Agent(
    model=OpenAIChat(id="gpt-4o-mini"),
    tools=[run_shell],
    tool_hooks=[prismor_tool_hook],
)
```

Use `make_tool_hook(subject="user:alice", mode="enforce", ...)` instead of
the bare `prismor_tool_hook` to customize subject/workspace/mode. A denied
call raises `RuntimeError` by default (Agno surfaces this to the model as a
tool error); pass `raise_on_block=True` (via `make_tool_hook`) to raise
`PrismorBlocked` instead for a hard stop. `mode="observe"` is log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user.

## Verified

Live-tested against a real `Agent(model=OpenAIChat(id="gpt-4o-mini"))` with
a genuine OpenAI API key: a shell tool call matching a destructive-command
policy rule was denied before the tool's Python implementation ever ran; a
benign command executed normally.
