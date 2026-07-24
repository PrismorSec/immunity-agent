# OpenAI Agents SDK integration

Prismor controls tool use in **production framework agents**, not just
coding agents. Framework agents (OpenAI Agents SDK, CrewAI, LangChain) expose no
hook-config files, so the control point is an **in-process SDK adapter**: a thin
wrapper around tool execution that routes every call through the same
`prismor.runtime.runtime.evaluate_tool_call` pipeline a local coding-agent hook uses.

The OpenAI Agents SDK adapter's source lives at
[`adapters/openai-agents/`](../adapters/openai-agents/), bundled into the
main `prismor` package (no separate PyPI package). Registry entry:
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml)
(`id: openai-agents`).

## Install

```bash
pip install "prismor[openai-agents]"
```

> Needs `prismor >= 1.14.2`. Until that version is on PyPI, the same one-liner
> works from source: `pip install "prismor[openai-agents] @ git+https://github.com/PrismorSec/prismor.git@main"`.

## Guard an agent (easy path)

```python
from agents import Agent, function_tool
from prismor.openai import guard_agent

@function_tool
def run_shell(command: str) -> str:
    ...

agent = Agent(name="ops", tools=[run_shell])
guard_agent(agent)          # every tool now policy-checked
```

To guard a single tool or a plain callable, use
`prismor_guard(tool, subject="user:alice")`. A denied call raises `PrismorBlocked`
(or, with `raise_on_block=False`, returns the `Decision`); `guard_agent` defaults
to returning a denial string to the model so the run recovers gracefully.
`mode="observe"` is log-only — findings are still recorded, the call proceeds.

## Per-user control (multi-tenant)

The production differentiator: **one deployed agent serves many users**, and each
tool call is attributed to the end-user, not the host device. Guard the agent
once with no bound subject, then set the user per request:

```python
from prismor.openai import use_subject

guard_agent(agent)                       # once, at startup

with use_subject("user:alice"):          # in your per-request handler
    Runner.run_sync(agent, prompt)       # alice's policy + IAM apply
```

`subject` / `use_subject` accept a `Subject`, a string (`"user:alice"`,
`"user=alice;team=data"`), or `None`. Resolution order: explicit arg →
`use_subject` context → `PRISMOR_SUBJECT` → device identity → anonymous (see
[`prismor/runtime/principal.py`](../prismor/runtime/principal.py)). The subject is threaded into
policy evaluation, **IAM** profile selection (`user:<id>` / `team:<id>` profiles
in `iam.yaml`), and telemetry — same agent, different rules per user, no code
changes.

> Verified live: one guarded agent, same safe command — `user:alice` allowed,
> `user:bob` (denied shell tools by IAM) blocked, switched purely via `use_subject`.

## Event mapping

| Concern | Mechanism | Code |
|---|---|---|
| Interception | wrap the callable | `prismor_guard(tool)` |
| Canonical event | `{type, agent, command/path/url, metadata}` | `build_event()` |
| Decision | `evaluate_tool_call(...) → Decision` | [`prismor/runtime/runtime.py`](../prismor/runtime/runtime.py) |
| Block | raise `PrismorBlocked` | adapter wrapper |
| Per-user | `Subject` | [`prismor/runtime/principal.py`](../prismor/runtime/principal.py) |

By default events are emitted as `type: shell`, so `destructive-command`,
`secret-exfiltration`, and the rest of the policy apply to tool arguments. For
tools whose risk is a path, URL, or output, pass `event_type="file_write"` /
`"network"` / `"tool_result"` and a `command_builder`.

## Reference

| Symbol | Purpose |
|---|---|
| `guard_agent(agent_obj, **kwargs)` | Guard all FunctionTools on an Agent in one call |
| `prismor_guard(tool, **kwargs)` | Guard a single tool or callable |
| `use_subject(value)` | Per-request subject contextmanager |
| `PrismorBlocked` | Raised on enforce-mode block (when `raise_on_block=True`) |
| `build_event(...)` | Build a canonical event dict for custom hook points |

All functions accept: `subject`, `workspace`, `agent`, `mode`, `session_id`,
`event_type`, `command_builder`, `raise_on_block`. See
[`adapters/openai-agents/`](../adapters/openai-agents/) for full signatures.

## Other frameworks

- [LangChain / LangGraph](frameworks-langchain.md) — `guard_tools([...])`, `PrismorCallbackHandler`
- [CrewAI](frameworks-crewai.md) — `guard_tools([...])`, BaseTool and structured tool support
- [browser-use](frameworks-browser-use.md) — `guard_controller(controller)`, network/file/shell event mapping
- [All frameworks — UX overview](frameworks-overview.md)
