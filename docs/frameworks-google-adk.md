# Google Agent Development Kit (ADK) integration

Prismor adapter for Google's Agent Development Kit. Source lives at
[`adapters/google-adk/`](../adapters/google-adk/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: google-adk` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[google-adk]"
```

## Why this hook point

`before_tool_callback(tool, args, tool_context)`, set on
`LlmAgent(before_tool_callback=fn)` (or as a `BasePlugin` method — plugin-level
callbacks run first and take precedence over agent-level ones). Deny is by
**substitution**, not exception: returning `None` lets the real tool run;
returning a `dict` **skips** the real tool call entirely and that dict
becomes the tool's result instead — the model never sees the tool actually
execute.

## Use

```python
from google.adk.agents import LlmAgent
from prismor.google_adk import make_before_tool_callback

agent = LlmAgent(
    model="gemini-2.0-flash",  # or a LiteLlm-wrapped model, e.g. openai/gpt-4o-mini
    name="ops",
    tools=[run_shell],
    before_tool_callback=make_before_tool_callback(subject="user:alice", mode="enforce"),
)
```

A denied call returns `{"error": "⛔ Prismor blocked this tool call: ..."}`
as the substituted tool result by default; pass `raise_on_block=True` to
raise `PrismorBlocked` instead for a hard stop. `mode="observe"` is
log-only.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## Verified

Live-tested against a real `LlmAgent` running `openai/gpt-4o-mini` via ADK's
`LiteLlm` model wrapper (`pip install "google-adk[extensions]"`) with a
genuine OpenAI API key: a shell tool call matching a destructive-command
policy rule was denied before the tool's Python implementation ever ran; a
benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
