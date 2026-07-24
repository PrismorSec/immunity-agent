# prismor-google-adk

Prismor adapter for **Google Agent Development Kit (ADK)**. Every tool call
is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: google-adk`.

## Why this hook point

`before_tool_callback(tool, args, tool_context)`, set on
`LlmAgent(before_tool_callback=fn)` (or as a `BasePlugin` method — plugin-level
callbacks run first and take precedence over agent-level ones). Deny is by
**substitution**, not exception: returning `None` lets the real tool run;
returning a `dict` **skips** the real tool call entirely and that dict
becomes the tool's result instead — the model never sees the tool actually
execute.

## Install

```bash
pip install "prismor-google-adk[adk]"
```

## Use

```python
from google.adk.agents import LlmAgent
from prismor_google_adk import make_before_tool_callback

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

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user.

## Verified

Live-tested against a real `LlmAgent` running `openai/gpt-4o-mini` via ADK's
`LiteLlm` model wrapper (`pip install "google-adk[extensions]"`) with a
genuine OpenAI API key: a shell tool call matching a destructive-command
policy rule was denied before the tool's Python implementation ever ran; a
benign command executed normally.
