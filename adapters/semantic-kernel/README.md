# prismor-semantic-kernel

Prismor adapter for **Semantic Kernel** (Microsoft). Every LLM-initiated
function (tool) call is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the call runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: semantic-kernel`.

## Why this hook point

`kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, filter_fn)`
registers a filter of the form `filter_fn(context, next)`. Every registered
filter composes into a single middleware stack; the innermost link calls
`context.function.invoke(...)`. Simply not calling `await next(context)`
means that inner call — and therefore the real tool — never runs. This is
the cleanest gate-then-continue semantics of any framework Prismor
integrates with.

## Install

```bash
pip install "prismor-semantic-kernel[semantic-kernel]"
```

## Use

```python
from semantic_kernel import Kernel
from semantic_kernel.filters import FilterTypes
from prismor_semantic_kernel import make_filter

kernel = Kernel()
kernel.add_service(...)
kernel.add_plugin(MyPlugin(), plugin_name="tools")
kernel.add_filter(
    FilterTypes.AUTO_FUNCTION_INVOCATION,
    make_filter(subject="user:alice", mode="enforce"),
)
```

A denied call skips `next(context)` and sets a synthetic
`context.function_result` so the model still sees a coherent (denied) tool
response — the same UX as the other adapters' default behavior. Pass
`raise_on_block=True` to raise `PrismorBlocked` instead for a hard stop.
`mode="observe"` is log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user.

## Verified

Live-tested against a real `Kernel` with an `OpenAIChatCompletion` service
(`gpt-4o-mini`) and a genuine OpenAI API key: a plugin function call matching
a destructive-command policy rule was denied before the tool's Python
implementation ever ran; a benign command executed normally.
