# LLM Gateway

`prismor gateway llm` is the **model lane** of the Prismor data plane. Where
[`prismor gateway mcp`](./mcp-gateway.md) governs the *tools* an agent calls,
this governs the *model* it calls: a local HTTP proxy you point an SDK at
instead of `api.anthropic.com` or `api.openai.com`.

Both lanes run the same policy engine as the PreToolUse hooks, emit to the
same control plane, and share a session id — so an agent's tool calls and its
model calls land on one trace.

## What routing through it buys

- **Policy.** Every request is evaluated as a `network` event carrying the
  outbound payload, so your egress allowlist, secret-in-payload rules, and
  taint escalation apply to model traffic with no new rules to write. A
  blocked call is refused *before* egress — the provider never sees the body.
- **Credential brokering.** The real provider key lives on the gateway, not on
  the laptop. Clients can send a Cloak placeholder (`@@SECRET:name@@`), a
  dummy value, or nothing at all.
- **Metering.** Token counts and cost come from the provider's own usage
  accounting, attributed per session and agent, and flushed as `llm_usage`
  telemetry through the same uploader (and offline spool) as every other
  record.
- **Response scanning.** The completion is re-evaluated as untrusted content
  before it is returned, so a poisoned or compromised upstream cannot inject
  directives into context.

## Quick start

```bash
# The gateway holds the real key; nothing else needs it.
export ANTHROPIC_API_KEY=sk-ant-...
prismor gateway llm --port 8787 --mode enforce
```

Point your SDK at it — only the base URL changes:

```python
from anthropic import Anthropic

client = Anthropic(base_url="http://127.0.0.1:8787", api_key="unused")
client.messages.create(model="claude-sonnet-5", max_tokens=256,
                       messages=[{"role": "user", "content": "hello"}])
```

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/openai
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic
```

## Provider routing

With no `--provider`, the gateway picks per request:

| Request path | Routed to |
|---|---|
| `/anthropic/...`, `/openai/...` | that provider (explicit prefix wins) |
| `/v1/messages`, `/v1/complete` | Anthropic |
| `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings` | OpenAI |

Pin a single provider with `--provider anthropic` to accept native paths
without a prefix. `--base-url` overrides the upstream entirely (self-hosted
or already-proxied providers).

## Streaming

SSE is a first-class path. Bytes are relayed to the client as they arrive —
no buffering, no added time-to-first-token — while a tap accumulates just
enough to recover the usage block and the assistant text. Because usage is
only knowable at the end of a stream, the response scan on a streamed call is
necessarily post-hoc; the pre-call policy check has already run, and the scan
result still lands in telemetry.

## Cost

Cost is estimated from a built-in table of USD per 1M tokens, matched by
longest model-id prefix, with cache reads discounted and cache writes at a
premium. An unknown model falls back to a conservative non-zero rate — a
silent `$0` would read as "this model is free". Override per deployment:

```bash
prismor gateway llm --pricing ./pricing.json
```

```json
{ "pricing": { "claude-sonnet": [3.0, 15.0], "our-finetune": [0.5, 1.5] } }
```

The gateway's job here is attribution and trend, not invoicing — reconcile
against your provider bill for accounting.

## Operating

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness, session id, mode |
| `GET /metrics` | in-process call count, token totals, cost, pending records |

`--mode observe` (default) logs verdicts without blocking; `--mode enforce`
blocks, and fails **closed** if the policy engine itself errors. Denials are
returned in the provider's own error shape (HTTP 403) so the SDK on the other
side surfaces a readable refusal rather than crashing.

Bind stays on `127.0.0.1` unless you set `--host`. Exposing the gateway on a
routable address makes it a credential-bearing egress point for anything that
can reach it — put it behind an authenticating proxy first.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--port` | `8787` | listen port |
| `--host` | `127.0.0.1` | loopback only by default |
| `--provider` | auto-detect | `anthropic` \| `openai` |
| `--base-url` | provider default | override upstream |
| `--mode` | `observe` | `observe` \| `enforce` |
| `--session-id` | fresh per process | env fallback `PRISMOR_SESSION_ID`; set it to join a hook session's trace |
| `--agent-name` | `llm-gateway` | instance label in telemetry |
| `--pricing` | built-in table | JSON cost override |
| `--flush-interval` | `30` | seconds between usage flushes |
