# Inference-hook channel

Prismor's local hook screens one **tool call** on the machine where the agent
runs. This channel screens one **prompt turn** from a transcript that a model
provider hands to Prismor before the model sees it.

That reaches the surfaces a local hook cannot: a browser chat session, an
unmanaged laptop, anything with no Prismor install. It is the same policy engine
and the same rules — a different place to render them.

```
                     ┌──────────────────────────┐
  local hook  ──────▶│                          │
  SDK adapters ─────▶│   evaluate_tool_call()   │──▶ Decision
  MCP gateway ──────▶│    (one policy engine)   │
  inference hook ───▶│                          │
                     └──────────────────────────┘
```

## What it screens, and what it does not

| | Local hook | Inference-hook channel |
|---|---|---|
| Grain | One tool call, before it runs | One prompt turn, before the model sees it |
| Sees | The real shell command, the real path | The transcript the provider sends |
| Reaches | Machines with Prismor installed | Any surface the provider routes through the hook |
| Verdicts | block · step_up · defer · modify · allow | allow · deny |
| Data | Stays on the machine | **The transcript transits this server** |

That last row is the one to be deliberate about. In local mode Prismor sees the
call and keeps it local. Here the provider sends you prompts, attachments and
tool output — potentially the PII and secrets you deployed this to catch. Run
this channel with the retention, regional-processing and encryption posture that
implies, and tell your users which mode they are on.

## Running it

```bash
prismor inference-hook-server --host 0.0.0.0 --port 7072 --config channel.json
```

| Flag | Default | Purpose |
|---|---|---|
| `--port` | `7072` | Port to listen on |
| `--host` | `127.0.0.1` | Bind address |
| `--workspace` | cwd | Workspace whose policy applies |
| `--api-key` | `$PRISMOR_INFERENCE_HOOK_KEY` | Single-tenant bearer key |
| `--config` | `$PRISMOR_INFERENCE_HOOK_CONFIG` | Per-org keys + posture (below) |

The bundled server is Python's stdlib `ThreadingHTTPServer`. That is the right
shape for a sidecar and for running the channel end to end locally. Hosting it
as a multi-tenant service on the critical path of real users wants an ASGI app
behind a front door that terminates TLS, rate-limits per org, and autoscales —
the evaluation core (`prismor/runtime/inference_hook.py`) is framework-free
precisely so that is a re-host rather than a rewrite.

### Endpoints

**`POST /v1/inference-hook`** — transcript in, verdict out.

```jsonc
{
  "session_id": "conv_123",
  "system": "You are a helpful assistant.",
  "messages": [
    {"role": "user",      "content": [{"type": "text", "text": "..."}]},
    {"role": "assistant", "content": [{"type": "tool_use", "id": "t1",
                                       "name": "Bash", "input": {"command": "ls"}}]},
    {"role": "user",      "content": [{"type": "tool_result", "tool_use_id": "t1",
                                       "content": "..."}]}
  ],
  "attachments": [{"name": "customers.csv", "text": "..."}]
}
```

`content` also accepts a plain string. A turn with **no tool call at all** is
valid — that is the common case and the thing `/v1/evaluate` cannot express.

```jsonc
{
  "decision": "deny",          // also mirrored as "allow": false / "action": "deny"
  "reason": "[HIGH] Detects SSN, credit card numbers, ... (pii-exposure)",
  "user_facing_reason": "...", // same string, under the explicit name
  "prismor": {
    "basis": "policy",         // policy | fail_closed | fail_open | empty
    "rule_id": "pii-exposure",
    "category": "pii_exposure",
    "severity": "HIGH",
    "finding_count": 1,
    "events_evaluated": 3,
    "transcript_truncated": false,
    "approval_id": null,
    "downgraded_action": null,
    "eval_ms": 42
  }
}
```

The binary verdict is stated three compatible ways because the field name a
given provider reads is not something Prismor controls; Prismor's own detail is
nested under `prismor` where it cannot collide. **The reason string carries the
rule, never the evidence** — the evidence is the card number that matched, and
this string is shown to an end user and logged by the provider.

**`GET /health`** — unauthenticated liveness. Returns `503` when the channel
config is unusable, so a load balancer pulls the instance rather than letting it
deny everybody's traffic.

## Configuration

```jsonc
{
  "defaults": {
    "fail_open": false,
    "timeout_s": 3.0,
    "deny_categories": ["pii_exposure", "secret_exfiltration", "secret_access",
                        "prompt_injection", "prompt_injection_semantic"]
  },
  "orgs": {
    "org_acme":  {"api_key": "..."},
    "org_globex": {"api_key": "...", "fail_open": true, "timeout_s": 1.5}
  }
}
```

The org is resolved **from the key that authenticated**, never from a body
field — otherwise any valid caller could request another org's posture by
changing a string. Unknown or missing keys get `401`.

| Key | Default | Meaning |
|---|---|---|
| `fail_open` | `false` | Verdict when screening cannot complete |
| `timeout_s` | `3.0` | Wall-clock budget for one turn |
| `deny_categories` | see below | Categories this channel denies on regardless of rule mode |
| `mode` | `enforce` | `observe` reports without denying |
| `step_up_verdict` / `defer_verdict` / `modify_verdict` | `deny` | `allow` to soften |
| `enqueue_approvals` | `true` | Queue step_up/defer for out-of-band approval |
| `max_transcript_chars` | `2_000_000` | Scan budget per request |

### `deny_categories` — why this channel has a floor

Most content rules ship as `warn`. On the local channel that is right: a
developer is watching a terminal, the tool call is still in front of them, and a
warning is information they can act on. Here there is no terminal and no second
chance — the turn either reaches the model or it does not, so a warning is
indistinguishable from an allow.

So this channel denies on the categories that are its reason to exist, even when
the active policy only rates them `warn`:

```
pii_exposure · secret_exfiltration · secret_access
prompt_injection · prompt_injection_semantic
```

Findings outside that set still follow the engine's own verdict. Set
`deny_categories` to `[]` to turn the floor off entirely and defer wholly to
policy — detection still runs and still reports, it just stops denying.

### Fail posture

Default is **fail-closed**: a timeout, a crash, an unparseable body or an
unreadable config denies the turn. There is a real cost to that — this server is
on the critical path of somebody's prompt, so failing closed means their model
stops working while you are down. Failing open means they are briefly unguarded.
Neither is right for everyone, which is why the default is the safe one and
changing it is an explicit per-org decision.

There is no path that returns a naked `500`.

## How a transcript becomes a decision

1. **Fan out.** The transcript maps onto the canonical events the engine already
   understands. `tool_use` blocks go through the *same* normalizer the local
   Claude hook uses, so `Bash` → `shell`, `Read` → `file_read`,
   `WebFetch` → `network`, `mcp__server__tool` → MCP classification — rather
   than a second mapping that drifts from the first. Prompts, the system prompt,
   attachments and `tool_result` blocks become `prompt` / `tool_result` events.
2. **Replay.** Each event runs through `evaluate_tool_call(persist=False)`, in
   transcript order.
3. **Reduce.** Deny wins: if any event denies, the turn denies, and the first
   denial is the one explained. Evaluation continues so the receipt records
   everything the turn tripped, not just the first thing.

### Taint without a local box

Session taint — "this session read something poisoned, so escalate what it does
next" — normally lives in a per-session file on the machine. There is no such
machine here, and a shared store keyed across tenants is state nobody wants to
own.

Instead taint is **reconstructed by replay**. The provider re-sends the whole
transcript every turn, so the events share one `InMemoryTaintStore` for the life
of the request and it is then discarded. An injection found in an earlier
`tool_result` still escalates a later `network` call in the same turn, exactly
as the on-disk store would across hook calls — with nothing persisted and no
cross-tenant state to leak.

Nothing about a request is written to the workspace: no session events, no
snapshot, no agent inventory.

### Verdict mapping

| Prismor | This channel |
|---|---|
| `allow` | allow |
| `block` | deny, with the rule as the reason |
| `step_up` | deny **now**, and queue an approval request out-of-band |
| `defer` | deny **now**, and queue out-of-band |
| `modify` | not expressible — resolved per `modify_verdict`, always logged |

`step_up` cannot mean "wait for a human" here: the answer is due in seconds, and
nobody approves that fast. So the turn is denied and the request is queued for
the approver; once granted, the user retries. `modify` has nowhere to go at all —
the prompt is the provider's to send, not Prismor's to rewrite — so it is
resolved by config and logged loudly, because a policy quietly losing its
remediation is worse than a policy that denies.

## Receipts

Each turn appends one signed record to the audit trail, alongside local
decisions, so both channels land in one pane of glass.

One honest caveat: there is no enrolled device on this path. Records carry a
null `device_id` and `"attestation": "service"` — they attest that *this service*
reached this verdict, not that a known machine did. That is genuinely weaker
non-repudiation than the local channel, and it is left visible in the record
rather than papered over.

## Semantic guard

The guard's default `hybrid` mode shells out to a local Claude CLI. On a laptop
that is the point; on a hosted host there is no CLI and no per-user session, so
it fails every call and silently degrades to nothing.

Set `settings.semantic_guard.mode` to `api` (needs `ANTHROPIC_API_KEY`) or
`heuristic` for this channel. The server checks this at startup and warns.

## See also

- [Prismor runtime](prismor-runtime.md) — the policy model and rule schema
- [Audit trail](audit-trail.md) — receipt signing and the hash chain
- [Semantic guard](semantic-guard.md) — the injection classifier
- [MCP gateway](mcp-gateway.md) — the other inbound-server channel
