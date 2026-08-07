# Agentic AI Architecture Review

A structured checklist for reviewing the **design** of a multi-agent or
tool-using AI system — before it ships, when you add a new tool or agent, or
on a recurring cadence. It is a companion to [Attestation
Bundle](attestation-bundle.md#framework-coverage): `prismor attest coverage`
reports what your *runtime* policy already enforces at the tool-call boundary;
this checklist covers the design decisions a tool-call interceptor cannot see
at all — service account scope, memory store architecture, inter-agent trust,
approval-gate placement. Some findings here translate into a Prismor policy
rule. Others are architecture choices no runtime guard can retrofit.

Every category below cites a real control ID already used in this repo's own
framework packs (`prismor/runtime/checklists/*.yaml`) so the mapping between
"design review finding" and "runtime control" stays concrete instead of
aspirational.

## When to use this

- Before an agent gets its first tool, API credential, or system-command
  access.
- When a new agent joins an existing multi-agent pipeline (orchestrator/worker,
  swarm, hierarchical delegation).
- When an agent gains persistent memory (vector store, session database,
  scratchpad) that survives across sessions.
- Before a compliance review (SOC 2, ISO 27001, EU AI Act high-risk
  obligations) that now needs an AI risk assessment.
- On a recurring cadence for any agent with standing credentials or write
  access — tool lists and permissions drift upward over time if nobody prunes
  them.

## Review categories

### 1. Permission scope (`owasp-llm-top10:LLM06`, `owasp-agentic-t10:T03`)

**Design question:** does every agent identity hold only the tools and data
access its specific task requires, or does it inherit a broader credential
(the deploying user's session, a shared service account, an admin-scoped API
key)?

**Look for:**
- Tool registrations broader than the task (an agent that only needs to read
  a table also has write/delete).
- One service account or API key shared across multiple agents.
- Tool lists that grow without a pruning step — permission drift.

**Runtime backstop:** Prismor's `privilege-escalation` and
`agent-config-tampering` rules catch an agent trying to *use* excess privilege
at the tool-call boundary; they cannot tell you the privilege was
over-provisioned in the first place. Least-privilege scoping is a design-time
fix. See [IAM](iam.md) for per-agent identity and permission profiles, and
[Scoped Agent](scoped-agent.md) for session-scoped, task-derived
`allowed_tools`/`deny_tools`.

### 2. Tool input/output handling (`owasp-agentic-t10:T02`, `owasp-llm-top10:LLM05`)

**Design question:** do tool schemas validate inputs, or does the agent pass
free-form, model-generated strings straight into a shell, a SQL query, or a
filesystem path? Are tool *outputs* sanitized before they re-enter the agent's
context?

**Look for:**
- A SQL or shell tool that accepts a raw string instead of parameterized
  arguments.
- Filesystem tools where the path argument is fully agent-controlled.
- No validation on tool results before they're fed back into the next
  reasoning step (a compromised or malicious tool output becomes trusted
  context).

**Runtime backstop:** `destructive-command`, `remote-execution`, and
`model-manipulation` cover known-dangerous command and output-tampering
patterns at runtime. Schema-level input validation and output sanitization on
custom tools is not something a hook can add after the fact — it has to be
built into the tool.

### 3. Persistent memory integrity (`owasp-agentic-t10:ASI06`)

**Design question:** can an agent write to its own long-term memory (vector
store, conversation history, shared scratchpad) based on content it did not
author — a document it summarized, a page it browsed, another agent's
output? If so, is that memory trusted the same way on the next session?

**Look for:**
- Vector databases the agent both reads from and writes to with no source
  provenance tracked.
- Shared memory in multi-agent systems where any agent can write context
  another agent later treats as fact.
- No TTL or review cycle on memory entries sourced from untrusted input.

**Runtime backstop:** four checks, all category `memory_poisoning`, all
**warn** rather than block — legitimate project conventions and a poisoned
instruction can read identically without further context, so these are
detection signals to review, not a guarantee the memory is clean.

| Check | Fires on | Catches |
| --- | --- | --- |
| `memory-embedded-directive` | session start | a directive already sitting in project memory when the session opens |
| `memory-directive-on-write` | `file_write` | a directive being written into an instruction file mid-session, before it lands |
| `memory-file-drift` | session start | an instruction file whose content changed since the last session — no pattern required, so it catches phrasings no regex anticipates |
| `memory-self-reinforcement` | `file_write` | untrusted content read earlier this session being copied verbatim into durable memory |

The scanned set covers `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`,
`GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`
and `.mcp.json`. Agents without a session-start hook get the scan on the first
event of the session instead, so this is not Claude-only.

`memory-directive-on-write` also names the `memory_redact` transform: an org
that wants writes cleaned rather than flagged sets `action: modify` on that
rule in an overlay. It ships as `warn` because `modify` fails closed to DENY on
surfaces that cannot rewrite tool input.

Broader agent-memory stores (vector DBs, custom scratchpads) remain outside
this scope and need their own provenance/TTL design — a hook layer never sees
those writes, so they have to be guarded at the store boundary in application
code. These checks cover the memory surface a coding agent actually loads at
session start: the instruction files on disk.

### 4. Inter-agent trust boundaries (`owasp-agentic-t10:T03`)

**Design question:** in a multi-agent system, does a receiving agent verify
the identity and authorization of the agent that sent it a message, or does
it treat inbound agent-to-agent messages as trusted by default?

**Look for:**
- Orchestrator/worker or swarm patterns where inter-agent messages are plain
  text with no authentication envelope.
- A downstream agent that executes instructions embedded in an upstream
  agent's output without re-validating them as untrusted input.
- No documented trust model stating which agents may instruct which others,
  and for what operations.

**Runtime backstop:** none today — Prismor governs the tool-call boundary
between an agent and its host machine, not agent-to-agent message passing
inside a custom orchestration framework. This is a pure design review item:
treat every inbound inter-agent message the same way you'd treat untrusted
user input.

### 5. Data exfiltration paths (`owasp-llm-top10:LLM02`)

**Design question:** does any single agent have simultaneous access to
sensitive data (source code, credentials, PII, financial records) *and* a
tool that can send data somewhere external (HTTP requests, email, webhooks,
chat integrations)?

**Look for:**
- One agent session with both a database-read tool and a web-request tool.
- Tool parameters that accept arbitrary URLs, email addresses, or webhook
  endpoints — each is an exfiltration channel.
- Agent-generated markdown or HTML that renders external image URLs (a known
  encode-data-in-the-request-line pattern).

**Runtime backstop:** `secret-exfiltration`, `bulk-pii-exfiltration`,
`secret-in-url-params`, and `credential-in-header` catch known exfiltration
shapes in tool-call parameters. [Network Isolation](network-isolation.md)
lets you allowlist egress destinations so an unexpected webhook or raw-IP
target is blocked regardless of what triggered the call. Separating
data-reading agents from communication-capable agents is still a design
choice these controls only backstop, not replace.

### 6. Human-in-the-loop placement (`nist-ai-rmf:MANAGE-2.1`, `eu-ai-act:ART14`)

**Design question:** for actions that need a human sign-off, is the approval
gate enforced outside the agent's reach (a separate service), or can the
agent influence whether the gate fires — batching actions below a threshold,
rephrasing a request to look routine, or hitting a fail-open path when the
approval service is unavailable?

**Look for:**
- Approval thresholds stored somewhere the agent can write to.
- Batch operations that bundle several risky actions into one low-context
  approval request.
- A fail-open path: if the approval service is down, the action proceeds
  instead of halting.

**Runtime backstop:** Prismor's step-up approval subsystem is the
human-oversight control mapped to `nist-ai-rmf:MANAGE-2.1` and
`eu-ai-act:ART14` in the framework crosswalk — a rule set to require approval
halts execution until a human confirms, and fails closed if that confirmation
never arrives. Whether the *right* actions are gated at all is still a design
decision made in your policy, not something the runtime infers on its own.

### 7. Resource and cost bounds (`owasp-llm-top10:LLM10`, `owasp-agentic-t10:T04`)

**Design question:** does any agent or recursive agent-spawning pattern have
a hard ceiling on tokens, API calls, or spend per session, or can a reasoning
loop or adversarial input run unbounded?

**Look for:**
- No token or cost budget per agent session or per identity.
- Recursive agent spawning (agent creates sub-agents) with no depth limit.
- Retry logic without a maximum attempt count or backoff.

**Runtime backstop:** the `dos-resource-exhaustion` rule catches known
resource-exhaustion command patterns at the tool-call layer. Token/cost
budgets and recursion depth limits live in the agent framework or
orchestrator configuration and need to be set independently of any runtime
guard.

### 8. Agent identity and credential hygiene (`owasp-llm-top10:LLM02`, `soc2:CC6.1`)

**Design question:** does each agent instance have its own verifiable,
short-lived identity, or do multiple agents share one long-lived API key —
making it impossible to tell, after an incident, which agent did what?

**Look for:**
- A single static API key referenced by every agent in the deployment.
- Credentials embedded in agent configuration or environment variables with
  no rotation.
- Audit logs that record actions under a generic "agent" identity instead of
  a specific agent/session ID.

**Runtime backstop:** [IAM](iam.md) gives each agent a named identity and
least-privilege permission profile; the [Signed Audit
Trail](audit-trail.md) hash-chains every action Prismor observes to the
identity that took it, so a post-incident review isn't blocked on "which
agent was this." Prismor cannot invent per-agent identity if your deployment
never creates one — that has to exist upstream.

## After the review

Findings that map to an existing Prismor rule (see `map:` in
`prismor/runtime/checklists/crosswalk.v1.yaml`) become a policy check you can
verify stays enforced over time:

```bash
prismor attest coverage        # confirm the mapped controls are covered by an active rule
prismor attest                 # bundle posture + coverage + audit-trail anchor into one signed file
```

Findings with no runtime backstop (categories 3's memory-store architecture,
category 4, most of category 6 and 8) are design fixes: least-privilege
service accounts, signed inter-agent messages, fail-closed approval services,
per-agent credential issuance. Track them the same way you'd track any other
architecture debt — they won't show up in `prismor audit` until you build the
control that makes them visible.

## Limitations

This is a design checklist, not a scanner. It depends on you (or the agent
running it) actually reading the architecture, tool schemas, and
configuration — it cannot prove a control exists or a threat is absent when
the evidence is unavailable or runtime-only. Treat every finding as a
hypothesis to confirm against the real system, not a verdict.
