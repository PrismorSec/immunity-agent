# Tool Tags & Tag Rules (policy as code)

Every tool an agent can call — built-in, shell, or MCP — carries zero or more
**tags** describing what it does: `untrusted_content` (reads
attacker-influenceable input), `critical_action` (sends / publishes / destroys
externally), or any tag you define (`private_data`, `external_comms`, …).
**Tag rules** then declare which tag combinations a single session must never
complete — the classic "lethal trifecta" (read untrusted content, then act
externally) is just the default rule.

The call that *completes* a forbidden combination is blocked before it
executes. Everything is observable first (`mode: observe`), then enforceable.

## How a tool gets its tags (precedence)

| Tier | Source | Who controls it |
|------|--------|-----------------|
| 1 | Explicit map — `tool_tags.tags` in policy (exact, glob, or regex) | You / org admin |
| 2 | Server-declared — `_meta.prismor.tags` on the MCP tool definition, read by `prismor mcp-gateway` | MCP server author |
| 3 | Built-in defaults — well-known tools (`WebFetch`, `mcp__*__send_email`, …) | Prismor |
| 4 | Inference — from the event type (`file_write` → critical, `tool_result` → untrusted, …) | Prismor |

The first non-empty tier wins, so an admin's explicit tag always beats a
server's self-declaration, which beats generic globs. Nothing is ever left
completely untagged unless you disable tiers 3–4.

Check what resolved where:

```console
$ prismor tags list
TOOL                        TAGS                 TIER
Bash                        critical_action      inference
WebFetch                    untrusted_content    default
mcp__crm__read_customers    private_data         _meta
mcp__Gmail__send_email      critical_action      explicit
```

### Declaring tags from an MCP server (`_meta`)

If you author an MCP server, self-declare tags on each tool definition and the
gateway picks them up automatically — no spreadsheet, no manual mapping:

```json
{
  "name": "read_customers",
  "inputSchema": { "type": "object" },
  "_meta": { "prismor": { "tags": ["private_data"] } }
}
```

Also honored: `_meta.tags` and `annotations["prismor/tags"]`. Tags are
sanitized (lowercase, `[a-z0-9][a-z0-9_.-]*`, max 8) — a server can suggest
tags but can never override the org map or inject arbitrary strings.
Disable the tier with `meta_tags_enabled: false`.

## The rule language

One rule per line. Three connectors with fixed precedence
(`with` binds tightest, then `or`, then `then`):

```
rule    :=  disj ( then disj )*  [ -> block|warn ]
disj    :=  conj ( or conj )*
conj    :=  TAG ( with TAG )*
```

- **`with`** — unordered co-occurrence: both tags appearing anywhere in the
  session is enough.
- **`or`** — alternatives at the same position: any one satisfies that step
  (e.g. `send_email or post_message` = either critical action).
- **`then`** — ordered sequence: the left step must occur *before* the right.
- **`-> block`** (default) or **`-> warn`** — warn logs the finding but never
  blocks, even in enforce mode.
- The call completing the **final step** is the one blocked/warned.
- `not`, `within`, `count` are reserved for future use.

An `or` rule expands to its **variants** (one alternative per step) and fires
when any variant completes — so `untrusted_content then send_email or
post_message` is exactly `untrusted_content then send_email` **and**
`untrusted_content then post_message` folded into one rule. Every alternative
must still be a real combination (two tags, or two ordered steps): a bare
`a or b` is rejected, since it would fire on a single tag.

```yaml
settings:
  tool_tags:
    enabled: true
    mode: enforce            # observe (log only) | enforce (terminal block)
    tags:
      mcp__Gmail__read_email: [untrusted_content]
      mcp__Gmail__send_email: [critical_action]
      mcp__crm__*: [private_data]
    rules:
      - "untrusted_content then critical_action -> block"
      - "untrusted_content then private_data then external_comms -> block"
      - "web_read with secrets_access -> warn"
```

More examples:

```
untrusted_content with critical_action -> block    # either order
untrusted_content then critical_action -> block    # read first, act later
untrusted_content with private_data then external_comms -> block
untrusted_content then send_email or post_message -> block   # either critical action
secrets_access with external_comms or customer_pii with external_comms -> warn
customer_pii then external_comms                   # implicit -> block
```

### `with` vs `then`, concretely

Session: `send_email` (critical) → `read_email` (untrusted) → `send_email`.

- `untrusted_content with critical_action` fires at call **2** — both tags now
  co-occur, order irrelevant.
- `untrusted_content then critical_action` allows calls 1–2 and fires at call
  **3** — the first critical action *after* untrusted content entered the
  session. Ordered rules cut false positives when a critical-first pattern is
  normal for your agents.

### Backward compatibility (guaranteed)

The pre-existing form keeps working forever and can be mixed with `rules:`:

```yaml
    incompatible:                       # same as "a with b -> block"
      - [untrusted_content, critical_action]
```

Both compile to the same internal representation. A policy with only
`incompatible` behaves byte-for-byte as before; if *neither* list is set, the
default red/blue pair applies. Old runtimes simply ignore an unknown `rules:`
key — there is no fleet flag day.

## CLI

```console
$ prismor tags list                  # tools seen + resolved tags + tier
$ prismor tags set 'mcp__crm__*' private_data
$ prismor tags rm  'mcp__crm__*'
$ prismor tags rules                 # active rules (DSL + legacy + default)
$ prismor tags rules add "untrusted_content then critical_action -> block"
$ prismor tags rules rm 0
$ prismor tags edit                  # interactive wizard
$ prismor tags lint                  # validate every rule expression
```

Invalid expressions fail with a caret diagnostic:

```console
$ prismor tags rules add "a then not b"
invalid rule:
  a then not b
         ^ 'not' is reserved for future use
```

### Test rules against real session logs (dry run)

Before enforcing anything, replay your recorded sessions through a candidate
ruleset. Nothing is blocked and no enforcement state is touched:

```console
$ prismor tags test --last 10
demo-session-1  2 hit(s) in 3 events
  [  2] WOULD BLOCK mcp__Gmail__send_email
        rule: untrusted_content then critical_action
        prior: untrusted_content by 'mcp__Gmail__read_email' at event 0

$ prismor tags test --rule "private_data then external_comms -> warn"   # what-if
$ prismor tags test --session <id> --fail-on-hit                        # CI gate
```

Recommended rollout: `mode: observe` → watch findings / `tags test` → tighten
tags → flip to `enforce`. An enforce block is terminal and non-overridable
(part of Prismor's safety floor).

## Semantics reference

- Any number of same-tag calls is always allowed; only *completing* a
  forbidden combination fires.
- A session that has entered the forbidden state stays restricted — every
  later call carrying a final-step tag keeps firing.
- A blocked call never executes, so its tags do not enter the session ledger
  (one denied call can't "use up" the rule).
- `warn` rules log a `lethal_trifecta` finding but never block — even under a
  device-level enforce override.
- Findings: category `lethal_trifecta`; ruleId `tool-category-crossover`
  (legacy/default rules) or `tag-rule:<id>` (expression rules). Both are part
  of the non-overridable enforcement floor.
- Per-session state lives under the Prismor data dir in `trifecta/<session>.json`;
  `prismor tags test` uses an in-memory replay ledger and never touches it.
