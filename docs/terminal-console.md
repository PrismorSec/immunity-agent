# Terminal Console (`prismor term`)

`prismor term` is a full-screen console for everything Prismor has recorded: a
tree of your agents and their sessions, a live event tail, the policy layer in
effect, and what each session cost in tokens.

It is a **renderer only**. Every number comes from
[`prismor/runtime/store.py`](../prismor/runtime/store.py) — the same data layer
behind [`prismor dashboard`](dashboard.md) — which aggregates across every
registered workspace and re-cloaks secrets on read, so evidence panes show
`@@SECRET:NAME@@` placeholders and never real values.

Implementation: [`prismor/runtime/term.py`](../prismor/runtime/term.py), cost in
[`prismor/runtime/cost.py`](../prismor/runtime/cost.py).

```bash
prismor term
```

Needs a real terminal. Piped or redirected (CI, `| head`, no tty), it prints a
plain agent + session table instead, so it stays scriptable.

---

## The layout

```
 >_ PRISMOR  TERM  │ Org: acme  │ Policy: default  │ Agents: 35  │ prices live  │ FOLLOW
 Agents ▸ sessions  ↓last run    │  Detail
────────────────────────────────│──────────────────────────────────────────────
   All agents                   │  Session    d981011d-6f54-4516-a698-2afe8db…
 ▾ ○ claude            512/229  │  Agent      claude  (claude)
     6a5d59a6-e  r90 2f   — 1d  │  Risk       70/100 · 1 findings
     d981011d-6  r70 1f $426 2d │  Immunity   active
     19d34f10-6  r0 0f $0.05 1d │  Cost       $426.00 est · 1629 turns · claude-opus-5
 ▸ ○ codex              64/32   │  Tokens     in 3.1k · out 1.4M · cache r687.6M/w7.4M
 ▸ ○ langchain          11/11   │
                                │  Events  [page 1/3 of 60 · session · filter: all]
                                │───────────────────────────────────────────────
                                │  23:08:18 claude  BLOCK shell: rm -rf /
                                │  23:08:01 claude  allow prompt
 [j/k] Move  [→/←] Expand  [Tab] Pane  [[/]] Page  [Enter] Detail  [s] Sort  …
```

**Header** — org (or `local` when unenrolled), the winning policy layer, agent
count, token-price freshness, and whether the tail is following.

**Left pane** — a two-level tree. Agents show `total/flagged` call counts and a
status dot. Expand one and its sessions appear beneath, each with risk,
findings, cost, and age: `r90 2f $426 2d`.

**Right pane** — detail for whatever is selected, above an event tail scoped to
the same thing: all agents, one agent, or one session.

---

## Keys

| Key | Does |
|---|---|
| `j` / `k`, `↑` / `↓` | Move in the focused pane |
| `→` / `l`, `←` / `h` | Expand / collapse an agent's sessions |
| `Tab` | Switch focus between the tree and the event tail |
| `Enter` | On an agent: expand. On an event: full detail (rule, category, evidence) |
| `[` / `]`, `PgUp` / `PgDn` | Page the event tail |
| `g` / `G` | Jump to top / bottom |
| `s` | Cycle session sort: last run → risk → findings → cost |
| `f` | Toggle follow (live tail, refreshes every 2s) |
| `v` | Cycle verdict filter: all → blocked → allowed |
| `p` | Policy precedence overlay |
| `P` | Pause / resume immunity for the selected session (asks first) |
| `R` | Resume the selected session in Claude Code (asks first) |
| `r` | Refresh everything, including token prices |
| `q` | Quit |

---

## Sessions

Expanding an agent loads its sessions newest-first. Two limits are worth knowing
because the UI states them rather than hiding them:

- At most **50 sessions per agent** are loaded (scanning up to 5 pages). When
  that bites, the tree shows `… showing first 50`. An agent with 512 sessions
  gives you the 50 most recent, not a random 50.
- `s` re-sorts **what is loaded**, not the full history. Sorting by cost ranks
  within those 50 most-recent sessions.

Selecting a session scopes the event tail to it and shows its risk, workspace,
scoped rules, and immunity state.

### Pausing a session

`P` toggles immunity for one session via the same control the web dashboard
uses. It confirms first, and it writes: paused sessions stop being screened
until you resume them. It affects that session only — not the agent, not the
workspace.

### Resuming a session in Claude Code

`R` hands the terminal to `claude --resume <session-id>`, run in that session's
original working directory. `prismor term` restores itself when you exit claude.

This works because Claude Code's conversation ids *are* the session ids Prismor
records. It refuses, with the reason, when the session ran under a different
framework, when the `claude` CLI isn't on `PATH`, or when the recorded workspace
no longer exists (common for sessions that ran in temp directories).

---

## Cost

Prismor's event store records *what* an agent did, never how many tokens it
took — there is no usage column and no usage payload in any event. So cost is
joined from two outside sources:

| | Source |
|---|---|
| **Prices** | The published feed at `https://www.aipricing.guru/api/pricing.json`, cached to `~/.prismor/pricing-cache.json` for 12h |
| **Usage** | The agent's own transcript — Claude Code writes `~/.claude/projects/<slug>/<session-id>.jsonl` with a `usage` block per turn |

The header reports which prices are in play: `prices live` (just fetched),
`prices cached` (within TTL), `prices STALE` (fetch failed, serving the cache),
or `prices n/a` (no network and no cache — costs render unpriced). Nothing
blocks on the network; the fetch has a 6s timeout and falls back.

**Read the numbers with these caveats**, all of which the UI marks:

- Cost is shown only for agents that keep transcripts — Claude Code today.
  Other frameworks show `—` (unknown), never `$0.00`. A `·` means *not priced
  yet*; it fills in within a second.
- Agent-level totals say `across N of M loaded sessions`. They are not a
  lifetime total for that agent.
- The price feed publishes no **cache-write** rate, so that component uses
  Anthropic's standard 1.25x input multiplier. That is the 5-minute-TTL figure;
  1-hour-TTL caching bills 2x, so long-cache sessions are underestimated.
  Everything is labelled `est` for this reason.
- These are **list-price API costs**. On a subscription plan your real marginal
  cost was the flat fee — the figure answers "what would this have cost on the
  API", which is useful for attribution, not a bill.

---

## Event paging

The tail fetches exactly one screenful at a time, so paging stays fast on a
large store.

Counts are reported honestly, and they differ by scope:

- **Session-scoped** events are read in full (the store returns up to 60) and
  sliced locally, so the count is exact: `page 1/3 of 60`.
- **Agent- and all-scoped** events come from a store query whose reported total
  grows as you page deeper — it is a floor, not a count. The header says
  `page 3 · 23 of 207+` and `]` simply stops when a page comes back short.

---

## Performance notes

The console is built to never block on a keypress:

- Navigation redraws immediately from cached rows and re-queries only once the
  selection has been still for ~120ms, so holding `j` never queues queries.
- The 24-hour aggregate (the "All agents" KPI panel) is the one expensive query
  in the app. It is never run on startup or during a redraw — the panel paints
  as `computing 24h totals…` and fills in when idle.
- Session pricing runs in small batches while idle.
- The screen repaints only when something changed.

If the terminal is smaller than 50x10 the console says so rather than drawing a
broken frame.

---

## See also

- [Dashboard & Sessions](dashboard.md) — the web dashboard and session forensics over the same store
- [Policy Layers & Exemptions](policy-layers-and-exemptions.md) — what the `p` overlay is showing
- [Scoped Agent](scoped-agent.md) — the per-session controls `P` toggles
- [CLI Reference](cli-reference.md) — all commands at a glance
