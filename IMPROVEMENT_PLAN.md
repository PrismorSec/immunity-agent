# Immunity Agent — Strategic Improvement Plan

**Date:** 2026-04-24
**Current version:** 0.2.0 (0.2.1 post-merge of PR #19)
**Scope:** 3–12 month roadmap

---

## Strategic positioning

Immunity Agent sits in a specific, defensible niche: **a local-first, hook-native, OSS runtime guardrail for AI coding agents**. The closest peer is Invariant Labs (mcp-scan + policy DSL gateway); everything else is either a hosted SaaS gateway (Lakera, Lasso, Prompt Security, Protect AI, Robust Intelligence) or a dialog/content classifier (NeMo Guardrails, LlamaGuard). None of them hook directly into a developer's Claude Code / Cursor / Windsurf process the way Immunity does.

The leverage point is clear: **own "OWASP LLM Top 10 + Agentic Top 10, enforced at the tool-call boundary, on the developer's own machine."** To hold that position, we need to close three categories of gap: (1) detection ceiling imposed by pure regex, (2) missing content-layer and trajectory-layer coverage, (3) enterprise-credibility items (benchmarks, standards mapping, SIEM export).

---

## Tier 1 — Weeks (quick wins, no architecture change)

These are high-ROI additions that fit the current regex-policy model or require only thin new code. Ship these to round out coverage immediately.

### 1.1 Canarytoken integration (3–5 days)
Plant fake `~/.aws/credentials`, SSH keys, `.env` entries that beacon to a user-owned webhook (Thinkst Canarytokens or self-hosted) when any process reads them. This catches exfil attempts at the attempt, not the leak. No tool does this for AI agents yet — we'd be first.

- New subcommand: `warden canary plant` / `warden canary list` / `warden canary status`
- Integrate with https://canarytokens.org (free) or let users point at a custom webhook URL
- Auto-seed on `warden init --with-canaries`

### 1.2 CLAUDE.md / .cursorrules tamper detection (1 day)
The current `agent-config-tampering` rule only covers `.claude/settings.json` and `.prismor-warden/policy.yaml`. Agent instruction files are a bigger prize for an attacker — rewriting `CLAUDE.md` silently redirects every future session. Add patterns for `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `AGENTS.md`, `.github/copilot-instructions.md`.

### 1.3 Unicode / homoglyph path detection (2 days)
Commands like `cat .еnv` (Cyrillic `е`) or `rm -rf /еtc` bypass every current rule. Add a pre-normalization step in `policy_engine._resolve_path` that flags paths containing mixed-script or confusable characters (use `unicodedata` + Unicode confusables list).

### 1.4 MCP schema auditing (3–4 days)
`warden scan` currently matches regex patterns against MCP config JSON. Upgrade it to statically analyze MCP `tools/list` schemas for:
- `any`-typed parameters on tools that touch filesystem/network
- Descriptions containing "sudo", "bypass", "all files", "any command"
- Tools that combine filesystem + network + execute in one server
- Over-broad `allowedPaths` / `allowedDomains`

This is extending what Invariant's `mcp-scan` does, but tighter integration with our runtime policy.

### 1.5 SIEM / telemetry export (1 week)
Enterprise procurement blocker. Add OTEL traces + Splunk HEC / syslog / webhook sinks for findings. Invariant and Lakera already offer this; it's table stakes for paid customers.

- `warden hook-dispatch` emits OTEL spans when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
- New `outputs:` section in policy.yaml for webhook / syslog / file destinations

### 1.6 Lockfile / dependency reverification on `warden deps` (2 days)
Today `deps` matches manifest names against the threat feed. Add:
- Detect `package-lock.json` divergence from `package.json` (tampering)
- Check `integrity:` hashes in lockfiles against npm registry
- Flag `file:` / `git+` deps in lockfiles (not just install commands)

### 1.7 `warden check` ergonomics (2 days)
- `--from-log <file>` to replay a session log through the current policy (useful for CI)
- `--explain` showing which rule(s) and which evidence token matched
- `--suggest-allowlist` emitting a ready-to-paste allowlist entry when the user confirms a finding is a FP

### 1.8 `warden policy test` (3 days)
Let users author `.prismor-warden/policy-tests.yaml` with `{command, expected: block|pass|warn}` cases. CI-friendly way to validate policy changes. Ship 50 starter cases mapped to OWASP LLM Top 10.

---

## Tier 2 — Months (fundamental capability upgrades)

These require real new code and unlock a step-change in detection quality.

### 2.1 Shell AST layer (2–3 weeks) — **highest-leverage single item**
Parse commands via `mvdan/sh` (Go, called via CGO or subprocess) or `bashlex` (Python) before applying policy. Unlocks:
- Variable indirection: `TARGET=/ && rm -rf $TARGET` becomes detectable
- `eval`/`source` resolution
- Pipeline tainting: "this arg came from $(curl evil.com)"
- Proper handling of quoted targets without regex gymnastics

The current regex-based approach has hit diminishing returns (see the quoted-path / combined-flag patches in PR #19). An AST layer is the only clean path beyond those patches.

Design: add a new evaluation mode `engine.evaluate_ast(ast, event)`; keep regex as fallback/fast-path. Existing rules keep working; new rules can be written against AST node types.

### 2.2 LLM-as-judge for warn-tier (2 weeks)
Route the ~5% of commands that hit `warn` (not `block`, not `pass`) to a fast model — Haiku 4.5, Llama 3.2 3B local, or Gemini Nano — with a compact prompt: "here's the command, the matched rule, the project context; is this destructive/exfiltrative/unsafe in context?"

Keeps p95 latency <500ms on the common case while handling ambiguity. Competitors (Lakera, Lasso, Invariant) all ship judge-style detection; we'd be the OSS option.

- Opt-in via `PRISMOR_JUDGE=anthropic` / `PRISMOR_JUDGE=local` / disabled
- Local option: ship a `ollama pull llama3.2:3b` setup command
- Judge decisions are logged + can be promoted to allowlist entries

### 2.3 Session / trajectory correlation (3–4 weeks)
Per-session taint graph: which bytes entered model context from `.env`/`.ssh/`/`.aws/`, which commands consumed them, does a downstream command send them over the network? Classic source→sink flow.

This is Prismor's documented "roadmap" item and the biggest detection-ceiling unlock after AST. Academic prior art: ToolEmu, AgentDojo, R-Judge. Commercially: Invariant and Protect AI advertise this.

- New `trajectory` event type; evaluated by rules with `event_types: [trajectory]`
- Per-session Python object tracking `sources` (file reads), `consumers` (tool calls with source-derived args), `sinks` (network calls)
- Ship three starter rules: creds-to-network, env-to-external-host, SSH-key-to-git-remote

### 2.4 MCP runtime proxy (4 weeks)
Today `warden scan` is static — it reads MCP configs once. But tool-poisoning attacks mutate at runtime (Invariant's "rug-pull" research; the CurXecute Cursor CVE in late 2025). A proxy that sits between the agent and each MCP server observes every `tools/call` and can:
- Diff tool schemas between sessions
- Block tools that change names/descriptions/parameters
- Log full arg payloads for audit
- Apply per-tool allowlists

Architecturally this is a stdio/SSE proxy (~500–800 LOC); Invariant's gateway is prior art but closed-source.

### 2.5 Tamper-evident audit log (1–2 weeks)
Append-only, hash-chained JSONL transcripts: each event includes `prev_hash = sha256(prev_line + event)`. Optionally sign periodic checkpoints with Sigstore / in-toto. A compromised agent can't silently rewrite history — `warden verify-log <path>` flags the break point.

No one in AI-agent security does this today. Low effort, strong story for regulated industries (finance, healthcare).

### 2.6 Cursor / Windsurf / Aider / Cline deep integration (2 weeks each)
Claude Code has the most coverage today. Cursor, Windsurf, and OpenCode hooks exist but are thinner. Aider and Cline have no hooks. Each deeper integration is worth its own release note — more supported agents = larger addressable market.

Priority order based on 2026 market share: Cursor > Cline > Aider > Windsurf > Copilot CLI.

### 2.7 Secrets detection beyond regex (1 week)
Current `secret-access` rule matches well-known filenames. Add:
- Shannon entropy check on file reads / output (TruffleHog-style)
- Bundled `gitleaks`/`trufflehog` invocation as optional backend
- Pre-built detectors for OpenAI, Anthropic, Stripe, Slack, AWS session tokens, GitHub PATs, JWT structure

This brings us to parity with TruffleHog v3 / gitleaks v8, inline to the tool-call.

### 2.8 `prismor run` — one-command sandbox (2 weeks)
UX wrapper that spawns `claude` / `cursor` / etc. in a rootless container with:
- Workspace mounted rw
- `$HOME/.ssh` and `$HOME/.aws` mounted ro via a throwaway overlay
- Egress proxy honoring the user's `egress_allowlist`
- Shared `.prismor-warden/` volume so policy + session logs persist

Ship Docker Compose templates. Users get Anthropic's recommended Docker hardening (`docs/docker.md`) in one command instead of a copy-paste wall.

---

## Tier 3 — Quarters (platform & ecosystem plays)

These take longer but move Immunity from "good OSS tool" to "category-defining platform."

### 3.1 Policy marketplace / signed rule packs (4–6 weeks)
Users install rule packs by name: `warden policy add owasp-llm-top10`, `warden policy add anthropic-claude-code`, `warden policy add finance-compliance-soc2`. Each pack is a signed YAML bundle hosted in a community GitHub org or OSV.dev-style index.

Invariant has a policy repo; we'd be the *curated marketplace* equivalent. Revenue model later: paid org-private packs.

### 3.2 OWASP / MITRE ATLAS rule mapping (1 week + ongoing curation)
Every rule gains `owasp_llm: LLM01`, `mitre_atlas: AML.TA0005` metadata. `warden audit --compliance owasp` / `--compliance nist-ai-rmf` / `--compliance eu-ai-act` reports which controls the current policy covers.

Enterprise buyers ask this on day one. It's a week of meta-work that unlocks procurement conversations.

### 3.3 AgentDojo / InjecAgent / ASB benchmark runs (2 weeks + ongoing)
Publish signed results on AgentDojo (https://github.com/ethz-spylab/agentdojo), InjecAgent, RedCode, and Agent Security Bench. This is how security tools get credibility in 2026 — same way AV engines cite AV-Test scores. Most competitors haven't done this either; whoever moves first claims the narrative.

### 3.4 eBPF companion (Linux) (4–6 weeks)
For users who want kernel-level enforcement: ship a Tetragon policy bundle that enforces the same allow-list as our egress policy, kills processes that try `/dev/tcp/*`, etc. Pure Linux, opt-in, positioned as "belt and suspenders" for regulated workstations and CI runners.

### 3.5 Landlock / sandbox-exec profiles (3 weeks)
OS-level allow-list enforcement that doesn't rely on agent hooks at all. `prismor run --sandbox landlock -- claude` restricts filesystem writes to the workspace; macOS gets a generated `.sb` profile. This catches attacks that bypass our tool-call hooks entirely.

### 3.6 Dashboard & team features (6–8 weeks)
Today: CLI-only. To sell into teams:
- Local web UI (`warden dashboard --serve 7700`) with findings timeline, rule coverage, session heatmap
- Multi-developer session aggregation (opt-in, workspace-scoped, no cloud by default)
- Optional: hosted team dashboard for orgs that want cross-developer visibility

### 3.7 Compliance output pack (2 weeks)
`warden compliance report --standard soc2` emits a PDF with: rules enforced, hook integrity, session-coverage stats, audit-log verification status. Same data, packaged for auditors.

### 3.8 Real-time threat-feed updates (2 weeks)
Current feed is manually regenerated. Ship a CI workflow + a `warden feed update` command that fetches signed deltas from an Anthropic-/Prismor-controlled update server. Daily/weekly cadence, with full key rotation support.

---

## Cross-cutting themes

### Content layer — close the model-text gap
Prismor's detection today is strictly tool-boundary. Three explicit gaps from `docs/docker.md` deserve a unified answer:

- **Model prose leaking secrets** — the model can type an API key in its response; no tool event fires. Mitigation ideas: on-the-fly scanning of model output (requires MCP/API-level proxy, out of scope for hooks) OR rely on Anthropic's Claude output filtering + the `--network none` fallback we already recommend.
- **Generated-file credential reads** — an attacker-crafted `.py` file reading `~/.aws/credentials` is a file_write followed by a file_read of a path that's on our secret-access list. Trajectory analysis (2.3) closes this.
- **Symlink TOCTOU** — partial mitigation exists via `_resolve_path`, but race windows remain. eBPF (3.4) or landlock (3.5) close this definitively.

### Community & open-source posture
- Move the policy feed to its own repo so non-maintainers can PR rules
- Publish `CONTRIBUTING.md` with a rule-authoring guide + test harness
- Claim rule IDs from a public namespace (e.g., `PW-2026-0001`) so third parties can extend
- Host a monthly "prompt injection of the month" writeup tied to the feed — this is how Simon Willison, Embrace the Red, and Invariant have built audiences; we can join that conversation

### Benchmarks & credibility (recap)
Run AgentDojo + InjecAgent + ASB + RedCode quarterly. Publish score deltas per release. This is the single highest-leverage marketing investment — it's how security tools cross the chasm from "cool OSS" to "procurement approved."

---

## Prioritization — what to do first

If I had to pick three things to ship in the next 30 days:

1. **Shell AST layer (2.1)** — the one thing that changes what's detectable. Every adversarial bypass we found in PR #19 testing (variable indirection, eval chains, quoted targets) comes back into reach.
2. **Canarytokens (1.1)** — cheap, novel, generates a great demo ("we planted a fake key and caught the agent reading it"). Strong marketing story and real defense.
3. **OWASP / ATLAS rule mapping (3.2) + AgentDojo benchmark (3.3)** — compliance + credibility in one move. Unlocks enterprise conversations without new code.

30–90 days: trajectory analysis (2.3), MCP runtime proxy (2.4), LLM-judge (2.2), tamper-evident logs (2.5).

90–180 days: `prismor run` sandbox UX (2.8), policy marketplace (3.1), dashboard (3.6).

---

## Risks / things to watch

- **Scope creep into hosted-SaaS territory.** Policy marketplace and team dashboards edge toward what Lakera / Prompt Security sell. Keep local-first as the north star; any cloud offering is opt-in and workspace-bounded.
- **Judge-jailbreak risk (2.2).** An LLM judge can itself be prompt-injected by the command it's evaluating. Mitigate with strict output schemas and treat the judge verdict as one signal, not the final word.
- **AST complexity tax (2.1).** Bash grammar has genuine edge cases. Use `mvdan/sh` (battle-tested), keep regex as fallback, ship with explicit "AST could not parse this command, falling back to regex" logging.
- **Feed / marketplace governance (3.1, 3.8).** The moment we sign and distribute third-party rules, we become a trust root. Need a published key-rotation and revocation process before launch.

---

## Reference — key files to touch

| Area | Files |
|---|---|
| Shell AST layer | new `warden/ast_engine.py`, wire into `warden/policy_engine.py:191` |
| Trajectory | new `warden/trajectory.py`, extend `warden/store.py` schema |
| MCP proxy | new `warden/mcp_proxy/`, CLI subcommand in `warden/cli.py` |
| Canarytokens | new `warden/canary.py`, subcommand, docs |
| LLM judge | new `warden/judge.py`, hook in `warden/policy_engine.py:evaluate` |
| OWASP mapping | extend `warden/default_policy.yaml` rule metadata, new `warden/compliance.py` |
| Tamper-evident log | extend `warden/store.py:append_session_event` |
| SIEM export | new `warden/sinks/` (otel, syslog, webhook, splunk) |
| `prismor run` | new `scripts/prismor-run.sh`, Docker templates under `templates/` |
| Dashboard | new `warden/dashboard/` (Flask or htmx) |

---

## Appendix — landscape snapshot

| Tool | Segment | Local hook? | OSS? | Coding-agent-native? |
|---|---|---|---|---|
| **Immunity Agent** | Runtime guardrail | **Yes** | **Yes** | **Yes** |
| Invariant Labs | Runtime guardrail | Partial (gateway) | Partial (mcp-scan) | Partial |
| Lakera Guard | LLM content classifier | No (SaaS) | No | No |
| Prompt Security | Enterprise DLP gateway | No | No | No |
| Lasso Security | Enterprise DLP gateway | No | No | No |
| Protect AI (Rebuff) | Prompt-injection classifier | No | Yes (Rebuff) | No |
| NeMo Guardrails | Dialog rail DSL | No | Yes | No |
| LlamaGuard | Content classifier | No | Yes | No |
| mcp-scan | MCP manifest audit | Yes (CLI) | Yes | Partial |
| Guardrails AI | Python validator library | No | Yes | No |

The "Yes / Yes / Yes" row is the moat. Everything in this plan reinforces it.
