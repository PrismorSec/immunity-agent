# Changelog

All notable changes to Immunity Agent (Prismor Warden) are documented here.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.5.6] — 2026-05-28

Hybrid semantic prompt-injection defense.

### Added

- **`warden/semantic_guard.py`** — heuristic semantic-injection detector with
  35+ weighted regex signals covering authority claims, compliance pretexts,
  friction-reduction manipulation, roleplay/jailbreak framing, instruction
  override, credential exfiltration, Warden self-bypass, nested file-injection
  markers, and indirect privilege escalation. Optional Claude API mode (no
  API key required for the default path).
- **`warden/semantic_guard_v2.py`** — hybrid guard with uncertain-zone
  escalation. Pipeline: heuristic pre-screen → if score in `[low, high)`,
  escalate to a local Claude Code CLI subagent (no API key needed); merge
  the stricter verdict. Falls back to heuristic-only when the CLI is absent.
- **`PolicyEngine` integration** — opt-in `settings.semantic_guard` block in
  `default_policy.yaml`. Emits `prompt_injection_semantic` findings alongside
  regex findings; participates in session taint marking. Off by default;
  zero overhead unless enabled per-project.
- **`warden semantic-check`** CLI subcommand — ad-hoc analyzer for tuning
  policies and debugging false positives. Supports `--mode hybrid|heuristic|api`
  and `--json` output.
- **`tests/test_semantic_guard.py`** — 15 unit tests covering heuristic
  detection, threshold gating, CLI-absent graceful degrade, and PolicyEngine
  integration.

### Notes

Benchmarked on 826 cases spanning OWASP LLM01–LLM10, OWASP Agentic T02–T04,
MITRE-ATLAS, and nested-file injection: F1 improves 0.697 → 0.822; semantic
attack recall improves 8% → 72%; the LLM subagent is invoked on 1.8% of
events (15/826). Enable per-project with:

```yaml
# .prismor-warden/policy.yaml
settings:
  semantic_guard:
    enabled: true
```

## [1.5.0] — 2026-05-13

Expanded IOC coverage and prompt injection defense.

### Added

- **Prompt injection defense** (`warden/sanitizer.py`, `warden/policy_engine.py`):
  - `sanitizer.py` — structural HTML detector catching injections hidden in HTML
    comments, CSS-invisible elements (`display:none`, `visibility:hidden`,
    `font-size:0`, transparent color), `aria-hidden` elements, and zero-width
    character obfuscation. Complement to YAML regex rules.
  - `_TaintStore` — per-session taint state persisted across hook invocations.
    Once a prompt injection is detected, all subsequent network calls in the
    session are escalated to CRITICAL, closing the response-blind exfiltration gap.
  - `_check_cloaked_secrets_in_url` — checks enrolled cloaking secrets against
    outbound URLs regardless of key shape (fills the gap the YAML patterns can't cover).
  - Two new CRITICAL policy rules: `prompt-injection-hidden` and `secret-in-url-params`
    (covers Anthropic, OpenAI, GitHub, AWS, Slack, Google, Stripe key shapes).

- **Expanded mini-shai-hulud IOC coverage** (`supplychain/ioc.py`):
  - New compromised namespaces: `@opensearch-project/*` (1.3M weekly downloads),
    `@uipath/*` (65 packages).
  - New PyPI packages: `mistralai==2.4.6`, `guardrails-ai==0.10.1`.
  - New C2 domain: `git-tanstack.com` (Cloudflare-flagged phishing domain).
  - New payload hash: `tanstack_runner.js` (SHA-256 `ce7e4199...`).
  - New script patterns: AWS IMDS probe (`169.254.169.254`), HashiCorp Vault
    probe (`127.0.0.1:8200`), GitHub GraphQL worm propagation
    (`createCommitOnBranch`), token regexes (`ghp_*`, `npm_*`), and new
    persistence paths (`.claude/setup.mjs`, `.claude/router_runtime.js`,
    `.vscode/setup.mjs`).
  - Attribution: TeamPCP — same actor as March 2026 Trivy supply chain compromise.

## [1.4.0] — 2026-05-12

Supply Chain Enforcement — `immunity` CLI. Intercepts package manager install
commands before execution, scores each package against live threat intelligence,
and blocks or warns based on risk signals. Ships with IOC coverage for the
mini-shai-hulud attack (May 11 2026) out of the box.

### Added

- **`immunity` CLI wrapper** — shebang script at repo root intercepts
  `npm/pip/pnpm/uv/cargo/go install` commands before execution.
- **`supplychain/ecosystems/detector.py`** — parses install argv into a
  structured `InstallEvent` across 9 ecosystems.
- **`supplychain/ecosystems/metadata.py`** — fetches npm and PyPI registry
  metadata (age, maintainers, install scripts); stdlib only, fail-open.
- **`supplychain/scoring/engine.py`** — additive signal scorer producing
  allow/warn/block verdicts.
- **`supplychain/ioc.py`** — IOC database covering `@tanstack/*`,
  `@mistralai/mistralai` 1.7.1–2.2.4, C2 domains (`getsession.org`,
  `masscan.cloud`), and install script patterns (Bun download,
  `router_init.js`, credential env var access, persistence writes).
- **`docs/supply-chain.md`** — full documentation: usage, scoring table,
  ecosystem support, IOC advisory for mini-shai-hulud, guide for adding new
  IOCs, internal architecture.

## [1.3.0] — 2026-05-11

Web Dashboard — `immunity serve`. Introduces a local HTTP API server and
self-contained browser dashboard that aggregates session, findings, and event
data from all registered workspaces.

### Added

- **`immunity serve` command** (`warden/server.py`, `warden/dashboard.html`).
  Starts a local HTTP server (default `127.0.0.1:7070`) serving a
  self-contained Prismor Warden dashboard. Accepts `--host` and `--port` flags.
- **Dashboard UI** with severity breakdown strip (critical/high/medium/low
  counts), recent sessions table with risk-score bars, and a findings drilldown
  with agent/severity/category filters, free-text search, and expandable
  evidence rows showing raw command/path and session ID.
- **Server-side pagination** for sessions (`/api/sessions`), findings
  (`/api/findings`), and events (`/api/events`) — each endpoint accepts
  `page`, `limit`, sort, and filter query params; returns
  `{items, total, page, pages, limit}`.
- **Live event feed** with verdict (blocked/allowed) and agent filter controls;
  auto-poll pauses when user has active filters or is past page 1.
- **`get_sessions_page()`, `get_findings_page()`, `get_events_page()`** added
  to `warden/store.py`; `get_aggregate_stats()` extended with
  `severityBreakdown`, `recentSessions`, and `recentFindings`.

### Fixed

- **XSS prevention in dashboard**: replaced all `innerHTML` string
  concatenation with a `safe()` helper that text-encodes untrusted values
  before inserting them into the DOM.

## [1.2.0] — 2026-04-27

Tier 3 — Scoped Agent and Session-Based Learning. Adds per-session rule
synthesis via the Anthropic API, a session-based learning engine that mines
uncovered command patterns and detects evasion attempts, and five security
and correctness fixes from code review.

### Added

- **Scoped Agent** (`warden/scoped_agent.py`). On `UserPromptSubmit`, Warden
  calls the Anthropic API (Haiku) to synthesise a minimal, task-specific rule
  set from the user's goal — restricting tools, file paths, and network access
  to only what the task genuinely requires. Falls back to keyword-based static
  heuristics when no API key is present. Scoped rules are stored as JSON
  sidecar files in `.prismor-warden/scoped/` and enforced alongside
  `policy.yaml` for the duration of that session only.
- **Session-Based Learning** (`warden/learning.py`). Mines historical session
  data for recurring uncovered command patterns, tracks false positives from
  dismissed findings, and detects evasion attempts where structurally similar
  commands (e.g. backtick vs `$()` substitution) bypass existing rules.
  Candidate rules can be reviewed and promoted to `policy.yaml`.
- **`immunity scope` subcommands** — `show`, `list`, `edit`, `clear` for
  inspecting and managing active scoped sessions.
- **`immunity learn` subcommands** — `--json`, `--apply`, `--reject`,
  `--candidates` for reviewing and acting on mined rule proposals.
- **Evasion detection** — shell commands that pass policy but are structurally
  similar (Jaccard ≥ 0.6 after substitution normalisation) to a recently
  blocked command in the same session are flagged as `HIGH` findings.
- **Dismissal tracking** — in observe mode, dismissed findings are recorded
  in the database and surfaced via `immunity learn` as false-positive candidates.

### Fixed

- **Prompt-injection mitigation in scoped rule synthesis**: LLM-returned
  `allowed_tools` and `deny_tools` are now clamped to the known-good
  `available_tools` list, preventing a crafted task prompt from expanding the
  scoped policy beyond what the agent actually has access to.
- **Command injection in `immunity scope edit`**: replaced
  `os.system(f'{editor} "{path}"')` with `subprocess.run([editor, path])`
  to prevent shell metacharacter exploitation via the `$EDITOR` env var.
- **`KeyError: 'id'` in `immunity learn` output**: `format_learning_report`
  now uses `c.get('id', c['rule'].get('id', '?'))` so freshly-mined
  candidates (not yet persisted to the DB) display correctly.
- **Misleading scoped-rules display text**: the rules box now correctly states
  that rules persist in `.prismor-warden/scoped/` rather than claiming they
  are not saved.
- **Removed dead `get_scoped_dir()` from `warden/store.py`**: the function
  was unreachable and pointed to a different path than `scoped_agent._scoped_dir`.

## [1.1.0] — 2026-04-24

Tier 1 coverage expansion from `IMPROVEMENT_PLAN.md` — focused on closing
audit-level detection gaps and adding the developer- and SIEM-facing
ergonomics features enterprise buyers expect. Continues from `1.0.2`.

### Added

- **Canarytoken subsystem** (`immunity canary plant|list|remove|status`). Plant
  realistic fake credentials (AWS, SSH, `.env`, generic) at arbitrary paths;
  any read raises a `CRITICAL` finding and optionally POSTs a signed payload
  to a user-provided webhook. First AI-agent-specific canarytoken
  implementation we're aware of. (`warden/canary.py`)
- **MCP schema auditor** — `immunity scan` now statically analyses MCP tool
  schemas for over-broad allowlists (`"*"`, `"/**"`), risky description
  language (`bypass`, `all files`, `sudo`), `any`-typed parameters on
  execution-capable tools, missing input schemas, and servers that combine
  execution with filesystem + network access in a single surface.
  (`warden/scanner.py::audit_mcp_schema`)
- **Lockfile integrity audit** — `immunity deps` now detects non-registry
  sources (`git+`, `file:`) in `package-lock.json`, missing `integrity:`
  hashes, and lockfile-injection (direct deps in the lockfile that aren't
  declared in `package.json`). (`warden/deps.py::check_lockfile_integrity`)
- **Agent instruction-file tamper detection** — new `agent-instruction-tampering`
  rule covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
  `.github/copilot-instructions.md`. Previously only `.claude/settings.json`
  was protected. (`warden/default_policy.yaml`)
- **Unicode / homoglyph path detection** — flags paths and commands that mix
  ASCII letters with Cyrillic, Greek, Latin-extended confusables, fullwidth
  letters, and zero-width joiners (e.g. `cat .еnv` where `е` is U+0435).
  (`warden/policy_engine.py::_has_suspicious_unicode`)
- **Telemetry sinks** — new `settings.outputs` section in `policy.yaml`
  forwards findings to webhook, syslog (UDP/TCP), and file sinks. File sink
  supports both JSON and ArcSight CEF formats for SIEM ingest. Env-var
  interpolation (`${SIEM_TOKEN}`) for secret headers. (`warden/sinks.py`)
- **Declarative policy tests** — `immunity policy test` runs
  `.prismor-warden/policy-tests.yaml` cases (`{input, expect: block|warn|pass}`)
  and ships a bundled OWASP LLM Top 10 + Agentic Top 10 + MITRE ATLAS
  starter pack (28 cases). (`warden/policy_test.py`,
  `templates/policy-tests-owasp.yaml`)
- **`immunity check --explain`** — shows matched rule's category, action,
  event types, field list, and full regex pattern.
- **`immunity check --from-log PATH`** — replay a JSONL session log through the
  current policy to validate rule changes.
- **`immunity check --suggest-allowlist`** — emits a ready-to-paste
  `allowlists:` entry when a command triggers a finding the user considers
  intentional.

### Changed

- **Destructive-command rule** now accepts positional arguments with
  optional quotes (`rm -rf "/etc"`), catches separate flags (`rm -r -f /`)
  and long-form (`rm --recursive --force /`), while still passing safe
  cleanup (`rm -rf ./node_modules`, `rm -rf /tmp/build`, `rm -rf ../build`).
- **Reverse-shell rule** catches `nc -lvp 4444 -e /bin/bash` (combined
  listen+port flag) in addition to the separate `-l` / `-p` form.
- **`/dev/tcp/<host>`** now matches any hostname, not just dotted-quad IPs.
- **TLS verification bypass** rule extended: `git -c http.sslVerify=false`
  inline override, `curl -sk` / `-ksL` / `-Lk` combined flags.
- **npm supply-chain** rules: `--registry` flag matched regardless of
  position (before or after `install|i|add`); yarn/pnpm parity.
- **Shell-obfuscation** rule now matches `perl pack(q{H*}, …)` alternate
  Perl quoting forms in addition to classic `pack("H*", …)`.

### Infrastructure

- `immunity deps` now prints a dedicated "Lockfile integrity issues"
  section and exits `1` when a HIGH-severity integrity issue is present.
- `immunity canary remove` by id or path; `immunity canary status` summarises
  registered canaries by type.
- `immunity hook-dispatch` now invokes telemetry sinks BEFORE the blocking
  decision so SIEMs see every event, including blocked ones.

### Tests

- 227 unit tests, all passing (no regression since 0.2.0).
- 28/28 OWASP starter policy-test cases pass on a clean install.
- Lightsail regression matrix: 97/97 adversarial and golden-path cases
  green (same matrix that validated PR #19).

## [0.2.0] — 2026-04-21

First comprehensive audit-fix release — see PR #19 in the GitHub repo for
details. Closes 15 detection/lifecycle gaps identified by external review
plus six adversarial bypass variations surfaced during variation testing.
