## [Unreleased]

### Added

- **`prismor.*` namespace imports for framework adapters** — the Python adapters are now importable as `from prismor.openai import guard_agent`, `from prismor.langchain import guard_tool`, `prismor.crewai`, and `prismor.browser_use` (PEP 420 namespace packages; adapter distributions bumped to 0.2.0). The old flat `prismor_*` module names keep working as aliases of the same module objects.

### Fixed

- Adapter distributions now depend on `prismor>=1.13.0` instead of the deprecated `immunity-agent` package name.
- The wheel now bundles the framework docs (`frameworks-*.md`), `sdk-integration.md`, and `connecting-to-the-platform.md` under `prismor/runtime/data/docs/`, so links from the installed skill's `SKILL.md` resolve.
- **`destructive-command` policy now catches world-writable chmod/chown in the live YAML-based `PolicyEngine`**, not just the legacy `evaluate_event()` path — `chmod 666`, `chmod 0777`/`1777`, `chmod -R 777 <any dir>`, and symbolic grants (`a+rwx`, `o+w`, `ugo+rwx`) are now blocked in enforce mode across `prismor check`, hook dispatch, and every SDK adapter, matching what `ae7e22e` already fixed in the legacy path. (#121)
- CLI `--help`/usage output and `--version` no longer say `immunity` / `immunity-agent` — both now report `prismor`. (#124)
- `scripts/install.sh` now verifies the `prismor` resolved on `$PATH` actually matches the version it just installed, and fails loudly instead of reporting success when a stale/conflicting prior install (e.g. an old `easy_install` script or leftover `immunity-agent` venv) shadows it. (#123)
- Post-install banner and `scripts/init.sh` no longer reference the old `immunity-agent` name/repo; `package.json` metadata updated to `prismor`.

## [1.13.0] — 2026-06-29

First release published to PyPI under the new **`prismor`** package name. `immunity-agent` is now a deprecated redirect package.

### Changed

- **`prismor` is the canonical PyPI package** — `pip install prismor` is the supported install path going forward. The package ships the full Prismor runtime, supply-chain engine, and CLI (`prismor`, with `immunity` kept as a deprecated alias).

### Deprecated

- **`immunity-agent` is now a thin redirect package** — `pip install immunity-agent` installs `prismor` as a dependency and surfaces a "renamed to prismor" notice on its PyPI page. It carries no code of its own; existing installs keep working via the bundled `prismor` CLI. Use `pip install -U prismor` instead.

## [1.11.0] — 2026-06-26

Supply-chain block/observe output now includes safe version recommendations, and setup writes agent context files for all supported agents.

### Added

- **Safe version recommendations in supply-chain output** — `_score_package()` now calls `recommend_safe_version()` and embeds `safe_version` and `remediation` fields in every `dependency_risk` finding. Block messages print the recommended fix version on stderr; observe mode emits all findings (not just the first) with remediation hints so agents know exactly which packages to pin.
- **Agent context files written on onboarding** — `prismor setup` now calls `_write_agent_context()` unconditionally, writing the key prismor commands (`prismor status`, `supplychain`, `check`, `deps`) into `.cursorrules`, `.windsurfrules`, or `AGENTS.md` depending on the agents selected. Cursor, Windsurf, Codex, Copilot, Hermes, and OpenClaw users all get the reference on first install.
- **SKILL.md installed for all agents** — removed the `if "claude" in agents` gate; SKILL.md now lands in every workspace regardless of agent choice.

## [1.10.0] — 2026-06-24

Setup wizard slimmed to 4 steps, live version banner, and removal of the security-playbook integration.

### Changed

- **Setup wizard is now 4 steps** — the detection-rules toggle step is gone; all rules ship enabled by default. The wizard flows mode → agents → cloak → scope.
- **Version banner reads the live package version** — the banner now reflects `__version__` (mirrored in `scripts/setup.py` with a file-parse fallback) instead of a hardcoded value.
- **Cloak install no longer shells out to the deprecated `prismor` binary** — the "`prismor` is deprecated" warning no longer appears during setup.

### Removed

- **All security-playbook references** — setup no longer wires the playbook into `CLAUDE.md` or prints a Guardrails link; references stripped from `CLAUDE.md`, `AGENTS.md`, and `PYPI.md`, pointing at local `SKILL.md`/docs instead.

## [1.9.0] — 2026-06-24

Setup wizard install-scope control and CLI help/rules-list polish.

### Added

- **Install-scope step in `prismor setup`** — a new wizard step lets you choose between installing Prismor hooks for the current workspace only (`.claude/settings.json`) or globally for every project (`~/.claude/settings.json`). The chosen scope now flows through hook and cloak installation (previously hard-coded to `project`). Exposed on `run_non_interactive` via `scope=`.

### Changed

- **Detection-rules step is sorted and truncated** — rules are ordered CRITICAL → HIGH → MEDIUM → LOW and the list shows the top 15 by default with an `e` to expand / `c` to collapse, so long rule sets stay readable.
- **`prismor help` shows full command names** — commands, sub-actions, and the Help/Deprecated sections now render the full `prismor <cmd>` form instead of bare names, so entries are copy-pasteable.

## [1.8.0] — 2026-06-23

CLI UX consolidation, Codex agent support, and supply-chain enforcement hardening.

### Added

- **Codex (OpenAI) agent support** — `--agent codex` wires Prismor hooks into Codex CLI (`.codex/hooks.json`) for real-time monitoring.
- **`prismor status --all`** — global overview across every registered workspace (the old `prismor dashboard` text view), with `--days N` to set the activity window.
- **Bundled Claude skill** — `prismor setup` now installs the `immunity-agent` skill (SKILL.md + docs) into `<workspace>/.claude/skills/immunity-agent/` for Claude Code, so the agent learns to drive the CLI. The skill ships inside the wheel.

### Changed

- **`prismor dashboard` opens the web dashboard** — it now starts the local server *and* opens a browser tab (`--no-open` for headless). `prismor serve` is kept as a deprecated alias of `dashboard --no-open`.
- **`prismor info` → real alias of `status`** — the duplicate workspace-info renderer is gone; `info` now delegates to `status`.
- **Complete, introspection-driven `prismor help`** — every command is listed (previously `sandbox`/`learn` were omitted), grouped, with each domain's sub-actions and each command's mode flags (`sweep --redact/--clean/…`, `audit --fix`, `status --all`) shown inline. Generated from the live parser so it can't drift.
- **`prismor` (bare) no longer dumps the argparse usage wall** — it prints a one-line deprecation pointer to `prismor help`. `prismor <cmd>` still warns and forwards.
- **Install banner relabeled** — `Hooks` / `Skill` / `Guardrails` (was the conflated "Skills").

### Fixed

- **Supply-chain enforcement gap** — closes a gap across hooks, ecosystems, and dependency depth so install gating applies consistently; adds lockfile-integrity coverage.

## [1.7.1] — 2026-06-17

Enterprise audit hardening and branding rename.

### Fixed

- **Non-overridable enforcement floor (audit #1/#3/#12)** — floor rules (core IDs and core block categories) get `mode: enforce` regardless of `default_mode` and can no longer be downgraded by a policy overlay. Synthetic `action: block` findings (canary, vault, secret-exfil, taint, HTML-injection) are normalized to `mode: enforce`, restoring block intent that per-rule modes had dropped.
- **Telemetry title redaction (audit #5)** — redacted-mode records no longer forward raw paths/hosts/URLs/secrets via the dynamic title; `assert_redacted` now also rejects path/host/URL leaks in the title.
- **Control-plane refresh clamp, heartbeat permissions, logout cleanup, spool age-cap (audit #11/#18/#20)** — `PRISMOR_POLICY_REFRESH_SECONDS` is clamped to `[5s, 600s]`; `heartbeat.json` is now `chmod 0600`; logout clears `heartbeat.json` and `workspace-scopes.json`; telemetry spool drops records older than 30 days (`PRISMOR_SPOOL_MAX_AGE_DAYS`).
- **Telemetry repo identifier gating (audit #17)** — personal/local-only workspaces never attach their git remote to telemetry, mirroring the existing heartbeat gate.

### Changed

- **Rebrand to "Prismor Immunity Agent"** — replaces "Prismor" / "PRISMOR IMMUNITY" labels across the CLI, setup wizard, hooks, dashboard, and tests; `--version` string updated.
- **Dashboard `--days` window + sparklines** — `prismor dashboard` accepts `--days N` (default 7) to filter session data; adds per-workspace and global sparkline bars showing the daily findings trend. Web dashboard gains a Period dropdown (7/14/30/90 days).

### Docs

- README: new "Disabling Immunity Agent" section covering hook uninstall, observe+dry-run soft-disable, and clearing per-session scoped-agent rules.

## [1.7.0] — 2026-06-16

Enterprise control-plane and policy hardening release.

### Added

- **Enterprise control-plane** — signed remote policy pulls, device identity and enrollment, layered workspace scoping, admin-granted exemptions, offline telemetry spool, and heartbeat / telemetry ingest hardening.
- **Per-rule enforcement** — policy-authoritative observe/enforce modes now gate on each rule's effective mode instead of the global install mode alone.
- **Pattern customization** — add/disable pattern overrides with compile isolation and a non-weakening floor for core rules.
- **Prompt-injection coverage** — deterministic regex and heuristic coverage expanded to close benchmark false negatives without adding LLM cost.
- **Supply-chain hardening** — gitleaks version gating, cross-platform install hints, AI-key ruleset, and graceful fallback scanning when the binary is absent.

### Fixed

- **Session-report follow-ups** — closes the remaining v1.6.0 report issues, including claude transcript scoping, exfiltration-directive detection, SCM-domain false positives, and shell-level PII detection.

## [1.6.0] — 2026-06-05

Hermes Agent secret cloaking plugin. Secret prevention now works natively inside Hermes Agent (Nous Research's AI agent platform), with dual-discovery via pip entry point or filesystem install.

### Added

- **Hermes Agent cloaking plugin** (`prismor/runtime/cloaking/hermes_plugin_entry.py`) — shared `register()` function consumed by both Hermes' pip entry-point discovery and filesystem install. Five hooks: `pre_tool_call` (decloak + secret guard), `post_tool_call` (audit), `transform_terminal_output` (scrub), `transform_tool_result` (scrub), `pre_gateway_dispatch` (paste guard).
- **Hermes installer** (`prismor/runtime/cloaking/hermes_installer.py`) — `install()`/`uninstall()`/`status()` for filesystem-level setup. Copies plugin files to `~/.hermes/plugins/prismor-cloak/`, enables it in Hermes config, and sets `PRISMOR_SECRETS_DIR` env var.
- **`pyproject.toml` entry point** — registers `prismor-cloak` under `[project.entry-points."hermes_agent.plugins"]` for auto-discovery when immunity-agent is pip-installed.
- **`prismor cloak install --agent hermes`** — new `--agent` flag on `cloak install`/`uninstall`/`status` supports `claude`, `hermes`, or `all`. Installs for both agents in one command.
- **`prismor cloak status`** — now shows both Claude Code and Hermes Agent state separately.
- **Auto-vaulting for pasted secrets** — `pre_gateway_dispatch` detects raw secrets in user prompts, vaults them under deterministic `auto_<sha256_prefix>` names, and re-sends the sanitized prompt with `@@SECRET:auto_xxx@@`. Bypass with `!!allow` prefix.
- **Documentation:** `docs/hermes.md` with architecture diagram, setup guide, and hook reference. AGENT_INTEGRATIONS.md updated with Hermes cloaking layer.

### Packaging

- Hermes plugin files (`plugin.yaml`, `__init__.py`) are force-included in the wheel under `prismor/runtime/data/cloaking/hermes-plugin/` for filesystem install.
# Changelog

All notable changes to Immunity Agent (Prismor) are documented here.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.5.7] — 2026-05-31

Onboarding reliability: the installer can no longer report success while
installing nothing, and a broken/partial install can no longer break the
host Python. Also ships the hybrid semantic prompt-injection defense from
1.5.6, which was bumped in code but never published to PyPI.

### Fixed

- **`scripts/init.sh` — honest install status.** The git-clone path printed
  `Prismor: hooks installed` unconditionally, even when every `install-hooks`
  call failed (errors were swallowed by `2>/dev/null`). The final banner is
  now driven by a real success counter: zero hooks installed → loud
  `Initialization FAILED` and exit 1, with the underlying error surfaced
  instead of hidden.
- **`immunity-agent.pth` — crash-proof startup hook.** The shipped `.pth`
  ran `import prismor.runtime._post_install` at every Python interpreter startup. If
  `prismor` was ever unimportable (e.g. an editable install whose source dir
  was later deleted), this printed a traceback on *every* `python3`
  invocation machine-wide and poisoned the `prismor` namespace so the cloned
  CLI also failed. Now wrapped in `try/except` so it can never raise.
- **`scripts/init.sh` — `immunity` on PATH.** The git-clone path never added
  the CLI to PATH, so the next documented command (`prismor cloak add`) was
  `command not found`. It now symlinks into `/usr/local/bin` (or appends to
  the shell rc).
- **`scripts/init.sh` — non-interactive exit code.** The trailing "Check
  current session?" prompt hit EOF under `set -e` in piped/CI runs and made
  the installer exit 1 *after* a fully successful install. It is now gated on
  a TTY. Also corrects the stale `prismor.git` → `immunity-agent.git` repo URL
  and only shows the "switch to enforce mode" hint when not already enforcing.

## [1.5.6] — 2026-05-28

Hybrid semantic prompt-injection defense.

### Added

- **`prismor/runtime/semantic_guard.py`** — heuristic semantic-injection detector with
  35+ weighted regex signals covering authority claims, compliance pretexts,
  friction-reduction manipulation, roleplay/jailbreak framing, instruction
  override, credential exfiltration, Prismor self-bypass, nested file-injection
  markers, and indirect privilege escalation. Optional Claude API mode (no
  API key required for the default path).
- **`prismor/runtime/semantic_guard_v2.py`** — hybrid guard with uncertain-zone
  escalation. Pipeline: heuristic pre-screen → if score in `[low, high)`,
  escalate to a local Claude Code CLI subagent (no API key needed); merge
  the stricter verdict. Falls back to heuristic-only when the CLI is absent.
- **`PolicyEngine` integration** — opt-in `settings.semantic_guard` block in
  `default_policy.yaml`. Emits `prompt_injection_semantic` findings alongside
  regex findings; participates in session taint marking. Off by default;
  zero overhead unless enabled per-project.
- **`prismor semantic-check`** CLI subcommand — ad-hoc analyzer for tuning
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
# .prismor/policy.yaml
settings:
  semantic_guard:
    enabled: true
```

## [1.5.0] — 2026-05-13

Expanded IOC coverage and prompt injection defense.

### Added

- **Prompt injection defense** (`prismor/runtime/sanitizer.py`, `prismor/runtime/policy_engine.py`):
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

Web Dashboard — `prismor serve`. Introduces a local HTTP API server and
self-contained browser dashboard that aggregates session, findings, and event
data from all registered workspaces.

### Added

- **`prismor serve` command** (`prismor/runtime/server.py`, `prismor/runtime/dashboard.html`).
  Starts a local HTTP server (default `127.0.0.1:7070`) serving a
  self-contained Prismor dashboard. Accepts `--host` and `--port` flags.
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
  to `prismor/runtime/store.py`; `get_aggregate_stats()` extended with
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

- **Scoped Agent** (`prismor/runtime/scoped_agent.py`). On `UserPromptSubmit`, Prismor
  calls the Anthropic API (Haiku) to synthesise a minimal, task-specific rule
  set from the user's goal — restricting tools, file paths, and network access
  to only what the task genuinely requires. Falls back to keyword-based static
  heuristics when no API key is present. Scoped rules are stored as JSON
  sidecar files in `.prismor/scoped/` and enforced alongside
  `policy.yaml` for the duration of that session only.
- **Session-Based Learning** (`prismor/runtime/learning.py`). Mines historical session
  data for recurring uncovered command patterns, tracks false positives from
  dismissed findings, and detects evasion attempts where structurally similar
  commands (e.g. backtick vs `$()` substitution) bypass existing rules.
  Candidate rules can be reviewed and promoted to `policy.yaml`.
- **`prismor scope` subcommands** — `show`, `list`, `edit`, `clear` for
  inspecting and managing active scoped sessions.
- **`prismor learn` subcommands** — `--json`, `--apply`, `--reject`,
  `--candidates` for reviewing and acting on mined rule proposals.
- **Evasion detection** — shell commands that pass policy but are structurally
  similar (Jaccard ≥ 0.6 after substitution normalisation) to a recently
  blocked command in the same session are flagged as `HIGH` findings.
- **Dismissal tracking** — in observe mode, dismissed findings are recorded
  in the database and surfaced via `prismor learn` as false-positive candidates.

### Fixed

- **Prompt-injection mitigation in scoped rule synthesis**: LLM-returned
  `allowed_tools` and `deny_tools` are now clamped to the known-good
  `available_tools` list, preventing a crafted task prompt from expanding the
  scoped policy beyond what the agent actually has access to.
- **Command injection in `prismor scope edit`**: replaced
  `os.system(f'{editor} "{path}"')` with `subprocess.run([editor, path])`
  to prevent shell metacharacter exploitation via the `$EDITOR` env var.
- **`KeyError: 'id'` in `prismor learn` output**: `format_learning_report`
  now uses `c.get('id', c['rule'].get('id', '?'))` so freshly-mined
  candidates (not yet persisted to the DB) display correctly.
- **Misleading scoped-rules display text**: the rules box now correctly states
  that rules persist in `.prismor/scoped/` rather than claiming they
  are not saved.
- **Removed dead `get_scoped_dir()` from `prismor/runtime/store.py`**: the function
  was unreachable and pointed to a different path than `scoped_agent._scoped_dir`.

## [1.1.0] — 2026-04-24

Tier 1 coverage expansion from `IMPROVEMENT_PLAN.md` — focused on closing
audit-level detection gaps and adding the developer- and SIEM-facing
ergonomics features enterprise buyers expect. Continues from `1.0.2`.

### Added

- **Canarytoken subsystem** (`prismor canary plant|list|remove|status`). Plant
  realistic fake credentials (AWS, SSH, `.env`, generic) at arbitrary paths;
  any read raises a `CRITICAL` finding and optionally POSTs a signed payload
  to a user-provided webhook. First AI-agent-specific canarytoken
  implementation we're aware of. (`prismor/runtime/canary.py`)
- **MCP schema auditor** — `prismor scan` now statically analyses MCP tool
  schemas for over-broad allowlists (`"*"`, `"/**"`), risky description
  language (`bypass`, `all files`, `sudo`), `any`-typed parameters on
  execution-capable tools, missing input schemas, and servers that combine
  execution with filesystem + network access in a single surface.
  (`prismor/runtime/scanner.py::audit_mcp_schema`)
- **Lockfile integrity audit** — `prismor deps` now detects non-registry
  sources (`git+`, `file:`) in `package-lock.json`, missing `integrity:`
  hashes, and lockfile-injection (direct deps in the lockfile that aren't
  declared in `package.json`). (`prismor/runtime/deps.py::check_lockfile_integrity`)
- **Agent instruction-file tamper detection** — new `agent-instruction-tampering`
  rule covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
  `.github/copilot-instructions.md`. Previously only `.claude/settings.json`
  was protected. (`prismor/runtime/default_policy.yaml`)
- **Unicode / homoglyph path detection** — flags paths and commands that mix
  ASCII letters with Cyrillic, Greek, Latin-extended confusables, fullwidth
  letters, and zero-width joiners (e.g. `cat .еnv` where `е` is U+0435).
  (`prismor/runtime/policy_engine.py::_has_suspicious_unicode`)
- **Telemetry sinks** — new `settings.outputs` section in `policy.yaml`
  forwards findings to webhook, syslog (UDP/TCP), and file sinks. File sink
  supports both JSON and ArcSight CEF formats for SIEM ingest. Env-var
  interpolation (`${SIEM_TOKEN}`) for secret headers. (`prismor/runtime/sinks.py`)
- **Declarative policy tests** — `prismor policy test` runs
  `.prismor/policy-tests.yaml` cases (`{input, expect: block|warn|pass}`)
  and ships a bundled OWASP LLM Top 10 + Agentic Top 10 + MITRE ATLAS
  starter pack (28 cases). (`prismor/runtime/policy_test.py`,
  `templates/policy-tests-owasp.yaml`)
- **`prismor check --explain`** — shows matched rule's category, action,
  event types, field list, and full regex pattern.
- **`prismor check --from-log PATH`** — replay a JSONL session log through the
  current policy to validate rule changes.
- **`prismor check --suggest-allowlist`** — emits a ready-to-paste
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

- `prismor deps` now prints a dedicated "Lockfile integrity issues"
  section and exits `1` when a HIGH-severity integrity issue is present.
- `prismor canary remove` by id or path; `prismor canary status` summarises
  registered canaries by type.
- `prismor hook-dispatch` now invokes telemetry sinks BEFORE the blocking
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
