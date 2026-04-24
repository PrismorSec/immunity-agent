# Changelog

All notable changes to Immunity Agent (Prismor Warden) are documented here.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.3.1] — 2026-04-24

UX and observability patch release. Surfaces issues found during the
end-to-end bench (120-attack / 539-benign suite, 1 000-call latency run).
All changes are behaviour-compatible for existing policy authors; SDK
embedders gain two new entry points.

### Fixed

- **`install-hooks` is now idempotent.** Re-running with a different
  `--mode` or `--scope` no longer appends a duplicate hook entry. The
  install path now first strips any existing Warden-owned hook
  (identified by the `warden/cli.py` marker) before inserting the new
  one, matching the uninstall semantics.
- **Session-log events now carry an ISO 8601 UTC timestamp.** Prior
  versions wrote `"ts": null` for every Claude/Cursor/Windsurf/Hermes/
  Openclaw/Copilot event because agent hook payloads don't include a
  `timestamp` field. SIEM sinks (webhook/syslog/file) that rely on the
  timestamp can now correlate findings with host logs.
- **`hook-dispatch` now surfaces WARN-level findings to stderr.**
  Previously the hook was silent on `action: warn` rules (exit 0, empty
  stderr), which meant a HIGH-severity warning could fire without the
  user ever seeing it. Each warn finding now emits a
  `[warden WARN] [SEV] rule-id: title` line; behaviour is unchanged for
  `action: block` findings.

### Added

- **`PolicyEngine.from_defaults(workspace=...)`** classmethod as an
  explicit factory for SDK embedders.
- **`PolicyEngine.evaluate(event)`** now works — `index` and
  `session_id` are keyword defaults. Calling code that passed them
  positionally is unaffected.
- **Event-type aliases in `PolicyEngine.evaluate`**. The engine now
  accepts the CLI-style vocabulary (`command`/`read`/`write`) in
  addition to the engine-internal canonical types (`shell`/`file_read`/
  `file_write`), so an embedder can pass whichever is natural for its
  layer without having to translate.
- **`warden policy show --json`** emits the rule list as structured
  JSON (workspace, project-policy path, per-rule id/severity/category/
  action/event types/fields, allowlists) for scripting.
- **Subcommand-scoped argparse errors.** When a flag is wrong inside a
  subcommand, Warden now prints that subcommand's usage plus a
  `warden <subcommand>: error: ...` line, instead of dumping the
  top-level wall of help.
- **Install-hooks scope hint.** After `warden install-hooks` succeeds,
  the CLI prints the scope + mode that was used and, when at project
  scope, a one-line hint about `--scope user` for global coverage.

### Bench artefacts

A full pre-0.3.1 run of the 120-attack / 539-benign / 1 000-call
benchmark is preserved under `/Users/ar9av/Downloads/warden-bench/`;
`warden_benchmark.pdf` in `/Users/ar9av/Downloads/warden-paper/` writes
it up. All six fixes above map to concrete issues disclosed in §7
("What we found that we didn't know before") of the bench report.

## [0.3.0] — 2026-04-24

Tier 1 coverage expansion from `IMPROVEMENT_PLAN.md` — focused on closing
audit-level detection gaps and adding the developer- and SIEM-facing
ergonomics features enterprise buyers expect.

### Added

- **Canarytoken subsystem** (`warden canary plant|list|remove|status`). Plant
  realistic fake credentials (AWS, SSH, `.env`, generic) at arbitrary paths;
  any read raises a `CRITICAL` finding and optionally POSTs a signed payload
  to a user-provided webhook. First AI-agent-specific canarytoken
  implementation we're aware of. (`warden/canary.py`)
- **MCP schema auditor** — `warden scan` now statically analyses MCP tool
  schemas for over-broad allowlists (`"*"`, `"/**"`), risky description
  language (`bypass`, `all files`, `sudo`), `any`-typed parameters on
  execution-capable tools, missing input schemas, and servers that combine
  execution with filesystem + network access in a single surface.
  (`warden/scanner.py::audit_mcp_schema`)
- **Lockfile integrity audit** — `warden deps` now detects non-registry
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
- **Declarative policy tests** — `warden policy test` runs
  `.prismor-warden/policy-tests.yaml` cases (`{input, expect: block|warn|pass}`)
  and ships a bundled OWASP LLM Top 10 + Agentic Top 10 + MITRE ATLAS
  starter pack (28 cases). (`warden/policy_test.py`,
  `templates/policy-tests-owasp.yaml`)
- **`warden check --explain`** — shows matched rule's category, action,
  event types, field list, and full regex pattern.
- **`warden check --from-log PATH`** — replay a JSONL session log through the
  current policy to validate rule changes.
- **`warden check --suggest-allowlist`** — emits a ready-to-paste
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

- `warden deps` now prints a dedicated "Lockfile integrity issues"
  section and exits `1` when a HIGH-severity integrity issue is present.
- `warden canary remove` by id or path; `warden canary status` summarises
  registered canaries by type.
- `warden hook-dispatch` now invokes telemetry sinks BEFORE the blocking
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
