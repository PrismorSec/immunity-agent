# CLI Reference

Every capability in the toolkit is reachable through the single `prismor`
command. This page is the **map**: it lists every command, what it does, and
links to the dedicated deep-dive doc for that capability.

```
prismor <command> [options...]
prismor <domain> <action> [options...]
prismor --help               # the same map, in your terminal
prismor <command> --help     # help for one command
```

There are two shapes:

- **Top-level commands** — `prismor status`, `prismor audit`, `prismor check …`
- **Domains** that take an action — `prismor cloak add …`, `prismor canary plant …`

`prismor` is a deprecated drop-in alias for `prismor`; it forwards everything
unchanged and prints a migration notice. Use `prismor`.

---

## Quick start

| Command | What it does | Deep dive |
|---|---|---|
| `prismor setup` | Interactive 4-step onboarding wizard: pick mode, select agents, enable cloaking, choose install scope. | [Onboarding](#onboarding--lifecycle) |
| `prismor status` | One-shot health check: workspace, hooks, mode, cloak, latest session, next action. | [Dashboard & sessions](dashboard.md) |
| `prismor audit` | Full security-posture audit across every subsystem. `--fix` auto-remediates. | [Prismor](prismor-runtime.md#security-audit) |
| `prismor --help` | The full command map. | — |

---

## The command map

```
prismor
│
├─ Onboarding & lifecycle
│   ├─ setup                  Interactive onboarding wizard (4-step TUI)
│   ├─ install-hooks          Wire Prismor hooks into an agent/IDE
│   ├─ uninstall-hooks        Remove hooks
│   ├─ update                 Self-update check / upgrade
│   └─ status [--all]         Health check (this workspace / all workspaces)
│
├─ Runtime protection (policy engine)
│   ├─ check                  Pre-check a command or path against policy
│   ├─ semantic-check         Hybrid LLM prompt-injection guard
│   ├─ sandbox <action>       status · check · run — Docker command sandbox
│   ├─ eval-server            HTTP evaluation endpoint for non-Python adapters
│   └─ policy <action>        init · validate · show · edit · test
│
├─ Visibility (audit & forensics)
│   ├─ audit                  Full posture audit (--fix to remediate)
│   ├─ scan                   Scan MCP servers & skills for risk
│   ├─ deps                   Check project deps vs. threat feed
│   ├─ analyze / ingest       Run the engine over a JSONL session
│   ├─ sessions / session     List / show stored sessions
│   ├─ trail <action>         verify · show · checkpoint — signed audit trail
│   ├─ attest [verify|coverage]  Signed evidence bundle + framework coverage
│   ├─ discover               Sweep host for ungoverned AI agents (shadow AI)
│   ├─ status --all           Terminal overview of all workspaces
│   └─ dashboard              Local web dashboard (127.0.0.1:7070, opens browser)
│
├─ Secret prevention
│   ├─ cloak <action>         install · add · list · remove · status · pattern
│   └─ sweep                  Find & vault leaked secrets on disk
│
├─ Identity & scoping
│   ├─ iam <action>           Named agent identities / permission profiles
│   ├─ agents <action>        Named agent instances — list · show · set (kill-switch, mode, IAM)
│   ├─ scope <action>         Session-scoped, task-specific rules
│   └─ canary <action>        Plant & manage honeytoken tripwires
│
├─ Adaptive defense
│   └─ learn                  Mine session history for new rules
│
├─ Enterprise / org
│   ├─ enroll <token>         Enroll this machine against your org's control plane
│   ├─ enroll-status          Show enrollment + applied policy version
│   ├─ workspace <action>     Show/set whether this workspace is org-managed or personal
│   ├─ exempt <action>        Request an admin exemption for this repo
│   └─ logout                 Un-enroll (remove device identity + cached policy)
│
└─ Supply chain
    └─ supplychain <action>   npm/pip/pnpm/uv/cargo/go install gate · harden
```

---

## Onboarding & lifecycle

| Command | Key flags | Description |
|---|---|---|
| `prismor setup [DIR]` | `--non-interactive`, `--mode`, `--agents`, `--cloak/--no-cloak` | Interactive wizard (or scripted with flags / `PRISMOR_MODE`, `PRISMOR_CLOAK` env vars). Picks mode, toggles rules, selects agents, enables cloaking. |
| `prismor install-hooks` | `--agent <name\|all>` (required), `--mode <observe\|enforce>`, `--scope <project\|user>` | Writes hook config for the chosen agent so Prismor sees tool calls. Without hooks, nothing is monitored. |
| `prismor uninstall-hooks` | `--agent <name\|all>`, `--scope` | Removes Prismor hooks for an agent. For `claude`/`all`, this also removes cloaking hooks (`prismor cloak install`) — secrets are no longer protected at the tool boundary until you reinstall with `prismor cloak install`. |
| `prismor status` | `--workspace`, `--all`, `--days N` | Health check: hooks, mode, cloak state, latest session, and the single next action. Run this first every session. `--all` shows every registered workspace. |
| `prismor update` | `--check` | Check for (or install) a newer prismor release. |
| `prismor info` | `--workspace` | _Deprecated_ alias of `status`. |

Agent → config matrix and per-agent details: [AGENT_INTEGRATIONS.md](../AGENT_INTEGRATIONS.md).
Modes (`observe` vs `enforce`): [Prismor](prismor-runtime.md).

---

## Runtime protection

| Command | Key flags | Description |
|---|---|---|
| `prismor check "<value>"` | `--type <command\|read\|write>`, `--explain`, `--from-log`, `--suggest-allowlist` | Dry-run a command or file path against the active policy. Returns ALLOW / WARN / BLOCK + reason without executing. Exit `2`=block, `1`=warn, `0`=clean. |
| `prismor semantic-check [TEXT]` | `--mode <hybrid\|heuristic\|api>`, `--json`, `--cli-path` | Run the semantic prompt-injection guard on text or stdin. See [Semantic Guard](semantic-guard.md). |
| `prismor policy init` | `--workspace` | Scaffold `.prismor/policy.yaml`. |
| `prismor policy show` | `--workspace` | Print active rules after merging defaults + project overrides. |
| `prismor policy export` | `--json`, `--output PATH`, `--workspace` | Print the effective merged policy as stable, sorted JSON — patterns already resolved and disabled rules dropped — for non-Python consumers and for committing/diffing. |
| `prismor policy edit` | `--workspace` | Interactive TUI to toggle rules on/off. |
| `prismor policy validate <file>` | — | Static-validate a policy YAML file. |
| `prismor policy test` | `--file` | Run declarative policy tests (falls back to the bundled OWASP LLM starter pack). |
| `prismor sandbox <status\|check\|run>` | `--workspace` | Docker-backed command sandbox: show config, check the backend, or run one command isolated. See [Docker sandbox](docker.md). |
| `prismor tags list` | `--last N`, `--workspace` | Tools seen in recent sessions + resolved tags + which tier resolved them (explicit / `_meta` / default / inference). See [Tool Tags](tool-tags.md). |
| `prismor tags set <tool> <tag>...` | `--workspace` | Tag a tool or glob in `.prismor/policy.yaml` (`tags rm` removes). |
| `prismor tags rules [add\|rm]` | `--workspace` | List, add, or remove tag-rule expressions, e.g. `"untrusted_content then critical_action -> block"`. Adds are parse-checked with caret diagnostics. |
| `prismor tags edit` | `--workspace` | Interactive wizard: tag tools, author rules, flip mode. |
| `prismor tags lint [file]` | `--workspace` | Validate every rule expression in a policy file. Exit `1` on errors. |
| `prismor tags test` | `--session <id>`, `--last N`, `--rule "<expr>"`, `--fail-on-hit` | Dry-run tag rules against recorded session logs: prints WOULD BLOCK / WOULD WARN per call, touches no enforcement state. `--rule` adds what-if candidates. |

### eval-server

| Command | Key flags | Description |
|---|---|---|
| `prismor eval-server` | `--port` (default 7071), `--host` (default 127.0.0.1), `--workspace` | HTTP evaluation endpoint (`POST /v1/evaluate`) so non-Python adapters (Vercel AI SDK, anything HTTP) get the same policy pipeline. See [Frameworks overview](frameworks-overview.md) and [Vercel AI SDK](frameworks-vercel-ai.md). |

Full policy model, rule schema, and the default rule list: [Prismor](prismor-runtime.md).

---

## Visibility

| Command | Key flags | Description |
|---|---|---|
| `prismor audit` | `--fix`, `--json`, `--workspace` | Posture audit across hooks, policy, cloak, permissions, feed, network, supply chain. `--fix` applies safe remediations. |
| `prismor scan` | `--agent`, `--json` | Scan installed MCP servers and skills for dangerous patterns. See [Skill Scanner](skill-scanner.md). |
| `prismor deps` | `--json`, `--workspace` | Cross-reference project dependencies against the signed IOC feed + lockfile integrity. See [Supply Chain](supply-chain.md). |
| `prismor analyze [FILE]` | `--input`, `--json`, `--sarif` | Run the engine over a JSONL session (or the most recent one). SARIF output feeds GitHub Code Scanning. |
| `prismor ingest --input <file>` | `--session-id`, `--agent` | Analyze a session and store it in the local DB. |
| `prismor sessions` | `--findings-only`, `--global`, `--limit`, `--json` | List stored sessions, optionally only flagged ones, optionally across all workspaces. |
| `prismor session <id>` | `--json` | Drill into one session's tool-call trace + findings. |
| `prismor trail verify` | `--pubkey`, `--json` | Verify the signed audit trail end-to-end: recompute hashes, prev-hash linkage, seq gaps, Ed25519 signatures. Exit non-zero on anything but a clean chain. See [Signed Audit Trail](audit-trail.md). |
| `prismor trail show` | `--last N` | Render recent audit-trail records (verdict, agent, tool, input). |
| `prismor trail checkpoint` | `--out FILE` | Export a signed chain-head checkpoint for anchoring outside the machine. |
| `prismor attest` | `--out FILE`, `--workspace` | Build a signed evidence bundle: posture findings, agent inventory, and the trail anchor in one Ed25519-signed file. See [Attestation Bundle](attestation-bundle.md). |
| `prismor attest verify <bundle>` | `--pubkey`, `--json` | Re-verify a bundle's content hash and signature. `--pubkey` pins an out-of-band signer key. Exit non-zero on failure. |
| `prismor attest coverage` | `--json`, `--workspace` | Show which compliance-framework controls the active policy covers (OWASP LLM/Agentic, NIST AI RMF, EU AI Act). |
| `prismor discover` | `--json`, `--workspace` | Sweep this host for AI agents and flag any running without Prismor hooks (shadow AI). Host-local, read-only. See [Host discovery](attestation-bundle.md#host-discovery). |
| `prismor status --all` | `--days N` | Terminal overview of every registered workspace. See [Dashboard](dashboard.md). |
| `prismor dashboard` | `--port`, `--host`, `--no-open` | Local web dashboard at `http://127.0.0.1:7070` (opens a browser tab). See [Dashboard](dashboard.md). |
| `prismor serve` | `--port`, `--host`, `--no-open` | _Deprecated_ alias of `dashboard --no-open` (headless server only). |

---

## Secret prevention

| Command | Key flags | Description |
|---|---|---|
| `prismor cloak install` | `--scope`, `--no-userprompt-guard`, `--no-secret-guard`, `--sweep-on-stop` | Install cloaking hooks so real secrets stay out of model context. |
| `prismor cloak add <name>` | `--from-file` | Register a secret under a placeholder. Value read from stdin / hidden prompt — never argv. |
| `prismor cloak add --env-file .env` | — | Import every `KEY=VALUE` entry from a dotenv file as `@@SECRET:KEY@@`. |
| `prismor cloak list` | — | List registered placeholder names (never values). |
| `prismor cloak remove <name>` | — | Delete a registered secret. |
| `prismor cloak status` | `--scope` | Show whether cloaking hooks are installed + secret count. |
| `prismor cloak run -- <command>` | — | Run a command with `@@SECRET:name@@` placeholders resolved locally and stdout/stderr scrubbed. Use this for Codex, whose hooks are block-only. |
| `prismor cloak pattern <list\|add\|remove>` | — | Manage the secret-detection regexes. |
| `prismor sweep` | `--redact`, `--clean`, `--restore`, `--show-vault`, `--purge` | Find secrets already leaked into AI tool configs and vault/redact them. |

Design, setup, best practices, and threat model: [Sweep & Cloak](sweep-and-cloak.md).

---

## Identity & scoping

| Command | Key flags | Description |
|---|---|---|
| `prismor iam init` | `--scope <global\|project>` | Scaffold an `iam.yaml` of agent identities. |
| `prismor iam list` | — | List defined identities; marks the active `PRISMOR_AGENT_ID`. |
| `prismor iam show <agent>` | — | Show one identity's permission profile. |
| `prismor iam check <agent> --value "<v>"` | `--type <command\|read\|write\|network>` | Test whether an identity may perform an action. |
| `prismor scope show` | `--session-id` | Show session-scoped rules (all, or one session). |
| `prismor scope list` | — | List sessions with active scoped rules. |
| `prismor scope edit <id>` | — | Edit a session's scoped rules in `$EDITOR`. |
| `prismor scope clear <id>` | — | Remove a session's scoped rules. |
| `prismor agents list` | — | List every named agent instance seen (the adapter's `name=`), with framework + control state. |
| `prismor agents show <name>` | — | Show one named agent's control settings (enabled, mode, IAM profile, last seen). |
| `prismor agents set <name>` | `--enabled/--disabled`, `--mode <observe\|enforce>`, `--iam-profile <p>` | Per-agent runtime control: kill-switch, mode override, forced IAM profile. Config lives in `agents.yaml`. |
| `prismor canary plant <path>` | `--type <aws\|ssh\|env\|generic>`, `--webhook`, `--force` | Plant a honeytoken credential tripwire. |
| `prismor canary list` | — | List planted canaries (markers redacted). |
| `prismor canary status` | — | Summary of canaries by type. |
| `prismor canary remove <id\|path>` | — | Remove a canary. |

Deep dives: [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Canary](canary.md).

---

## Adaptive defense

| Command | Key flags | Description |
|---|---|---|
| `prismor learn` | `--min-support`, `--fp-threshold`, `--json` | Mine session history for repeated blocked / near-miss patterns and propose new rules. |
| `prismor learn --candidates` | — | List pending candidate rules. |
| `prismor learn --apply <id>` | — | Accept a candidate into project policy. |
| `prismor learn --reject <id>` | — | Reject a candidate. |

Deep dive: [Learning](learning.md).

---

## Enterprise / org

| Command | Key flags | Description |
|---|---|---|
| `prismor enroll <token>` | `--label`, `--api-base` | Exchange a single-use org token (minted in the dashboard) for this machine's device identity; pulls the signed org policy. |
| `prismor enroll-status` | — | Show enrollment state, device label, and the applied policy version. |
| `prismor workspace [managed\|personal\|auto]` | — | With no argument, shows whether this workspace is org-managed (org policy + telemetry) or personal (local-only). Pass `managed`/`personal`/`auto` to set it. Org-claimed repos can't be downgraded. |
| `prismor exempt request` | `--reason` | Ask an org admin to relax specific non-floor rules for this repo; served back in the signed policy. |
| `prismor logout` | — | Un-enroll: removes the device identity and cached remote policy. Local protection stays on. |

Deep dive: [Connecting to the platform](connecting-to-the-platform.md) · [Policy layers & exemptions](policy-layers-and-exemptions.md).

---

## Supply chain

| Command | Description |
|---|---|
| `prismor supplychain npm install <pkg>` | Score `<pkg>` (age, maintainers, install scripts, IOC match) and block if dangerous before npm runs. |
| `prismor supplychain pip install <pkg>` | Same gate for PyPI. |
| `prismor supplychain <pnpm\|yarn\|uv\|cargo\|go> …` | Same gate per ecosystem. Non-install commands pass through transparently. |
| `prismor supplychain harden [--dry-run] [PATH]` | Write hardening settings (`ignore-scripts`, `save-exact`, pinned fetch) into package-manager configs. |

Scoring table, IOC feed, ecosystem support: [Supply Chain](supply-chain.md).

---

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `PRISMOR_MODE` | `setup --non-interactive` | Default enforcement mode (`observe` / `enforce`). |
| `PRISMOR_CLOAK` | `setup --non-interactive` | Enable cloaking (`1`/`true`/`yes`/`on`). |
| `PRISMOR_WORKSPACE` | all commands | Override the resolved workspace path. |
| `PRISMOR_AGENT_ID` | `iam` | Active agent identity for IAM enforcement. See [IAM](iam.md). |
| `PRISMOR_SWEEP_PASS` | `sweep` | Vault passphrase for non-interactive runs. |
| `EDITOR` | `scope edit` | Editor for scoped-rule editing. |

---

## See also

- [Prismor](prismor-runtime.md) — policy engine, session logs, audit, modes
- [Supply Chain](supply-chain.md) — install-time enforcement and scoring
- [Network Isolation](network-isolation.md) — egress allowlists, raw-IP detection
- [Skill Scanner](skill-scanner.md) — MCP + skill risk scanning
- [Sweep & Cloak](sweep-and-cloak.md) — secret prevention
- [Semantic Guard](semantic-guard.md) — LLM-assisted injection defense
- [Canary](canary.md) · [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Learning](learning.md) · [Dashboard](dashboard.md)
- [Docker & Containers](docker.md) · [Architecture](architecture.md)
