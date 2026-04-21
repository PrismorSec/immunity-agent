# AI Coding Agent Integrations

How Prismor Warden integrates with each major AI coding agent — what ships today, what's planned, and what mechanism each agent exposes for runtime security monitoring.

_Last updated: 2026-04-21._

---

## Status at a glance

| Agent | Warden hooks | Sweep scan | Skill scan | Integration surface |
|---|---|---|---|---|
| Claude Code | ✅ | ✅ | ✅ | `~/.claude/settings.json` hooks |
| Cursor | ✅ | ✅ | ✅ | `.cursor/hooks.json` |
| Windsurf | ✅ | ✅ | ✅ | `.windsurf/hooks.json` |
| OpenClaw | ✅ | — | ✅ | JS plugin at `~/.openclaw/hooks/` |
| Hermes | ✅ | — | ✅ | JS plugin at `~/.hermes/hooks/` |
| Codex (OpenAI) | 🟡 partial | ✅ | — | `~/.codex/hooks.json` (experimental, Bash-only) |
| Gemini CLI | 🟡 roadmap | — | — | `settings.json` hooks block (stable) |
| OpenCode | 🟡 roadmap | — | — | JS plugin `tool.execute.before` |
| Kiro | 🟡 roadmap | — | — | `preToolUse` hooks (exit-2 blocks) |
| Factory Droid | 🟡 roadmap | — | — | `PreToolUse` plugin (`permissionDecision`) |
| GitHub Copilot CLI | 🟡 roadmap | — | — | `permissionRequest` hook |
| VS Code Copilot Chat | 🟡 roadmap (preview) | — | — | `PreToolUse` hook |
| Google Antigravity | — | ✅ | — | no hooks — rules + interactive permissions |
| Aider | — | — | — | `CONVENTIONS.md` — no hooks |
| Trae / Trae CN | — | — | — | `.trae/rules/` — no hooks (MCP is the only dynamic surface) |
| Kilocode | soft only | — | — | `session.chat.before` injects guardrail prompt, can't veto |

✅ shipped · 🟡 planned (adapter not implemented) · — not applicable

---

## Currently supported

### Claude Code (Anthropic)

- **Config:** `.claude/settings.json` (project) or `~/.claude/settings.json` (user).
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PostToolUse` with matcher `Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch`.
- **Blocking:** exit 2 from hook → block; stderr → rejection reason.
- **Sweep target:** `~/.claude/`.
- **Cloaking:** `warden/cloaking/` installs `PreToolUse:Bash` + `PostToolUse:mcp__.*` + `UserPromptSubmit` hooks for `@@SECRET:<name>@@` substitution and scrub-on-output.
- **Code:** `warden/hooks.py` `_merge_claude()`, `_normalize_claude()`.

### Cursor

- **Config:** `.cursor/hooks.json` (schema-validated).
- **Events hooked:** `beforeSubmitPrompt`, `beforeShellCommand`, `afterShellCommand`, `beforeFileWrite`, `afterFileWrite`.
- **Sweep target:** `~/.config/Cursor/`.
- **Code:** `warden/hooks.py` `_merge_cursor()`, `_normalize_cursor()`.

### Windsurf (Codeium Cascade)

- **Config:** `.windsurf/hooks.json` (project) or `~/.codeium/windsurf/hooks.json` (user).
- **Events hooked:** `pre_user_prompt`, `pre_read_code`, `post_read_code`, `pre_write_code`, `post_write_code`, `pre_run_command`, `post_run_command`, `pre_mcp_tool_use`, `post_mcp_tool_use`, `post_cascade_response`.
- **Sweep target:** `~/.codeium/`.
- **Code:** `warden/hooks.py` `_merge_windsurf()`, `_normalize_windsurf()`.

### OpenClaw

- **Config:** `~/.openclaw/config.json` — registers a JS plugin scaffolded at `warden/openclaw-plugin/`.
- **Plugin hooks:** `before_tool_call`, `message_sending`, plus an internal `message:received` hook at `~/.openclaw/hooks/prismor-warden/`.
- **Blocking:** non-zero exit from the Warden dispatcher → plugin returns `{block: true, reason}`.
- **Code:** `warden/hooks.py` `_merge_openclaw()`, `_normalize_openclaw()`.

### Hermes (NousResearch gateway)

- **Config:** `~/.hermes/config.json` — registers a JS plugin scaffolded at `warden/hermes-plugin/`.
- **Plugin hooks:** `before_tool_call`, `message_sending`, internal `message:received` hook at `~/.hermes/hooks/prismor-warden/`.
- **Session ingest:** offline analysis of `~/.hermes/sessions/*.jsonl` via `warden ingest --input <file> --agent hermes`.
- **Code:** `warden/hooks.py` `_merge_hermes()`, `_normalize_hermes()`.

---

## Roadmap — hook adapters planned

Each agent below exposes a blocking pre-tool hook. An adapter requires (1) config-merge in `warden/hooks.py`, (2) `_normalize_*` function, (3) registration in `_SUPPORTED_AGENTS` and `warden/store.py`, (4) sweep target in `warden/sweep.py` if applicable.

### Codex (OpenAI) — partial

- **Why partial:** hooks are experimental, opt-in via `[features] codex_hooks = true` in `~/.codex/config.toml`. `PreToolUse`/`PostToolUse` currently fire only for Bash/shell — `apply_patch` file writes are **not** hooked ([openai/codex#16732](https://github.com/openai/codex/issues/16732)).
- **Config:** `~/.codex/hooks.json` (user) or `<repo>/.codex/hooks.json` (project). All matching layers run additively.
- **Events:** `SessionStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `UserPromptSubmit`, `Stop`.
- **Payload:** JSON on stdin — shared `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, plus event-specific fields (`tool_input.command`, etc.). Default timeout 600s.
- **Blocking:** exit 2 → block, stderr → reason. `PreToolUse` and `PermissionRequest` support `systemMessage` output.
- **Sweep target:** `~/.codex/` (already covered).
- **Adapter work:** payload shape mirrors Claude Code — `_normalize_claude` can be reused with minor field renames. Document the `apply_patch` blind spot to users.

### Gemini CLI (Google)

- **Status:** stable — launched as a core feature on the [Google Developers Blog](https://developers.googleblog.com/tailor-gemini-cli-to-your-workflow-with-hooks/). Cleanest drop-in of the roadmap set.
- **Config:** `.gemini/settings.json` (project) → `~/.gemini/settings.json` (user) → `/etc/gemini-cli/settings.json` (system), layered. `hooks.<Event>[].matcher` + `.hooks[]` with `{name, type: "command", command, timeout}`.
- **Events:** `BeforeTool`, `AfterTool`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `BeforeToolSelection`, `AfterModel`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompress`.
- **Payload:** JSON on stdin — shared `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`, plus event-specific fields (`tool_name`, `prompt`, etc.).
- **Blocking:** exit 2 → "System Block" (stderr → rejection reason; for tool events blocks the call but agent continues; for agent/model events aborts the turn). Other non-zero exits → non-fatal warning.
- **Adapter work:** write hooks block into `~/.gemini/settings.json`, map `BeforeTool`→pre, `AfterTool`→post, `SessionStart`. Reuse Claude-shape normalizer.

### OpenCode

- **Config:** `.opencode/plugins/*.js` (project) or `~/.config/opencode/plugins/*.js` (global); npm-package plugins declared in `opencode.json` under `"plugin": [...]`.
- **Hooks:** `tool.execute.before`, `tool.execute.after`, plus `file.edited`, `file.watcher.updated`, `session.created|compacted|updated`, `message.updated|removed`, `shell.env`, `permission.asked|replied`.
- **Handler signature:** `export const name = async ({ project, client, $, directory, worktree }) => ({ "tool.execute.before": async (input, output) => { ... } })`. `input.tool` = tool name; `output.args` is mutable — supports input rewriting as well as blocking.
- **Blocking:** `throw new Error(reason)` inside `tool.execute.before`.
- **Adapter work:** ship `@prismor/opencode-plugin` (or a drop-in `warden-plugin.js`) that translates the hook payload to Warden's canonical event, calls the dispatcher, and `throw`s on deny. Different shape than OpenClaw/Hermes: in-process JS, not subprocess-per-call — the shim is the only agent-side code.

### Kiro (AWS)

- **Config:** `~/.kiro/` (global), `.kiro/` (workspace) with `hooks/`, `steering/`, `agents/`, `settings/mcp.json`.
- **Hooks:** `preToolUse`, `postToolUse` with a `matcher` field.
- **Blocking:** exit 2 → block execution, stderr returned to the LLM.
- **Adapter work:** shape is close to Claude Code — reuse dispatcher and normalizer. Scaffold the `.kiro/hooks/` entry.

### Factory Droid

- **Config:** `~/.factory/` (global); project `.factory-plugin/plugin.json` with sibling `hooks/hooks.json`.
- **Hooks:** `PreToolUse`, `PostToolUse` (Claude-Code-compatible JSON contract). Matchers like `Write|Edit` shown in plugin examples.
- **Blocking:** return `{permissionDecision: "deny", reason}`; `updatedInput` supports input rewriting before execution.
- **Adapter work:** the JSON-response contract differs from Claude's exit-2 convention — dispatcher needs to emit a response object, not just an exit code. Otherwise reuse normalizer.

### GitHub Copilot CLI

- **Config:** `~/.copilot/` (hooks in the Copilot CLI config file).
- **Hooks:** `permissionRequest` (fires after static allow/deny rules miss), plus lifecycle hooks (`PreToolUse`, `PostToolUse`, etc.).
- **Blocking:** return `permissionDecision: "deny"`. Only `"deny"` is currently processed — `"allow"` and `"ask"` are no-ops.
- **Static layer:** `--allow-tool`, `--deny-tool`, `--allow-all-tools` flags apply before the hook (deny beats allow) — useful as defense-in-depth, not a substitute for the hook.
- **Adapter work:** hook adapter plus an optional `warden export --copilot-cli` subcommand that emits a stable `--deny-tool` list from the policy.

### VS Code Copilot Chat — preview

- **Config:** `.vscode/` (workspace) + user `settings.json`.
- **Hooks:** `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`.
- **Blocking:** return `hookSpecificOutput.permissionDecision: "allow"|"deny"|"ask"` — most-restrictive wins; `continue: false` halts the turn.
- **Caveat:** preview feature — recheck GA status and payload stability before shipping. Distinct from Copilot CLI.
- **Adapter work:** similar to Claude adapter shape. Payload TBD against GA.

---

## Sweep / rules-only — no runtime enforcement

These agents don't expose a programmable pre-tool hook. Integration is limited to:

- **Sweep** — scanning the agent's config directory for leaked secrets with `warden sweep`.
- **Rules** — shipping `AGENTS.md` / rules-file content the agent loads on every turn (static guardrails, no runtime enforcement).

### Google Antigravity

- **Hooks:** none. Community requests open on the [Antigravity forum](https://discuss.ai.google.dev/t/hooks-in-antigravity/120458). Permission UI is interactive, not programmable.
- **Surface:** `AGENTS.md`, `GEMINI.md`, interactive permission prompts.
- **Config dir:** `~/.antigravity/` (already swept).

### Aider

- **Hooks:** none for agent tool calls. `--git-commit-verify` is a static toggle for git pre-commit only.
- **Surface:** `.aider.conf.yml` + `CONVENTIONS.md` (referenced via `read:`).
- **Config dir:** `~/.aider/`, repo-level `.aider.conf.yml`, `.aider.tags.cache.v*/`.

### Trae / Trae CN (ByteDance)

- **Hooks:** none. MCP is the only dynamic surface — wrapping Warden as an MCP proxy is feasible but out of scope.
- **Surface:** `.trae/rules/` markdown + MCP server registration.
- **Config dir:** `~/.trae/`, workspace `.trae/rules/` and `.trae/agents/`.

### Kilocode

- **Hooks:** soft only. `session.chat.before` can inject a guardrail prompt into chat params but cannot veto a tool call. Tool filtering is permission/approval UI, not programmable.
- **Surface:** `AGENTS.md`, `.kilocode/rules/`, `kilo.jsonc`; plugin can inject prompt-level policy.
- **Config dir:** `~/.kilocode/`, workspace `.kilocode/rules/`.

---

## Adding a new agent

When a new AI coding agent ships a pre-tool hook API, the checklist is:

1. Add the agent name to `_SUPPORTED_AGENTS` in `warden/hooks.py`.
2. Add a `_config_path(...)` branch returning the right project/user path.
3. Write `_merge_<agent>(config, command, ...)` producing the hook config.
4. Write `_strip_<agent>(config, marker)` for clean uninstall.
5. Write `_normalize_<agent>(payload, session_id)` mapping the agent's payload to Warden's canonical `{type, session_id, agent, agent_event, ...}` shape.
6. Add the config directory to `TOOL_DIRS` in `warden/sweep.py` if sweep applies.
7. Add MCP/skill config locations to `warden scan` discovery.
8. Update this file.

---

## Sources (verified 2026-04-21)

Internal code is authoritative for the five supported agents.

**Hooks-capable roadmap agents:**

- Codex — [Hooks](https://developers.openai.com/codex/hooks) · [Advanced config](https://developers.openai.com/codex/config-advanced) · [Issue #16732 — `apply_patch` not hooked](https://github.com/openai/codex/issues/16732)
- Gemini CLI — [Hooks reference](https://geminicli.com/docs/hooks/reference/) · [Overview](https://geminicli.com/docs/hooks/) · [Google Developers Blog launch](https://developers.googleblog.com/tailor-gemini-cli-to-your-workflow-with-hooks/)
- OpenCode — [Plugins](https://opencode.ai/docs/plugins/)
- Kiro — [CLI hooks](https://kiro.dev/docs/cli/hooks/)
- Factory Droid — [Plugins](https://docs.factory.ai/cli/configuration/plugins) · [Hooks reference](https://docs.factory.ai/reference/hooks-reference)
- GitHub Copilot CLI — [Hooks configuration](https://docs.github.com/en/copilot/reference/hooks-configuration) · [Allow/deny tools](https://docs.github.com/en/copilot/how-tos/copilot-cli/allowing-tools)
- VS Code Copilot Chat — [Agent hooks](https://code.visualstudio.com/docs/copilot/customization/hooks)

**Rules-only / sweep-only:**

- [Antigravity — hooks request forum thread](https://discuss.ai.google.dev/t/hooks-in-antigravity/120458)
- [Aider — options](https://aider.chat/docs/config/options.html)
- [Trae — rules docs](https://docs.trae.ai/ide/rules?_lang=en)
- [Kilocode — tool filtering & permissions (DeepWiki)](https://deepwiki.com/Kilo-Org/kilocode/6.3-tool-filtering-and-permissions)
