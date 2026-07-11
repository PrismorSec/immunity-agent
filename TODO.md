# Prismor Immunity — TODO

Items are ordered by priority. Each has a registry anchor where relevant.

---

## High priority

### ~~MCP proxy (`prismor mcp-proxy`)~~ — DONE
Registry: `id: mcp-proxy, status: shipped`

stdio/HTTP shim in front of downstream MCP servers. Intercepts `tools/call`,
normalizes to the canonical event shape, calls `evaluate_tool_call`, denies on
enforce. Zero per-framework code.

- `prismor mcp-proxy --stdio -- <upstream-command…>`
- `prismor mcp-proxy --upstream <url> [--port 8080]`
- Deny: MCP `isError` result (or `--jsonrpc-error` for JSON-RPC error)
- Module: `prismor/runtime/mcp_proxy.py`

---

## Medium priority

### Dashboard subject filter
Data is already captured and tagged per-user in findings/events (field: `subject`). The dashboard (`prismor/runtime/server.py` `/api/findings`, `/api/events`) and `prismor/runtime/dashboard.html` don't yet expose a subject filter or column. Add:
- `?subject=user:alice` query param on `/api/findings` / `/api/events`
- A "User" column in the findings table
- A user dropdown filter in `dashboard.html`

### ~~Docs: framework docs~~ — DONE
All framework docs written: frameworks-openai-agents.md, frameworks-langchain.md, frameworks-crewai.md, frameworks-browser-use.md, frameworks-overview.md.

### Coding-agent adapters: Gemini CLI, Kiro, OpenCode
Registry entries exist (`status: roadmap`), hook surfaces documented. Need normalizers + `_merge_*`/`_normalize_*` functions in `prismor/runtime/hooks.py`, entries in `_SUPPORTED_AGENTS`. Gemini and Kiro use `exit-2` (same convention as Claude/Cursor); OpenCode uses `throw`.

---

## Low priority / nice-to-have

### `verify_registry.sh` in CI
Add `bash scripts/verify_registry.sh` to the CI workflow (`.github/workflows/`) alongside the existing test step. Catches registry drift and matrix out-of-sync.

### Per-user telemetry SIEM field
`prismor/runtime/enterprise/telemetry.py` `build_record()` already has `"subject"` field added. Verify that SIEM sinks (Splunk, Datadog, generic HTTP) forward it correctly, and document the field in the sink schema.

### `guard_agent` for LangChain/LangGraph
LangChain equivalent of OpenAI's `guard_agent(agent)` — accept a `RunnableSequence` or `AgentExecutor`, extract the bound tools, call `guard_tools`, return the same object. Currently callers must extract tools manually.

### Sweep-only agents: Aider, Trae, Kilocode
Registry entries exist (`status: sweep-only`). These have no programmable pre-tool hook; the only coverage is rules injection into their config files. Consider a `immunity sweep-inject <agent>` subcommand that writes Prismor guardrail rules into `.aider.conf.yml` / `.trae/rules/` / `.kilocode/rules/`.
