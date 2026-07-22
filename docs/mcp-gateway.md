# MCP Gateway

`prismor mcp-gateway` is a single MCP connector that fronts **all** of your MCP
servers. Your agent (Claude Code, Cursor, Claude Desktop — any MCP client) is
configured with one MCP server: Prismor. The gateway aggregates your real
servers behind it and becomes the enforcement point for every tool call:

- **Outbound**: every `tools/call` is evaluated against your Prismor policy
  before it is forwarded — org tool denies, lethal-trifecta tag crossover
  (e.g. *read email* + *send message* in one session), per-agent kill
  switches, IAM, and all policy rules.
- **Inbound**: every tool **result** is scanned as untrusted content (prompt
  injection, poisoned tool output) before the model ever sees it. A flagged
  response is withheld and replaced with the reason.
- **Telemetry**: with a `PRISMOR_AGENT_KEY` (or an enrolled device), every
  verdict streams to the control plane and signed policy updates are pulled
  on the hot path — an admin's tool deny or kill switch takes effect on the
  next call.

Zero per-framework code: any MCP-speaking agent gets coverage without a hook
install or SDK adapter.

## Quick start

1. Move your existing `mcpServers` block into the gateway config
   (`~/.prismor/mcp-gateway.json`) — verbatim, same shape:

   ```json
   {
     "mcpServers": {
       "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
       "linear": {"url": "https://mcp.linear.app/sse", "type": "sse"}
     }
   }
   ```

2. Point your agent's `.mcp.json` at the gateway instead:

   ```json
   {
     "mcpServers": {
       "prismor": {
         "command": "prismor",
         "args": ["mcp-gateway", "--config", "~/.prismor/mcp-gateway.json"]
       }
     }
   }
   ```

Or let Prismor do both steps for the current workspace:

```bash
prismor mcp-gateway install     # moves .mcp.json servers behind the gateway (backup kept)
prismor mcp-gateway uninstall   # restores the original .mcp.json
```

Your agent now sees the same tools, namespaced as `<server>__<tool>`
(e.g. `github__create_issue`), and every call and response flows through
Prismor.

## Modes and flags

```bash
prismor mcp-gateway [serve] [--config PATH] [--mode enforce|observe]
                    [--upstream <url|'command'>] [--server name=<url|command>]
                    [--namespace plain|none] [--workspace PATH]
```

- `--mode enforce` (default) blocks policy violations; `observe` logs only.
  The control plane can still force enforce per agent/device.
- **Shim mode** — front a single server with no config file:
  `prismor mcp-gateway --upstream 'npx -y @modelcontextprotocol/server-github'`
  or `--upstream https://mcp.linear.app/sse`. Add `--namespace none` to keep
  raw tool names.
- `--server github='npx -y @modelcontextprotocol/server-github'` declares
  upstreams inline (repeatable).

Downstream transports: stdio subprocesses and streamable-HTTP/SSE URLs. The
client-facing side is stdio.

## How blocking looks to the agent

A denied call returns a normal MCP tool result with `isError: true`:

```
Blocked by Prismor: [critical] Untrusted content + critical action in one
session (rule: trifecta-crossover)
Recommended fix: ...
```

The model reads the reason and can adapt or ask the user. A flagged tool
*response* is replaced the same way (`[Prismor] response withheld: ...`).
JSON-RPC errors are used only for protocol failures (unknown tool, upstream
server died).

## Policy matching

Events are recorded with `tool_name = mcp__<server>__<tool>` using the **real
downstream server name** — so existing matchers work unchanged: trifecta tag
defaults (`mcp__*__send_email`), org tool denies, tool-tag rules pushed from
the control plane, and the console's tool inventory. One gateway process is
one Prismor session; the trifecta ledger spans your whole agent session.

## Server-declared tags (`_meta`)

At `tools/list` time the gateway reads tags a server self-declares on each
tool definition — `_meta.prismor.tags` (also `_meta.tags` or
`annotations["prismor/tags"]`) — sanitizes them, and stamps them onto every
call event. They feed tool-tag classification *below* the explicit org map:
an admin's tag always wins over a server's self-declaration. See
[Tool Tags](tool-tags.md).

## Notes

- The gateway config may contain tokens in `env` blocks; `install` writes it
  with `0600` permissions and Prismor never logs config values.
- Aggregation is tools-only: resources/prompts from downstream servers are
  not advertised in v1.
- If policy evaluation itself fails in enforce mode, the call is **denied**
  (fail-closed), never silently allowed.
