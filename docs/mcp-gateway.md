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
prismor mcp-gateway install       # moves this workspace's .mcp.json servers (backup kept)
prismor mcp-gateway install --all # every MCP config on this machine
prismor mcp-gateway uninstall     # restores the original .mcp.json
```

`--all` migrates every config `prismor discover` can find — Claude Desktop,
Cursor, Windsurf, VS Code, Cline — not just the workspace's own `.mcp.json`.
It handles any JSON config declaring servers under `mcpServers` or `servers`
(VS Code's spelling), preserves everything outside that block verbatim, and
writes a `.bak` alongside each file before changing it.

A config whose shape it does not recognise is reported and **left untouched**
rather than guessed at — Zed declares servers under `context_servers`, and
Codex uses TOML. Move those two by hand.

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

## Governing tools (admins)

Beyond blocking a whole server, an admin can turn off **individual tools** —
for everyone, or for one person — from the console **MCP Hub** (per-server
*Tools* panel):

- **For everyone:** an org-scoped tool deny on `mcp__<server>__<tool>`. It
  rides the signed org policy, so it applies to every gateway — local and
  hosted alike. The same thing can be set as code in `policy.yaml`
  (`settings.tool_denies`) and shipped with `prismor-cli policy apply`.
- **For one person:** a per-user rule (`settings.subject_controls` →
  `deny_tools` for `user:<id>`). It applies when the gateway runs under that
  person's subject — a hosted instance bound to them, or `PRISMOR_SUBJECT`
  set locally. A denied tool is blocked before it reaches the server, with the
  usual `isError` reason returned to the model.

## Hosted instances (Enterprise)

Everything above runs the gateway **locally** on your machine — available on
every plan. Enterprise adds a **hosted** option: from the MCP Hub in the
console, *Spin up MCP instance* provisions a governed MCP URL on Prismor's
managed edge:

```
https://mcp.prismor.dev/mcp/<instance-key>
```

Paste that one URL into any agent, on any machine — no local install. The
servers you registered in the Hub are attached automatically (their secrets
stay server-side, encrypted at rest and only ever decrypted for the fleet).
The instance is a service identity, so the full control loop applies: every
call is policy-evaluated and streamed to your Activity feed, an admin can flip
it between observe/enforce from the console, and revoking it is an instant kill
switch. The instance key *is* the credential in the URL — treat it like a
secret; it's shown only once.

Local gateway vs hosted instance:

| | Local (`prismor mcp-gateway`) | Hosted instance |
|---|---|---|
| Plan | Any | Enterprise |
| Runs on | Your machine | Prismor edge (mcp.prismor.dev) |
| Setup | CLI / config file | One click, paste a URL |
| Secrets | In your local config | Encrypted server-side |
| Telemetry / policy / kill switch | Yes (enrolled) | Yes (built in) |

## Notes

- The gateway config may contain tokens in `env` blocks; `install` writes it
  with `0600` permissions and Prismor never logs config values.
- Aggregation is tools-only: resources/prompts from downstream servers are
  not advertised in v1.
- If policy evaluation itself fails in enforce mode, the call is **denied**
  (fail-closed), never silently allowed.
