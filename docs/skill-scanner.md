# Skill Scanner

MCP servers and skills extend what your agent can do, but they also extend the attack surface. Studies have found that a significant percentage of community skills contain malicious patterns. Warden's skill scanner checks every MCP server and skill config installed on your machine before you use them.

```bash
warden scan                    # scan all agents (Claude, Cursor, Windsurf, OpenClaw, Hermes)
warden scan --agent claude     # only Claude Code configs
warden scan --json             # machine-readable output
```

## Config locations

The scanner automatically discovers configs from:

| Agent       | Config locations checked                                           |
| ----------- | ------------------------------------------------------------------ |
| Claude Code | `~/.claude/settings.json`, `.claude/settings.json`                 |
| Cursor      | `~/.cursor/mcp.json`, `.cursor/mcp.json`                           |
| Windsurf    | `~/.codeium/windsurf/mcp_config.json`, `.windsurf/mcp.json`        |
| OpenClaw    | `~/.openclaw/config.json`, `~/.openclaw/skills.json`               |
| Hermes      | `~/.hermes/config.json`, `~/.hermes/skills.json`, `~/.hermes/plugins.json` |

Each MCP server and skill entry is evaluated against Warden's policy rules. Findings are sorted by severity (critical first) so the most dangerous issues are always at the top.

## Hermes gateway

Hermes stores per-session JSONL transcripts at `~/.hermes/sessions/` and a queryable SQLite index with FTS5 at `~/.hermes/state.db`. Warden hooks intercept tool calls at the gateway layer before the transcript is written. The session store can also be ingested offline for retrospective analysis:

```bash
warden ingest --input ~/.hermes/sessions/<id>.jsonl --agent hermes
```
