# prismor-claude-agent-sdk

Prismor adapter for the **Claude Agent SDK** (Python). Every `PreToolUse`
hook call is routed through Prismor's policy engine before Claude is
allowed to run the tool — same observe/enforce model and per-user
attribution as the other adapters.

## Why this hook point

This is the exact same hooks system the Claude Code CLI itself uses
(and that this repo's own `prismor/runtime/hooks.py` `_merge_claude()` /
`_normalize_claude()` already install into `.claude/settings.json`),
exposed programmatically instead of via config file: `hooks` on
`ClaudeAgentOptions`, matched with `HookMatcher(matcher=..., hooks=[cb])`
against a `PreToolUseHookInput` (`tool_name`, `tool_input`). Returning
`hookSpecificOutput.permissionDecision: "deny"` blocks the tool call
before it runs — this overrides even `bypassPermissions` permission mode.

## ⚠️ Verification methodology note

Unlike the other adapters in this repo, this one can't be live-tested with
the shared OpenAI key — the Claude Agent SDK requires genuine
Anthropic/Claude Code authentication to run at all. It was instead
live-tested on a separate host with an authenticated Claude Code CLI
session (`claude-agent-sdk` shells out to the installed `claude` binary).

Naive destructive test commands (`rm -rf /`, cloud-metadata SSRF) turned
out to be an **unreliable** way to verify this particular adapter: Claude
refuses those on its own, hook or no hook — confirmed with a baseline run
that had *zero* Prismor hooks installed and still refused. The test that
actually isolates the adapter's effect is a benign-framed write to
`.claude/settings.json` (Prismor's own `agent-config-tampering` rule):
Claude executes it readily with no hook installed, and the adapter denies
it once installed. This discriminating test is also what caught a real
bug during development — an earlier default `matcher` regex
(`"Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch"`) never matched
custom MCP tool names (`mcp__<server>__<tool>`), so the hook silently
never fired for anything but Claude's built-in tools. `matcher` now
defaults to `None` (every tool call) for exactly this reason.

## Install

```bash
pip install "prismor-claude-agent-sdk[sdk]"
```

## Use

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from prismor_claude_agent_sdk import prismor_hook_matcher

options = ClaudeAgentOptions(
    hooks={"PreToolUse": [prismor_hook_matcher(mode="enforce", subject="user:alice")]},
)

async with ClaudeSDKClient(options=options) as client:
    ...
```

A denied call returns `hookSpecificOutput.permissionDecision: "deny"`
with a human-readable reason (or raises `PrismorBlocked` if
`raise_on_block=True`), which Claude surfaces as a permission denial
instead of running the tool.
