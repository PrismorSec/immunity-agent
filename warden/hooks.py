from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from warden.store import append_session_event

_SUPPORTED_AGENTS = ["claude", "cursor", "windsurf", "openclaw", "hermes", "copilot"]


def install_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str, mode: str) -> List[Dict[str, str]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        config = _read_json(config_path)
        command = _dispatcher_command(repo_root=repo_root, workspace=workspace, agent=current_agent, mode=mode)
        if current_agent == "claude":
            config = _merge_claude(config, command, workspace)
        elif current_agent == "cursor":
            config = _merge_cursor(config, command)
        elif current_agent == "openclaw":
            config = _merge_openclaw(config, command, repo_root)
        elif current_agent == "hermes":
            config = _merge_hermes(config, command, repo_root)
        elif current_agent == "copilot":
            config = _merge_copilot(config, command)
        else:
            config = _merge_windsurf(config, command, workspace)

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        results.append({"agent": current_agent, "configPath": str(config_path)})
    return results


def uninstall_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str) -> List[Dict[str, Any]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        removed = False
        if config_path.exists():
            config = _read_json(config_path)
            marker = str(repo_root / "warden" / "cli.py")
            if current_agent == "claude":
                config, removed = _strip_claude(config, marker)
            elif current_agent == "cursor":
                config, removed = _strip_cursor(config, marker)
            elif current_agent == "openclaw":
                config, removed = _strip_openclaw(config, marker)
            elif current_agent == "hermes":
                config, removed = _strip_hermes(config, marker)
            elif current_agent == "copilot":
                config, removed = _strip_copilot(config, marker)
            else:
                config, removed = _strip_windsurf(config, marker)
            if removed:
                config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        # Also clean up internal hook directory for openclaw / hermes
        if current_agent == "openclaw":
            internal_hook = Path.home() / ".openclaw" / "hooks" / "prismor-warden"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        if current_agent == "hermes":
            internal_hook = Path.home() / ".hermes" / "hooks" / "prismor-warden"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        # Claude Code also installs separate cloaking hooks (decloak.sh,
        # recloak-mcp.sh, userprompt-guard.sh). The detection-hook strip
        # above only removes entries that reference cli.py, so cloaking
        # stays behind unless we explicitly uninstall it too.
        if current_agent == "claude":
            try:
                from warden.cloaking import uninstall as cloak_uninstall
                cloak_result = cloak_uninstall(workspace=workspace, scope=scope)
                if cloak_result.get("removed"):
                    removed = True
            except Exception:
                # Cloaking is optional — swallow any error so detection-hook
                # removal still reports cleanly.
                pass
        results.append({"agent": current_agent, "configPath": str(config_path), "removed": removed})
    return results


def normalize_payload(*, agent: str, payload: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    session_id = (
        payload.get("session_id")
        or payload.get("sessionId")
        or payload.get("trajectory_id")
        or payload.get("trajectoryId")
        or payload.get("execution_id")
        or payload.get("executionId")
        or _ephemeral_session_id(agent, workspace)
    )

    if agent == "claude":
        event = _normalize_claude(payload, session_id, workspace)
    elif agent == "windsurf":
        event = _normalize_windsurf(payload, session_id, workspace)
    elif agent == "openclaw":
        event = _normalize_openclaw(payload, session_id)
    elif agent == "hermes":
        event = _normalize_hermes(payload, session_id)
    elif agent == "copilot":
        event = _normalize_copilot(payload, session_id)
    else:
        event = _normalize_cursor(payload, session_id)
    return {"sessionId": session_id, "event": event}


def _default_block_categories() -> set:
    """Return block categories from the bundled default_policy.yaml.

    Cached on first call. Falls back to a hardcoded safe default if the
    policy cannot be loaded (e.g. PyYAML missing in a minimal environment).
    """
    cached = getattr(_default_block_categories, "_cache", None)
    if cached is not None:
        return cached
    try:
        from warden.policy_engine import PolicyEngine
        cats = set(PolicyEngine().block_categories)
    except Exception:
        cats = {
            "destructive_command", "secret_exfiltration", "secret_access",
            "remote_execution", "prompt_injection", "dos_resource_exhaustion",
            "rce_canary", "db_modification", "privilege_escalation",
            "skill_risk", "persistence", "security_bypass", "dependency_risk",
        }
    _default_block_categories._cache = cats  # type: ignore[attr-defined]
    return cats


def should_block(
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    block_categories: set | None = None,
) -> Dict[str, Any] | None:
    if not _is_pre_action(str(event.get("agent_event", ""))):
        return None

    categories = block_categories if block_categories is not None else _default_block_categories()
    for finding in findings:
        if finding.get("category") in categories:
            # Reads are generally safe, so they only block for secret access —
            # except for IAM, where an operator has explicitly scoped which
            # paths/tools an identity may read, and that intent must be honored.
            if (
                event.get("type") == "file_read"
                and finding.get("category") not in ("secret_access", "iam")
            ):
                continue
            return finding
    return None


def _config_path(agent: str, scope: str, workspace: Path) -> Path:
    home = Path.home()
    if scope == "project":
        if agent == "claude":
            return workspace / ".claude" / "settings.json"
        if agent == "cursor":
            return workspace / ".cursor" / "hooks.json"
        if agent == "openclaw":
            return workspace / ".openclaw" / "plugins.json"
        if agent == "hermes":
            return workspace / ".hermes" / "plugins.json"
        if agent == "copilot":
            return workspace / ".github" / "copilot" / "hooks.json"
        return workspace / ".windsurf" / "hooks.json"

    if agent == "claude":
        return home / ".claude" / "settings.json"
    if agent == "cursor":
        return home / ".cursor" / "hooks.json"
    if agent == "openclaw":
        return home / ".openclaw" / "config.json"
    if agent == "hermes":
        return home / ".hermes" / "config.json"
    if agent == "copilot":
        return home / ".copilot" / "hooks.json"
    return home / ".codeium" / "windsurf" / "hooks.json"


def _dispatcher_command(*, repo_root: Path, workspace: Path, agent: str, mode: str) -> str:
    script_path = repo_root / "warden" / "cli.py"
    return f'python3 "{script_path}" hook-dispatch --agent {agent} --workspace "{workspace}" --mode {mode}'


def _merge_claude(config: Dict[str, Any], command: str, workspace: Path) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch", "hooks": [{"type": "command", "command": command}]},
    )
    hooks["PostToolUse"] = _merge_claude_entries(
        hooks.get("PostToolUse", []),
        {"matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch", "hooks": [{"type": "command", "command": command}]},
    )
    # Skip "Stop" hook — the payload contains the full assistant response which
    # exceeds OS argument limits (E2BIG) on long conversations. Stop fires after
    # all actions are complete so it has no security enforcement value.
    env = dict(config.get("env", {}))
    env["PRISMOR_WARDEN_WORKSPACE"] = str(workspace)
    return {**config, "hooks": hooks, "env": env}


def _merge_cursor(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in [
        "beforeSubmitPrompt",
        "beforeShellCommand",
        "afterShellCommand",
        "beforeFileWrite",
        "afterFileWrite",
    ]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "version": config.get("version", 1), "hooks": hooks}


def _merge_windsurf(config: Dict[str, Any], command: str, workspace: Path) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in [
        "pre_user_prompt",
        "pre_read_code",
        "post_read_code",
        "pre_write_code",
        "post_write_code",
        "pre_run_command",
        "post_run_command",
        "pre_mcp_tool_use",
        "post_mcp_tool_use",
        "post_cascade_response",
    ]:
        hooks[event_name] = _merge_windsurf_entries(hooks.get(event_name, []), command, workspace)
    return {**config, "hooks": hooks}


def _strip_claude(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    env = dict(config.get("env", {}))
    if "PRISMOR_WARDEN_WORKSPACE" in env:
        del env["PRISMOR_WARDEN_WORKSPACE"]
        removed = True
    return {**config, "hooks": hooks, "env": env}, removed


def _strip_cursor(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _strip_windsurf(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _merge_openclaw(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the plugin package
    plugin_dir = repo_root / "warden" / "openclaw-plugin"
    _scaffold_openclaw_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".openclaw" / "hooks" / "prismor-warden"
    _scaffold_openclaw_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_openclaw(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "prismor" not in p.lower() and "warden" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_OPENCLAW_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const WARDEN_COMMAND = "__WARDEN_COMMAND__";

function dispatch(payload) {
  try {
    execSync(WARDEN_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor Warden" };
    }
    return { block: false };
  }
}

exports.before_tool_call = function (event) {
  return dispatch({
    hookEvent: "before_tool_call",
    toolName: event.toolName || "",
    toolInput: event.toolInput || {},
    sessionId: event.sessionId || "",
    agentId: event.agentId || "",
    timestamp: event.timestamp || Date.now(),
  });
};

exports.message_sending = function (event) {
  return dispatch({
    hookEvent: "message_sending",
    toolName: "__message__",
    toolInput: { content: event.content || "" },
    sessionId: event.sessionId || "",
    agentId: event.agentId || "",
    timestamp: event.timestamp || Date.now(),
  });
};
"""

_OPENCLAW_HOOK_MD = """---
event: message:received
---

Prismor Warden prompt injection detection hook.
Scans inbound messages for prompt injection patterns.
"""

_OPENCLAW_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const WARDEN_COMMAND = "__WARDEN_COMMAND__";

module.exports = function (event) {
  var payload = {
    hookEvent: "message_received",
    toolName: "__message__",
    toolInput: {
      content: (event.context && event.context.content) || "",
      from: (event.context && event.context.from) || "",
    },
    sessionId: event.sessionKey || "",
    timestamp: event.timestamp || Date.now(),
  };
  try {
    execSync(WARDEN_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
  } catch (err) {
    // Internal hooks cannot block — stderr warnings still surface
  }
};
"""


def _scaffold_openclaw_plugin(plugin_dir: Path, command: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": "@prismor/openclaw-warden",
        "version": "0.1.0",
        "description": "Prismor Warden security hooks for OpenClaw",
        "main": "index.js",
        "openclaw": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _OPENCLAW_PLUGIN_JS.replace("__WARDEN_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_openclaw_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_OPENCLAW_HOOK_MD, encoding="utf-8")
    js = _OPENCLAW_HOOK_JS.replace("__WARDEN_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_hermes(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the plugin package
    plugin_dir = repo_root / "warden" / "hermes-plugin"
    _scaffold_hermes_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".hermes" / "hooks" / "prismor-warden"
    _scaffold_hermes_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_hermes(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "prismor" not in p.lower() and "warden" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_HERMES_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const WARDEN_COMMAND = "__WARDEN_COMMAND__";

function dispatch(payload) {
  try {
    execSync(WARDEN_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor Warden" };
    }
    return { block: false };
  }
}

exports.before_tool_call = function (event) {
  return dispatch({
    hookEvent: "before_tool_call",
    toolName: event.toolName || "",
    toolInput: event.toolInput || {},
    sessionId: event.sessionId || "",
    gatewayId: event.gatewayId || "",
    timestamp: event.timestamp || Date.now(),
  });
};

exports.message_sending = function (event) {
  return dispatch({
    hookEvent: "message_sending",
    toolName: "__message__",
    toolInput: { content: event.content || "" },
    sessionId: event.sessionId || "",
    gatewayId: event.gatewayId || "",
    timestamp: event.timestamp || Date.now(),
  });
};
"""

_HERMES_HOOK_MD = """---
event: message:received
---

Prismor Warden prompt injection detection hook for Hermes gateway.
Scans inbound messages for prompt injection patterns before they reach
the model.
"""

_HERMES_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const WARDEN_COMMAND = "__WARDEN_COMMAND__";

module.exports = function (event) {
  var payload = {
    hookEvent: "message_received",
    toolName: "__message__",
    toolInput: {
      content: (event.context && event.context.content) || "",
      from: (event.context && event.context.from) || "",
    },
    sessionId: event.sessionKey || "",
    timestamp: event.timestamp || Date.now(),
  };
  try {
    execSync(WARDEN_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
  } catch (err) {
    // Internal hooks cannot block — stderr warnings still surface
  }
};
"""


def _scaffold_hermes_plugin(plugin_dir: Path, command: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": "@prismor/hermes-warden",
        "version": "0.1.0",
        "description": "Prismor Warden security hooks for Hermes gateway",
        "main": "index.js",
        "hermes": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _HERMES_PLUGIN_JS.replace("__WARDEN_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_hermes_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_HERMES_HOOK_MD, encoding="utf-8")
    js = _HERMES_HOOK_JS.replace("__WARDEN_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_copilot(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in ["PreToolUse", "PostToolUse", "UserPromptSubmitted"]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "version": config.get("version", 1), "hooks": hooks}


def _strip_copilot(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _normalize_copilot(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEventName") or payload.get("hook_event_name") or "unknown"
    tool_name = payload.get("toolName") or payload.get("tool_name") or ""
    # Copilot sends toolArgs as a JSON-encoded string; parse it.
    tool_args_raw = payload.get("toolArgs") or payload.get("tool_args") or "{}"
    if isinstance(tool_args_raw, str):
        try:
            tool_args: Dict[str, Any] = json.loads(tool_args_raw)
        except (json.JSONDecodeError, ValueError):
            tool_args = {"raw": tool_args_raw}
    else:
        tool_args = tool_args_raw
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "copilot",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmitted":
        return {**base, "type": "prompt", "prompt": payload.get("prompt") or tool_args.get("prompt", "")}
    if tool_name in {"ShellCommand", "run_shell_command", "Bash"}:
        return {**base, "type": "shell", "command": tool_args.get("command") or tool_args.get("cmd", "")}
    if tool_name in {"ReadFile", "read_file", "Read"}:
        return {**base, "type": "file_read", "path": tool_args.get("path") or tool_args.get("filePath", "")}
    if tool_name in {"WriteFile", "write_file", "EditFile", "Write", "Edit"}:
        return {**base, "type": "file_write", "path": tool_args.get("path") or tool_args.get("filePath", ""), "content": tool_args.get("content", "")}
    if tool_name in {"WebFetch", "web_fetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_args.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _merge_claude_entries(entries: List[Dict[str, Any]], new_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    existing = next((entry for entry in next_entries if entry.get("matcher") == new_entry["matcher"]), None)
    if existing is None:
        next_entries.append(new_entry)
        return next_entries

    existing_commands = {hook.get("command") for hook in existing.get("hooks", [])}
    for hook in new_entry["hooks"]:
        if hook.get("command") not in existing_commands:
            existing.setdefault("hooks", []).append(hook)
    return next_entries


def _merge_simple_command_entries(entries: List[Dict[str, Any]], command: str) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    if not any(entry.get("command") == command for entry in next_entries):
        next_entries.append({"command": command})
    return next_entries


def _merge_windsurf_entries(entries: List[Dict[str, Any]], command: str, workspace: Path) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    if not any(entry.get("command") == command for entry in next_entries):
        next_entries.append(
            {
                "command": command,
                "show_output": False,
                "working_directory": str(workspace),
            }
        )
    return next_entries


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


# ── MCP tool-call classification ─────────────────────────────────────────────
# MCP tool calls arrive as opaque tool names (``mcp__<server>__<tool>``) and
# would otherwise fall through to a generic ``tool_result`` event — bypassing
# the egress allowlist, taint tracking, and clean injection scanning. The
# helpers below resolve the backing server's transport from the agent's MCP
# config and re-shape the event so the existing policy rules apply:
#   • remote (HTTP/SSE) tool *calls*  -> ``network`` event (egress + taint +
#     secret-in-URL/args rules)
#   • tool *responses*                -> clean ``tool_result`` (injection scan)

_MCP_REMOTE_TRANSPORTS = {
    "http", "https", "sse", "streamable-http", "streamable_http",
    "streamablehttp", "ws", "wss", "websocket",
}
_MCP_URL_KEYS = ("url", "endpoint", "serverUrl", "server_url", "uri", "href")

# Per-workspace cache of {server_name_lower: {"url", "transport", "remote"}}.
_mcp_index_cache: Dict[str, Dict[str, Dict[str, Any]]] = {}


def _mcp_endpoint_meta(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract endpoint metadata from a single MCP server config."""
    url = ""
    if isinstance(cfg, dict):
        for k in _MCP_URL_KEYS:
            v = cfg.get(k)
            if isinstance(v, str) and v.strip():
                url = v.strip()
                break
        transport = str(cfg.get("type") or cfg.get("transport") or "").lower()
    else:
        transport = ""
    return {"url": url, "transport": transport,
            "remote": bool(url) or transport in _MCP_REMOTE_TRANSPORTS}


def _mcp_server_index(workspace: Path) -> Dict[str, Dict[str, Any]]:
    """Build (and cache) a name->endpoint map from all discovered MCP configs."""
    key = str(workspace)
    cached = _mcp_index_cache.get(key)
    if cached is not None:
        return cached
    index: Dict[str, Dict[str, Any]] = {}
    try:
        from warden.scanner import discover_configs, parse_config
        for cfg in discover_configs(workspace=workspace):
            for entry in parse_config(cfg["path"]):
                nm = str(entry.get("name", "")).lower()
                if nm:
                    index[nm] = _mcp_endpoint_meta(entry.get("config") or {})
    except Exception:
        pass
    _mcp_index_cache[key] = index
    return index


def _parse_mcp_tool(tool_name: str) -> Optional[Tuple[str, str]]:
    """Parse ``mcp__<server>__<tool>`` into (server, tool); None if not MCP."""
    if not tool_name or not tool_name.startswith("mcp__"):
        return None
    server, _, tool = tool_name[len("mcp__"):].partition("__")
    return server, tool


def _extract_mcp_response_text(response: Any) -> str:
    """Flatten an MCP tool response into plain text for injection scanning.

    Handles the common content-block shapes (``[{"type":"text","text":...}]``,
    ``{"content":[...]}``) and falls back to a JSON dump.
    """
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    parts: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            text = node.get("text")
            if isinstance(text, str):
                parts.append(text)
            else:
                for v in node.values():
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(response)
    joined = "\n".join(p for p in parts if p)
    if joined:
        return joined
    try:
        return json.dumps(response, default=str)
    except Exception:
        return str(response)


def _classify_mcp_event(
    *,
    base: Dict[str, Any],
    tool_name: str,
    tool_input: Any,
    response: Any,
    is_post: bool,
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    """Re-shape an MCP tool call/response into a policy-aware event.

    Returns ``None`` when ``tool_name`` is not an MCP tool, so callers fall
    through to their default classification.
    """
    parsed = _parse_mcp_tool(tool_name)
    if parsed is None:
        return None
    server, mcp_tool = parsed
    meta = _mcp_server_index(workspace).get(server.lower(), {})
    url = meta.get("url", "")
    remote = bool(meta.get("remote"))
    mcp_meta = {"mcp_server": server, "mcp_tool": mcp_tool}

    if is_post:
        # Tool output is untrusted remote content — scan it as a tool_result
        # so the prompt-injection rules and HTML sanitizer apply cleanly.
        event = {**base, "type": "tool_result",
                 "response": _extract_mcp_response_text(response), **mcp_meta}
        if url:
            event["url"] = url
        return event

    # Pre-call. Serialize arguments so secret-in-args detection can see them.
    try:
        args_text = json.dumps(tool_input, default=str)
    except Exception:
        args_text = str(tool_input)

    if remote and url:
        # Route through the network path: egress allowlist, raw-IP, suspicious
        # destination, secret-in-URL, taint escalation, and (via outbound_payload)
        # enrolled-secret-in-arguments checks all apply.
        return {**base, "type": "network", "url": url,
                "outbound_payload": args_text, **mcp_meta}

    # Local stdio MCP server: keep arguments visible to injection rules.
    return {**base, "type": "tool_result", "response": args_text, **mcp_meta}


def _normalize_claude(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "claude",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {**base, "type": "shell", "command": tool_input.get("command", ""), "stdout": payload.get("stdout", ""), "stderr": payload.get("stderr", "")}
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": _join_edits(tool_input.get("edits", [])) or tool_input.get("content", ""),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_input.get("url", ""), "response": payload.get("response", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_windsurf(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("agent_action_name", "unknown")
    tool_info = payload.get("tool_info", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "windsurf",
        "agent_event": hook_event,
        "metadata": {"execution_id": payload.get("execution_id"), "raw": payload},
    }
    if hook_event == "pre_user_prompt":
        return {**base, "type": "prompt", "prompt": tool_info.get("prompt", "")}
    if "run_command" in hook_event:
        return {**base, "type": "shell", "command": tool_info.get("command", ""), "stdout": tool_info.get("stdout", ""), "stderr": tool_info.get("stderr", "")}
    if "read_code" in hook_event:
        return {**base, "type": "file_read", "path": tool_info.get("file_path", "")}
    if "write_code" in hook_event:
        return {**base, "type": "file_write", "path": tool_info.get("file_path", ""), "content": _join_edits(tool_info.get("edits", []))}
    if "mcp_tool_use" in hook_event:
        server = str(tool_info.get("server") or tool_info.get("server_name") or "")
        tool = str(tool_info.get("tool") or tool_info.get("tool_name") or tool_info.get("name") or "")
        synthetic = f"mcp__{server}__{tool}" if server else f"mcp__{tool}__{tool}"
        mcp_event = _classify_mcp_event(
            base=base,
            tool_name=synthetic,
            tool_input=tool_info.get("arguments") or tool_info.get("args") or tool_info.get("input") or {},
            response=tool_info.get("result") or tool_info.get("response") or tool_info.get("output"),
            is_post=hook_event.startswith("post"),
            workspace=workspace,
        )
        if mcp_event is not None:
            # Windsurf configs may carry the endpoint inline on the call.
            if mcp_event.get("type") == "network" and not mcp_event.get("url"):
                inline = str(tool_info.get("url") or tool_info.get("endpoint") or "")
                if inline:
                    mcp_event["url"] = inline
            return mcp_event
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_cursor(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = (
        payload.get("hook_event_name")
        or payload.get("hookEventName")
        or payload.get("event_name")
        or payload.get("eventName")
        or payload.get("event")
        or "unknown"
    )
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "cursor",
        "agent_event": hook_event,
        "metadata": {"raw": payload},
    }
    if "prompt" in hook_event.lower():
        return {**base, "type": "prompt", "prompt": payload.get("prompt") or payload.get("message", "")}
    if "shell" in hook_event.lower():
        return {**base, "type": "shell", "command": payload.get("command") or payload.get("commandLine") or ""}
    if "write" in hook_event.lower():
        return {**base, "type": "file_write", "path": payload.get("path") or payload.get("filePath") or "", "content": payload.get("content", "")}
    if "read" in hook_event.lower():
        return {**base, "type": "file_read", "path": payload.get("path") or payload.get("filePath") or ""}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_hermes(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEvent", "before_tool_call")
    tool_name = payload.get("toolName", "")
    tool_input = payload.get("toolInput", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "hermes",
        "agent_event": hook_event,
        "metadata": {"gatewayId": payload.get("gatewayId"), "raw": payload},
    }
    if hook_event == "message_received":
        return {**base, "type": "prompt", "prompt": tool_input.get("content", "")}
    if hook_event == "message_sending":
        return {**base, "type": "tool_result", "response": tool_input.get("content", "")}
    if tool_name in {"Bash", "shell", "exec"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"FileRead", "Read", "read"}:
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"FileWrite", "FileEdit", "Write", "Edit", "write"}:
        return {**base, "type": "file_write", "path": tool_input.get("file_path") or tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name in {"WebFetch", "WebSearch", "web_search", "browser"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_openclaw(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEvent", "before_tool_call")
    tool_name = payload.get("toolName", "")
    tool_input = payload.get("toolInput", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "openclaw",
        "agent_event": hook_event,
        "metadata": {"agentId": payload.get("agentId"), "raw": payload},
    }
    if hook_event == "message_received":
        return {**base, "type": "prompt", "prompt": tool_input.get("content", "")}
    if hook_event == "message_sending":
        return {**base, "type": "tool_result", "response": tool_input.get("content", "")}
    if tool_name in {"Bash", "shell", "exec"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"FileRead", "Read", "read"}:
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"FileWrite", "FileEdit", "Write", "Edit", "write"}:
        return {**base, "type": "file_write", "path": tool_input.get("file_path") or tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name in {"WebFetch", "WebSearch", "web_search", "browser"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _ephemeral_session_id(agent: str, workspace: Path) -> str:
    digest = hashlib.sha1(f"{agent}:{workspace}:{os.getpid()}".encode("utf-8")).hexdigest()[:12]
    return f"{agent}-{digest}"


def _join_edits(edits: List[Dict[str, Any]]) -> str:
    return "\n".join(edit.get("new_string") or edit.get("newText") or "" for edit in edits if isinstance(edit, dict))


def _is_pre_action(agent_event: str) -> bool:
    lower = agent_event.lower()
    return (
        lower.startswith("pre")
        or lower.startswith("before")
        or agent_event in {"PreToolUse", "UserPromptSubmit"}
    )
