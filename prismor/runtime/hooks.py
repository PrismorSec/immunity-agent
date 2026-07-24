from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.store import append_session_event

_SUPPORTED_AGENTS = [
    "claude", "cursor", "windsurf", "openclaw", "hermes", "codex", "copilot", "grok", "kiro",
    "crush", "openhands", "qwen", "continue", "goose",
]


def _strip_for_agent(agent: str, config: Dict[str, Any], marker: str) -> Tuple[Dict[str, Any], bool]:
    """Remove hooks whose command contains `marker`, for the given agent's config."""
    if agent == "claude":
        return _strip_claude(config, marker)
    if agent == "cursor":
        return _strip_cursor(config, marker)
    if agent == "openclaw":
        return _strip_openclaw(config, marker)
    if agent == "hermes":
        return _strip_hermes(config, marker)
    if agent == "codex":
        return _strip_codex(config, marker)
    if agent == "copilot":
        return _strip_copilot(config, marker)
    if agent == "grok":
        return _strip_grok(config, marker)
    if agent == "kiro":
        return _strip_kiro(config, marker)
    if agent == "crush":
        return _strip_crush(config, marker)
    if agent == "openhands":
        return _strip_openhands(config, marker)
    if agent == "qwen":
        return _strip_qwen(config, marker)
    if agent == "continue":
        return _strip_continue(config, marker)
    if agent == "goose":
        return _strip_goose(config, marker)
    return _strip_windsurf(config, marker)


def install_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str, mode: str) -> List[Dict[str, str]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        config = _read_json(config_path)
        # Idempotent + auto-migrating: drop any prior hook-dispatch hook (this
        # version's, or an older one that used a prismor/runtime/cli.py path) before adding
        # the current command, so re-running install never double-dispatches.
        config, _ = _strip_for_agent(current_agent, config, "hook-dispatch")
        command = _dispatcher_command(repo_root=repo_root, workspace=workspace, agent=current_agent, mode=mode)
        if current_agent == "claude":
            config = _merge_claude(config, command, workspace)
        elif current_agent == "cursor":
            config = _merge_cursor(config, command)
        elif current_agent == "openclaw":
            config = _merge_openclaw(config, command, repo_root)
        elif current_agent == "hermes":
            config = _merge_hermes(config, command, repo_root)
        elif current_agent == "codex":
            config = _merge_codex(config, command)
        elif current_agent == "copilot":
            config = _merge_copilot(config, command)
        elif current_agent == "grok":
            config = _merge_grok(config, command)
        elif current_agent == "kiro":
            config = _merge_kiro(config, command)
        elif current_agent == "crush":
            config = _merge_crush(config, command)
        elif current_agent == "openhands":
            config = _merge_openhands(config, command)
        elif current_agent == "qwen":
            config = _merge_qwen(config, command)
        elif current_agent == "continue":
            config = _merge_continue(config, command)
        elif current_agent == "goose":
            # Goose auto-discovers any plugin directory under .../plugins/<name>/
            # containing hooks/hooks.json — the plugin dir is config_path's
            # grandparent (.../plugins/prismor/hooks/hooks.json -> .../plugins/prismor/).
            config = _merge_goose(config, command, config_path.parent.parent)
        else:
            config = _merge_windsurf(config, command, workspace)

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        results.append({"agent": current_agent, "configPath": str(config_path)})
        if current_agent == "codex":
            # Codex only reads [features].hooks from the USER-level config.toml
            # -- verified live: with a project-scoped .codex/config.toml setting
            # hooks=true but the user config unavailable, hooks still never
            # dispatched. So this always targets $CODEX_HOME (Codex's own home-dir
            # override, default ~/.codex) even when scope == "project" (hooks.json
            # itself is correctly scoped).
            codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else Path.home() / ".codex"
            _ensure_codex_hooks_feature_enabled(codex_home / "config.toml")
    return results


def hook_installed(agent: str, scope: str, workspace: Path) -> bool:
    """True if a Prismor PreToolUse hook is present in this agent's config at
    ``scope`` ("project" | "global"). Text-based — the dispatcher command embeds
    the stable ``hook-dispatch`` marker in every agent's config format — so it
    works regardless of the JSON/TOML shape."""
    try:
        path = _config_path(agent, scope, workspace)
        return path.exists() and "hook-dispatch" in path.read_text(encoding="utf-8")
    except Exception:
        return False


def coverage(workspace: Path) -> Dict[str, Dict[str, bool]]:
    """Per *detected* agent on this machine, whether a Prismor hook is present at
    project and global scope. A detected agent with neither is an UNGUARDED
    install — a coverage gap an enrolled device must surface (and self-heal)."""
    from prismor.runtime.setup_wizard import _detect_agents
    out: Dict[str, Dict[str, bool]] = {}
    for agent, present in _detect_agents(workspace).items():
        if not present:
            continue
        out[agent] = {
            "project": hook_installed(agent, "project", workspace),
            "global": hook_installed(agent, "global", workspace),
        }
    return out


def unguarded_agents(workspace: Path) -> List[str]:
    """Detected agents with no Prismor hook at any scope — trivially bypassable."""
    return [a for a, s in coverage(workspace).items() if not (s["project"] or s["global"])]


def ensure_global_coverage(*, repo_root: Path, workspace: Path, mode: str = "observe") -> List[str]:
    """Self-heal: re-assert the GLOBAL hook for any detected agent that has no
    hook at all — the repair for a removed/absent hook on an enrolled device.
    Returns the agents that were (re)installed. Best-effort; never raises.

    Note this can only run when *some* Prismor code is already executing (another
    agent's hook, or the debounced policy refresh) — a machine with every hook
    removed and no Prismor invocation cannot heal itself. Global-scope install at
    enroll time is the primary guarantee; this is defense-in-depth on top."""
    repaired: List[str] = []
    try:
        gaps = unguarded_agents(workspace)
    except Exception:
        return repaired
    for agent in gaps:
        try:
            install_hooks(repo_root=repo_root, workspace=workspace, agent=agent, scope="global", mode=mode)
            repaired.append(agent)
        except Exception:
            pass
    return repaired


def _ensure_codex_hooks_feature_enabled(config_toml_path: Path) -> None:
    """Ensure Codex's own ``[features].hooks`` flag is set in the USER-level
    config.toml (``config_toml_path`` must always be ``~/.codex/config.toml``
    — Codex does not read this flag from a project-scoped config.toml, even
    when hooks.json itself is correctly project-scoped; verified live).

    Without it, Codex's hook dispatcher never runs at all — PreToolUse/
    PostToolUse/etc. are silently no-ops and every tool call passes straight
    through, with no error and no indication hooks aren't active. This is
    a *complete* silent bypass, verified live against codex-cli 0.142.5: a
    destructive command that should have been blocked ran and deleted the
    target file when this flag was unset. See PrismorSec/prismor#149.

    Written as a targeted text patch rather than a full TOML parse+rewrite
    so it never reformats or drops comments/sections in a config.toml that
    may carry substantial unrelated user configuration (plugins, MCP
    servers, project trust state, ...).
    """
    import re

    if not config_toml_path.exists():
        config_toml_path.parent.mkdir(parents=True, exist_ok=True)
        config_toml_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
        return

    text = config_toml_path.read_text(encoding="utf-8")
    if re.search(r"^\s*hooks\s*=\s*true\s*$", text, re.MULTILINE):
        return  # Already using the modern key.

    if re.search(r"^\s*codex_hooks\s*=\s*true\s*$", text, re.MULTILINE):
        # Migrate the deprecated key name in place.
        text = re.sub(
            r"^(\s*)codex_hooks(\s*=\s*true\s*)$", r"\1hooks\2", text, flags=re.MULTILINE
        )
    elif re.search(r"^\[features\]\s*$", text, re.MULTILINE):
        text = re.sub(r"^\[features\]\s*$", "[features]\nhooks = true", text, count=1, flags=re.MULTILINE)
    else:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n[features]\nhooks = true\n"

    config_toml_path.write_text(text, encoding="utf-8")


def uninstall_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str) -> List[Dict[str, Any]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        removed = False
        if config_path.exists():
            config = _read_json(config_path)
            # Match the stable hook-dispatch token rather than a specific script
            # path, so uninstall removes BOTH the current immunity-routed hooks
            # and any installed by an older build (which used a prismor/runtime/cli.py path).
            marker = "hook-dispatch"
            config, removed = _strip_for_agent(current_agent, config, marker)
            if removed:
                config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        # Also clean up internal hook directory for openclaw / hermes
        if current_agent == "openclaw":
            internal_hook = Path.home() / ".openclaw" / "hooks" / "prismor"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        if current_agent == "hermes":
            internal_hook = Path.home() / ".hermes" / "hooks" / "prismor"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        # Claude Code also installs separate cloaking hooks (decloak.sh,
        # recloak-mcp.sh, userprompt-guard.sh). The detection-hook strip
        # above only removes entries that reference cli.py, so cloaking
        # stays behind unless we explicitly uninstall it too. Tracked
        # separately (cloak_removed) so the CLI can call this out — see
        # PrismorSec/prismor#126.
        cloak_removed = False
        if current_agent == "claude":
            try:
                from prismor.runtime.cloaking import uninstall as cloak_uninstall
                cloak_result = cloak_uninstall(workspace=workspace, scope=scope)
                if cloak_result.get("removed"):
                    removed = True
                    cloak_removed = True
            except Exception:
                # Cloaking is optional — swallow any error so detection-hook
                # removal still reports cleanly.
                pass
        results.append({
            "agent": current_agent,
            "configPath": str(config_path),
            "removed": removed,
            "cloakRemoved": cloak_removed,
        })
    return results


def _strip_prismor_scrub_wrapper(cmd: str) -> str:
    """Recover the agent's real command from Prismor's own decloak wrapper.

    The cloaking decloak hook (cloaking/hooks/decloak.sh) rewrites every Bash
    command so its output is scrubbed of secrets:
        { <orig> ; } 2>&1 | PRISMOR_SECRETS_DIR=<dir> <scrubber>; exit ${PIPESTATUS[0]}
    Recording that wrapper verbatim clutters the dashboard and — because the
    injected PRISMOR_SECRETS_DIR path points at ~/.prismor/secrets — trips
    Prismor's own prismor-vault-access guard, blocking benign commands. Strip
    the wrapper so both storage and policy evaluation see the original command.
    Fail-safe: anything that does not match the exact wrapper shape is returned
    unchanged, so a real command that merely mentions the vault still evaluates.
    """
    if not cmd:
        return cmd
    marker = " 2>&1 | PRISMOR_SECRETS_DIR="
    i = cmd.rfind(marker)
    if i == -1:
        return cmd
    tail = cmd[i + len(marker):]
    if "scrub-stream" not in tail or "PIPESTATUS" not in tail:
        return cmd
    inner = cmd[:i].strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1].strip()
        if inner.endswith(";"):
            inner = inner[:-1].strip()
    return inner or cmd


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
    elif agent == "codex":
        event = _normalize_codex(payload, session_id, workspace)
    elif agent == "copilot":
        event = _normalize_copilot(payload, session_id, workspace)
    elif agent == "grok":
        event = _normalize_grok(payload, session_id, workspace)
    elif agent == "kiro":
        event = _normalize_kiro(payload, session_id, workspace)
    elif agent == "crush":
        event = _normalize_crush(payload, session_id)
    elif agent == "openhands":
        event = _normalize_openhands(payload, session_id)
    elif agent == "qwen":
        event = _normalize_qwen(payload, session_id, workspace)
    elif agent == "continue":
        event = _normalize_continue(payload, session_id, workspace)
    elif agent == "goose":
        event = _normalize_goose(payload, session_id)
    else:
        event = _normalize_cursor(payload, session_id)
    if isinstance(event, dict) and event.get("type") == "shell" and event.get("command"):
        event["command"] = _strip_prismor_scrub_wrapper(event["command"])
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
        from prismor.runtime.policy_engine import PolicyEngine
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
    block_categories: set | None = None,  # legacy/no-op; kept for call-site compat
) -> Dict[str, Any] | None:
    if not _is_pre_action(str(event.get("agent_event", ""))):
        return None

    # Authoritative enforce lever is the per-finding `mode` (derived from the
    # rule's mode, else the policy's default_mode — both default to "observe").
    # A finding blocks only when its effective mode is "enforce". block_categories
    # no longer gates this (every category is observe-by-default until enforced).
    # DENY-wins precedence: when several enforce findings fire on one event
    # with mixed actions, the strongest verdict wins (block > step_up > defer
    # > modify) rather than whichever the engine surfaced first. Unknown
    # actions (warn/log/unset on an enforce finding) rank as block — enforce
    # means "stop". Ties keep first-surfaced order (min() is stable).
    _ACTION_RANK = {"block": 0, "step_up": 1, "defer": 2, "modify": 3}
    eligible: List[Dict[str, Any]] = []
    for finding in findings:
        if str(finding.get("mode", "observe")).lower() == "enforce":
            # Reads are generally safe, so they only block for secret access —
            # except for IAM, where an operator has explicitly scoped which
            # paths/tools an identity may read, and that intent must be honored.
            if (
                event.get("type") == "file_read"
                and finding.get("category") not in ("secret_access", "iam")
            ):
                continue
            eligible.append(finding)
    if not eligible:
        return None
    return min(eligible, key=lambda f: _ACTION_RANK.get(str(f.get("action") or "block").lower(), 0))


def legacy_should_block(
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    block_categories: set,
) -> Dict[str, Any] | None:
    """Backward-compat block decision for policies that predate per-rule
    observe/enforce (see PolicyEngine.is_legacy_policy). Replicates the original
    semantics: on a pre-action event, block a finding whose category is in the
    policy's ``block_categories`` — with the same read carve-out as the modern
    path. Only invoked by cli.py when installed with ``--mode enforce``.
    """
    if not block_categories:
        return None
    if not _is_pre_action(str(event.get("agent_event", ""))):
        return None
    for finding in findings:
        if finding.get("category") in block_categories:
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
        if agent == "codex":
            return workspace / ".codex" / "hooks.json"
        if agent == "copilot":
            return workspace / ".github" / "copilot" / "hooks.json"
        if agent == "grok":
            return workspace / ".grok" / "hooks" / "prismor.json"
        if agent == "kiro":
            return workspace / ".kiro" / "agents" / "kiro_default.json"
        if agent == "crush":
            return workspace / "crush.json"
        if agent == "openhands":
            return workspace / ".openhands" / "hooks.json"
        if agent == "qwen":
            return workspace / ".qwen" / "settings.json"
        if agent == "continue":
            return workspace / ".continue" / "settings.json"
        if agent == "goose":
            return workspace / ".agents" / "plugins" / "prismor" / "hooks" / "hooks.json"
        return workspace / ".windsurf" / "hooks.json"

    if agent == "claude":
        return home / ".claude" / "settings.json"
    if agent == "cursor":
        return home / ".cursor" / "hooks.json"
    if agent == "openclaw":
        return home / ".openclaw" / "config.json"
    if agent == "hermes":
        return home / ".hermes" / "config.json"
    if agent == "codex":
        return home / ".codex" / "hooks.json"
    if agent == "copilot":
        return home / ".copilot" / "hooks.json"
    if agent == "grok":
        return home / ".grok" / "hooks" / "prismor.json"
    if agent == "kiro":
        return home / ".kiro" / "agents" / "kiro_default.json"
    if agent == "crush":
        return home / ".config" / "crush" / "crush.json"
    if agent == "openhands":
        # OpenHands only documents a project-scoped `.openhands/hooks.json`; no
        # official global path exists. Fall back to $OPENHANDS_PERSISTENCE_DIR
        # (default ~/.openhands), matching where its other global state lives,
        # for a "global"-scope install rather than erroring — unverified.
        return home / ".openhands" / "hooks.json"
    if agent == "qwen":
        return home / ".qwen" / "settings.json"
    if agent == "continue":
        return home / ".continue" / "settings.json"
    if agent == "goose":
        return home / ".agents" / "plugins" / "prismor" / "hooks" / "hooks.json"
    return home / ".codeium" / "windsurf" / "hooks.json"


def _dispatcher_command(*, repo_root: Path, workspace: Path, agent: str, mode: str) -> str:
    # Route through the prismor CLI for consistency (one canonical entry point),
    # invoked as a module with the current interpreter. Using `-m` + sys.executable
    # — rather than a raw path to prismor/runtime/cli.py — keeps the hook working across
    # editable installs (no physical file to vanish) and avoids depending on the
    # `prismor` console-script being on PATH inside the IDE's hook environment.
    #
    # PYTHONPATH is prepended so the hook works regardless of how the IDE/agent
    # launcher configures the environment (Claude Code strips user site-packages).
    py = sys.executable or "python3"
    return (
        f'PYTHONPATH="{repo_root}" "{py}" -m prismor.runtime.immunity_cli hook-dispatch '
        f'--agent {agent} --workspace "{workspace}" --mode {mode}'
    )


def _merge_claude(config: Dict[str, Any], command: str, workspace: Path) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*", "hooks": [{"type": "command", "command": command}]},
    )
    hooks["PostToolUse"] = _merge_claude_entries(
        hooks.get("PostToolUse", []),
        {"matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*", "hooks": [{"type": "command", "command": command}]},
    )
    # SessionStart carries the project-memory files (CLAUDE.md/AGENTS.md) that
    # Claude auto-loads before any tool call. Scanning them here brings their
    # directives under the same content rules as untrusted tool output so a
    # poisoned memory file is detected at session start. See issue #155.
    hooks["SessionStart"] = _merge_claude_entries(
        hooks.get("SessionStart", []),
        {"matcher": "startup|resume|clear|compact", "hooks": [{"type": "command", "command": command}]},
    )
    # Skip "Stop" hook — the payload contains the full assistant response which
    # exceeds OS argument limits (E2BIG) on long conversations. Stop fires after
    # all actions are complete so it has no security enforcement value.
    env = dict(config.get("env", {}))
    env["PRISMOR_WORKSPACE"] = str(workspace)
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
    if "PRISMOR_WORKSPACE" in env:
        del env["PRISMOR_WORKSPACE"]
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
    plugin_dir = repo_root / "prismor" / "runtime" / "openclaw-plugin"
    _scaffold_openclaw_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".openclaw" / "hooks" / "prismor"
    _scaffold_openclaw_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_openclaw(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "warden" not in p.lower() and "prismor" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_OPENCLAW_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

function dispatch(payload) {
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor" };
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

Prismor prompt injection detection hook.
Scans inbound messages for prompt injection patterns.
"""

_OPENCLAW_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

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
    execSync(PRISMOR_COMMAND, {
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
        "name": "@prismor/openclaw-prismor",
        "version": "0.1.0",
        "description": "Prismor security hooks for OpenClaw",
        "main": "index.js",
        "openclaw": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _OPENCLAW_PLUGIN_JS.replace("__PRISMOR_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_openclaw_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_OPENCLAW_HOOK_MD, encoding="utf-8")
    js = _OPENCLAW_HOOK_JS.replace("__PRISMOR_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_hermes(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the plugin package
    plugin_dir = repo_root / "prismor" / "runtime" / "hermes-plugin"
    _scaffold_hermes_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".hermes" / "hooks" / "prismor"
    _scaffold_hermes_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_hermes(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "warden" not in p.lower() and "prismor" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_HERMES_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

function dispatch(payload) {
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor" };
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

Prismor prompt injection detection hook for Hermes gateway.
Scans inbound messages for prompt injection patterns before they reach
the model.
"""

_HERMES_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

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
    execSync(PRISMOR_COMMAND, {
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
        "name": "@prismor/hermes-prismor",
        "version": "0.1.0",
        "description": "Prismor security hooks for Hermes gateway",
        "main": "index.js",
        "hermes": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _HERMES_PLUGIN_JS.replace("__PRISMOR_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_hermes_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_HERMES_HOOK_MD, encoding="utf-8")
    js = _HERMES_HOOK_JS.replace("__PRISMOR_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_copilot(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in ["PreToolUse", "PostToolUse", "UserPromptSubmitted"]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "version": config.get("version", 1), "hooks": hooks}


def _merge_codex(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PermissionRequest", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|apply_patch|mcp__.*",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


def _merge_grok(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


# Kiro CLI's built-in default agent ("kiro_default") has no on-disk config
# until one is created; whether Kiro merges a partial override with the
# built-in tool list or replaces it outright is undocumented (kiro.dev has
# no example of overriding kiro_default, only creating new named agents).
# So a *fresh* file is seeded as a fully self-contained agent -- explicit
# tools list included -- rather than a hooks-only fragment, so that even in
# a full-replace scenario the user does not silently lose default-agent
# tools the moment Prismor installs hooks. An existing file (the user's own
# customized kiro_default, or a prior Prismor install) is left otherwise
# untouched; only "hooks" is merged into it.
_KIRO_DEFAULT_TOOLS = [
    "read", "glob", "grep", "write", "shell", "aws", "web_search", "web_fetch",
    "code", "introspect", "tool_search", "delegate", "subagent", "report",
    "session", "goal", "knowledge", "thinking", "todo",
]


def _merge_kiro(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    if "name" not in config:
        config = {**config, "name": "kiro_default", "tools": list(_KIRO_DEFAULT_TOOLS)}
    hooks = dict(config.get("hooks", {}))
    # No "matcher" field on an entry means Kiro applies it to every tool --
    # the broadest coverage, matching the other agents' "*"/mcp__.* matchers.
    for event_name in ["userPromptSubmit", "preToolUse", "postToolUse"]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "hooks": hooks}


def _merge_crush(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Crush's hooks config is a flat dict of event -> list of {name, matcher,
    # command} entries (no nested "hooks" array like Claude/Codex). Verified
    # live (2026-07): only PreToolUse is actually dispatched -- there is no
    # PostToolUse/UserPromptSubmit hook surface in crush v0.86.x despite the
    # SDK schema exposing a HookConfig type generically. Matcher "" matches
    # every tool (verified: an empty-matcher rule fired for a non-bash tool).
    hooks = dict(config.get("hooks", {}))
    entries = list(hooks.get("PreToolUse", []))
    if not any(e.get("command") == command for e in entries):
        entries.append({"name": "prismor", "matcher": "", "command": command})
    hooks["PreToolUse"] = entries
    return {**config, "hooks": hooks}


def _merge_openhands(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Same nested {matcher, hooks:[{type, command}]} shape as Claude/Codex.
    # Verified live (2026-07): PreToolUse fires and a non-zero exit blocks the
    # tool call. "*" matches every tool (docs: "*" | exact tool name | /regex/).
    hooks = dict(config.get("hooks", {}))
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 60}]},
    )
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command, "timeout": 60}]},
    )
    return {**config, "hooks": hooks}


def _merge_qwen(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Claude-Code-shaped hooks (nested matcher + hooks[]), but Qwen Code's own
    # tool ids, NOT Claude's ("run_shell_command" not "Bash" -- verified live,
    # a matcher of "Bash" silently never fires). "*" matches every tool.
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
        )
    return {**config, "hooks": hooks}


def _merge_continue(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Continue CLI's hooks.json schema is intentionally Claude-Code-compatible
    # (same event names, same tool-name convention -- "Bash"). WARNING, verified
    # live (2026-07, cn v1.5.47): hooks configured exactly per this schema, in
    # every documented config location, did not fire in headless (`cn -p`)
    # mode for ANY event including UserPromptSubmit -- not just PreToolUse.
    # Ship anyway (interactive-mode users still benefit; the config is inert,
    # not harmful, if the headless bug is present) but never assume this is
    # actually enforcing anything without checking `cn` in the target
    # environment first. See AGENT_INTEGRATIONS.md.
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|Fetch|Search",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


def _merge_goose(config: Dict[str, Any], command: str, plugin_dir: Path) -> Dict[str, Any]:
    # Goose auto-discovers plugin directories containing hooks/hooks.json --
    # no central "plugins": [...] list to register, unlike OpenClaw/Hermes.
    # `config` here IS the plugin's own hooks.json; plugin.json is a static
    # manifest scaffolded once as a side effect. Verified live (2026-07,
    # goose v1.44.0): the built-in shell tool's real name is "shell", NOT
    # "developer__shell" as goose's own official docs example shows -- a
    # matcher of "developer__shell" silently never fires. ".*" matches every
    # tool and is what's used here to avoid depending on that undocumented
    # exact name for coverage.
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.exists():
        manifest_path.write_text(
            json.dumps(
                {"name": "prismor", "version": "0.1.0", "description": "Prismor security hooks"},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    hooks = dict(config.get("hooks", {}))
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": ".*", "hooks": [{"type": "command", "command": command, "timeout": 15}]},
    )
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command, "timeout": 15}]},
    )
    return {**config, "hooks": hooks}


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


def _strip_codex(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _strip_grok(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _strip_kiro(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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


def _strip_crush(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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


def _strip_openhands(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _strip_qwen(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _strip_continue(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _strip_goose(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
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
    return {**config, "hooks": hooks}, removed


def _normalize_copilot(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
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
    # Copilot is an approval-capable surface (inline "ask"), so MCP calls must
    # be classified like the other agents' — otherwise `mcp` guardrail rules
    # (block / step_up on mcp__server__tool) silently never fire here.
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_args,
        response=payload.get("toolResult", payload.get("tool_result", payload.get("response"))),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_codex(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "codex",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {
            **base,
            "type": "shell",
            "command": tool_input.get("command", ""),
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write", "apply_patch"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            # A plain single Edit call (as opposed to MultiEdit) has shape
            # {file_path, old_string, new_string} — no "edits" list and no
            # "content" key — so new_string must be its own fallback or the
            # written text is invisible to every content-based check.
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
                or tool_input.get("command", "")
            ),
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


def _normalize_grok(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hookEventName") or payload.get("hook_event_name") or "unknown"
    tool_name = payload.get("toolName") or payload.get("tool_name") or ""
    tool_input = payload.get("toolInput") or payload.get("tool_input") or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "grok",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {
            **base,
            "type": "shell",
            "command": tool_input.get("command", ""),
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_input.get("url", ""), "response": payload.get("response", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("toolResponse", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_kiro(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "kiro",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "userPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    # Kiro's canonical tool names are snake_case (execute_bash, fs_read,
    # fs_write, use_aws); it also accepts camelCase/short aliases (shell,
    # read, write, aws) depending on how the calling agent config lists
    # its tools, so match on either form.
    if tool_name in {"shell", "execute_bash", "execute_cmd"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"read", "fs_read", "fsRead"}:
        return {**base, "type": "file_read", "path": tool_input.get("path", "")}
    if tool_name in {"write", "fs_write", "fsWrite"}:
        # fs_write's documented shape is {"operations": [{"mode": ..., "path": ...}]}
        # rather than a flat {path, content} -- the exact per-mode content field
        # is not documented, so this is a best-effort extraction from the first
        # operation with several fallback field names.
        ops = tool_input.get("operations") or []
        first_op = ops[0] if ops and isinstance(ops[0], dict) else {}
        path = tool_input.get("path") or first_op.get("path", "")
        content = (
            tool_input.get("content")
            or first_op.get("content")
            or first_op.get("text")
            or first_op.get("newText", "")
        )
        return {**base, "type": "file_write", "path": path, "content": content}
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_crush(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, crush v0.86.x):
    # {"event": "PreToolUse", "session_id", "cwd", "tool_name": "bash",
    #  "tool_input": {"command": ..., "description": ...}}
    hook_event = payload.get("event", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "crush",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if tool_name == "bash":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "view":
        return {**base, "type": "file_read", "path": tool_input.get("path", "")}
    if tool_name in {"write", "edit", "multiedit"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path") or tool_input.get("file_path", ""),
            "content": tool_input.get("content") or tool_input.get("new_string", ""),
        }
    if tool_name in {"fetch", "download", "sourcegraph"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_openhands(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, openhands v1.21.0). Field name is
    # "event_type" -- NOT "hook_event_name" like the Claude/Codex-family
    # agents -- and the shell tool's name is "terminal", not "execute_bash".
    hook_event = payload.get("event_type") or payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "openhands",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("working_dir"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("message") or payload.get("prompt", "")}
    if tool_name == "terminal":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "file_editor":
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path", ""),
            "content": tool_input.get("content") or tool_input.get("new_str", ""),
        }
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


def _normalize_qwen(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    # Same field-naming convention as Claude/Codex (hook_event_name, tool_name,
    # tool_input) but Qwen Code's own tool ids -- verified live (2026-07,
    # qwen-code v0.20.1): "run_shell_command", not "Bash".
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "qwen",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "run_shell_command":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "read_file":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"write_file", "edit", "replace"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": tool_input.get("content") or tool_input.get("new_string", ""),
        }
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
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


def _normalize_continue(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    # Continue CLI's hooks payload is intentionally Claude-Code-compatible
    # (same field names AND tool-name convention -- "Bash", "Read", "Edit",
    # ...). NOTE: hooks were not observed to fire at all in headless (`cn -p`)
    # mode in live testing (2026-07, cn v1.5.47) -- this normalizer may never
    # actually receive a payload in that mode. See _merge_continue.
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "continue",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
        }
    if tool_name in {"Fetch", "Search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
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


def _normalize_goose(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, goose v1.44.0): field name is
    # "event" (not "hook_event_name"), and the built-in shell tool's real
    # name is "shell" -- NOT "developer__shell" as goose's own official docs
    # example shows. See _merge_goose.
    hook_event = payload.get("event", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "goose",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("working_dir"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("message", "")}
    if tool_name == "shell":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "write":
        return {**base, "type": "file_write", "path": tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name == "edit":
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path", ""),
            "content": tool_input.get("after", ""),
        }
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
        from prismor.runtime.scanner import discover_configs, parse_config
        for cfg in discover_configs(workspace=workspace):
            for entry in parse_config(cfg["path"], agent=cfg["agent"]):
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


# Project-memory files auto-loaded by the agent at session start. Their
# directives are trusted implicitly by the model, so Prismor treats them as an
# untrusted content source (issue #155).
_MEMORY_FILENAMES = ("CLAUDE.md", "AGENTS.md")
# Cap total scanned memory content so a huge memory file can't blow the OS
# argument limit / telemetry payload. Detection patterns fire on the leading
# directive-shaped text; a truncated tail is acceptable.
_MEMORY_SCAN_LIMIT = 64_000


def _read_project_memory(workspace: Path) -> Dict[str, Any]:
    """Collect CLAUDE.md/AGENTS.md content the agent loads at session start.

    Searches the workspace and its ancestors (project-scoped memory) plus the
    user's ~/.claude directory (global memory). Returns the concatenated text
    and the list of files it came from. Best-effort: unreadable files are
    skipped rather than failing the hook.
    """
    seen: set[Path] = set()
    parts: List[str] = []
    files: List[str] = []

    search_dirs: List[Path] = []
    try:
        ws = workspace.resolve()
        search_dirs.append(ws)
        search_dirs.extend(ws.parents[:3])
    except Exception:
        search_dirs.append(workspace)
    search_dirs.append(Path.home() / ".claude")

    for directory in search_dirs:
        for name in _MEMORY_FILENAMES:
            candidate = directory / name
            try:
                resolved = candidate.resolve()
            except Exception:
                resolved = candidate
            if resolved in seen or not candidate.is_file():
                continue
            seen.add(resolved)
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            files.append(str(candidate))
            parts.append(f"# {candidate}\n{text}")

    content = "\n\n".join(parts)[:_MEMORY_SCAN_LIMIT]
    return {"content": content, "files": files}


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
    if hook_event == "SessionStart":
        # payload["cwd"] is the live directory of *this* session, sent by
        # Claude on every hook call. `workspace` is whatever was configured
        # at `install-hooks` time (often a fixed dir for --scope user
        # installs) — falling back to it when cwd is absent, but preferring
        # cwd means the scan actually covers the project the agent is
        # running in, not wherever hooks happened to be installed from. See
        # PrismorSec/prismor#155 follow-up: a user-scope install pointed at
        # $HOME meant every session's memory scan silently read $HOME's
        # CLAUDE.md instead of the real project's, regardless of cwd.
        raw_cwd = payload.get("cwd")
        memory_root = Path(raw_cwd) if raw_cwd else workspace
        memory = _read_project_memory(memory_root)
        base["metadata"]["memory_files"] = memory["files"]
        return {**base, "type": "memory", "content": memory["content"]}
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
            # A plain single Edit call (as opposed to MultiEdit) has shape
            # {file_path, old_string, new_string} — no "edits" list and no
            # "content" key — so new_string must be its own fallback or the
            # written text is invisible to every content-based check.
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
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
        or agent_event in {"PreToolUse", "UserPromptSubmit", "PermissionRequest"}
    )
