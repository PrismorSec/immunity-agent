"""Install/uninstall cloaking hooks in a Claude Code settings.json.

Mirrors the merge-in-place pattern used by ``warden/hooks.py`` so that
cloaking hooks coexist cleanly with Warden's existing runtime-monitor
hooks on the same ``.claude/settings.json`` file. Each hook entry is
identified by a unique marker string (its absolute script path), and
uninstall only strips entries matching the marker — leaving everything
else intact.

Currently supports Claude Code only. Cursor, Windsurf, OpenClaw, and Hermes
do not yet expose equivalent ``updatedInput`` / ``updatedMCPToolOutput``
fields.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from warden.cloaking.secrets_store import secrets_dir

# Hook scripts shipped under warden/cloaking/hooks/
_HOOKS_SUBDIR = Path(__file__).resolve().parent / "hooks"

_DECLOAK = _HOOKS_SUBDIR / "decloak.sh"
_RECLOAK_MCP = _HOOKS_SUBDIR / "recloak-mcp.sh"
_USERPROMPT_GUARD = _HOOKS_SUBDIR / "userprompt-guard.sh"
_SWEEP_ON_STOP = _HOOKS_SUBDIR / "sweep-on-stop.sh"

# All cloaking hook commands share this marker so uninstall can find them.
_MARKER = "warden/cloaking/hooks/"


def _claude_settings_path(workspace: Path, scope: str) -> Path:
    if scope == "project":
        return workspace / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _merge_claude_entries(
    entries: List[Dict[str, Any]], new_entry: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Merge a matcher block into an existing list, deduping by command.

    This mirrors the helper in ``warden/hooks.py``. We do not import it
    directly to keep cloaking independently usable.
    """
    next_entries = list(entries)
    existing = next(
        (e for e in next_entries if e.get("matcher") == new_entry.get("matcher")),
        None,
    )
    if existing is None:
        next_entries.append(new_entry)
        return next_entries
    existing_commands = {h.get("command") for h in existing.get("hooks", [])}
    for hook in new_entry["hooks"]:
        if hook.get("command") not in existing_commands:
            existing.setdefault("hooks", []).append(hook)
    return next_entries


def _hook_entry(script: Path) -> Dict[str, Any]:
    return {"type": "command", "command": str(script)}


_CLAUDE_MD_BLOCK = """
## Secrets (Prismor Cloak)

Real secret values are cloaked by Prismor Warden. When you need to use a secret
in a shell command or tool call, reference it as `@@SECRET:name@@`. The Warden
decloak hook substitutes the real value at execution time and scrubs it back out
of the captured output before it reaches this context. Never echo, print, log,
or narrate real secret values — use the placeholder form in all code, commands,
and prose. Use `warden cloak list` to see registered placeholder names.
"""


def _inject_claude_md(workspace: Path) -> None:
    """Append the cloak convention block to the project CLAUDE.md if missing."""
    claude_md = workspace / "CLAUDE.md"
    marker = "@@SECRET:"
    if claude_md.exists() and marker in claude_md.read_text(encoding="utf-8"):
        return
    with claude_md.open("a", encoding="utf-8") as f:
        f.write(_CLAUDE_MD_BLOCK)


def install(
    *,
    workspace: Path,
    scope: str = "project",
    enable_userprompt_guard: bool = True,
    enable_sweep_on_stop: bool = False,
) -> Dict[str, Any]:
    """Install the cloaking hooks into ``settings.json``.

    Args:
        workspace: Project directory (used when ``scope='project'``).
        scope: ``'project'`` writes to ``<workspace>/.claude/settings.json``;
            ``'user'`` writes to ``~/.claude/settings.json``.
        enable_userprompt_guard: Wire the soft-block UserPromptSubmit hook.
            Disable if you plan to use a clipboard-level filter instead.
        enable_sweep_on_stop: Wire the Stop-hook dry-run sweep. Off by
            default because it runs ``warden sweep`` against ``~/.claude``
            on every session end, which is noisy for quick sessions.

    Returns:
        Dict with ``configPath``, ``hooksInstalled`` (list of event names),
        and ``secretsDir``.
    """
    # Ensure the secrets directory exists with correct permissions before
    # the first hook fires.
    sdir = secrets_dir()
    sdir.mkdir(parents=True, exist_ok=True)
    try:
        sdir.chmod(0o700)
    except PermissionError:
        pass

    path = _claude_settings_path(workspace, scope)
    config = _read_json(path)
    hooks = dict(config.get("hooks", {}))

    installed: List[str] = []

    # PreToolUse: decloak on Bash matcher.
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "Bash", "hooks": [_hook_entry(_DECLOAK)]},
    )
    installed.append("PreToolUse:Bash (decloak)")

    # PostToolUse: recloak MCP responses.
    hooks["PostToolUse"] = _merge_claude_entries(
        hooks.get("PostToolUse", []),
        {"matcher": "mcp__.*", "hooks": [_hook_entry(_RECLOAK_MCP)]},
    )
    installed.append("PostToolUse:mcp__.* (recloak)")

    # UserPromptSubmit: soft-block with auto-cloak.
    if enable_userprompt_guard:
        hooks["UserPromptSubmit"] = _merge_claude_entries(
            hooks.get("UserPromptSubmit", []),
            {"hooks": [_hook_entry(_USERPROMPT_GUARD)]},
        )
        installed.append("UserPromptSubmit (guard)")

    # Stop: dry-run sweep for residue.
    if enable_sweep_on_stop:
        hooks["Stop"] = _merge_claude_entries(
            hooks.get("Stop", []),
            {"hooks": [_hook_entry(_SWEEP_ON_STOP)]},
        )
        installed.append("Stop (sweep)")

    # Also seed the secrets-dir env var so the scripts pick up overrides
    # set through ``warden cloak`` rather than the default location.
    env = dict(config.get("env", {}))
    env["PRISMOR_SECRETS_DIR"] = str(sdir)

    new_config = {**config, "hooks": hooks, "env": env}
    _write_json(path, new_config)

    if scope == "project":
        _inject_claude_md(workspace)

    return {
        "configPath": str(path),
        "hooksInstalled": installed,
        "secretsDir": str(sdir),
    }


def uninstall(*, workspace: Path, scope: str = "project") -> Dict[str, Any]:
    """Remove cloaking hooks from ``settings.json``.

    Only entries whose command path contains ``_MARKER`` are stripped. Any
    other Warden or user hooks in the file are left untouched.
    """
    path = _claude_settings_path(workspace, scope)
    if not path.exists():
        return {"configPath": str(path), "removed": False}

    config = _read_json(path)
    hooks = dict(config.get("hooks", {}))
    removed_any = False

    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for entry in entries:
            inner = entry.get("hooks", [])
            filtered = [
                h for h in inner if _MARKER not in str(h.get("command", ""))
            ]
            if len(filtered) < len(inner):
                removed_any = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
        # Drop the event key entirely if it became empty.
        if not cleaned:
            del hooks[event_name]

    env = dict(config.get("env", {}))
    if "PRISMOR_SECRETS_DIR" in env:
        del env["PRISMOR_SECRETS_DIR"]
        removed_any = True

    new_config = {**config, "hooks": hooks}
    if env:
        new_config["env"] = env
    elif "env" in new_config:
        del new_config["env"]

    if removed_any:
        _write_json(path, new_config)

    return {"configPath": str(path), "removed": removed_any}


def status(*, workspace: Path, scope: str = "project") -> Dict[str, Any]:
    """Report installation state of cloaking hooks."""
    path = _claude_settings_path(workspace, scope)
    result: Dict[str, Any] = {
        "configPath": str(path),
        "installed": False,
        "events": [],
        "secretsDir": str(secrets_dir()),
    }
    if not path.exists():
        return result

    try:
        config = _read_json(path)
    except json.JSONDecodeError:
        return result

    events_found: List[str] = []
    for event_name, entries in config.get("hooks", {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            for h in entry.get("hooks", []):
                if _MARKER in str(h.get("command", "")):
                    label = f"{event_name}"
                    matcher = entry.get("matcher")
                    if matcher:
                        label += f":{matcher}"
                    if label not in events_found:
                        events_found.append(label)

    result["installed"] = bool(events_found)
    result["events"] = events_found
    return result
