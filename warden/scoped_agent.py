"""Scoped Agent — task-specific rule synthesis for Warden.

Generates a minimal, session-scoped rule set at the start of each session
based on the user's task description. Rules are enforced alongside
policy.yaml for the duration of that session only.

The active rule set becomes:  policy.yaml (base) + scoped_agent (session-only)
"""
from __future__ import annotations

import json
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Tool name mapping ──────────────────────────────────────────────────────
# Maps normalized event types to the tool names used in scoped rules.

_EVENT_TYPE_TO_TOOL = {
    "shell": "Bash",
    "file_read": "Read",
    "file_write": "Write",
    "network": "WebFetch",
}


# ── Rule synthesis ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security policy synthesizer for an AI coding agent.
Given a task description and a list of available tools, output a minimal
JSON object that scopes the agent to only what this task genuinely requires.
Be conservative — if a tool is not clearly needed, exclude it.
Output only valid JSON, no explanation, no markdown fences.
Schema:
{
  "allowed_tools": [...],
  "allowed_paths": [...],
  "deny_tools": [...],
  "deny_network": true | false
}
Rules:
- allowed_tools: tool names the task needs (from the available list)
- allowed_paths: glob patterns for file paths the task should access
- deny_tools: tools explicitly not needed (complement of allowed)
- deny_network: true to block all network access, false to allow
- If the task involves reading/editing code, allow Read/Edit/Write for relevant paths
- If the task does NOT mention network, web, fetch, install, or download, set deny_network: true
- Always include Read in allowed_tools (agents need to read files to orient)
"""


def synthesize_scoped_rules(
    goal: str,
    available_tools: List[str],
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    """Call the Anthropic API to generate scoped rules for a task.

    Returns a parsed dict on success, or falls back to static heuristics
    if the SDK is unavailable or the API call fails. Returns None only if
    the static fallback also fails (should not happen).
    """
    try:
        import anthropic  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "[warden] anthropic SDK not installed — using static scoped rules. "
            "Install with: pip3 install anthropic\n"
        )
        return _static_fallback_rules(goal, available_tools)

    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        sys.stderr.write(
            "[warden] ANTHROPIC_API_KEY not set — using static scoped rules.\n"
        )
        return _static_fallback_rules(goal, available_tools)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            temperature=0,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Task: {goal}\nAvailable tools: {', '.join(available_tools)}",
            }],
        )

        text = response.content[0].text.strip()
        rules = json.loads(text)

        # Validate shape
        if not isinstance(rules.get("allowed_tools"), list):
            raise ValueError("allowed_tools must be a list")
        if not isinstance(rules.get("deny_tools"), list):
            rules["deny_tools"] = []
        if not isinstance(rules.get("allowed_paths"), list):
            rules["allowed_paths"] = ["**"]
        if "deny_network" not in rules:
            rules["deny_network"] = True

        # Clamp to the known-good available_tools list to prevent prompt injection
        # from expanding the allowed set beyond what the agent actually has.
        available_set = set(available_tools)
        rules["allowed_tools"] = [t for t in rules["allowed_tools"] if t in available_set]
        rules["deny_tools"] = [t for t in rules["deny_tools"] if t in available_set]

        return rules

    except Exception as exc:
        sys.stderr.write(f"[warden] scoped agent API error: {exc} — using static fallback.\n")
        return _static_fallback_rules(goal, available_tools)


def _static_fallback_rules(goal: str, available_tools: List[str]) -> Dict[str, Any]:
    """Keyword-based heuristic fallback when no API is available."""
    goal_lower = goal.lower()

    # Start with Read always allowed
    allowed = {"Read"}
    deny_network = True

    # Detect task intent from keywords
    edit_keywords = {"edit", "fix", "refactor", "update", "change", "modify", "add", "implement", "create", "write"}
    test_keywords = {"test", "run", "execute", "build", "compile", "lint", "check"}
    network_keywords = {"fetch", "download", "install", "deploy", "push", "pull", "clone", "api", "http", "url"}
    search_keywords = {"search", "find", "grep", "look"}

    if any(kw in goal_lower for kw in edit_keywords):
        allowed.update({"Edit", "MultiEdit", "Write", "Bash"})
    if any(kw in goal_lower for kw in test_keywords):
        allowed.update({"Bash"})
    if any(kw in goal_lower for kw in network_keywords):
        allowed.update({"WebFetch", "WebSearch"})
        deny_network = False
    if any(kw in goal_lower for kw in search_keywords):
        allowed.update({"Bash"})  # for grep/find

    deny = [t for t in available_tools if t not in allowed]

    return {
        "allowed_tools": sorted(allowed),
        "allowed_paths": ["**"],  # broad by default in static mode
        "deny_tools": deny,
        "deny_network": deny_network,
    }


# ── Sidecar persistence ───────────────────────────────────────────────────

def _scoped_dir(workspace: Path) -> Path:
    return workspace / ".prismor-warden" / "scoped"


def _scoped_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    return _scoped_dir(workspace) / f"{safe}.json"


def save_scoped_rules(workspace: Path, session_id: str, rules: Dict[str, Any]) -> Path:
    """Write scoped rules to a session-specific sidecar file."""
    path = _scoped_path(workspace, session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules, indent=2) + "\n", encoding="utf-8")
    return path


def load_scoped_rules(workspace: Path, session_id: str) -> Optional[Dict[str, Any]]:
    """Load scoped rules for a session. Returns None if no rules exist."""
    path = _scoped_path(workspace, session_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def clear_scoped_rules(workspace: Path, session_id: str) -> bool:
    """Remove scoped rules for a session. Returns True if file was deleted."""
    path = _scoped_path(workspace, session_id)
    if path.exists():
        path.unlink()
        return True
    return False


def list_scoped_sessions(workspace: Path) -> List[Dict[str, Any]]:
    """List all sessions that have active scoped rules."""
    scoped = _scoped_dir(workspace)
    if not scoped.exists():
        return []
    results = []
    for f in sorted(scoped.glob("*.json")):
        try:
            rules = json.loads(f.read_text(encoding="utf-8"))
            results.append({
                "session_id": f.stem,
                "path": str(f),
                "rules": rules,
            })
        except (json.JSONDecodeError, OSError):
            continue
    return results


# ── Enforcement ────────────────────────────────────────────────────────────

def check_scoped_rules(
    rules: Dict[str, Any],
    event: Dict[str, Any],
    session_id: str = "",
) -> Optional[Dict[str, Any]]:
    """Check an event against session-scoped rules.

    Returns a finding dict if the event is blocked, None if allowed.
    """
    event_type = event.get("type", "")
    tool_name = _EVENT_TYPE_TO_TOOL.get(event_type)

    # Tool check
    if tool_name:
        allowed = rules.get("allowed_tools", [])
        denied = rules.get("deny_tools", [])

        # Handle Write/Edit distinction: if event is file_write, check both Write and Edit
        if event_type == "file_write":
            if "Write" not in allowed and "Edit" not in allowed and "MultiEdit" not in allowed:
                return _scoped_finding(
                    session_id,
                    f"Tool '{tool_name}' is not in scope for this session",
                    event_type,
                )
        elif tool_name not in allowed or tool_name in denied:
            return _scoped_finding(
                session_id,
                f"Tool '{tool_name}' is not in scope for this session",
                event_type,
            )

    # Path check for file events
    if event_type in ("file_read", "file_write"):
        path = event.get("path", "")
        if path:
            allowed_paths = rules.get("allowed_paths", ["**"])
            if not any(fnmatch(path, pattern) for pattern in allowed_paths):
                return _scoped_finding(
                    session_id,
                    f"Path '{path}' is outside the scoped paths for this session",
                    event_type,
                )

    # Network check
    if event_type == "network":
        if rules.get("deny_network", False):
            url = event.get("url", "")
            return _scoped_finding(
                session_id,
                f"Network access denied by scoped rules (url: {url[:100]})",
                event_type,
            )

    return None


def _scoped_finding(session_id: str, reason: str, event_type: str) -> Dict[str, Any]:
    """Build a finding dict for a scoped rule violation."""
    return {
        "id": f"{session_id}:scoped-agent",
        "severity": "HIGH",
        "category": "scoped_agent",
        "title": f"[scoped agent] {reason}",
        "evidence": reason,
        "ruleId": "scoped-agent",
        "action": "block",
    }


# ── Display ────────────────────────────────────────────────────────────────

_BOLD = "\033[1m"
_NC = "\033[0m"
_CYAN = "\033[0;36m"
_DIM = "\033[37m"


def format_scoped_rules_box(rules: Dict[str, Any]) -> str:
    """Format scoped rules as an ASCII box for stderr display."""
    allowed = ", ".join(rules.get("allowed_tools", []))
    paths = ", ".join(rules.get("allowed_paths", []))
    denied = ", ".join(rules.get("deny_tools", []))
    network = "denied" if rules.get("deny_network", True) else "allowed"

    content_lines = [
        f"  allowed_tools:  [{allowed}]",
        f"  allowed_paths:  [{paths}]",
        f"  deny_tools:     [{denied}]",
        f"  deny_network:   {network}",
        "",
        "  These rules apply this session only and persist in .prismor-warden/scoped/",
    ]

    max_width = max(len(line) for line in content_lines) + 4
    border = max_width + 2

    lines = []
    header = " scoped agent rules for this session "
    pad = border - 2 - len(header)
    lines.append(f"{_CYAN}\u250c\u2500{header}" + "\u2500" * pad + f"\u2510{_NC}")
    for cl in content_lines:
        padding = border - 2 - len(cl)
        lines.append(f"{_CYAN}\u2502{_NC}{cl}" + " " * padding + f"{_CYAN}\u2502{_NC}")
    lines.append(f"{_CYAN}\u2514" + "\u2500" * border + f"\u2518{_NC}")

    return "\n".join(lines)
