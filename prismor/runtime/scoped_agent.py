"""Scoped Agent — task-specific rule synthesis for Prismor.

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

_KNOWN_TOOLS = {"Read", "Write", "Edit", "MultiEdit", "Bash", "WebFetch", "WebSearch"}


def _resolve_tool_name(event: Dict[str, Any]) -> Optional[str]:
    """Resolve the concrete tool name for an event.

    Prefers the original tool name carried in ``metadata.tool_name`` (set by the
    hook normalizer) so deny_tools can target the specific tool that ran — e.g.
    distinguishing Edit from Write within a single file_write event, and
    allowing operators to scope arbitrary MCP tool tags such as
    ``mcp__node_repl__js`` from the dashboard. Falls back to the event-type
    mapping for synthetic events that carry no metadata (the CLI ``iam check``
    path and unit tests).
    """
    meta_tool = (event.get("metadata") or {}).get("tool_name") or ""
    if isinstance(meta_tool, str) and meta_tool.strip():
        return meta_tool.strip()
    return _EVENT_TYPE_TO_TOOL.get(event.get("type", ""))


# The tool tag a Claude Code skill invocation arrives under. Every skill shares
# it — the specific skill lives in the tool_input, not the tag.
_SKILL_TOOL = "Skill"

# Qualified skill tags are namespaced so they can never collide with a real
# tool tag, and so the console can classify them without a side-channel field.
_SKILL_PREFIX = "Skill:"

_MAX_SKILL_NAME = 120


def resolve_skill_name(event: Dict[str, Any]) -> Optional[str]:
    """Return the skill name for a ``Skill`` tool call, else None.

    Every skill invocation shares the tool tag ``Skill``; the name that says
    WHICH skill ran is only in the raw hook payload's tool_input. Without this
    the whole skill surface collapses to one undifferentiated tag.
    """
    meta = event.get("metadata") or {}
    raw = meta.get("raw")
    if not isinstance(raw, dict):
        return None
    tool_input = raw.get("tool_input") or raw.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        return None
    name = tool_input.get("skill") or ""
    if not isinstance(name, str):
        return None
    return name.strip()[:_MAX_SKILL_NAME] or None


def resolve_tool_tags(event: Dict[str, Any]) -> List[str]:
    """Tool tags this event may be inventoried or denied under.

    Usually just the resolved tool name. A skill call additionally yields the
    qualified ``Skill:<name>`` tag, so an operator can deny one skill without
    denying the whole mechanism. The bare tag stays first: denying ``Skill``
    must keep blocking every skill.
    """
    base = _resolve_tool_name(event)
    if not base:
        return []
    if base == _SKILL_TOOL:
        skill = resolve_skill_name(event)
        if skill:
            return [base, f"{_SKILL_PREFIX}{skill}"]
    return [base]


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
- If the task prompt contains @@SECRET:name@@ placeholders, include Bash so shell-based secret use can go through the agent's decloak hook or `prismor cloak run`.
"""


def _remote_scoped_rules(
    goal: str,
    available_tools: List[str],
    context: Optional[List[Dict[str, str]]] = None,
) -> Optional[Dict[str, Any]]:
    """Ask the control plane to synthesize the scope. None = not available.

    Only enrolled devices ask, and the org decides whether the request is
    honoured at all (scopeSynthesis) and how much of the session may be sent
    (scopeContextTurns, itself gated on full capture). The server is
    authoritative on both — the device only offers what it has.

    Returning None on ANY failure is the point. This runs inside the
    UserPromptSubmit hook, in front of a developer: an unreachable or declining
    control plane must mean "scope locally", never a hang or a traceback.
    """
    try:
        from prismor.runtime.enterprise import identity as _identity
        if not _identity.is_enrolled():
            return None
        ident = _identity.load_identity() or {}
        key = ident.get("device_key")
        if not key:
            return None

        import urllib.request
        base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
        payload: Dict[str, Any] = {"goal": goal, "availableTools": list(available_tools)}
        if context:
            payload["context"] = context
        req = urllib.request.Request(
            f"{base}/api/scope",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
        if not body.get("ok") or not isinstance(body.get("rules"), dict):
            return None
        rules = body["rules"]
        if not isinstance(rules.get("allowed_tools"), list):
            return None
        return rules
    except Exception:
        return None


def synthesize_scoped_rules(
    goal: str,
    available_tools: List[str],
    workspace: Path,
    context: Optional[List[Dict[str, str]]] = None,
) -> Optional[Dict[str, Any]]:
    """Generate scoped rules for a task.

    An enrolled device asks the control plane first, so an org can standardise
    scoping on one model and one key. Today every machine uses its own
    ANTHROPIC_API_KEY and a machine without one silently drops to keyword
    heuristics — the same prompt scopes differently per device, with nothing in
    the console to say which. The org must opt in; by default this is a no-op
    and nothing about the task leaves the machine.

    Falls back in order: control plane -> local Anthropic -> static heuristics.
    Returns None only if the static fallback also fails (should not happen).
    """
    remote = _remote_scoped_rules(goal, available_tools, context)
    if remote is not None:
        # Re-applied locally: the server applies it too, but a local safety
        # invariant must not rest on a remote promise.
        return _apply_cloak_invariant(remote, goal)

    try:
        import anthropic  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "[prismor] anthropic SDK not installed — using static scoped rules. "
            "Install with: pip3 install anthropic\n"
        )
        return _static_fallback_rules(goal, available_tools)

    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        sys.stderr.write(
            "[prismor] ANTHROPIC_API_KEY not set — using static scoped rules.\n"
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

        return _apply_cloak_invariant(rules, goal)

    except Exception as exc:
        sys.stderr.write(f"[prismor] scoped agent API error: {exc} — using static fallback.\n")
        return _static_fallback_rules(goal, available_tools)


def _apply_cloak_invariant(rules: Dict[str, Any], goal: str) -> Dict[str, Any]:
    """Enforce the cloaking invariant deterministically, regardless of how the
    rules were produced (LLM or static heuristic).

    A prompt that references a cloaked secret (``@@SECRET:name@@``) usually
    needs shell execution: Claude/Hermes can use their decloak hooks, while
    block-only agents such as Codex must use ``prismor cloak run``. So Bash MUST
    be allowed and network MUST be permitted whenever the goal carries a
    placeholder. The LLM path is advisory and sometimes drops Bash; this
    code-level guard makes the invariant non-negotiable so the secret-cloaking
    flow never self-blocks.
    """
    if "@@secret:" not in goal.lower():
        return rules
    allowed = [t for t in rules.get("allowed_tools", []) if t != "Bash"]
    rules["allowed_tools"] = allowed + ["Bash"]
    rules["deny_tools"] = [t for t in rules.get("deny_tools", []) if t != "Bash"]
    rules["deny_network"] = False
    return rules


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

    rules = {
        "allowed_tools": sorted(allowed),
        "allowed_paths": ["**"],  # broad by default in static mode
        "deny_tools": deny,
        "deny_network": deny_network,
    }
    # Cloaked-secret placeholders always require Bash (decloak runs in shell).
    return _apply_cloak_invariant(rules, goal)


# ── Sidecar persistence ───────────────────────────────────────────────────

def _scoped_dir(workspace: Path) -> Path:
    from prismor.runtime.store import prismor_home

    return prismor_home() / "scoped"


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
    if rules.get("paused", False):
        return None  # prismor paused by human operator via dashboard

    event_type = event.get("type", "")
    tool_name = _resolve_tool_name(event)

    # Tool check
    if tool_name:
        allowed = rules.get("allowed_tools", [])
        denied = rules.get("deny_tools", [])

        # deny_tools takes precedence over allowed_tools: an explicitly denied
        # tool is blocked even when a broader allow-rule would otherwise permit
        # it (e.g. allowed_tools:[Read,Edit] + deny_tools:[Write] blocks Write).
        if tool_name in denied:
            return _scoped_finding(
                session_id,
                f"Tool '{tool_name}' is explicitly denied for this session",
                event_type,
            )

        # "*" in allowed_tools = allow-all-except-denied. The dashboard writes
        # this when an operator denies a single tool for a session that had no
        # prior allowlist, so the deny does not silently turn into an allowlist
        # that blocks every other tool.
        if "*" not in allowed:
            if event_type == "file_write":
                # A write may arrive as Write, Edit, or MultiEdit. Permit it only if
                # the concrete tool is allowed, or — when the event carries no
                # tool name — any write-family tool is allowed and not denied.
                write_family = ("Write", "Edit", "MultiEdit")
                permitted = [t for t in write_family if t in allowed and t not in denied]
                if tool_name not in allowed and not permitted:
                    return _scoped_finding(
                        session_id,
                        f"Tool '{tool_name}' is not in scope for this session",
                        event_type,
                    )
            elif tool_name not in allowed:
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
        # Scope denials (IAM / scoped-agent) are explicit operator intent, not
        # observe-by-default detection — they always enforce.
        "mode": "enforce",
    }


# ── Display ────────────────────────────────────────────────────────────────

_BOLD = "\033[1m"
_NC = "\033[0m"
_CYAN = "\033[0;36m"
_DIM = "\033[37m"


def format_scoped_rules_box(rules: Dict[str, Any]) -> str:
    """Format scoped rules as an ASCII box. Colors only on an interactive
    terminal (honors NO_COLOR) so piped/redirected output doesn't leak raw
    ANSI escape sequences as literal text."""
    import os as _os
    _use_color = sys.stdout.isatty() and not _os.environ.get("NO_COLOR")
    _C = _CYAN if _use_color else ""
    _N = _NC if _use_color else ""
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
        "  These rules apply this session only and persist in .prismor/scoped/",
    ]

    max_width = max(len(line) for line in content_lines) + 4
    border = max_width + 2

    lines = []
    header = " scoped agent rules for this session "
    pad = border - 2 - len(header)
    lines.append(f"{_C}\u250c\u2500{header}" + "\u2500" * pad + f"\u2510{_N}")
    for cl in content_lines:
        padding = border - 2 - len(cl)
        lines.append(f"{_C}\u2502{_N}{cl}" + " " * padding + f"{_C}\u2502{_N}")
    lines.append(f"{_C}\u2514" + "\u2500" * border + f"\u2518{_N}")

    return "\n".join(lines)
