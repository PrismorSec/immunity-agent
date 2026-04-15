"""Skill / MCP server scanner for Prismor Warden.

Discovers MCP server and skill configurations across supported agents
(Claude Code, Cursor, Windsurf, OpenClaw, Hermes), synthesizes skill_manifest
events from each entry, and evaluates them through the PolicyEngine.

Usage (from CLI):
    warden scan                   # scan all discovered configs
    warden scan --agent claude    # only Claude Code configs
    warden scan --json            # machine-readable output
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from warden.policy_engine import PolicyEngine

# Severity ordering for descending sort.
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ── Config discovery ────────────────────────────────────────────────────────

def _claude_configs() -> List[Path]:
    """Return Claude Code settings paths (user + project-level)."""
    home = Path.home()
    candidates = [
        home / ".claude" / "settings.json",
        home / ".claude.json",
    ]
    # Also look for project-level .claude/settings.json in cwd
    cwd_config = Path.cwd() / ".claude" / "settings.json"
    if cwd_config.exists():
        candidates.append(cwd_config)
    return [p for p in candidates if p.exists()]


def _cursor_configs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".cursor" / "mcp.json",
        Path.cwd() / ".cursor" / "mcp.json",
    ]
    return [p for p in candidates if p.exists()]


def _windsurf_configs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".codeium" / "windsurf" / "mcp_config.json",
        Path.cwd() / ".windsurf" / "mcp.json",
    ]
    return [p for p in candidates if p.exists()]


def _openclaw_configs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".openclaw" / "config.json",
        home / ".openclaw" / "skills.json",
    ]
    return [p for p in candidates if p.exists()]


def _hermes_configs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".hermes" / "config.json",
        home / ".hermes" / "skills.json",
        home / ".hermes" / "plugins.json",
    ]
    return [p for p in candidates if p.exists()]


_AGENT_DISCOVERERS = {
    "claude": _claude_configs,
    "cursor": _cursor_configs,
    "windsurf": _windsurf_configs,
    "openclaw": _openclaw_configs,
    "hermes": _hermes_configs,
}


def discover_configs(agent: Optional[str] = None) -> List[Dict[str, Any]]:
    """Find all agent config files. Returns list of {agent, path}."""
    agents = [agent] if agent else list(_AGENT_DISCOVERERS.keys())
    results: List[Dict[str, Any]] = []
    for a in agents:
        discoverer = _AGENT_DISCOVERERS.get(a)
        if not discoverer:
            continue
        for p in discoverer():
            results.append({"agent": a, "path": p})
    return results


# ── Config parsing ──────────────────────────────────────────────────────────

def _extract_mcp_servers(data: Dict[str, Any], agent: str) -> List[Dict[str, Any]]:
    """Extract MCP server entries from a parsed config.

    Returns a list of dicts, each with at least {name, raw} where raw is the
    full server config object as a string for pattern matching.
    """
    servers: List[Dict[str, Any]] = []

    # Claude Code: {"mcpServers": {"name": {...}}}
    mcp_block = data.get("mcpServers") or data.get("mcp_servers") or {}
    if isinstance(mcp_block, dict):
        for name, cfg in mcp_block.items():
            servers.append({"name": name, "config": cfg, "raw": json.dumps(cfg, indent=2)})

    # Cursor / Windsurf: {"mcpServers": {"name": {...}}} — same shape
    # Some configs nest under "servers"
    if not servers:
        srv_block = data.get("servers") or {}
        if isinstance(srv_block, dict):
            for name, cfg in srv_block.items():
                servers.append({"name": name, "config": cfg, "raw": json.dumps(cfg, indent=2)})

    # OpenClaw skills: {"skills": [{"name": ..., ...}]}
    skills_list = data.get("skills") or []
    if isinstance(skills_list, list):
        for skill in skills_list:
            if isinstance(skill, dict):
                name = skill.get("name") or skill.get("id") or "unnamed"
                servers.append({"name": name, "config": skill, "raw": json.dumps(skill, indent=2)})

    return servers


def parse_config(config_path: Path) -> List[Dict[str, Any]]:
    """Parse a single config file and return extracted skill/server entries."""
    try:
        text = config_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return []

    agent = "unknown"
    path_str = str(config_path)
    for a in _AGENT_DISCOVERERS:
        if a in path_str.lower() or (a == "claude" and ".claude" in path_str):
            agent = a
            break

    entries = _extract_mcp_servers(data, agent)
    for entry in entries:
        entry["source"] = str(config_path)
        entry["agent"] = agent
    return entries


# ── Event synthesis ─────────────────────────────────────────────────────────

def _synthesize_event(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a parsed skill/server entry into a skill_manifest event."""
    # Combine all text for pattern matching: name + raw JSON config
    combined = f"name: {entry['name']}\n{entry['raw']}"

    # Also include any nested prompt/description fields
    cfg = entry.get("config", {})
    if isinstance(cfg, dict):
        for key in ("description", "prompt", "system_prompt", "instructions",
                     "command", "args", "url", "env"):
            val = cfg.get(key)
            if val:
                if isinstance(val, list):
                    combined += "\n" + " ".join(str(v) for v in val)
                elif isinstance(val, dict):
                    combined += "\n" + json.dumps(val)
                else:
                    combined += f"\n{val}"

    return {
        "type": "skill_manifest",
        "content": combined,
        "prompt": combined,
        "path": entry.get("source", ""),
    }


# ── Main scan entry point ──────────────────────────────────────────────────

def scan_skills(
    workspace: Optional[Path] = None,
    agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan all discovered skill/MCP configs and return findings.

    Returns:
        {
            "configs": [...],       # configs that were scanned
            "entries": int,         # total skill/server entries found
            "findings": [...],      # findings sorted by severity (desc)
            "summary": {...},       # counts by severity
        }
    """
    engine = PolicyEngine(workspace=workspace)
    configs = discover_configs(agent=agent)

    all_entries: List[Dict[str, Any]] = []
    for cfg in configs:
        entries = parse_config(cfg["path"])
        all_entries.extend(entries)

    findings: List[Dict[str, Any]] = []
    for i, entry in enumerate(all_entries):
        event = _synthesize_event(entry)
        entry_findings = engine.evaluate(event, index=i, session_id="scan")
        # Attach skill context to each finding
        for f in entry_findings:
            f["skillName"] = entry["name"]
            f["skillSource"] = entry.get("source", "")
            f["agent"] = entry.get("agent", "unknown")
        findings.extend(entry_findings)

    # Sort by severity: CRITICAL first, then HIGH, MEDIUM, LOW
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "UNKNOWN"), 99))

    # Build summary
    summary: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "configs": [{"agent": c["agent"], "path": str(c["path"])} for c in configs],
        "entries": len(all_entries),
        "findings": findings,
        "summary": summary,
    }
