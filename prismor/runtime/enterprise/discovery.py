"""Local-host AI discovery — find agents on this machine Prismor doesn't govern.

Prismor already inventories the agents that run through its hooks
(``agents.list_agents``). That misses the ones nobody wired up: a Claude Code
or Codex install sitting on the machine with no Prismor hooks, quietly making
tool calls Prismor never sees. This module sweeps the host for those.

For each supported agent it answers three questions from files already on disk:

  * **present**  — is the agent's config or CLI on this machine?
  * **governed** — are Prismor hooks wired into that config?
  * **seen**     — has the agent actually run through Prismor (in the registry)?

An agent that's present and *not* governed is the finding: shadow AI tooling
outside Prismor's coverage. The sweep is read-only and host-local. It does not
touch the network — that's a separate, heavier project. It reuses the config
locations `scanner.py` already knows and the registry `agents.py` maintains.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

# Where each agent's presence and CLI show up, beyond the config files
# scanner.py already enumerates. Config discovery drives "present"; these add
# a CLI/state signal so an agent installed but not yet configured still counts.
_AGENT_CLI_MARKERS = {
    "claude": [".claude"],
    "cursor": [".cursor"],
    "windsurf": [".codeium", ".windsurf"],
    "openclaw": [".openclaw"],
    "hermes": [".hermes"],
    "codex": [".codex"],
}

# Substring that marks a config as Prismor-governed. The installers write the
# dispatcher command (`prismor ... hook-dispatch`) into each agent's hook
# config, so its presence in any config file for that agent means governed.
_GOVERNED_MARKER = "prismor"


def _config_has_marker(path: Path) -> bool:
    try:
        return _GOVERNED_MARKER in path.read_text(encoding="utf-8", errors="ignore").lower()
    except (OSError, UnicodeError):
        return False


def _governed_frameworks(workspace: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Registry view keyed by framework id: whether Prismor has seen it run."""
    out: Dict[str, Dict[str, Any]] = {}
    try:
        from prismor.runtime.agents import list_agents
        for a in list_agents(workspace):
            fw = a.framework or a.name
            entry = out.setdefault(fw, {"seen": True, "last_seen": a.last_seen})
            # keep the most recent last_seen if several instances share a framework
            if a.last_seen and (not entry["last_seen"] or a.last_seen > entry["last_seen"]):
                entry["last_seen"] = a.last_seen
    except Exception:
        pass
    return out


def discover(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Sweep this host. Returns a report::

        {
          "agents": [
            {"agent", "present", "governed", "seen",
             "last_seen", "config_paths": [...]}
          ],
          "summary": {"present", "governed", "ungoverned", "seen"}
        }

    ``ungoverned`` counts agents present on the host with no Prismor hooks —
    the shadow-AI number.
    """
    from prismor.runtime.scanner import _AGENT_DISCOVERERS, discover_configs

    ws = workspace or Path.cwd()
    home = Path.home()
    registry = _governed_frameworks(workspace)

    # Config files present, grouped by agent (existence check — discover_configs
    # returns candidate paths whether or not they exist).
    configs_by_agent: Dict[str, List[Path]] = {}
    for entry in discover_configs(workspace=ws):
        p = entry["path"]
        if p.exists():
            configs_by_agent.setdefault(entry["agent"], []).append(p)

    agents_out: List[Dict[str, Any]] = []
    for agent in sorted(_AGENT_DISCOVERERS):
        cfgs = configs_by_agent.get(agent, [])
        cli_present = any((home / m).exists() for m in _AGENT_CLI_MARKERS.get(agent, []))
        present = bool(cfgs) or cli_present
        governed = any(_config_has_marker(p) for p in cfgs)
        reg = registry.get(agent, {})
        agents_out.append({
            "agent": agent,
            "present": present,
            "governed": governed,
            "seen": bool(reg.get("seen")),
            "last_seen": reg.get("last_seen"),
            "config_paths": [str(p) for p in cfgs],
        })

    present = [a for a in agents_out if a["present"]]
    summary = {
        "present": len(present),
        "governed": sum(1 for a in present if a["governed"]),
        "ungoverned": sum(1 for a in present if not a["governed"]),
        "seen": sum(1 for a in agents_out if a["seen"]),
    }
    return {"agents": agents_out, "summary": summary}
