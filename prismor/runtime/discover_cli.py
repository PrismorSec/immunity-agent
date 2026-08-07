"""`prismor discover` — find AI agents, MCP servers and provider keys on this
machine that Prismor is not governing.

Sections:
    (default)   all three inventories plus a coverage score
    agents      AI coding agents installed, and whether hooks are in place
    mcp         MCP servers declared anywhere, and whether they route through
                the gateway
    keys        AI-provider credentials, and whether Cloak has them

The inventory and diff logic lives in ``discover``; this module is UX only.

Output never contains a secret value — the ``keys`` section reports provider
and location only, by construction (see ``discover.CredentialRecord``).
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime import discover as _discover

# ── output helpers (match cli.py's ANSI style, no deps) ──────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RESET}"


def _home_relative(path: str) -> str:
    home = str(Path.home())
    return path.replace(home, "~") if path.startswith(home) else path


_RISK_COLOR = {"high": _RED, "medium": _YELLOW, "low": _CYAN, "none": _DIM}


def _badge(managed: bool) -> str:
    return _c("governed", _GREEN) if managed else _c("SHADOW", _RED)


# ── sections ─────────────────────────────────────────────────────────────────


def _print_agents(agents: List[Dict[str, Any]]) -> None:
    print(f"  {_c('AGENTS', _BOLD)}")
    if not agents:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for agent in agents:
        managed = agent["managed"]
        coverable = agent.get("coverable", True)
        # An agent Prismor has no hook for is not a shadow finding — nothing
        # was skipped. Badge it distinctly so it matches the shadow count.
        if managed:
            badge = _badge(True)
        elif coverable:
            badge = _badge(False)
        else:
            badge = _c("no coverage", _YELLOW)
        line = f"    {badge:<22} {agent['name']}"
        if managed and agent.get("mode"):
            line += _c(f"  ({agent['mode']})", _DIM)
        if not coverable:
            line += _c("  (Prismor has no hook for this agent)", _DIM)
        print(line)
        detail = _home_relative((agent.get("config_paths") or [""])[0])
        if detail:
            print(f"      {_c(detail, _DIM)}")
    print()


def _print_mcp(servers: List[Dict[str, Any]]) -> None:
    print(f"  {_c('MCP SERVERS', _BOLD)}")
    visible = [s for s in servers if not s.get("is_gateway")]
    if not visible:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for server in visible:
        risk = server.get("risk", "none")
        line = f"    {_badge(server['managed']):<22} {server['name']}"
        line += _c(f"  [{server['agent']}]", _DIM)
        if risk != "none":
            line += "  " + _c(risk, _RISK_COLOR.get(risk, _DIM))
        print(line)
        target = server.get("url") or " ".join(server.get("command") or [])
        if target:
            print(f"      {_c(target[:88], _DIM)}")
        for finding in server.get("findings") or []:
            print(f"      {_c('· ' + finding, _DIM)}")
    print()


def _print_credentials(creds: List[Dict[str, Any]]) -> None:
    print(f"  {_c('PROVIDER KEYS', _BOLD)}")
    if not creds:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for cred in creds:
        where = cred["location"]
        if cred["location_kind"] == "file":
            where = _home_relative(where)
        line = f"    {_badge(cred['managed']):<22} {cred['provider']}"
        line += _c(f"  {where}", _DIM)
        print(line)
    print()


def _print_summary(report: Dict[str, Any]) -> None:
    summary = report["summary"]
    context = report["context"]
    coverage = summary["coverage"]

    print(f"  {_c('─' * 58, _DIM)}")
    if coverage is None:
        print(f"  {_c('No governable AI surface found on this machine.', _DIM)}")
        print()
        return

    color = _GREEN if coverage >= 80 else (_YELLOW if coverage >= 40 else _RED)
    print(f"  {_c('Coverage:', _BOLD)}  {_c(str(coverage) + '%', color)}"
          f"  {_c('of discovered AI surface is governed', _DIM)}")

    shadow_total = (summary["agents_shadow"] + summary["mcp_shadow"]
                    + summary["credentials_shadow"])
    if shadow_total:
        parts = []
        if summary["agents_shadow"]:
            parts.append(f"{summary['agents_shadow']} agent(s)")
        if summary["mcp_shadow"]:
            parts.append(f"{summary['mcp_shadow']} MCP server(s)")
        if summary["credentials_shadow"]:
            parts.append(f"{summary['credentials_shadow']} key(s)")
        print(f"  {_c('Shadow:', _BOLD)}    {_c(', '.join(parts), _RED)}")
    if summary["high_risk_mcp"]:
        print(f"  {_c('High risk:', _BOLD)} "
              f"{_c(str(summary['high_risk_mcp']) + ' ungoverned MCP server(s)', _RED)}")

    print()
    if not context["enrolled"]:
        print(f"  {_c('This device is not enrolled.', _YELLOW)} "
              f"Findings stay local and are not visible to your team.")
        print(f"  Next: {_c('prismor enroll', _CYAN)}"
              f"   {_c('— report coverage to the console', _DIM)}")
    elif shadow_total:
        print(f"  Next: {_c('prismor install', _CYAN)}"
              f"        {_c('— hook the unmanaged agents', _DIM)}")
        if summary["mcp_shadow"]:
            print(f"        {_c('prismor mcp-gateway install', _CYAN)}"
                  f" {_c('— route MCP servers through the gateway', _DIM)}")
        if summary["credentials_shadow"]:
            print(f"        {_c('prismor cloak add <name>', _CYAN)}"
                  f"   {_c('— cloak the exposed keys', _DIM)}")
    else:
        print(f"  {_c('All discovered AI surface is governed.', _GREEN)}")
    print()


# ── commands ─────────────────────────────────────────────────────────────────


def discover_all(workspace: Path, *, as_json: bool = False,
                 scan_files: bool = True, fail_on_shadow: bool = False,
                 report_to_console: bool = False) -> None:
    """Full report: agents, MCP servers, keys, and a coverage score."""
    report = _discover.build_report(workspace, scan_files=scan_files)
    sent: Optional[bool] = None
    if report_to_console:
        sent = _discover.send_report(report)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print(f"  {_c('PRISMOR', _BOLD)}  discover"
              f"   {_c(_home_relative(str(workspace)), _DIM)}")
        print(f"  {_c('─' * 58, _DIM)}")
        print()
        _print_agents(report["agents"])
        _print_mcp(report["mcp"])
        _print_credentials(report["credentials"])
        _print_summary(report)
        if sent is True:
            print(f"  {_c('Reported to your organization console.', _DIM)}")
            print()
        elif sent is False:
            # Say which of the two reasons it was — "not enrolled" is a
            # different action from "the console did not answer".
            enrolled = report["context"].get("enrolled")
            reason = ("this device is not enrolled" if not enrolled
                      else "the console could not be reached")
            print(f"  {_c('Not reported — ' + reason + '.', _YELLOW)}")
            print()

    if fail_on_shadow:
        summary = report["summary"]
        shadow = (summary["agents_shadow"] + summary["mcp_shadow"]
                  + summary["credentials_shadow"])
        if shadow:
            sys.exit(1)


def discover_agents(workspace: Path, *, as_json: bool = False) -> None:
    """AI coding agents installed here, and whether Prismor hooks them."""
    records = [asdict(a) for a in _discover.discover_agents(workspace)]
    if as_json:
        print(json.dumps({"agents": records}, indent=2))
        return
    print()
    _print_agents(records)


def discover_mcp(workspace: Path, *, as_json: bool = False) -> None:
    """MCP servers declared anywhere, and whether they route through the gateway."""
    records = [asdict(m) for m in _discover.discover_mcp(workspace)]
    if as_json:
        print(json.dumps({"mcp": records}, indent=2))
        return
    print()
    _print_mcp(records)


def discover_keys(workspace: Path, *, as_json: bool = False,
                  scan_files: bool = True) -> None:
    """AI-provider credentials found here, and whether Cloak has them."""
    records = [asdict(c)
               for c in _discover.discover_credentials(workspace,
                                                       scan_files=scan_files)]
    if as_json:
        print(json.dumps({"credentials": records}, indent=2))
        return
    print()
    _print_credentials(records)
