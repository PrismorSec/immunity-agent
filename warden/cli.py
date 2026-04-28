#!/usr/bin/env python3
"""Prismor Warden CLI — local session-security utility for AI coding agents.

Commands:
  check         Quick pre-check a command or file path against policy rules
  scan          Scan all MCP servers and skills for security risks
  deps          Check workspace dependencies against threat feed
  audit         Full security posture check across all Warden subsystems
  audit --fix   Auto-remediate fixable issues
  status        Show findings from the most recent session
  analyze       Analyze a JSONL session file
  ingest        Analyze and store a session
  sessions      List stored sessions
  session       Show a specific session
  install-hooks Install IDE hooks for real-time monitoring
  uninstall-hooks Remove IDE hooks
  hook-dispatch Internal: called by IDE hooks (not for direct use)
  policy init   Generate a starter policy.yaml for your project
  policy validate  Validate a policy.yaml file
  sweep         Scan AI tool configs for leaked secrets
  sweep --redact  Redact secrets and save to encrypted vault
  sweep --clean   Delete residue files (passphrase required)
  sweep --restore Restore secrets from vault
  cloak install   Install secret-cloaking hooks (Claude Code)
  cloak uninstall Remove cloaking hooks
  cloak add NAME  Register a real secret under a placeholder name
  cloak list      List registered placeholder names (never values)
  cloak remove NAME  Delete a registered secret
  cloak status    Show whether cloaking hooks are installed
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from warden import __version__

# ── Dependency check ────────────────────────────────────────────────
# PyYAML is required for the policy engine to load any rules.
# Without it, all security checks silently pass — a total bypass.
try:
    import yaml as _yaml_check  # noqa: F401
except ImportError:
    sys.stderr.write(
        "\n"
        "ERROR: PyYAML is required but not installed.\n"
        "  Warden cannot load any policy rules without it.\n"
        "\n"
        "  Install with:  pip3 install pyyaml\n"
        "           or:   apt-get install python3-yaml\n"
        "\n"
    )
    sys.exit(1)

from warden.feed import load_feed, match_advisories
from warden.hooks import install_hooks, normalize_payload, should_block, uninstall_hooks
from warden.policy_engine import PolicyEngine, validate_policy
from warden.store import (
    append_session_event,
    get_db_path,
    get_sessions_dir,
    get_session,
    infer_default_workspace,
    initialize_database,
    list_registered_workspaces,
    list_sessions,
    read_session_events,
    register_workspace,
    save_session_snapshot,
)

SEVERITY_WEIGHT = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 3,
    "UNKNOWN": 1,
}

# ANSI colors for terminal output
_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_GREEN = "\033[0;32m"
_CYAN = "\033[0;36m"
_DIM = "\033[37m"  # light gray — \033[2m is invisible on dark terminals
_BOLD = "\033[1m"
_NC = "\033[0m"


def _color(text: str, color: str) -> str:
    """Apply ANSI color if stdout is a terminal."""
    if not sys.stderr.isatty():
        return text
    return f"{color}{text}{_NC}"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    repo_root = Path(__file__).resolve().parent.parent

    # Resolve workspace: explicit --workspace flag (at any position) wins,
    # then PRISMOR_WARDEN_WORKSPACE env var, then inferred from cwd.
    # argparse subparsers that also declare --workspace clobber the top-level
    # value with None when the flag isn't repeated on the subcommand — so we
    # fall back to a manual scan of argv to recover the original value.
    ws_value = getattr(args, "workspace", None)
    if not ws_value:
        argv = sys.argv[1:]
        for i, tok in enumerate(argv):
            if tok == "--workspace" and i + 1 < len(argv):
                ws_value = argv[i + 1]
                break
            if tok.startswith("--workspace="):
                ws_value = tok.split("=", 1)[1]
                break
    if not ws_value:
        ws_value = os.environ.get("PRISMOR_WARDEN_WORKSPACE")
    workspace = Path(ws_value).resolve() if ws_value else infer_default_workspace(Path.cwd())

    # ── dashboard: global overview ───────────────────────────────────────
    if args.command == "dashboard":
        _print_dashboard()
        return

    # ── info: quick workspace summary ───────────────────────────────────
    if args.command == "info":
        _print_info(workspace)
        return

    # ── check: quick pre-check a command or path ───────────────────────
    if args.command == "check":
        engine = PolicyEngine(workspace=workspace)

        # --from-log: replay a session file through the current policy
        if getattr(args, "from_log", None):
            log_path = Path(args.from_log)
            if not log_path.exists():
                sys.stderr.write(f"error: log file not found: {log_path}\n")
                raise SystemExit(1)
            total_findings: List[Dict[str, Any]] = []
            total_events = 0
            for line in log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total_events += 1
                # Accept either already-normalised events or raw hook payloads.
                if "type" not in event and "hook_event_name" in event:
                    # map Claude-style hook to normalised event
                    if "tool_input" in event and isinstance(event["tool_input"], dict):
                        cmd = event["tool_input"].get("command")
                        path_v = event["tool_input"].get("file_path")
                        if cmd:
                            event = {"type": "shell", "command": cmd}
                        elif path_v:
                            t = "file_read" if event.get("hook_event_name") == "PreToolUse" else "file_read"
                            event = {"type": t, "path": path_v}
                total_findings.extend(engine.evaluate(event, total_events))
            print(f"Replayed {total_events} event(s) from {log_path}")
            if not total_findings:
                print(_color("PASS", _GREEN) + "  no findings")
                return
            _print_findings(total_findings, engine=engine,
                            explain=args.explain, suggest=args.suggest_allowlist)
            if any(f.get("action") == "block" for f in total_findings):
                raise SystemExit(2)
            raise SystemExit(1)

        if not args.value:
            sys.stderr.write("error: either a value or --from-log is required\n")
            raise SystemExit(2)

        if args.type == "command":
            findings = engine.check_command(args.value)
        elif args.type in ("read", "write"):
            event_type = "file_read" if args.type == "read" else "file_write"
            findings = engine.check_path(args.value, event_type=event_type)
        else:
            findings = engine.check_command(args.value)

        if not findings:
            print(_color("PASS", _GREEN) + f"  {args.value}")
            return

        _print_findings(findings, engine=engine,
                        explain=args.explain, suggest=args.suggest_allowlist,
                        input_value=args.value)

        # Exit 2 if any finding has action=block, 1 for warn-only, 0 for log-only.
        if any(f.get("action") == "block" for f in findings):
            raise SystemExit(2)
        if any(f.get("action") == "warn" for f in findings):
            raise SystemExit(1)
        return

    # ── scan: scan MCP servers and skills ────────────────────────────
    if args.command == "scan":
        from warden.scanner import scan_skills
        result = scan_skills(workspace=workspace, agent=getattr(args, "agent", None))

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return

        configs = result["configs"]
        findings = result["findings"]
        n_entries = result["entries"]
        summary = result["summary"]

        print()
        print(f"  {_color('PRISMOR WARDEN', _BOLD)}  skill scanner")
        print(f"  {_color('─' * 50, _DIM)}")
        print()

        if not configs:
            print(f"  {_color('No agent configs found.', _DIM)}")
            print(f"  Looked for MCP/skill configs in Claude Code, Cursor, Windsurf, OpenClaw, Hermes.")
            print()
            return

        for cfg in configs:
            print(f"  {_color('Config:', _GREEN)}  [{cfg['agent']}] {cfg['path']}")
        print(f"  {_color('Entries:', _GREEN)} {n_entries} skill(s) / MCP server(s)")
        print()

        if not findings:
            print(f"  {_color('PASS', _GREEN)}  No issues found across {n_entries} entries.")
            print()
            return

        for f in findings:
            sev = f["severity"]
            color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
            action_label = f.get("action", "warn").upper()
            print(f"  {_color(f'[{sev}]', color)}  {f['title']}")
            print(f"           skill: {_color(f['skillName'], _CYAN)}  ({f['agent']})")
            print(f"           rule: {f.get('ruleId', '?')}  ({action_label})")
            evidence = f.get("evidence", "")
            if evidence:
                # Truncate long evidence lines for display
                if len(evidence) > 100:
                    evidence = evidence[:97] + "..."
                print(f"           evidence: {_color(evidence, _DIM)}")
            print()

        # Summary line
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = summary.get(sev, 0)
            if count:
                color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
                parts.append(_color(f"{count} {sev.lower()}", color))
        print(f"  {_color('─' * 50, _DIM)}")
        print(f"  {len(findings)} finding(s): {', '.join(parts)}")

        has_blocking = any(f.get("action") == "block" for f in findings)
        if has_blocking:
            print(f"  {_color('Recommendation: review blocking findings before using these skills.', _RED)}")
        print()

        if has_blocking:
            raise SystemExit(2)
        return

    # ── deps: dependency-to-feed correlation ─────────────────────────
    if args.command == "deps":
        from warden.deps import scan_workspace as deps_scan
        feed = load_feed(repo_root)
        result = deps_scan(workspace, feed)

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return

        print()
        print(f"  {_color('PRISMOR WARDEN', _BOLD)}  dependency check")
        print(f"  {_color('─' * 50, _DIM)}")
        print()

        manifests = result["manifests"]
        if not manifests:
            print(f"  {_color('No dependency manifests found.', _DIM)}")
            print()
            return

        for m in manifests:
            print(f"  {_color('Manifest:', _GREEN)}  [{m['ecosystem']}] {m['path']}")
        print(f"  {_color('Dependencies:', _GREEN)} {result['dependencies']} total")
        print()

        feed_matches = result["feed_matches"]
        lockfile_issues = result["lockfile_issues"]
        integrity_issues = result.get("integrity_issues", [])

        if not feed_matches and not lockfile_issues and not integrity_issues:
            print(f"  {_color('PASS', _GREEN)}  No known vulnerabilities or lockfile issues found.")
            print()
            return

        if feed_matches:
            print(f"  {_color('Feed matches:', _BOLD)}")
            for match in feed_matches:
                sev = match["severity"]
                color = _RED if sev in ("critical", "high") else _YELLOW
                print(f"    {_color(f'[{sev.upper()}]', color)}  {match['advisory_id']}: {match['title']}")
                print(f"             affected: {match['affected']}")
                if match.get("action"):
                    print(f"             action: {match['action']}")
            print()

        if lockfile_issues:
            print(f"  {_color('Lockfile issues:', _BOLD)}")
            for issue in lockfile_issues:
                sev = issue["severity"]
                print(f"    {_color(f'[{sev}]', _YELLOW)}  {issue['message']}")
            print()

        if integrity_issues:
            print(f"  {_color('Lockfile integrity issues:', _BOLD)}")
            for issue in integrity_issues:
                sev = issue["severity"]
                color = _RED if sev == "HIGH" else _YELLOW
                print(f"    {_color(f'[{sev}]', color)}  {issue['message']}")
                print(f"             lockfile: {issue.get('lockfile','')}")
            print()

        # Summary
        total_issues = len(feed_matches) + len(lockfile_issues) + len(integrity_issues)
        print(f"  {_color('─' * 50, _DIM)}")
        print(f"  {total_issues} issue(s) found")
        print()

        if feed_matches or any(i["severity"] == "HIGH" for i in integrity_issues):
            raise SystemExit(1)
        return

    # ── audit: full security posture check ──────────────────────────
    if args.command == "audit":
        from warden.audit import run_audit, apply_fixes, AuditFinding
        findings = run_audit(workspace=workspace, repo_root=repo_root)

        if getattr(args, "json", False):
            print(json.dumps([f.to_dict() for f in findings], indent=2))
            return

        print()
        print(f"  {_color('PRISMOR WARDEN', _BOLD)}  security audit")
        print(f"  {_color('─' * 58, _DIM)}")
        print()

        # Group findings by category for clean display
        categories_seen: list[str] = []
        grouped: dict[str, list] = {}
        for f in findings:
            if f.category not in grouped:
                grouped[f.category] = []
                categories_seen.append(f.category)
            grouped[f.category].append(f)

        # Category display labels
        _CAT_LABELS = {
            "hooks": "Hook Integrations",
            "policy": "Policy Coverage",
            "cloaking": "Cloaking (Secret Prevention)",
            "permissions": "Secret Permissions",
            "feed": "Threat Feed",
            "network": "Network Isolation",
            "supply_chain": "Supply Chain",
        }

        _SEV_ICON = {
            "CRITICAL": _color("CRITICAL", _RED),
            "HIGH":     _color("HIGH", _RED),
            "MEDIUM":   _color("MEDIUM", _YELLOW),
            "LOW":      _color("LOW", _DIM),
            "INFO":     _color("INFO", _DIM),
            "PASS":     _color("PASS", _GREEN),
        }

        for cat in categories_seen:
            label = _CAT_LABELS.get(cat, cat.title())
            print(f"  {_color(label, _BOLD)}")

            for f in grouped[cat]:
                icon = _SEV_ICON.get(f.severity, f.severity)
                fix_hint = ""
                if f.fixable:
                    fix_hint = f"  {_color('[fixable]', _CYAN)}"
                print(f"    {icon}  {f.message}{fix_hint}")

            print()

        # Summary
        total = len(findings)
        passed = sum(1 for f in findings if f.severity == "PASS")
        issues = total - passed
        fixable = sum(1 for f in findings if f.fixable)

        print(f"  {_color('─' * 58, _DIM)}")

        if issues == 0:
            print(f"  {_color('All checks passed.', _GREEN)}  ({passed} passed)")
        else:
            # Count by severity
            sev_counts: dict[str, int] = {}
            for f in findings:
                if f.severity != "PASS":
                    sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = sev_counts.get(sev, 0)
                if count:
                    color = _RED if sev in ("CRITICAL", "HIGH") else _YELLOW if sev == "MEDIUM" else _DIM
                    parts.append(_color(f"{count} {sev.lower()}", color))
            print(f"  {issues} issue(s): {', '.join(parts)}  |  {_color(f'{passed} passed', _GREEN)}")

            if fixable > 0:
                print(f"  {_color(f'{fixable} issue(s) can be auto-fixed', _CYAN)} — run {_color('warden audit --fix', _BOLD)}")

        print()

        # Apply fixes if requested
        if getattr(args, "fix", False) and fixable > 0:
            print(f"  {_color('Applying fixes...', _BOLD)}")
            print()
            actions = apply_fixes(findings)
            for action in actions:
                print(f"    {_color('FIXED', _GREEN)}  {action}")
            if actions:
                print()
                print(f"  {_color(f'{len(actions)} fix(es) applied.', _GREEN)} Run {_color('warden audit', _BOLD)} again to verify.")
            else:
                print(f"    {_color('No fixes were applied.', _DIM)}")
            print()

        # Exit code: 2 for critical, 1 for high/medium, 0 for clean
        if any(f.severity == "CRITICAL" for f in findings):
            raise SystemExit(2)
        if any(f.severity in ("HIGH", "MEDIUM") for f in findings):
            raise SystemExit(1)
        return

    # ── status: show most recent session findings ──────────────────────
    if args.command == "status":
        sessions = list_sessions(workspace, 1)
        if not sessions:
            print("No sessions found.")
            return
        latest = sessions[0]
        session = get_session(workspace, latest["sessionId"])
        if session is None:
            print("No session data available.")
            return
        _print_status(session)
        return

    # ── analyze ────────────────────────────────────────────────────────
    if args.command == "analyze":
        # Accept `analyze <file>` as shorthand for `analyze --input <file>`.
        if not args.input and getattr(args, "file", None):
            args.input = args.file
        # If no input specified, use most recent session
        if args.input:
            events = parse_jsonl(read_text(args.input))
        else:
            # Find most recent session in current workspace
            sessions = list_sessions(workspace, limit=1)
            if not sessions:
                raise SystemExit("No sessions found in this workspace. Use --input to analyze a file, or run a session first.")
            session = get_session(workspace, sessions[0]["sessionId"])
            if not session:
                raise SystemExit(f"Could not load session {sessions[0]['sessionId']}")
            events = session.get("events", [])
            if not events:
                print(_color("[analyze]", _CYAN) + f" No events in session {sessions[0]['sessionId']}")
                return

        result = analyze_events(events, repo_root=repo_root, workspace=workspace)
        if getattr(args, "sarif", False):
            print(json.dumps(format_sarif(result, workspace=workspace), indent=2))
        else:
            emit(result, as_json=args.json, formatter=format_analysis)
        return

    # ── ingest ─────────────────────────────────────────────────────────
    if args.command == "ingest":
        events = parse_jsonl(read_text(args.input))
        result = analyze_events(events, repo_root=repo_root, workspace=workspace)
        session_id = args.session_id or derive_session_id(events)
        db_path = save_session_snapshot(
            workspace=workspace,
            session_id=session_id,
            agent=args.agent or infer_agent(events),
            source="ingest",
            repo_url=None,
            events=events,
            analysis=result,
        )
        print(f"Stored session {session_id} in {db_path} with {result['summary']['totalFindings']} findings.")
        return

    # ── sessions ───────────────────────────────────────────────────────
    if args.command == "sessions":
        if getattr(args, "global_view", False):
            sessions = []
            for ws in list_registered_workspaces():
                for s in list_sessions(ws, args.limit):
                    s["_workspace"] = str(ws)
                    sessions.append(s)
        else:
            sessions = list_sessions(workspace, args.limit)
        if getattr(args, "findings_only", False):
            sessions = [s for s in sessions if s.get("findingsCount", 0) > 0]
            # Sort by risk score (highest first)
            sessions.sort(key=lambda s: s.get("riskScore", 0), reverse=True)
            # Enrich with actual findings for display
            for s in sessions:
                ws = Path(s.get("_workspace", s.get("workspacePath", str(workspace))))
                full = get_session(ws, s["sessionId"])
                if full:
                    s["findings"] = full.get("findings", [])
        emit({"sessions": sessions}, as_json=args.json, formatter=format_sessions)
        return

    if args.command == "session":
        # Accept `session <id>` as shorthand for `session --session-id <id>`.
        session_id = args.session_id or getattr(args, "session_id_pos", None)
        if not session_id:
            raise SystemExit("session: --session-id or a positional session id is required")
        session = get_session(workspace, session_id)
        if session is None:
            raise SystemExit(f"Session not found: {session_id}")
        emit(session, as_json=args.json, formatter=format_session)
        return

    # ── install-hooks ──────────────────────────────────────────────────
    if args.command == "install-hooks":
        results = install_hooks(
            repo_root=repo_root,
            workspace=workspace,
            agent=args.agent,
            scope=args.scope,
            mode=args.mode,
        )
        register_workspace(workspace)
        for item in results:
            print(f"Installed {item['agent']} hooks at {item['configPath']}")
        return

    # ── uninstall-hooks ────────────────────────────────────────────────
    if args.command == "uninstall-hooks":
        results = uninstall_hooks(
            repo_root=repo_root,
            workspace=workspace,
            agent=args.agent,
            scope=args.scope,
        )
        for item in results:
            if item["removed"]:
                print(f"Removed {item['agent']} hooks from {item['configPath']}")
            else:
                print(f"No Prismor hooks found for {item['agent']} at {item['configPath']}")
        return

    # ── hook-dispatch (called by IDE hooks) ────────────────────────────
    if args.command == "hook-dispatch":
        register_workspace(workspace)
        payload = json.loads(sys.stdin.read() or "{}")
        normalized = normalize_payload(agent=args.agent, payload=payload, workspace=workspace)
        event = normalized["event"]
        append_session_event(workspace, normalized["sessionId"], event)

        # ── Scoped agent: synthesize rules on first prompt ────────────
        if event.get("agent_event") == "UserPromptSubmit":
            try:
                from warden.scoped_agent import (
                    load_scoped_rules as _load_scoped,
                    synthesize_scoped_rules as _synthesize_scoped,
                    save_scoped_rules as _save_scoped,
                    format_scoped_rules_box as _format_scoped_box,
                )
                _existing_scoped = _load_scoped(workspace, normalized["sessionId"])
                if _existing_scoped is None and event.get("prompt"):
                    _available_tools = ["Bash", "Read", "Edit", "MultiEdit", "Write", "WebFetch", "WebSearch"]
                    _scoped_rules = _synthesize_scoped(
                        goal=event["prompt"],
                        available_tools=_available_tools,
                        workspace=workspace,
                    )
                    if _scoped_rules:
                        _save_scoped(workspace, normalized["sessionId"], _scoped_rules)
                        sys.stderr.write(_format_scoped_box(_scoped_rules) + "\n")
            except Exception as _scoped_exc:
                sys.stderr.write(f"[warden] scoped agent error: {_scoped_exc}\n")

        events = read_session_events(workspace, normalized["sessionId"])
        result = analyze_events(events, repo_root=repo_root, workspace=workspace, session_id=normalized["sessionId"])
        save_session_snapshot(
            workspace=workspace,
            session_id=normalized["sessionId"],
            agent=args.agent,
            source="hook",
            repo_url=None,
            events=events,
            analysis=result,
        )
        # Only evaluate the current event for real-time blocking decisions.
        # Using all session findings would cause stale shell-event findings
        # (e.g. from a previous agent run) to block unrelated UserPromptSubmit
        # events, creating a false-positive loop.
        from warden.policy_engine import PolicyEngine as _PolicyEngine
        _current_engine = _PolicyEngine(workspace=workspace)
        current_findings = _current_engine.evaluate(event, len(events) - 1, session_id=normalized["sessionId"])

        # ── Scoped agent: enforce session-scoped rules ────────────────
        try:
            from warden.scoped_agent import load_scoped_rules as _load_sr, check_scoped_rules as _check_sr
            _sr = _load_sr(workspace, normalized["sessionId"])
            if _sr is not None:
                _sr_finding = _check_sr(_sr, event, session_id=normalized["sessionId"])
                if _sr_finding:
                    current_findings.append(_sr_finding)
        except Exception as _sr_exc:
            sys.stderr.write(f"[warden] scoped enforcement error: {_sr_exc}\n")

        # ── Learning: evasion detection on passing shell events ───────
        if not current_findings and event.get("type") == "shell":
            try:
                from warden.learning import detect_evasion as _detect_evasion
                _evasion_findings = _detect_evasion(workspace, normalized["sessionId"], event, current_findings)
                if _evasion_findings:
                    current_findings.extend(_evasion_findings)
            except Exception as _ev_exc:
                sys.stderr.write(f"[warden] evasion detection error: {_ev_exc}\n")

        # Forward findings to configured telemetry sinks (webhook/syslog/file)
        # BEFORE the blocking decision — so a SIEM sees every event, even
        # the ones that get blocked. Dispatch is best-effort.
        if _current_engine.outputs and current_findings:
            try:
                from warden.sinks import dispatch as _sink_dispatch
                _sink_dispatch(
                    current_findings,
                    _current_engine.outputs,
                    extra={
                        "session_id": normalized["sessionId"],
                        "agent": args.agent,
                        "mode": args.mode,
                        "workspace": str(workspace),
                    },
                )
            except Exception as _sink_exc:
                sys.stderr.write(f"[warden] sink dispatch error: {_sink_exc}\n")

        blocking = should_block(current_findings, event, block_categories=set(result.get("blockCategories", [])))
        if args.mode == "enforce" and blocking is not None:
            if args.agent == "copilot":
                # Copilot CLI reads permissionDecision from stdout; exit 2 is ignored.
                reason = f"[{blocking['severity']}] {blocking['title']}"
                if blocking.get("evidence"):
                    reason += f"\n{blocking['evidence']}"
                sys.stdout.write(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}) + "\n")
            else:
                sys.stderr.write(f"Prismor Warden blocked this action: [{blocking['severity']}] {blocking['title']}\n")
                if blocking.get("evidence"):
                    sys.stderr.write(f"{blocking['evidence']}\n")
                raise SystemExit(2)
        elif args.mode == "observe" and blocking is not None:
            # Show warnings in observe mode so humans/agents see feedback.
            sys.stderr.write(_color(f"[warden] ", _YELLOW) + f"[{blocking['severity']}] {blocking['title']}\n")
            # Record as dismissal for learning (observe mode = user saw but continued)
            try:
                from warden.learning import record_dismissal as _record_dismissal
                _record_dismissal(
                    workspace, normalized["sessionId"],
                    blocking.get("ruleId", "unknown"),
                    blocking.get("evidence", ""),
                    "user_skip",
                )
            except Exception:
                pass  # best-effort, don't break the hook
        return

    # ── sweep ──────────────────────────────────────────────────────────
    if args.command == "sweep":
        from warden.sweep import (
            scan, report_findings, redact, restore, clean, show_vault,
            _vault_exists, _prompt_passphrase, _read_vault, info as sweep_info,
            ok as sweep_ok, warn as sweep_warn, err as sweep_err,
        )

        def _need_passphrase(confirm: bool = False) -> str:
            """Wrap _prompt_passphrase with a clean error when no TTY is
            available. Prevents an unhandled RuntimeError traceback in
            CI / hook contexts."""
            try:
                return _prompt_passphrase(confirm=confirm)
            except RuntimeError as exc:
                sys.stderr.write(
                    _color("[sweep] ", _RED)
                    + f"{exc}\n"
                    + "        Set the PRISMOR_SWEEP_PASS environment variable\n"
                    + "        (non-interactive) or re-run from a terminal.\n"
                )
                raise SystemExit(1)

        # Show vault contents
        if getattr(args, "show_vault", False):
            passphrase = _need_passphrase()
            show_vault(passphrase)
            return

        # Restore mode
        if getattr(args, "restore", False):
            passphrase = _need_passphrase()
            restore(passphrase, target_file=getattr(args, "file", None), all_entries=getattr(args, "all", False))
            return

        # Merge positional paths + --dirs
        custom_dirs = (getattr(args, "paths", None) or []) + (getattr(args, "dirs", None) or [])
        custom_dirs = custom_dirs or None

        # Scan first (needed for redact, clean, and dry-run)
        findings = scan(custom_dirs=custom_dirs)
        if not findings:
            return

        # Clean mode (delete residue files)
        if getattr(args, "clean", False):
            sweep_info("Passphrase required to authorize deletion and update vault.")
            if _vault_exists():
                passphrase = _need_passphrase()
            else:
                passphrase = _need_passphrase(confirm=True)
            clean(findings, passphrase)
            return

        # Redact mode
        if getattr(args, "redact", False):
            purge = getattr(args, "purge", False)
            if purge:
                sweep_warn("Purge mode — secrets will be redacted with NO vault backup.")
                report_findings(findings)
                print()
                passphrase = ""
            elif _vault_exists():
                report_findings(findings)
                print()
                sweep_info("Passphrase required to update the vault.")
                passphrase = _need_passphrase()
            else:
                report_findings(findings)
                print()
                sweep_info("First-time vault setup — creating encrypted vault for secret recovery.")
                passphrase = _need_passphrase(confirm=True)

            count = redact(findings, passphrase, purge=purge)
            if count:
                print()
                sweep_ok(f"Redacted {count} secret(s)")
            return

        # Default: dry-run scan and report
        report_findings(findings)
        print()
        sweep_warn("Dry run — no files modified. Use --redact or --clean to take action.")
        return

    # ── cloak ──────────────────────────────────────────────────────────
    if args.command == "cloak":
        from warden.cloaking import (
            install as cloak_install,
            uninstall as cloak_uninstall,
            status as cloak_status,
            add_secret,
            list_secrets,
            remove_secret,
            secrets_dir,
        )

        sub = getattr(args, "cloak_command", None)

        if sub == "install":
            result = cloak_install(
                workspace=workspace,
                scope=args.scope,
                enable_userprompt_guard=not args.no_userprompt_guard,
                enable_sweep_on_stop=args.sweep_on_stop,
            )
            print(f"Installed cloaking hooks at {result['configPath']}")
            for label in result["hooksInstalled"]:
                print(f"  + {label}")
            print(f"Secrets directory: {result['secretsDir']}")
            print()
            print("Next step: register your first secret with")
            print(f"  {_color('warden cloak add <name>', _CYAN)}  (reads the value from stdin)")
            return

        if sub == "uninstall":
            result = cloak_uninstall(workspace=workspace, scope=args.scope)
            if result["removed"]:
                print(f"Removed cloaking hooks from {result['configPath']}")
            else:
                print(f"No cloaking hooks found at {result['configPath']}")
            return

        if sub == "status":
            result = cloak_status(workspace=workspace, scope=args.scope)
            installed_color = _GREEN if result["installed"] else _YELLOW
            print()
            print(f"  {_color('CLOAKING', _BOLD)}")
            print(f"  {_color('─' * 50, _DIM)}")
            print(f"  {_color('Config:', _GREEN)}    {result['configPath']}")
            state = "installed" if result["installed"] else "not installed"
            print(f"  {_color('State:', _GREEN)}     {_color(state, installed_color)}")
            if result["events"]:
                print(f"  {_color('Hooks:', _GREEN)}     {', '.join(result['events'])}")
            print(f"  {_color('Secrets:', _GREEN)}   {result['secretsDir']}")
            secrets = list_secrets()
            if secrets:
                print(f"  {_color('Registered:', _GREEN)}  {len(secrets)} placeholder(s)")
            else:
                print(f"  {_color('Registered:', _GREEN)}  {_color('none', _DIM)}")
            print()
            return

        if sub == "add":
            name = args.name
            if args.value_file:
                value = Path(args.value_file).read_text(encoding="utf-8").rstrip("\n")
            else:
                # Read from stdin (so the value never appears in argv / history).
                if sys.stdin.isatty():
                    from getpass import getpass
                    value = getpass(f"Enter value for @@SECRET:{name}@@ (input hidden): ")
                else:
                    value = sys.stdin.read().rstrip("\n")
            try:
                path = add_secret(name, value)
            except ValueError as exc:
                sys.stderr.write(f"error: {exc}\n")
                raise SystemExit(1)
            print(f"Registered @@SECRET:{name}@@ ({len(value)} bytes) at {path}")
            print("The model can now reference this secret in tool calls as:")
            print(f"  {_color(f'@@SECRET:{name}@@', _CYAN)}")
            return

        if sub == "list":
            secrets = list_secrets()
            if not secrets:
                print(f"No secrets registered at {secrets_dir()}")
                return
            print(f"Registered secrets at {secrets_dir()}:")
            print()
            for entry in secrets:
                ts = datetime.fromtimestamp(entry["modified"]).strftime("%Y-%m-%d %H:%M")
                tag = _color("[auto]", _DIM) + " " if entry["auto"] else ""
                print(f"  {tag}@@SECRET:{entry['name']}@@"
                      f"  ({entry['bytes']} bytes, updated {ts})")
            print()
            return

        if sub == "remove":
            removed = remove_secret(args.name)
            if removed:
                print(f"Removed @@SECRET:{args.name}@@")
            else:
                print(f"No secret named {args.name!r}")
            return

        raise SystemExit("Usage: warden cloak {install|uninstall|add|list|remove|status}")

    # ── canary subcommands ─────────────────────────────────────────────
    if args.command == "canary":
        from warden import canary as canary_mod
        sub = getattr(args, "canary_command", None)
        if sub == "plant":
            try:
                entry = canary_mod.plant(
                    Path(args.path),
                    template=args.type,
                    webhook=args.webhook,
                    force=args.force,
                )
            except FileExistsError as exc:
                sys.stderr.write(f"error: {exc}\n")
                raise SystemExit(1)
            except ValueError as exc:
                sys.stderr.write(f"error: {exc}\n")
                raise SystemExit(1)
            print(_color(f"Planted {args.type} canary", _GREEN) + f" at {entry['path']}")
            print(f"  id:     {entry['id']}")
            print(f"  type:   {entry['type']}")
            if entry.get("webhook"):
                print(f"  beacon: {entry['webhook']}")
            print(f"  marker: {entry['marker']}  " + _color("(keep private)", _DIM))
            print()
            print(_color("Any read of this file by any agent will raise a CRITICAL finding.", _YELLOW))
            return
        if sub == "list" or sub is None:
            entries = canary_mod.list_canaries()
            if not entries:
                print("No canaries planted. Try:  warden canary plant ~/.aws/credentials.canary --type aws")
                return
            print(f"  {_color('PRISMOR WARDEN', _BOLD)}  canaries")
            print(f"  {_color('─' * 50, _DIM)}")
            for e in entries:
                print(f"  {e['id']}  {e['type']:7s}  {e['path']}")
                if e.get("webhook"):
                    print(f"     beacon: {e['webhook']}")
            return
        if sub == "remove":
            removed = canary_mod.unplant(args.identifier)
            if removed is None:
                sys.stderr.write(f"No canary matching '{args.identifier}'\n")
                raise SystemExit(1)
            print(_color("Removed canary", _GREEN) + f" {removed['id']} at {removed['path']}")
            return
        if sub == "status":
            entries = canary_mod.list_canaries()
            markers = len(canary_mod.get_markers())
            print(f"  Canaries planted: {len(entries)}")
            print(f"  Active markers:   {markers}")
            if entries:
                by_type: Dict[str, int] = {}
                for e in entries:
                    by_type[e["type"]] = by_type.get(e["type"], 0) + 1
                for t, n in sorted(by_type.items()):
                    print(f"    {t:8s}  {n}")
            return

    # ── policy subcommands ─────────────────────────────────────────────
    if args.command == "policy":
        if args.policy_command == "init":
            _policy_init(workspace)
            return
        if args.policy_command == "validate":
            _policy_validate(Path(args.file))
            return
        if args.policy_command == "show":
            _policy_show(workspace)
            return
        if args.policy_command == "edit":
            _policy_edit(workspace)
            return
        if args.policy_command == "test":
            _policy_test(workspace, test_file=getattr(args, "file", None))
            return

    # ── scope subcommands ───────────────────────────────────────────────
    if args.command == "scope":
        from warden.scoped_agent import (
            load_scoped_rules, clear_scoped_rules,
            list_scoped_sessions, format_scoped_rules_box,
        )
        sub = getattr(args, "scope_command", None)
        if sub == "show":
            sid = getattr(args, "session_id", None)
            if sid:
                rules = load_scoped_rules(workspace, sid)
                if rules is None:
                    print(f"No scoped rules for session '{sid}'")
                    return
                print(format_scoped_rules_box(rules))
            else:
                sessions = list_scoped_sessions(workspace)
                if not sessions:
                    print("No active scoped sessions.")
                    return
                for s in sessions:
                    print(f"\n  Session: {s['session_id']}")
                    print(format_scoped_rules_box(s["rules"]))
            return
        if sub == "list":
            sessions = list_scoped_sessions(workspace)
            if not sessions:
                print("No active scoped sessions.")
                return
            print(f"  {_color('PRISMOR WARDEN', _BOLD)}  scoped sessions")
            print(f"  {_color('─' * 50, _DIM)}")
            for s in sessions:
                tools = ", ".join(s["rules"].get("allowed_tools", []))
                print(f"  {s['session_id']}  tools: [{tools}]")
            return
        if sub == "edit":
            sid = args.session_id
            from warden.scoped_agent import _scoped_path
            path = _scoped_path(workspace, sid)
            if not path.exists():
                sys.stderr.write(f"No scoped rules for session '{sid}'\n")
                raise SystemExit(1)
            editor = os.environ.get("EDITOR", "vi")
            subprocess.run([editor, str(path)])
            return
        if sub == "clear":
            sid = args.session_id
            if clear_scoped_rules(workspace, sid):
                print(_color("Cleared", _GREEN) + f" scoped rules for session '{sid}'")
            else:
                print(f"No scoped rules for session '{sid}'")
            return
        # Default: show all
        sessions = list_scoped_sessions(workspace)
        if not sessions:
            print("No active scoped sessions. Scoped rules are created automatically on session start.")
            return
        for s in sessions:
            print(f"\n  Session: {s['session_id']}")
            print(format_scoped_rules_box(s["rules"]))
        return

    # ── learn subcommand ──────────────────────────────────────────────
    if args.command == "learn":
        from warden.learning import (
            mine_patterns, track_false_positives, propose_rule_refinements,
            save_candidate_rules, list_candidate_rules,
            accept_candidate_rule, reject_candidate_rule,
            format_learning_report,
        )

        # Accept a candidate
        if getattr(args, "apply", None) is not None:
            rule = accept_candidate_rule(workspace, args.apply)
            if rule is None:
                sys.stderr.write(f"No pending candidate with id {args.apply}\n")
                raise SystemExit(1)
            # Append to project policy
            import yaml
            policy_path = workspace / ".prismor-warden" / "policy.yaml"
            policy: Dict[str, Any] = {}
            if policy_path.exists():
                policy = yaml.safe_load(policy_path.read_text()) or {}
            rules_list = policy.setdefault("rules", [])
            rules_list.append(rule)
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(yaml.dump(policy, default_flow_style=False, sort_keys=False))
            print(_color("Accepted", _GREEN) + f" candidate rule '{rule['id']}' → .prismor-warden/policy.yaml")
            return

        # Reject a candidate
        if getattr(args, "reject", None) is not None:
            if reject_candidate_rule(workspace, args.reject):
                print(_color("Rejected", _YELLOW) + f" candidate #{args.reject}")
            else:
                sys.stderr.write(f"No pending candidate with id {args.reject}\n")
                raise SystemExit(1)
            return

        # List candidates
        if getattr(args, "candidates", False):
            pending = list_candidate_rules(workspace, status="pending")
            if not pending:
                print("No pending candidate rules.")
                return
            print(f"  {_color('PRISMOR WARDEN', _BOLD)}  candidate rules")
            print(f"  {_color('─' * 50, _DIM)}")
            for c in pending:
                rule = c["rule"]
                print(f"  [{c['id']}] {rule.get('title', rule.get('id', '?'))}")
                print(f"       Confidence: {c['confidence']:.0%}  |  Support: {c['support_count']}  |  Source: {c['source']}")
                if c.get("sample_evidence"):
                    print(f"       Sample: {c['sample_evidence'][:100]}")
                print()
            print(f"Use {_color('warden learn --apply ID', _BOLD)} to accept a rule.")
            return

        # Run full learning analysis
        candidates = mine_patterns(workspace, min_support=args.min_support)
        false_pos = track_false_positives(workspace, threshold=args.fp_threshold)
        refinements = propose_rule_refinements(workspace)

        # Save mined candidates
        if candidates:
            saved = save_candidate_rules(workspace, candidates)
            if saved:
                sys.stderr.write(f"[warden] saved {saved} candidate rule(s) to database\n")

        if getattr(args, "json_output", False):
            print(json.dumps({
                "candidates": [{"id": c.get("id"), "rule": c["rule"], "confidence": c["confidence"],
                                "support_count": c["support_count"], "source": c["source"]}
                               for c in candidates],
                "false_positives": false_pos,
                "refinements": refinements,
            }, indent=2))
        else:
            print(format_learning_report(candidates, false_pos, refinements))
        return

    raise SystemExit(f"Unsupported command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prismor Warden — local session-security utility for AI coding agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--workspace", help="Workspace path (applies to all commands)")
    parser.add_argument("--version", action="version", version=f"prismor-warden {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # ── info ───────────────────────────────────────────────────────────
    subparsers.add_parser("info", help="Show workspace, mode, rules, and hook status")

    # ── dashboard ─────────────────────────────────────────────────────
    subparsers.add_parser("dashboard", help="Global overview of all registered workspaces")

    # ── check ──────────────────────────────────────────────────────────
    check_parser = subparsers.add_parser("check", help="Quick pre-check a command or file path")
    check_parser.add_argument("value", nargs="?", help="The command string or file path to check (omit with --from-log)")
    check_parser.add_argument(
        "--type", "-t",
        choices=["command", "read", "write"],
        default="command",
        help="What to check: command (default), read (file read), write (file write)",
    )
    check_parser.add_argument("--workspace", help="Workspace path for project-level policy")
    check_parser.add_argument("--explain", action="store_true",
                              help="Show the rule patterns and matched substring for each finding")
    check_parser.add_argument("--from-log", metavar="PATH",
                              help="Replay a JSONL session log and check every event")
    check_parser.add_argument("--suggest-allowlist", action="store_true",
                              help="Print a ready-to-paste allowlist entry when a finding is produced")

    # ── scan ──────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan all MCP servers and skills for security risks")
    scan_parser.add_argument("--workspace", help="Workspace path")
    scan_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "openclaw", "hermes", "copilot"], help="Only scan configs for this agent")
    scan_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # ── deps ──────────────────────────────────────────────────────────
    deps_parser = subparsers.add_parser("deps", help="Check workspace dependencies against threat feed")
    deps_parser.add_argument("--workspace", help="Workspace path")
    deps_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # ── audit ──────────────────────────────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Full security posture audit across all Warden subsystems")
    audit_parser.add_argument("--workspace", help="Workspace path")
    audit_parser.add_argument("--fix", action="store_true", help="Auto-remediate fixable issues")
    audit_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # ── status ─────────────────────────────────────────────────────────
    status_parser = subparsers.add_parser("status", help="Show findings from the most recent session")
    status_parser.add_argument("--workspace", help="Workspace path")

    # ── analyze ────────────────────────────────────────────────────────
    analyze = subparsers.add_parser("analyze", help="Analyze a session (or current session if no --input)")
    analyze.add_argument("file", nargs="?", help="Path to JSONL session file (same as --input). If omitted, analyzes most recent session")
    analyze.add_argument("--input", help="Path to JSONL session file (or - for stdin). If omitted, analyzes most recent session")
    analyze.add_argument("--workspace", help="Workspace path")
    analyze.add_argument("--json", action="store_true", help="Output raw JSON")
    analyze.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 format")

    # ── ingest ─────────────────────────────────────────────────────────
    ingest = subparsers.add_parser("ingest", help="Analyze and store a session")
    ingest.add_argument("--input", required=True, help="Path to JSONL session file")
    ingest.add_argument("--workspace", help="Workspace path")
    ingest.add_argument("--session-id", help="Override session ID")
    ingest.add_argument("--agent", help="Agent name")

    # ── sessions ───────────────────────────────────────────────────────
    sessions_parser = subparsers.add_parser("sessions", help="List stored sessions")
    sessions_parser.add_argument("--workspace", help="Workspace path")
    sessions_parser.add_argument("--limit", type=int, default=20, help="Max sessions to show (default: 20)")
    sessions_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    sessions_parser.add_argument("--findings-only", action="store_true", help="Only show sessions with findings")
    sessions_parser.add_argument("--global", dest="global_view", action="store_true", help="Show sessions across all registered workspaces")

    # ── session ────────────────────────────────────────────────────────
    session_parser = subparsers.add_parser("session", help="Show a specific session")
    session_parser.add_argument("session_id_pos", nargs="?", help="Session ID to view (same as --session-id)")
    session_parser.add_argument("--workspace", help="Workspace path")
    session_parser.add_argument("--session-id", help="Session ID to view")
    session_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # ── install-hooks ──────────────────────────────────────────────────
    install_parser = subparsers.add_parser("install-hooks", help="Install IDE hooks for real-time monitoring")
    install_parser.add_argument("--workspace", help="Workspace path")
    install_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "openclaw", "hermes", "copilot", "all"], required=True, help="Which agent/IDE")
    install_parser.add_argument("--scope", choices=["project", "user"], default="project", help="Hook scope (default: project)")
    install_parser.add_argument("--mode", choices=["observe", "enforce"], default="observe", help="observe=log only, enforce=block dangerous actions")

    # ── uninstall-hooks ────────────────────────────────────────────────
    uninstall_parser = subparsers.add_parser("uninstall-hooks", help="Remove IDE hooks")
    uninstall_parser.add_argument("--workspace", help="Workspace path")
    uninstall_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "openclaw", "hermes", "copilot", "all"], required=True, help="Which agent/IDE")
    uninstall_parser.add_argument("--scope", choices=["project", "user"], default="project", help="Hook scope")

    # ── hook-dispatch (internal) ───────────────────────────────────────
    hook_dispatch = subparsers.add_parser("hook-dispatch", help="(internal) Called by IDE hooks")
    hook_dispatch.add_argument("--workspace", help="Workspace path")
    hook_dispatch.add_argument("--agent", choices=["claude", "cursor", "windsurf", "openclaw", "hermes", "copilot"], required=True)
    hook_dispatch.add_argument("--mode", choices=["observe", "enforce"], default="observe")

    # ── policy ─────────────────────────────────────────────────────────
    policy_parser = subparsers.add_parser("policy", help="Manage Warden policies")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    policy_init = policy_sub.add_parser("init", help="Create a starter policy.yaml in your workspace")
    policy_init.add_argument("--workspace", help="Workspace path")

    policy_validate = policy_sub.add_parser("validate", help="Validate a policy YAML file")
    policy_validate.add_argument("file", help="Path to policy.yaml")
    policy_validate.add_argument("--workspace", help="Workspace path")

    policy_show = policy_sub.add_parser("show", help="Show active policy rules (default + project overrides)")
    policy_show.add_argument("--workspace", help="Workspace path")

    policy_edit = policy_sub.add_parser("edit", help="Interactive rule toggle — select which rules to enable/disable")
    policy_edit.add_argument("--workspace", help="Workspace path")

    policy_test = policy_sub.add_parser("test", help="Run declarative policy tests from policy-tests.yaml")
    policy_test.add_argument("--file", help="Path to policy-tests.yaml (default: .prismor-warden/policy-tests.yaml)")
    policy_test.add_argument("--workspace", help="Workspace path")

    # ── sweep ──────────────────────────────────────────────────────────
    sweep_parser = subparsers.add_parser("sweep", help="Scan AI tool configs for leaked secrets, redact with encrypted vault")
    sweep_parser.add_argument("--redact", action="store_true", help="Redact found secrets and save originals to encrypted vault")
    sweep_parser.add_argument("--clean", action="store_true", help="Delete residue files containing secrets (vault backup first)")
    sweep_parser.add_argument("--restore", action="store_true", help="Restore secrets from the encrypted vault")
    sweep_parser.add_argument("--show-vault", action="store_true", help="Show vault contents (requires passphrase)")
    sweep_parser.add_argument("--purge", action="store_true", help="With --redact: skip vault, no recovery possible")
    sweep_parser.add_argument("--all", action="store_true", help="With --restore: restore all entries")
    sweep_parser.add_argument("--file", help="With --restore: restore only this file")
    sweep_parser.add_argument("paths", nargs="*", help="Directories to scan (default: AI tool config dirs)")
    sweep_parser.add_argument("--dirs", nargs="+", help="(deprecated) Same as positional paths")

    # ── cloak ──────────────────────────────────────────────────────────
    cloak_parser = subparsers.add_parser(
        "cloak",
        help="Secret prevention layer — cloak/decloak secrets at the tool boundary",
    )
    cloak_sub = cloak_parser.add_subparsers(dest="cloak_command")

    t_install = cloak_sub.add_parser("install", help="Install cloaking hooks in .claude/settings.json")
    t_install.add_argument("--workspace", help="Workspace path")
    t_install.add_argument("--scope", choices=["project", "user"], default="project",
                           help="Hook scope (default: project)")
    t_install.add_argument("--no-userprompt-guard", action="store_true",
                           help="Skip the UserPromptSubmit soft-block hook (use a clipboard filter instead)")
    t_install.add_argument("--sweep-on-stop", action="store_true",
                           help="Also wire a Stop-hook dry-run sweep for residue detection")

    t_uninstall = cloak_sub.add_parser("uninstall", help="Remove cloaking hooks")
    t_uninstall.add_argument("--workspace", help="Workspace path")
    t_uninstall.add_argument("--scope", choices=["project", "user"], default="project",
                             help="Hook scope (default: project)")

    t_add = cloak_sub.add_parser("add", help="Register a real secret under a placeholder name")
    t_add.add_argument("name", help="Placeholder name (used as @@SECRET:name@@ in tool calls)")
    t_add.add_argument("--from-file", dest="value_file",
                       help="Read value from this file (otherwise read from stdin / hidden prompt)")

    cloak_sub.add_parser("list", help="List registered placeholder names (never values)")

    t_remove = cloak_sub.add_parser("remove", help="Delete a registered secret")
    t_remove.add_argument("name", help="Placeholder name to remove")

    t_status = cloak_sub.add_parser("status", help="Show whether cloaking hooks are installed")
    t_status.add_argument("--workspace", help="Workspace path")
    t_status.add_argument("--scope", choices=["project", "user"], default="project",
                          help="Hook scope (default: project)")

    # ── canary ─────────────────────────────────────────────────────────
    canary_parser = subparsers.add_parser(
        "canary",
        help="Plant and manage honey-token credentials (canarytokens)",
    )
    canary_sub = canary_parser.add_subparsers(dest="canary_command")

    c_plant = canary_sub.add_parser("plant", help="Plant a canarytoken at PATH")
    c_plant.add_argument("path", help="Where to plant the canary")
    c_plant.add_argument("--type", choices=["aws", "ssh", "env", "generic"],
                         default="generic", help="Template (default: generic)")
    c_plant.add_argument("--webhook", help="URL to POST on access (optional)")
    c_plant.add_argument("--force", action="store_true", help="Overwrite if path exists")

    canary_sub.add_parser("list", help="List registered canaries (markers redacted)")

    c_remove = canary_sub.add_parser("remove", help="Remove a canary by id or path")
    c_remove.add_argument("identifier", help="Canary id or path")

    canary_sub.add_parser("status", help="Summary of registered canaries and recent hits")

    # ── scope ─────────────────────────────────────────────────────────
    scope_parser = subparsers.add_parser(
        "scope",
        help="Manage session-scoped agent rules",
    )
    scope_sub = scope_parser.add_subparsers(dest="scope_command")

    scope_show = scope_sub.add_parser("show", help="Show active scoped rules for a session")
    scope_show.add_argument("--session-id", help="Session ID (default: list all active)")

    scope_edit = scope_sub.add_parser("edit", help="Edit scoped rules in $EDITOR")
    scope_edit.add_argument("session_id", help="Session ID to edit")

    scope_clear = scope_sub.add_parser("clear", help="Remove scoped rules for a session")
    scope_clear.add_argument("session_id", help="Session ID to clear")

    scope_sub.add_parser("list", help="List all sessions with active scoped rules")

    # ── learn ─────────────────────────────────────────────────────────
    learn_parser = subparsers.add_parser(
        "learn",
        help="Analyze session history and propose new rules or improvements",
    )
    learn_parser.add_argument("--min-support", type=int, default=3,
                              help="Minimum occurrences for pattern mining (default: 3)")
    learn_parser.add_argument("--fp-threshold", type=int, default=5,
                              help="Dismissal count to flag false positives (default: 5)")
    learn_parser.add_argument("--json", action="store_true", dest="json_output",
                              help="Output raw JSON instead of formatted report")
    learn_parser.add_argument("--apply", metavar="RULE_ID", type=int,
                              help="Accept a candidate rule and append to project policy")
    learn_parser.add_argument("--reject", metavar="RULE_ID", type=int,
                              help="Reject a candidate rule")
    learn_parser.add_argument("--candidates", action="store_true",
                              help="List pending candidate rules")

    return parser


def _print_findings(
    findings: List[Dict[str, Any]],
    *,
    engine: Optional["PolicyEngine"] = None,
    explain: bool = False,
    suggest: bool = False,
    input_value: Optional[str] = None,
) -> None:
    """Shared finding renderer used by ``check`` and ``check --from-log``."""
    for f in findings:
        sev = f["severity"]
        color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
        action_label = f.get("action", "warn").upper()
        print(_color(f"[{sev}]", color) + f" {f['title']}  " + _color(f"({action_label})", color))
        evidence = str(f.get("evidence", "")).split("\n", 1)[0]
        print(f"  rule: {f.get('ruleId', '?')}  evidence: {evidence}")

        if explain and engine is not None:
            rule = next((r for r in engine.rules if r.id == f.get("ruleId")), None)
            if rule is not None:
                print(f"  category: {f.get('category')}  action: {f.get('action')}")
                print(f"  event_types: {sorted(rule.event_types)}")
                print(f"  fields: {rule.fields}")
                print(f"  pattern: {_truncate_str(rule.patterns.pattern, 160)}")
            else:
                print(f"  (built-in rule — no YAML pattern)")

        if suggest:
            value = input_value if input_value is not None else evidence
            rid = f.get("ruleId", "?")
            print()
            print(_color("  # Paste into .prismor-warden/policy.yaml to suppress this finding:", _DIM))
            print("  allowlists:")
            print(f"    - id: allow-{rid}-{abs(hash(value)) % 10000:04d}")
            print(f"      rule_ids: [{rid}]")
            print(f"      reason: \"intentional — reviewed on {datetime.now().date().isoformat()}\"")
            print(f"      patterns: [{json.dumps(re.escape(value))}]")


def _truncate_str(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _print_info(workspace: Path) -> None:
    """Show a quick summary of the workspace config."""
    home = str(Path.home())
    ws_display = str(workspace).replace(home, "~")

    print()
    print(f"  {_color('PRISMOR WARDEN', _BOLD)}  workspace info")
    print(f"  {_color('─' * 50, _DIM)}")
    print()

    # Workspace
    print(f"  {_color('Workspace:', _GREEN)}    {ws_display}")

    # Policy
    policy_path = workspace / ".prismor-warden" / "policy.yaml"
    if policy_path.exists():
        print(f"  {_color('Policy:', _GREEN)}       {str(policy_path).replace(home, '~')}")
    else:
        print(f"  {_color('Policy:', _GREEN)}       {_color('defaults only (no project overrides)', _DIM)}")

    # Rules
    engine = PolicyEngine(workspace=workspace)
    # Count how many rules come from defaults vs how many are disabled
    default_path = Path(__file__).resolve().parent / "default_policy.yaml"
    total_default = 0
    try:
        from warden.policy_engine import _load_yaml
        data = _load_yaml(default_path)
        if data:
            total_default = len(data.get("rules", []))
    except Exception:
        total_default = len(engine.rules)
    n_active = len(engine.rules)
    n_disabled = total_default - n_active
    rules_str = f"{n_active} active"
    if n_disabled > 0:
        rules_str += f", {_color(f'{n_disabled} disabled', _YELLOW)}"
    print(f"  {_color('Rules:', _GREEN)}        {rules_str}")

    # Allowlists
    if engine.allowlists:
        print(f"  {_color('Allowlists:', _GREEN)}   {len(engine.allowlists)}")

    # Hooks — check which agents have hooks installed
    agents_with_hooks = []
    mode = None
    for agent_name in ("claude", "cursor", "windsurf", "openclaw", "hermes", "copilot"):
        hook_path = _find_hook_config(agent_name, workspace)
        if hook_path and hook_path.exists():
            try:
                content = hook_path.read_text()
                if "warden" in content.lower() or "prismor" in content.lower():
                    agents_with_hooks.append(agent_name)
                    # Try to detect mode from hook config
                    if mode is None:
                        if "--mode enforce" in content:
                            mode = "enforce"
                        elif "--mode observe" in content:
                            mode = "observe"
            except Exception:
                pass

    if agents_with_hooks:
        mode_color = _GREEN if mode == "enforce" else _YELLOW
        mode_str = _color(mode or "unknown", mode_color)
        print(f"  {_color('Hooks:', _GREEN)}       {', '.join(agents_with_hooks)}  ({mode_str})")
    else:
        print(f"  {_color('Hooks:', _GREEN)}       {_color('not installed', _YELLOW)}")

    # Sessions
    sessions = list_sessions(workspace, 5)
    sessions_with_findings = [s for s in sessions if s.get("findingsCount", 0) > 0]
    total_sessions = len(list_sessions(workspace, 999))
    print(f"  {_color('Sessions:', _GREEN)}     {total_sessions} total, {len(sessions_with_findings)} with findings")

    # Latest risk
    if sessions:
        latest = sessions[0]
        risk = latest.get("riskScore", 0)
        risk_color = _RED if risk >= 50 else _YELLOW if risk >= 20 else _GREEN
        print(f"  {_color('Latest risk:', _GREEN)}  {_color(f'{risk}/100', risk_color)}  ({latest['sessionId'][:20]})")

    print()


def _find_hook_config(agent: str, workspace: Path) -> Path:
    """Find the hook config file for an agent."""
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


def _print_dashboard() -> None:
    """Global overview across all registered workspaces."""
    home = str(Path.home())
    workspaces = list_registered_workspaces()

    print()
    print(f"  {_color('PRISMOR WARDEN', _BOLD)}  dashboard")
    print(f"  {_color('─' * 50, _DIM)}")

    if not workspaces:
        print()
        print(f"  {_color('No registered workspaces found.', _DIM)}")
        print(f"  Run {_color('warden install-hooks --agent all --mode enforce', _CYAN)} in a project to register it.")
        print()
        return

    print()

    for ws in workspaces:
        ws_display = str(ws).replace(home, "~")

        # Get sessions
        sessions = list_sessions(ws, 50)
        total = len(sessions)
        with_findings = sum(1 for s in sessions if s.get("findingsCount", 0) > 0)

        # Latest session
        latest_risk = 0
        latest_agent = ""
        latest_time = ""
        if sessions:
            latest = sessions[0]
            latest_risk = latest.get("riskScore", 0)
            latest_agent = latest.get("agent", "")
            ts = latest.get("updatedAt") or latest.get("startedAt") or ""
            if ts:
                latest_time = _relative_time(ts)

        # Risk color
        risk_color = _RED if latest_risk >= 50 else _YELLOW if latest_risk >= 20 else _GREEN

        # Mode detection
        mode = ""
        for agent_name in ("claude", "cursor", "windsurf", "openclaw", "hermes", "copilot"):
            hook_path = _find_hook_config(agent_name, ws)
            if hook_path and hook_path.exists():
                try:
                    content = hook_path.read_text()
                    if "prismor" in content.lower() or "warden" in content.lower():
                        if "--mode enforce" in content:
                            mode = "enforce"
                        elif "--mode observe" in content:
                            mode = "observe"
                        break
                except Exception:
                    pass

        # Status line
        risk_str = _color(f"risk={latest_risk}/100", risk_color)
        findings_str = f"{with_findings} findings" if with_findings > 0 else _color("clean", _GREEN)
        mode_str = _color(mode, _GREEN if mode == "enforce" else _YELLOW) if mode else _color("no hooks", _DIM)
        time_str = _color(latest_time, _DIM) if latest_time else ""

        print(f"  {_color(ws_display, _BOLD)}")
        print(f"    {risk_str}  {findings_str}  {mode_str}  {time_str}")
        print()

    total_ws = len(workspaces)
    total_findings = sum(
        sum(1 for s in list_sessions(ws, 999) if s.get("findingsCount", 0) > 0)
        for ws in workspaces
    )
    print(f"  {_color('─' * 50, _DIM)}")
    print(f"  {total_ws} workspace{'s' if total_ws != 1 else ''}  |  {total_findings} session{'s' if total_findings != 1 else ''} with findings")
    print()


def _relative_time(ts: str) -> str:
    """Convert ISO timestamp to relative time string."""
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        diff = now - dt
        secs = int(diff.total_seconds())
        if secs < 60:
            return "just now"
        if secs < 3600:
            m = secs // 60
            return f"{m}m ago"
        if secs < 86400:
            h = secs // 3600
            return f"{h}h ago"
        d = secs // 86400
        return f"{d}d ago"
    except Exception:
        return ts[:10] if len(ts) >= 10 else ts


# ── New command implementations ─────────────────────────────────────────

def _print_status(session: Dict[str, Any]) -> None:
    """Pretty-print the latest session status."""
    risk = session.get("riskScore", 0)
    findings_count = session.get("findingsCount", 0)
    sid = session.get("sessionId", "?")

    if findings_count == 0:
        print(_color("CLEAN", _GREEN) + f"  session={sid}  risk={risk}/100")
        return

    risk_color = _RED if risk >= 50 else _YELLOW if risk >= 20 else _GREEN
    print(_color(f"RISK {risk}/100", risk_color) + f"  session={sid}  findings={findings_count}")
    print()
    for finding in session.get("findings", []):
        sev = finding.get("severity", "?")
        color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
        print(f"  {_color(f'[{sev}]', color)} {finding['title']} ({finding['category']})")
        if finding.get("evidence"):
            print(f"         {finding['evidence']}")


def _policy_init(workspace: Path) -> None:
    """Generate a starter policy.yaml with comments explaining each section."""
    target_dir = workspace / ".prismor-warden"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "policy.yaml"
    if target.exists():
        print(f"Policy already exists at {target}")
        raise SystemExit(1)

    starter = '''version: "1.0"

# Project-level Warden policy overrides.
# Rules here merge with the defaults — override a rule by matching its id,
# or add new rules with unique ids.
#
# Docs: https://github.com/PrismorSec/prismor

rules: []
  # Example: add a custom rule
  # - id: block-prod-db
  #   severity: CRITICAL
  #   category: db_access
  #   title: Direct production database access blocked
  #   event_types: [shell]
  #   fields: [command]
  #   patterns: ["psql.*prod", "mysql.*production"]
  #   action: block

  # Example: disable a default rule
  # - id: risky-write
  #   enabled: false

allowlists:
  # Example: allow reading .env in this project (it has no real secrets)
  # - id: allow-dotenv
  #   rule_ids: ["secret-access"]
  #   patterns: ["\\.env$"]
  #   reason: ".env in this project only has non-sensitive defaults"
'''
    target.write_text(starter, encoding="utf-8")
    print(f"Created {target}")
    print(f"Edit this file to customize detection rules and allowlists for your project.")


def _policy_validate(path: Path) -> None:
    """Validate a policy YAML and print errors."""
    errors = validate_policy(path)
    if not errors:
        print(_color("VALID", _GREEN) + f"  {path}")
        return
    print(_color("INVALID", _RED) + f"  {path}")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)


def _policy_test(workspace: Path, test_file: Optional[str] = None) -> None:
    """Run declarative policy tests from policy-tests.yaml."""
    from warden.policy_test import run_cases, load_cases

    if test_file:
        path = Path(test_file)
    else:
        path = workspace / ".prismor-warden" / "policy-tests.yaml"

    if not path.exists():
        # If the user hasn't written their own, fall back to the bundled
        # OWASP LLM Top 10 starter pack shipped with the repo.
        bundled = Path(__file__).parent.parent / "templates" / "policy-tests-owasp.yaml"
        if bundled.exists():
            path = bundled
            print(_color("[policy test]", _CYAN)
                  + f" using bundled starter pack: {path.name}")
        else:
            sys.stderr.write(f"error: no policy tests found at {path}\n")
            raise SystemExit(1)

    try:
        cases = load_cases(path)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        raise SystemExit(1)

    result = run_cases(cases, workspace=workspace)
    print()
    print(f"  {_color('PRISMOR WARDEN', _BOLD)}  policy tests ({path.name})")
    print(f"  {_color('─' * 50, _DIM)}")
    print()

    for r in result["results"]:
        if r["status"] == "ok":
            print(f"  {_color('PASS', _GREEN)}  {r['name']}")
        else:
            print(f"  {_color('FAIL', _RED)}  {r['name']}")
            print(f"         input:    {r['input']!r}")
            print(f"         expected: {r['expected']}"
                  + (f" (rule={r['expected_rule']})" if r.get('expected_rule') else ""))
            print(f"         got:      {r['got']}  matched_rules={r['matched_rules']}")

    print()
    color = _GREEN if result["failed"] == 0 else _RED
    print(f"  {_color(str(result['passed']) + '/' + str(result['total']) + ' passed', color)}"
          + (f"  ({result['failed']} failed)" if result["failed"] else ""))
    print()
    if result["failed"]:
        raise SystemExit(1)


def _policy_show(workspace: Path) -> None:
    """Show all active rules after merging defaults + project overrides."""
    engine = PolicyEngine(workspace=workspace)
    print(f"Active rules: {len(engine.rules)}")
    print(f"Allowlists:   {len(engine.allowlists)}")
    print()

    override_path = workspace / ".prismor-warden" / "policy.yaml"
    if override_path.exists():
        print(f"Project policy: {override_path}")
    else:
        print(f"Project policy: (none — using defaults only)")
    print()

    for rule in sorted(engine.rules, key=lambda r: SEVERITY_WEIGHT.get(r.severity, 0), reverse=True):
        sev = rule.severity
        color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
        print(f"  {_color(f'[{sev}]', color)} {rule.id}: {rule.title}  ({rule.action})")

    if engine.allowlists:
        print()
        print("Allowlists:")
        for al in engine.allowlists:
            targets = ", ".join(al.rule_ids) if "*" not in al.rule_ids else "all rules"
            print(f"  {al.id}: {targets}" + (f"  — {al.reason}" if al.reason else ""))


def _policy_edit(workspace: Path) -> None:
    """Interactive rule toggle for the current workspace."""
    import tty
    import termios
    import atexit as _atexit

    engine = PolicyEngine(workspace=workspace)

    # Load existing project overrides to know what's already disabled
    override_path = workspace / ".prismor-warden" / "policy.yaml"
    disabled_ids: set = set()
    if override_path.exists():
        try:
            from warden.policy_engine import _load_yaml
            data = _load_yaml(override_path)
            if data:
                for r in data.get("rules", []):
                    if not r.get("enabled", True):
                        disabled_ids.add(r["id"])
        except Exception:
            pass

    # Build rule list from default policy (all rules, including disabled)
    default_path = Path(__file__).resolve().parent / "default_policy.yaml"
    all_rules = []
    try:
        from warden.policy_engine import _load_yaml
        data = _load_yaml(default_path)
        if data:
            for r in data.get("rules", []):
                all_rules.append({
                    "id": r["id"],
                    "severity": r["severity"],
                    "title": r.get("title", r["id"]),
                    "on": r["id"] not in disabled_ids,
                })
    except Exception:
        pass

    if not all_rules:
        print("Could not load rules from default policy.")
        return

    # Terminal setup
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)

    def _restore():
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    _atexit.register(_restore)
    tty.setcbreak(fd)

    def _read_key():
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ch2 = sys.stdin.read(1)
            if ch2 == '[':
                ch3 = sys.stdin.read(1)
                return 'ESC[' + ch3
            return ch
        return ch

    sel = 0
    while True:
        n_on = sum(1 for r in all_rules if r["on"])
        buf = "\033[H\033[J\033[?25l"  # home, clear, hide cursor
        buf += f"\n  {_BOLD}PRISMOR WARDEN{_NC}  policy edit\n"
        buf += f"  {_DIM}Workspace: {workspace}{_NC}\n"
        buf += f"  {_DIM}{'─' * 64}{_NC}\n\n"
        buf += f"  {n_on}/{len(all_rules)} rules enabled\n\n"

        for i, r in enumerate(all_rules):
            arrow = f"{_CYAN}▸ {_NC}" if i == sel else "  "
            dot = f"{_GREEN}●{_NC}" if r["on"] else f"{_DIM}○{_NC}"
            sev = r["severity"]
            sev_c = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
            sev_s = f"{sev_c}{sev:<10}{_NC}"
            rid = f"{_BOLD}{r['id']:<28}{_NC}" if i == sel else f"{r['id']:<28}"
            title = f"{_DIM}{r['title']}{_NC}"
            buf += f"  {arrow}{dot}  {sev_s}{rid} {title}\n"

        buf += f"\n  {_CYAN}{_BOLD}↑↓{_NC}{_DIM} move  ·  {_NC}"
        buf += f"{_CYAN}{_BOLD}space{_NC}{_DIM} toggle  ·  {_NC}"
        buf += f"{_CYAN}{_BOLD}a{_NC}{_DIM} all  ·  {_NC}"
        buf += f"{_CYAN}{_BOLD}n{_NC}{_DIM} none  ·  {_NC}"
        buf += f"{_CYAN}{_BOLD}enter{_NC}{_DIM} save  ·  {_NC}"
        buf += f"{_CYAN}{_BOLD}q{_NC}{_DIM} cancel{_NC}\n"
        sys.stdout.write(buf)
        sys.stdout.flush()

        key = _read_key()
        if key == 'ESC[A':    sel = (sel - 1) % len(all_rules)
        elif key == 'ESC[B':  sel = (sel + 1) % len(all_rules)
        elif key == ' ':      all_rules[sel]["on"] = not all_rules[sel]["on"]
        elif key in ('a','A'):
            for r in all_rules: r["on"] = True
        elif key in ('n','N'):
            for r in all_rules: r["on"] = False
        elif key in ('\r', '\n'):
            break  # save
        elif key in ('q', 'Q', '\x03'):
            _restore()
            sys.stdout.write("\033[H\033[J")
            print("  Cancelled — no changes made.")
            return

    _restore()
    sys.stdout.write("\033[H\033[J")

    # Write policy
    disabled = [r["id"] for r in all_rules if not r["on"]]
    policy_dir = workspace / ".prismor-warden"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_file = policy_dir / "policy.yaml"

    if disabled:
        lines = ['version: "1.0"\n\nrules:\n']
        for rid in disabled:
            lines.append(f"  - id: {rid}\n    enabled: false\n")
        lines.append("\nallowlists: []\n")
        policy_file.write_text("".join(lines))
        n_on = sum(1 for r in all_rules if r["on"])
        print(f"  {_color('✓', _GREEN)} Saved to {policy_file}")
        print(f"  {n_on}/{len(all_rules)} rules enabled, {len(disabled)} disabled")
    else:
        # All enabled — remove override file if it exists (use defaults)
        if policy_file.exists():
            policy_file.write_text('version: "1.0"\n\nrules: []\n\nallowlists: []\n')
        print(f"  {_color('✓', _GREEN)} All rules enabled (using defaults)")

    print(f"\n  Run {_color('warden policy show', _CYAN)} to verify.")


# ── SARIF output ────────────────────────────────────────────────────────

def format_sarif(
    result: Dict[str, Any],
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Format analysis results as SARIF 2.1.0 for GitHub Code Scanning.

    Populates rules[] from the full policy (not just triggered rules) so
    GitHub Code Scanning, VS Code SARIF viewer, and other consumers have
    complete rule metadata for severity, title, and category.
    """
    # Build rules[] from the loaded policy — gives consumers full context
    # even for rules that didn't trigger during this run.
    rule_index: Dict[str, int] = {}
    sarif_rules: List[Dict[str, Any]] = []
    try:
        from warden.policy_engine import PolicyEngine
        engine = PolicyEngine(workspace=workspace)
        for rule in engine.rules:
            rule_index[rule.id] = len(sarif_rules)
            sarif_rules.append({
                "id": rule.id,
                "name": rule.id.replace("-", " ").replace("_", " ").title(),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": f"{rule.title} (category: {rule.category})"},
                "defaultConfiguration": {"level": _sarif_level(rule.severity)},
                "properties": {
                    "category": rule.category,
                    "severity": rule.severity,
                    "action": rule.action,
                },
                "helpUri": "https://github.com/PrismorSec/prismor/blob/main/docs/warden.md",
            })
    except Exception:
        # Policy engine may be unavailable in some test environments.
        pass

    sarif_results: List[Dict[str, Any]] = []
    for finding in result.get("findings", []):
        rule_id = finding.get("ruleId") or finding.get("category", "unknown")
        # Fallback: synthesize a rule descriptor if a finding references a
        # rule that isn't in the policy (e.g. dynamic egress-allowlist rule).
        if rule_id not in rule_index:
            rule_index[rule_id] = len(sarif_rules)
            sarif_rules.append({
                "id": rule_id,
                "name": rule_id.replace("-", " ").replace("_", " ").title(),
                "shortDescription": {"text": finding.get("title", rule_id)},
                "defaultConfiguration": {
                    "level": _sarif_level(finding.get("severity", "MEDIUM")),
                },
            })

        sarif_results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _sarif_level(finding.get("severity", "MEDIUM")),
            "message": {
                "text": f"{finding.get('title', '')}. Evidence: {finding.get('evidence', 'N/A')}",
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Prismor Warden",
                    "version": __version__,
                    "informationUri": "https://github.com/PrismorSec/prismor",
                    "rules": sarif_rules,
                },
            },
            "results": sarif_results,
        }],
    }


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(severity, "warning")


# ── Existing functionality (unchanged) ──────────────────────────────────

def analyze_events(
    events: List[Dict[str, Any]],
    *,
    repo_root: Path,
    workspace: Optional[Path] = None,
    session_id: str = "",
) -> Dict[str, Any]:
    engine = PolicyEngine(workspace=workspace)
    findings: List[Dict[str, Any]] = []
    for index, event in enumerate(events):
        findings.extend(engine.evaluate(event, index, session_id=session_id))

    feed_matches = match_advisories(findings, load_feed(repo_root))
    summary = {
        "totalEvents": len(events),
        "totalFindings": len(findings),
        "riskScore": min(100, sum(SEVERITY_WEIGHT.get(finding.get("severity", "UNKNOWN"), 1) for finding in findings)),
        "severityBreakdown": severity_breakdown(findings),
    }
    return {
        "summary": summary,
        "findings": sorted(findings, key=lambda item: SEVERITY_WEIGHT.get(item.get("severity", "UNKNOWN"), 0), reverse=True),
        "feedMatches": feed_matches,
        "blockCategories": sorted(engine.block_categories),
    }


def severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        summary[finding.get("severity", "UNKNOWN")] += 1
    return summary


def parse_jsonl(text: str) -> List[Dict[str, Any]]:
    events = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON on line {index}: {exc}") from exc
    return events


def read_text(input_path: str) -> str:
    if input_path == "-":
        return sys.stdin.read()
    return Path(input_path).read_text(encoding="utf-8")


def derive_session_id(events: List[Dict[str, Any]]) -> str:
    if events and events[0].get("session_id"):
        return str(events[0]["session_id"])
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"session-{Path.cwd().name}-{timestamp}"


def infer_agent(events: List[Dict[str, Any]]) -> str:
    if events and events[0].get("agent"):
        return str(events[0]["agent"])
    return "unknown"


def emit(payload: Any, *, as_json: bool, formatter=None) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    if formatter is None:
        print(json.dumps(payload, indent=2))
        return
    print(formatter(payload))


_SECRET_PATTERNS = re.compile(
    r"((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,})"    # GitHub tokens
    r"|((?:sk|pk)[-_][A-Za-z0-9-]{16,})"                            # Stripe/OpenAI keys
    r"|((?:AKIA)[A-Z0-9]{12,})"                                    # AWS access keys
    r"|(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})"           # JWTs
    r"|((?:token|secret|password|bearer|apikey)[\s=:\"']+\S{8,})", # key=value secrets
    re.IGNORECASE,
)


def _redact_evidence(evidence: str) -> str:
    """Redact secrets in evidence strings with ****."""
    if not evidence:
        return evidence
    def _mask(m):
        full = m.group(0)
        if len(full) <= 8:
            return full
        return full[:6] + "****" + full[-2:]
    return _SECRET_PATTERNS.sub(_mask, evidence)


def format_sessions(payload: Dict[str, Any]) -> str:
    sessions = payload["sessions"]
    lines = ["Prismor Warden Sessions", "======================="]
    if not sessions:
        lines.append("No sessions stored.")
        return "\n".join(lines)
    for index, session in enumerate(sessions, start=1):
        risk = session['riskScore']
        risk_color = _RED if risk >= 50 else _YELLOW if risk >= 20 else _GREEN
        lines.append(
            f"\n{_color(f'{index}.', _BOLD)} {session['sessionId']}"
            f"  {_color(f'risk={risk}/100', risk_color)}"
            f"  findings={session['findingsCount']}"
            f"  agent={session['agent']}"
        )
        # Show inline findings if they were enriched (--findings-only)
        findings = session.get("findings", [])
        if findings:
            for f in findings:
                sev = f.get("severity", "?")
                sev_color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
                evidence = _redact_evidence(f.get("evidence", ""))
                lines.append(f"   {_color(f'[{sev}]', sev_color)} {f.get('title', f.get('category', ''))}")
                if evidence:
                    lines.append(f"          {_color(evidence, _DIM)}")
    return "\n".join(lines)


def format_analysis(result: Dict[str, Any]) -> str:
    lines = [
        "Prismor Warden Report",
        "=====================",
        f"Events: {result['summary']['totalEvents']}",
        f"Findings: {result['summary']['totalFindings']}",
        f"Risk score: {result['summary']['riskScore']}/100",
        (
            "Severity: "
            f"CRITICAL={result['summary']['severityBreakdown']['CRITICAL']}, "
            f"HIGH={result['summary']['severityBreakdown']['HIGH']}, "
            f"MEDIUM={result['summary']['severityBreakdown']['MEDIUM']}, "
            f"LOW={result['summary']['severityBreakdown']['LOW']}"
        ),
        "",
        "Findings",
        "--------",
    ]

    if not result["findings"]:
        lines.append("No findings.")
    else:
        for finding in result["findings"]:
            lines.append(f"- [{finding['severity']}] {finding['title']} ({finding['category']})")
            if finding.get("evidence"):
                lines.append(f"  {finding['evidence']}")

    if result["feedMatches"]:
        lines.extend(["", "Relevant advisories", "------------------"])
        for advisory in result["feedMatches"]:
            lines.append(f"- [{advisory['severity']}] {advisory['id']} {advisory['title']}")

    return "\n".join(lines)


def format_session(session: Dict[str, Any]) -> str:
    lines = [
        f"Session {session['sessionId']}",
        "=" * (8 + len(session["sessionId"])),
        f"Agent: {session['agent']}",
        f"Source: {session['source']}",
        f"Workspace: {session['workspacePath']}",
        f"Started: {session['startedAt']}",
        f"Updated: {session['updatedAt']}",
        f"Risk score: {session['riskScore']}",
        f"Findings: {session['findingsCount']}",
        "",
        "Findings",
        "--------",
    ]
    for finding in session["findings"]:
        lines.append(f"- [{finding['severity']}] {finding['title']} ({finding['category']})")
        if finding.get("evidence"):
            lines.append(f"  {finding['evidence']}")
    lines.extend(["", "Recent events", "-------------"])
    for event in session["events"][-10:]:
        parts = [event.get("ts"), event.get("type"), event.get("path"), event.get("command"), event.get("url")]
        lines.append(f"- {' | '.join(part for part in parts if part)}")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
