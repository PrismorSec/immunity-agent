"""Render a sweep as the answer to "what would my policy have done?".

The report is built around one question an operator cannot otherwise answer
without waiting days in observe mode: *if I turn enforce on, what breaks?*
Because the would-block set comes from `hooks.should_block` — the same function
the live dispatcher calls — the counts here are what enforcement would actually
have done, not an approximation of it.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.transcripts.driver import SweepResult, SessionResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ago(value: Any, *, now: Optional[datetime] = None) -> str:
    parsed = _parse_ts(value)
    if parsed is None:
        return ""
    now = now or datetime.now(timezone.utc)
    delta = now - parsed
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _group(entries: List[Dict[str, Any]]) -> List[Tuple[str, int, str, str]]:
    """Group findings by rule -> (ruleId, count, severity, most-recent-ts)."""
    counts: collections.Counter = collections.Counter()
    severities: Dict[str, str] = {}
    latest: Dict[str, Any] = {}
    for entry in entries:
        rule = str(entry.get("ruleId") or entry.get("id") or "unknown")
        counts[rule] += 1
        severities.setdefault(rule, str(entry.get("severity") or "UNKNOWN"))
        stamp = _parse_ts(entry.get("ts"))
        if stamp is not None:
            current = latest.get(rule)
            if current is None or stamp > current:
                latest[rule] = stamp
    ordered = sorted(
        counts.items(),
        key=lambda kv: (
            _SEVERITY_ORDER.index(severities.get(kv[0], "UNKNOWN"))
            if severities.get(kv[0], "UNKNOWN") in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            -kv[1],
        ),
    )
    return [
        (
            rule,
            count,
            severities.get(rule, "UNKNOWN"),
            latest[rule].isoformat() if rule in latest else "",
        )
        for rule, count in ordered
    ]


def partition(
    result: SweepResult,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split findings into (would-block, would-warn).

    The driver stores a blocked verdict as a *copy* of the winning finding, so
    the two lists cannot be separated by object identity. Every finding carries
    a unique ``id`` (``<session>:<rule>-<index>``), which is what actually
    distinguishes them.
    """
    blocked = [b for s in result.sessions for b in s.would_block]
    blocked_keys = {str(b.get("id")) for b in blocked if b.get("id") is not None}
    warnings = [
        f
        for s in result.sessions
        for f in s.findings
        if str(f.get("id")) not in blocked_keys
    ]
    return blocked, warnings


def format_report(result: SweepResult, *, since_label: str = "all history") -> str:
    lines: List[str] = []
    agents = collections.Counter(s.agent for s in result.sessions)
    events = collections.Counter()
    labels: Dict[str, str] = {}
    for session in result.sessions:
        events[session.agent] += session.event_count
        labels[session.agent] = session.label

    lines.append("")
    lines.append(
        f"Scanned {_plural(len(result.sessions), 'session')} · "
        f"{_plural(result.total_events, 'event')} · {since_label}"
        f"   ({result.elapsed_seconds:.1f}s)"
    )
    lines.append("")
    for agent, count in agents.most_common():
        lines.append(
            f"  {labels.get(agent, agent):<14} {count:>4} sessions {events[agent]:>7} events"
        )
    for agent in result.empty_agents:
        lines.append(f"  {agent:<14}    no transcripts found")
    # An agent whose every transcript predates the window would otherwise be
    # absent from the report entirely, which reads as "no data" rather than
    # "nothing recent".
    for agent, count in sorted(result.filtered_out.items()):
        if agent in agents:
            continue
        lines.append(
            f"  {labels.get(agent, agent):<14}    "
            f"{_plural(count, 'transcript')} outside --since window"
        )
    lines.append("")

    would_block, warnings = partition(result)

    if would_block:
        lines.append(f"Would BLOCK ({len(would_block)})")
        for rule, count, severity, latest in _group(would_block):
            recency = f"   most recent {_ago(latest)}" if latest else ""
            lines.append(f"  {rule:<32} {count:>4}  {severity:<8}{recency}")
    else:
        lines.append("Would BLOCK (0)")
        lines.append("  Nothing in this window would be blocked by the current policy.")
    lines.append("")

    if warnings:
        lines.append(f"Would WARN ({len(warnings)})")
        for rule, count, severity, latest in _group(warnings)[:12]:
            recency = f"   most recent {_ago(latest)}" if latest else ""
            lines.append(f"  {rule:<32} {count:>4}  {severity:<8}{recency}")
        remaining = len(_group(warnings)) - 12
        if remaining > 0:
            lines.append(f"  … and {_plural(remaining, 'more rule')}")
        lines.append("")

    if result.silent_sessions:
        lines.append(
            f"⚠  {_plural(len(result.silent_sessions), 'transcript')} produced no events "
            f"despite containing records — likely an adapter format mismatch."
        )
        for session in result.silent_sessions[:5]:
            lines.append(f"     {session.agent}: {session.path}")
        lines.append("")

    if result.truncated:
        lines.append(
            "⚠  Event budget reached — results are partial. "
            "Raise --max-events or narrow --since."
        )
        lines.append("")

    if would_block or warnings:
        example = (_group(would_block) or _group(warnings))[0][0]
        lines.append(f"  prismor ingest --discover --show {example}    # see the calls")
        lines.append("")
    return "\n".join(lines)


def format_rule_detail(result: SweepResult, rule_id: str, *, limit: int = 25) -> str:
    """Show the individual calls behind one rule."""
    lines: List[str] = ["", f"Calls matching '{rule_id}'", ""]
    shown = 0
    for session in result.sessions:
        blocked_indices = {b.get("eventIndex") for b in session.would_block}
        for finding in session.findings:
            if str(finding.get("ruleId") or "") != rule_id:
                continue
            if shown >= limit:
                lines.append(f"  … and more; showing first {limit}")
                return "\n".join(lines) + "\n"
            verdict = "BLOCK" if finding.get("eventIndex") in blocked_indices else "warn"
            when = _ago(finding.get("ts"))
            evidence = " ".join(str(finding.get("evidence") or "").split())[:150]
            lines.append(
                f"  [{verdict:<5}] {session.agent}  {when:<9} "
                f"{session.original_session_id[:8]}"
            )
            lines.append(f"          {evidence}")
            shown += 1
    if shown == 0:
        lines.append(f"  No calls matched rule '{rule_id}' in this window.")
    lines.append("")
    return "\n".join(lines)


def report_payload(result: SweepResult) -> Dict[str, Any]:
    """Machine-readable form of the same report, for `--json`."""
    would_block, warnings = partition(result)
    return {
        "sessions": len(result.sessions),
        "events": result.total_events,
        "findings": result.total_findings,
        "elapsedSeconds": round(result.elapsed_seconds, 2),
        "truncated": result.truncated,
        "emptyAgents": result.empty_agents,
        "silentSessions": [str(s.path) for s in result.silent_sessions],
        "wouldBlock": [
            {"ruleId": r, "count": c, "severity": s, "mostRecent": t}
            for r, c, s, t in _group(would_block)
        ],
        "wouldWarn": [
            {"ruleId": r, "count": c, "severity": s, "mostRecent": t}
            for r, c, s, t in _group(warnings)
        ],
        "byAgent": [
            {
                "agent": agent,
                "sessions": sum(1 for s in result.sessions if s.agent == agent),
                "events": sum(s.event_count for s in result.sessions if s.agent == agent),
            }
            for agent in sorted({s.agent for s in result.sessions})
        ],
    }
