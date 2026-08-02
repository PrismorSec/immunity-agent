"""Find agent sessions that ran without Prismor watching.

`prismor discover` answers "is this agent hooked *right now*". It cannot answer
"did anything run while it wasn't". Transcripts can: every session the agent
persisted is compared against the sessions Prismor actually captured live, and
the difference is activity that executed ungoverned.

Classification leans on a per-agent **watermark** — the earliest live capture
Prismor holds for that agent. It is a heuristic, and deliberately reported as
one: a gap after the watermark means Prismor was installed for that agent yet
holds no record of the session, which is consistent with hooks being removed,
an agent running from a different workspace, or a session predating a
re-install. The tool reports the gap and its timing; it does not assert intent.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.transcripts.driver import SweepResult, SessionResult

#: Sessions captured by the live hook dispatcher.
LIVE_SOURCE = "hook"


@dataclass
class LiveSession:
    session_id: str
    agent: str
    started_at: Optional[str]


@dataclass
class Gap:
    session: SessionResult
    reason: str
    detail: str


@dataclass
class CoverageReport:
    on_disk: int = 0
    governed: List[SessionResult] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)
    #: agent -> ISO timestamp of the earliest live capture Prismor holds.
    watermarks: Dict[str, str] = field(default_factory=dict)

    @property
    def ungoverned(self) -> int:
        return len(self.gaps)

    def by_reason(self) -> Dict[str, List[Gap]]:
        grouped: Dict[str, List[Gap]] = {}
        for gap in self.gaps:
            grouped.setdefault(gap.reason, []).append(gap)
        return grouped

    @property
    def ungoverned_findings(self) -> int:
        return sum(len(g.session.findings) for g in self.gaps)

    @property
    def ungoverned_would_block(self) -> int:
        return sum(len(g.session.would_block) for g in self.gaps)


def _parse(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def load_live_sessions(workspace: Path) -> Dict[str, LiveSession]:
    """Every session the live dispatcher captured, keyed by session id."""
    from prismor.runtime.store import get_db_path

    db_path = get_db_path(workspace)
    if not Path(db_path).exists():
        return {}
    try:
        connection = sqlite3.connect(str(db_path))
    except sqlite3.Error:
        return {}
    try:
        rows = connection.execute(
            "SELECT session_id, agent, started_at FROM sessions WHERE source = ?",
            (LIVE_SOURCE,),
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        connection.close()
    return {
        str(row[0]): LiveSession(
            session_id=str(row[0]), agent=str(row[1] or ""), started_at=row[2]
        )
        for row in rows
    }


def build_coverage(result: SweepResult, workspace: Path) -> CoverageReport:
    live = load_live_sessions(workspace)
    report = CoverageReport(on_disk=len(result.sessions))

    # Watermark: earliest live capture per agent. Anything before it ran
    # before Prismor was watching that agent at all.
    watermarks: Dict[str, datetime] = {}
    for entry in live.values():
        stamp = _parse(entry.started_at)
        if stamp is None or not entry.agent:
            continue
        current = watermarks.get(entry.agent)
        if current is None or stamp < current:
            watermarks[entry.agent] = stamp
    report.watermarks = {a: t.isoformat() for a, t in watermarks.items()}

    for session in result.sessions:
        if session.original_session_id in live:
            report.governed.append(session)
            continue

        watermark = watermarks.get(session.agent)
        started = _parse(session.started_at)
        if watermark is None:
            reason = "never-governed"
            detail = f"Prismor holds no live capture for {session.agent} at all"
        elif started is not None and started < watermark:
            reason = "predates-install"
            detail = f"ran before the first {session.agent} capture on {watermark.date()}"
        else:
            reason = "gap-after-install"
            detail = (
                f"ran after {session.agent} capture began on {watermark.date()}, "
                f"but no live record exists"
            )
        report.gaps.append(Gap(session=session, reason=reason, detail=detail))

    return report


def format_coverage(report: CoverageReport) -> str:
    lines: List[str] = ["", "Coverage audit", ""]
    lines.append(f"  Sessions on disk    {report.on_disk:>5}")
    lines.append(f"    governed (live)   {len(report.governed):>5}")
    lines.append(f"    UNGOVERNED        {report.ungoverned:>5}")
    lines.append("")

    grouped = report.by_reason()
    if grouped:
        lines.append("  Blind spots")
        titles = {
            "predates-install": "before Prismor was installed",
            "gap-after-install": "no live record despite hooks being active",
            "never-governed": "agent never captured live",
        }
        for reason, gaps in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            agents = sorted({g.session.agent for g in gaps})
            lines.append(
                f"    {len(gaps):>4}  {titles.get(reason, reason):<44} "
                f"[{', '.join(agents)}]"
            )
        lines.append("")

    if report.gaps:
        lines.append("  In ungoverned sessions")
        lines.append(f"    {report.ungoverned_would_block:>4}  would have been blocked")
        lines.append(f"    {report.ungoverned_findings:>4}  findings total")
        lines.append("")
        lines.append(
            "  Note: a gap means Prismor holds no live record for that session. "
            "It is\n  evidence of unmonitored activity, not proof that hooks were "
            "removed."
        )
        lines.append("")
    else:
        lines.append("  Every session on disk has a matching live capture.")
        lines.append("")
    return "\n".join(lines)


def coverage_payload(report: CoverageReport) -> Dict[str, Any]:
    return {
        "onDisk": report.on_disk,
        "governed": len(report.governed),
        "ungoverned": report.ungoverned,
        "watermarks": report.watermarks,
        "ungovernedWouldBlock": report.ungoverned_would_block,
        "ungovernedFindings": report.ungoverned_findings,
        "blindSpots": [
            {
                "reason": reason,
                "count": len(gaps),
                "agents": sorted({g.session.agent for g in gaps}),
                "sessions": [g.session.original_session_id for g in gaps[:50]],
            }
            for reason, gaps in report.by_reason().items()
        ],
    }
