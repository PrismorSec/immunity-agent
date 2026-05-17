from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import fcntl  # POSIX advisory locks
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False
    try:
        import msvcrt  # Windows file locking
        _HAS_MSVCRT = True
    except ImportError:
        _HAS_MSVCRT = False

# Region size for Windows msvcrt.locking. Must be larger than any single event
# payload to provide effective mutual exclusion, since msvcrt locks are
# byte-range based. 1 GiB comfortably covers Warden's bounded event payloads.
_WIN_LOCK_BYTES = 1 << 30
# Acquisition retry deadline for the Windows non-blocking lock path.
_WIN_LOCK_DEADLINE_SECONDS = 5.0
_WIN_LOCK_RETRY_INTERVAL = 0.001


# ── Global workspace registry ────────────────────────────────────────────────

def _registry_path() -> Path:
    return Path.home() / ".prismor" / "workspaces.json"


def register_workspace(workspace: Path) -> None:
    """Add a workspace to the global registry (idempotent)."""
    ws = str(workspace.resolve())
    reg = _registry_path()
    paths: List[str] = []
    if reg.exists():
        try:
            paths = json.loads(reg.read_text())
        except Exception:
            paths = []
    if ws not in paths:
        paths.append(ws)
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_text(json.dumps(paths, indent=2))


def list_registered_workspaces() -> List[Path]:
    """Return all registered workspace paths that still exist and have a warden.db."""
    reg = _registry_path()
    if not reg.exists():
        return []
    try:
        paths = json.loads(reg.read_text())
    except Exception:
        return []
    result = []
    for p in paths:
        ws = Path(p)
        if (ws / ".prismor-warden" / "warden.db").exists():
            result.append(ws)
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def infer_default_workspace(cwd: Path) -> Path:
    resolved = cwd.resolve()
    if resolved.name == "prismor":
        return resolved
    if resolved.name == "warden":
        return resolved.parent
    return resolved


def get_data_dir(workspace: Path) -> Path:
    return workspace / ".prismor-warden"


def get_db_path(workspace: Path) -> Path:
    return get_data_dir(workspace) / "warden.db"


def get_sessions_dir(workspace: Path) -> Path:
    return get_data_dir(workspace) / "sessions"




def ensure_data_dirs(workspace: Path) -> None:
    get_sessions_dir(workspace).mkdir(parents=True, exist_ok=True)


def session_log_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in session_id)
    return get_sessions_dir(workspace) / f"{safe}.jsonl"


def append_session_event(workspace: Path, session_id: str, event: Dict[str, Any]) -> Path:
    ensure_data_dirs(workspace)
    log_path = session_log_path(workspace, session_id)
    line = json.dumps(event) + "\n"
    with log_path.open("a", encoding="utf-8") as handle:
        if _HAS_FCNTL:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.write(line)
                handle.flush()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        elif _HAS_MSVCRT:
            locked = False
            deadline = time.monotonic() + _WIN_LOCK_DEADLINE_SECONDS
            while time.monotonic() < deadline:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, _WIN_LOCK_BYTES)
                    locked = True
                    break
                except OSError:
                    time.sleep(_WIN_LOCK_RETRY_INTERVAL)
            try:
                handle.write(line)
                handle.flush()
            finally:
                if locked:
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, _WIN_LOCK_BYTES)
                    except OSError:
                        pass
        else:
            handle.write(line)
            handle.flush()
    return log_path


def read_session_events(workspace: Path, session_id: str) -> List[Dict[str, Any]]:
    log_path = session_log_path(workspace, session_id)
    events: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    with log_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            text = raw_line.strip()
            if not text:
                continue
            idx = 0
            length = len(text)
            while idx < length:
                try:
                    obj, end = decoder.raw_decode(text, idx)
                except json.JSONDecodeError:
                    break
                events.append(obj)
                idx = end
                while idx < length and text[idx].isspace():
                    idx += 1
    return events


def initialize_database(workspace: Path) -> Path:
    ensure_data_dirs(workspace)
    db_path = get_db_path(workspace)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent TEXT,
                source TEXT,
                workspace_path TEXT,
                repo_url TEXT,
                started_at TEXT,
                updated_at TEXT,
                risk_score INTEGER,
                findings_count INTEGER,
                summary_json TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ts TEXT,
                type TEXT,
                agent_event TEXT,
                command_text TEXT,
                path_text TEXT,
                url_text TEXT,
                content_text TEXT,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                event_index INTEGER,
                severity TEXT,
                category TEXT,
                title TEXT,
                evidence TEXT,
                enrichment_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id);
            CREATE TABLE IF NOT EXISTS supply_chain_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                workspace_path TEXT,
                ecosystem TEXT,
                package_name TEXT,
                package_version TEXT,
                install_cmd TEXT,
                verdict TEXT,
                score INTEGER,
                signals_json TEXT,
                ioc_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sc_ts ON supply_chain_events(ts);
            CREATE INDEX IF NOT EXISTS idx_sc_verdict ON supply_chain_events(verdict);
            """
        )
        # Add learning tables (Tier 3: Session-Based Learning)
        from warden.learning import initialize_learning_tables
        initialize_learning_tables(connection)

        connection.commit()
    finally:
        connection.close()
    return db_path


def save_session_snapshot(
    *,
    workspace: Path,
    session_id: str,
    agent: str,
    source: str,
    repo_url: Optional[str],
    events: List[Dict[str, Any]],
    analysis: Dict[str, Any],
) -> Path:
    db_path = initialize_database(workspace)
    timestamps = sorted(event.get("ts") for event in events if event.get("ts"))
    started_at = timestamps[0] if timestamps else None
    updated_at = timestamps[-1] if timestamps else None

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                agent,
                source,
                str(workspace),
                repo_url,
                started_at,
                updated_at,
                analysis["summary"]["riskScore"],
                analysis["summary"]["totalFindings"],
                json.dumps(analysis["summary"]),
            ),
        )
        cursor.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM findings WHERE session_id = ?", (session_id,))

        cursor.executemany(
            """
            INSERT INTO events (
                session_id, ts, type, agent_event, command_text, path_text, url_text, content_text, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    session_id,
                    event.get("ts"),
                    event.get("type"),
                    event.get("agent_event"),
                    event.get("command"),
                    event.get("path"),
                    event.get("url"),
                    _truncate(
                        event.get("content")
                        or event.get("response")
                        or event.get("prompt")
                        or ""
                    ),
                    json.dumps(event),
                )
                for event in events
            ],
        )

        cursor.executemany(
            """
            INSERT INTO findings (
                finding_id, session_id, event_index, severity, category, title, evidence, enrichment_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    finding["id"],
                    session_id,
                    finding.get("eventIndex"),
                    finding.get("severity"),
                    finding.get("category"),
                    finding.get("title"),
                    _truncate(finding.get("evidence", "")),
                    json.dumps(
                        {
                            "feedMatches": analysis.get("feedMatches", []),
                        }
                    ),
                )
                for finding in analysis["findings"]
            ],
        )
        connection.commit()
    finally:
        connection.close()
    return db_path


def list_sessions(workspace: Path, limit: int = 20) -> List[Dict[str, Any]]:
    db_path = initialize_database(workspace)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
            FROM sessions
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        connection.close()
    return [_session_from_row(row) for row in rows]


def get_session(workspace: Path, session_id: str) -> Optional[Dict[str, Any]]:
    db_path = initialize_database(workspace)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        session_row = connection.execute(
            """
            SELECT session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
            FROM sessions
            WHERE session_id = ?
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        if session_row is None:
            return None

        event_rows = connection.execute(
            """
            SELECT ts, type, agent_event, command_text, path_text, url_text, content_text, raw_json
            FROM events
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        ).fetchall()

        finding_rows = connection.execute(
            """
            SELECT finding_id, event_index, severity, category, title, evidence, enrichment_json
            FROM findings
            WHERE session_id = ?
            ORDER BY
              CASE severity
                WHEN 'CRITICAL' THEN 5
                WHEN 'HIGH' THEN 4
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 2
                ELSE 1
              END DESC,
              event_index ASC
            """,
            (session_id,),
        ).fetchall()
    finally:
        connection.close()

    session = _session_from_row(session_row)
    session["events"] = [
        {
            "ts": row["ts"],
            "type": row["type"],
            "agentEvent": row["agent_event"],
            "command": row["command_text"],
            "path": row["path_text"],
            "url": row["url_text"],
            "content": row["content_text"],
            "raw": json.loads(row["raw_json"]),
        }
        for row in event_rows
    ]
    session["findings"] = [
        {
            "id": row["finding_id"],
            "eventIndex": row["event_index"],
            "severity": row["severity"],
            "category": row["category"],
            "title": row["title"],
            "evidence": row["evidence"],
            "enrichment": json.loads(row["enrichment_json"]) if row["enrichment_json"] else None,
        }
        for row in finding_rows
    ]
    return session


def _session_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "sessionId": row["session_id"],
        "agent": row["agent"],
        "source": row["source"],
        "workspacePath": row["workspace_path"],
        "repoUrl": row["repo_url"],
        "startedAt": row["started_at"],
        "updatedAt": row["updated_at"],
        "riskScore": row["risk_score"],
        "findingsCount": row["findings_count"],
        "summary": json.loads(row["summary_json"]) if row["summary_json"] else None,
    }


def _truncate(value: str, max_length: int = 4000) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."


# ── Dashboard aggregate stats ─────────────────────────────────────────────────

_CATEGORY_MAP: Dict[str, str] = {
    "prompt_injection":        "prompt_injection",
    "jailbreak":               "jailbreak_attempt",
    "remote_execution":        "tool_call_abuse",
    "privilege_escalation":    "tool_call_abuse",
    "db_modification":         "tool_call_abuse",
    "rce_canary":              "tool_call_abuse",
    "secret_exfiltration":     "secret_exfil",
    "secret_access":           "secret_exfil",
    "skill_risk":              "malicious_mcp",
    "malicious_mcp":           "malicious_mcp",
    "destructive_command":     "dangerous_command",
    "dos_resource_exhaustion": "dangerous_command",
    "persistence":             "dangerous_command",
    "security_bypass":         "dangerous_command",
    "dependency_risk":         "dangerous_command",
}

_DASH_CATEGORIES = [
    "prompt_injection", "jailbreak_attempt", "tool_call_abuse",
    "secret_exfil", "malicious_mcp", "dangerous_command",
]

_TYPE_LABEL: Dict[str, str] = {
    "shell":        "bash",
    "file_read":    "file_read",
    "file_write":   "file_write",
    "network":      "network",
    "prompt":       "prompt",
    "tool_result":  "tool_result",
}


def _relative_time_store(ts: str) -> str:
    """Return a human-readable relative time string from an ISO timestamp."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = int((now - dt).total_seconds())
        if diff < 60:
            return f"{diff}s ago"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"
    except Exception:
        return ts


def _connect_ro(db_path: Path):
    """Open a SQLite DB read-only; returns None if unavailable."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def get_aggregate_stats(hours: int = 24) -> Dict[str, Any]:
    """Query all registered workspace DBs and return dashboard-shaped data.

    Returns empty/zero structures if no workspaces are registered or all DBs
    are unavailable.
    """
    from collections import Counter
    from datetime import datetime, timezone, timedelta

    workspaces = list_registered_workspaces()

    # Accumulators
    active_sessions = 0
    tool_calls_24h = 0
    dangerous_prevented_24h = 0
    tool_calls_prev = 0      # prior 24h window (for delta)
    dangerous_prev = 0
    active_prev = 0

    threats_by_category: Counter = Counter()
    agent_blocks: Counter = Counter()
    tool_breakdown: Counter = Counter()

    # keyed by date string → [total, flagged]
    timeseries_acc: Dict[str, List[int]] = {}

    patterns_acc: Dict[str, Dict[str, Any]] = {}  # key = title

    live_events_raw: List[Dict[str, Any]] = []
    top_users_acc: Dict[str, Dict[str, Any]] = {}
    top_mcp_acc: Dict[str, Dict[str, Any]] = {}
    severity_breakdown: Counter = Counter()

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            # ── KPIs ──────────────────────────────────────────────────────
            row = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE updated_at >= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            active_sessions += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE updated_at >= datetime('now', ?) "
                "AND updated_at < datetime('now', ?)",
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            active_prev += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            tool_calls_24h += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now', ?) "
                "AND ts < datetime('now', ?)",
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            tool_calls_prev += (row[0] or 0)

            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings f
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE f.category IN ('destructive_command','dos_resource_exhaustion')
                  AND e.ts >= datetime('now', ?)
                """,
                (f"-{hours} hours",),
            ).fetchone()
            dangerous_prevented_24h += (row[0] or 0)

            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings f
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE f.category IN ('destructive_command','dos_resource_exhaustion')
                  AND e.ts >= datetime('now', ?)
                  AND e.ts < datetime('now', ?)
                """,
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            dangerous_prev += (row[0] or 0)

            # ── Threats by category ───────────────────────────────────────
            for row in conn.execute("SELECT category, COUNT(*) as cnt FROM findings GROUP BY category"):
                dash_cat = _CATEGORY_MAP.get(row["category"] or "", "dangerous_command")
                threats_by_category[dash_cat] += row["cnt"]

            # ── Block rate timeseries (30 days) ───────────────────────────
            for row in conn.execute(
                """
                SELECT date(e.ts) as day,
                       COUNT(DISTINCT e.id) as total_events,
                       COUNT(DISTINCT f.rowid) as flagged_events
                FROM events e
                LEFT JOIN findings f ON f.session_id = e.session_id
                WHERE e.ts >= datetime('now', '-30 days')
                GROUP BY day
                """
            ):
                day = row["day"] or ""
                if day not in timeseries_acc:
                    timeseries_acc[day] = [0, 0]
                timeseries_acc[day][0] += row["total_events"] or 0
                timeseries_acc[day][1] += row["flagged_events"] or 0

            # ── Agent blocked commands ────────────────────────────────────
            for row in conn.execute(
                """
                SELECT s.agent, COUNT(f.finding_id) as blocked
                FROM findings f JOIN sessions s ON s.session_id = f.session_id
                GROUP BY s.agent
                """
            ):
                agent = row["agent"] or "unknown"
                agent_blocks[agent] += row["blocked"] or 0

            # ── Tool call breakdown ───────────────────────────────────────
            for row in conn.execute("SELECT type, COUNT(*) as count FROM events GROUP BY type"):
                label = _TYPE_LABEL.get(row["type"] or "", row["type"] or "other")
                tool_breakdown[label] += row["count"] or 0

            # ── Top patterns ─────────────────────────────────────────────
            for row in conn.execute(
                """
                SELECT f.title, f.category, f.severity,
                       COUNT(*) as count, MAX(e.ts) as last_seen_ts
                FROM findings f
                LEFT JOIN events e ON e.session_id = f.session_id
                GROUP BY f.title, f.category, f.severity
                ORDER BY count DESC LIMIT 30
                """
            ):
                title = row["title"] or "Unknown"
                if title not in patterns_acc:
                    patterns_acc[title] = {
                        "pattern": title,
                        "category": _CATEGORY_MAP.get(row["category"] or "", "dangerous_command"),
                        "severity": (row["severity"] or "low").lower(),
                        "count": 0,
                        "lastSeen": "",
                        "lastSeenTs": "",
                    }
                patterns_acc[title]["count"] += row["count"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > patterns_acc[title]["lastSeenTs"]:
                    patterns_acc[title]["lastSeenTs"] = ts
                    patterns_acc[title]["lastSeen"] = _relative_time_store(ts) if ts else ""

            # ── Live events ───────────────────────────────────────────────
            for row in conn.execute(
                """
                SELECT e.ts, s.agent, e.type as action_type,
                       e.command_text, e.path_text, e.url_text,
                       f.severity,
                       CASE WHEN f.finding_id IS NOT NULL THEN 'blocked' ELSE 'allowed' END as verdict
                FROM events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id
                WHERE e.ts >= datetime('now', '-24 hours')
                ORDER BY e.ts DESC LIMIT 100
                """
            ):
                action_parts = []
                if row["action_type"]:
                    action_parts.append(row["action_type"])
                detail = row["command_text"] or row["path_text"] or row["url_text"] or ""
                if detail:
                    action_parts.append(detail[:60])
                live_events_raw.append({
                    "ts": (row["ts"] or "")[-8:] or "00:00:00",
                    "agent": row["agent"] or "unknown",
                    "action": ": ".join(action_parts) if action_parts else "event",
                    "verdict": row["verdict"] or "allowed",
                    "severity": (row["severity"] or "low").lower(),
                })

            # ── Top users by blocks ───────────────────────────────────────
            for row in conn.execute(
                """
                SELECT substr(f.session_id, 1, 10) as userId,
                       COUNT(f.finding_id) as blocked, MAX(e.ts) as last_seen_ts
                FROM findings f
                LEFT JOIN events e ON e.session_id = f.session_id
                GROUP BY userId
                ORDER BY blocked DESC LIMIT 10
                """
            ):
                uid = row["userId"] or "unknown"
                if uid not in top_users_acc:
                    top_users_acc[uid] = {"userId": uid, "blocked": 0, "lastSeen": "", "lastSeenTs": ""}
                top_users_acc[uid]["blocked"] += row["blocked"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > top_users_acc[uid]["lastSeenTs"]:
                    top_users_acc[uid]["lastSeenTs"] = ts
                    top_users_acc[uid]["lastSeen"] = _relative_time_store(ts) if ts else ""

            # ── Top MCP / skills ─────────────────────────────────────────
            for row in conn.execute(
                """
                SELECT COALESCE(e.agent_event, e.type, 'unknown') as name,
                       e.type,
                       COUNT(*) as calls,
                       COUNT(f.finding_id) as blocked
                FROM events e
                LEFT JOIN findings f ON f.session_id = e.session_id
                GROUP BY name
                ORDER BY calls DESC LIMIT 15
                """
            ):
                name = row["name"] or "unknown"
                if name not in top_mcp_acc:
                    top_mcp_acc[name] = {
                        "name": name,
                        "type": "mcp" if "mcp" in name.lower() else "skill",
                        "calls": 0,
                        "blocked": 0,
                    }
                top_mcp_acc[name]["calls"] += row["calls"] or 0
                top_mcp_acc[name]["blocked"] += row["blocked"] or 0

            # ── Severity breakdown ────────────────────────────────────────
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ):
                sev = (row["severity"] or "low").lower()
                severity_breakdown[sev] += row["cnt"]

        except Exception:
            pass
        finally:
            conn.close()

    # ── Deltas ────────────────────────────────────────────────────────────────
    def _pct_delta(current: int, prior: int) -> float:
        if prior == 0:
            return 0.0
        return round((current - prior) / prior * 100, 1)

    # ── Block rate timeseries — fill 30-day window ────────────────────────────
    today = datetime.now(timezone.utc).date()
    timeseries: List[Dict[str, Any]] = []
    for i in range(29, -1, -1):
        day_date = today - timedelta(days=i)
        day_str = day_date.isoformat()
        total, flagged = timeseries_acc.get(day_str, [0, 0])
        timeseries.append({
            "date": day_str,
            "intercepted": flagged,
            "passed": max(0, total - flagged),
        })

    # ── Assemble threatsByCategory with all 6 keys always present ────────────
    threats_out = {cat: threats_by_category.get(cat, 0) for cat in _DASH_CATEGORIES}

    # ── Sort and trim ─────────────────────────────────────────────────────────
    top_patterns = sorted(patterns_acc.values(), key=lambda x: x["count"], reverse=True)[:20]
    for p in top_patterns:
        p.pop("lastSeenTs", None)

    top_users = sorted(top_users_acc.values(), key=lambda x: x["blocked"], reverse=True)[:10]
    for u in top_users:
        u.pop("lastSeenTs", None)

    # Deduplicate live events (same ts+agent+action), keep 50
    seen = set()
    live_events_deduped = []
    for ev in live_events_raw:
        key = (ev["ts"], ev["agent"], ev["action"][:30])
        if key not in seen:
            seen.add(key)
            live_events_deduped.append(ev)
        if len(live_events_deduped) >= 50:
            break

    return {
        "kpis": {
            "activeSessions": active_sessions,
            "toolCallsInspected24h": tool_calls_24h,
            "dangerousCommandsPrevented24h": dangerous_prevented_24h,
            "deltas": {
                "threats": _pct_delta(sum(threats_out.values()), 0),
                "tools": _pct_delta(tool_calls_24h, tool_calls_prev),
                "dangerous": _pct_delta(dangerous_prevented_24h, dangerous_prev),
            },
        },
        "threatsByCategory": threats_out,
        "blockRateTimeseries": timeseries,
        "agentBlockedCommands": [
            {"agent": agent, "blocked": count}
            for agent, count in agent_blocks.most_common(10)
        ],
        "toolCallBreakdown": [
            {"tool": tool, "count": count}
            for tool, count in tool_breakdown.most_common(10)
        ],
        "topPatterns": top_patterns,
        "liveEvents": live_events_deduped,
        "topUsersByBlocks": top_users,
        "topMcpAndSkills": sorted(top_mcp_acc.values(), key=lambda x: x["calls"], reverse=True)[:15],
        "severityBreakdown": {
            "critical": severity_breakdown.get("critical", 0),
            "high": severity_breakdown.get("high", 0),
            "medium": severity_breakdown.get("medium", 0),
            "low": severity_breakdown.get("low", 0),
        },
    }


# ── Reverse category map (dashboard cat → list of raw DB cats) ────────────────
_REVERSE_CATEGORY_MAP: Dict[str, List[str]] = {}
for _raw_cat, _dash_cat in _CATEGORY_MAP.items():
    _REVERSE_CATEGORY_MAP.setdefault(_dash_cat, []).append(_raw_cat)

_VALID_SESSION_SORTS: Dict[str, str] = {
    "sessionId": "session_id",
    "agent": "agent",
    "workspace": "workspace_path",
    "riskScore": "risk_score",
    "findingsCount": "findings_count",
    "startedAt": "started_at",
    "updatedAt": "updated_at",
}


def get_sessions_page(
    page: int = 1,
    limit: int = 20,
    sort: str = "updatedAt",
    direction: str = "desc",
) -> Dict[str, Any]:
    """Return a paginated list of sessions across all registered workspaces."""
    sort_col = _VALID_SESSION_SORTS.get(sort, "updated_at")
    reverse = direction.lower() != "asc"
    workspaces = list_registered_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            for row in conn.execute(
                "SELECT session_id, agent, risk_score, findings_count, "
                "started_at, updated_at, workspace_path FROM sessions LIMIT 5000"
            ):
                rows.append({
                    "sessionId": (row["session_id"] or "")[:20],
                    "agent": row["agent"] or "unknown",
                    "riskScore": row["risk_score"] or 0,
                    "findingsCount": row["findings_count"] or 0,
                    "startedAt": _relative_time_store(row["started_at"]) if row["started_at"] else "",
                    "updatedAt": _relative_time_store(row["updated_at"]) if row["updated_at"] else "",
                    "_sortRaw": row[sort_col] or "",
                    "workspace": Path(row["workspace_path"] or "").name if row["workspace_path"] else "",
                })
        except Exception:
            pass
        finally:
            conn.close()

    rows.sort(key=lambda x: x["_sortRaw"] or "", reverse=reverse)
    total = len(rows)
    limit = max(1, min(limit, 200))
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = rows[offset: offset + limit]
    for r in items:
        r.pop("_sortRaw", None)

    return {"items": items, "total": total, "page": page, "pages": pages, "limit": limit}


def get_findings_page(
    page: int = 1,
    limit: int = 25,
    agent: str = "",
    severity: str = "",
    category: str = "",
    search: str = "",
) -> Dict[str, Any]:
    """Return a paginated, filtered list of findings across all registered workspaces."""
    severity_filter = severity.lower() if severity else ""
    raw_cats = _REVERSE_CATEGORY_MAP.get(category, []) if category else []
    workspaces = list_registered_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            where_clauses: List[str] = []
            params: List[Any] = []
            if severity_filter:
                where_clauses.append("LOWER(f.severity) = ?")
                params.append(severity_filter)
            if raw_cats:
                placeholders = ",".join("?" * len(raw_cats))
                where_clauses.append(f"f.category IN ({placeholders})")
                params.extend(raw_cats)
            if agent:
                where_clauses.append("s.agent = ?")
                params.append(agent)
            if search:
                where_clauses.append("(LOWER(f.title) LIKE ? OR LOWER(COALESCE(f.evidence,'')) LIKE ?)")
                params.extend([f"%{search.lower()}%"] * 2)
            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            for row in conn.execute(
                f"""
                SELECT f.finding_id, f.session_id, f.title, f.category,
                       f.severity, f.evidence, s.agent,
                       MAX(e.ts) as ts,
                       MAX(e.command_text) as command_text,
                       MAX(e.path_text) as path_text,
                       MAX(e.url_text) as url_text
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                {where}
                GROUP BY f.finding_id
                ORDER BY ts DESC LIMIT 5000
                """,
                params,
            ):
                rows.append({
                    "id": (row["finding_id"] or "")[:20],
                    "sessionId": (row["session_id"] or "")[:20],
                    "title": row["title"] or "Unknown",
                    "category": _CATEGORY_MAP.get(row["category"] or "", "dangerous_command"),
                    "severity": (row["severity"] or "low").lower(),
                    "evidence": (row["evidence"] or "")[:500],
                    "agent": row["agent"] or "unknown",
                    "ts": _relative_time_store(row["ts"]) if row["ts"] else "",
                    "_tsRaw": row["ts"] or "",
                    "command": (row["command_text"] or row["path_text"] or row["url_text"] or "")[:160],
                })
        except Exception:
            pass
        finally:
            conn.close()

    rows.sort(key=lambda x: x["_tsRaw"] or "", reverse=True)
    all_agents = sorted({r["agent"] for r in rows})
    all_cats = sorted({r["category"] for r in rows})
    total = len(rows)
    limit = max(1, min(limit, 200))
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = rows[offset: offset + limit]
    for r in items:
        r.pop("_tsRaw", None)

    return {
        "items": items, "total": total, "page": page, "pages": pages, "limit": limit,
        "agents": all_agents, "categories": all_cats,
    }


def get_events_page(
    page: int = 1,
    limit: int = 30,
    verdict: str = "",
    agent: str = "",
) -> Dict[str, Any]:
    """Return a paginated, filtered list of events across all registered workspaces."""
    workspaces = list_registered_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            where_clauses: List[str] = []
            params: List[Any] = []
            if agent:
                where_clauses.append("s.agent = ?")
                params.append(agent)
            if verdict == "blocked":
                where_clauses.append("s.findings_count > 0")
            elif verdict == "allowed":
                where_clauses.append("s.findings_count = 0")
            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            for row in conn.execute(
                f"""
                SELECT e.ts, s.agent, e.type as action_type,
                       e.command_text, e.path_text, e.url_text,
                       f.severity,
                       CASE WHEN s.findings_count > 0 THEN 'blocked' ELSE 'allowed' END as verdict
                FROM events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id
                {where}
                GROUP BY e.id
                ORDER BY e.ts DESC LIMIT 5000
                """,
                params,
            ):
                action_parts = []
                if row["action_type"]:
                    action_parts.append(row["action_type"])
                detail = row["command_text"] or row["path_text"] or row["url_text"] or ""
                if detail:
                    action_parts.append(detail[:80])
                rows.append({
                    "ts": _relative_time_store(row["ts"]) if row["ts"] else "",
                    "_tsRaw": row["ts"] or "",
                    "agent": row["agent"] or "unknown",
                    "action": ": ".join(action_parts) if action_parts else "event",
                    "verdict": row["verdict"] or "allowed",
                    "severity": (row["severity"] or "low").lower(),
                })
        except Exception:
            pass
        finally:
            conn.close()

    # Deduplicate then sort
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for ev in rows:
        key = (ev["_tsRaw"], ev["agent"], ev["action"][:40])
        if key not in seen:
            seen.add(key)
            deduped.append(ev)
    deduped.sort(key=lambda x: x["_tsRaw"] or "", reverse=True)

    all_agents = sorted({ev["agent"] for ev in deduped})
    total = len(deduped)
    limit = max(1, min(limit, 200))
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = deduped[offset: offset + limit]
    for r in items:
        r.pop("_tsRaw", None)

    return {
        "items": items, "total": total, "page": page, "pages": pages, "limit": limit,
        "agents": all_agents,
    }


# ── Supply chain store ────────────────────────────────────────────────────────

def write_supply_chain_event(
    *,
    workspace: Path,
    session_id: str,
    ts: str,
    ecosystem: str,
    install_cmd: str,
    verdicts: list,
) -> None:
    """Record immunity CLI scoring results into the warden DB. Fail-open."""
    import uuid as _uuid
    try:
        db_path = initialize_database(workspace)
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()

            n_findings = sum(1 for v in verdicts if v.verdict in ("block", "warn"))
            max_score = max((v.score for v in verdicts), default=0)
            cursor.execute(
                """
                INSERT OR IGNORE INTO sessions (
                    session_id, agent, source, workspace_path,
                    started_at, updated_at, risk_score, findings_count, summary_json
                ) VALUES (?, 'immunity-cli', 'supply_chain', ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, str(workspace), ts, ts,
                    max_score, n_findings,
                    json.dumps({"ecosystem": ecosystem}),
                ),
            )

            for v in verdicts:
                ioc_id = next(
                    (s.id[len("ioc_"):] for s in v.signals if s.id.startswith("ioc_")),
                    None,
                )
                cursor.execute(
                    """
                    INSERT INTO events (
                        session_id, ts, type, agent_event, command_text, raw_json
                    ) VALUES (?, ?, 'supply_chain', ?, ?, ?)
                    """,
                    (
                        session_id, ts, ecosystem, install_cmd,
                        json.dumps({
                            "package": v.spec.raw,
                            "ecosystem": ecosystem,
                            "verdict": v.verdict,
                            "score": v.score,
                        }),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO supply_chain_events (
                        ts, workspace_path, ecosystem, package_name, package_version,
                        install_cmd, verdict, score, signals_json, ioc_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts, str(workspace), ecosystem,
                        v.spec.name,
                        getattr(v.meta, "version", None) or "",
                        install_cmd,
                        v.verdict,
                        v.score,
                        json.dumps([
                            {"id": s.id, "points": s.points, "description": s.description}
                            for s in v.signals
                        ]),
                        ioc_id,
                    ),
                )

                if v.verdict in ("block", "warn"):
                    top = next(iter(sorted(v.signals, key=lambda s: s.points, reverse=True)), None)
                    has_ioc = any(s.id.startswith("ioc_") for s in v.signals)
                    severity = "CRITICAL" if has_ioc else ("HIGH" if v.score >= 60 else "MEDIUM")
                    cursor.execute(
                        """
                        INSERT INTO findings (
                            finding_id, session_id, severity, category, title, evidence
                        ) VALUES (?, ?, ?, 'supply_chain_block', ?, ?)
                        """,
                        (
                            str(_uuid.uuid4()),
                            session_id,
                            severity,
                            f"{v.verdict.upper()}: {v.spec.raw} [{ecosystem}] score {v.score}",
                            "; ".join(s.description for s in v.signals[:3]),
                        ),
                    )

            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def get_supply_chain_stats(hours: int = 24) -> Dict[str, Any]:
    """Aggregate supply chain enforcement data across all registered workspaces."""
    from collections import Counter

    workspaces = list_registered_workspaces()

    checked_24h = 0
    blocked_24h = 0
    warned_24h = 0
    ecosystem_total: Counter = Counter()
    ecosystem_blocked: Counter = Counter()
    pkg_blocks: Counter = Counter()
    pkg_ecosystem: Dict[str, str] = {}
    pkg_ioc: Dict[str, str] = {}
    recent_blocks: list = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            for row in conn.execute(
                "SELECT verdict, COUNT(*) as cnt FROM supply_chain_events "
                "WHERE ts >= datetime('now', ?) GROUP BY verdict",
                (f"-{hours} hours",),
            ):
                v = row["verdict"] or "allow"
                if v == "block":
                    blocked_24h += row["cnt"]
                elif v == "warn":
                    warned_24h += row["cnt"]
                checked_24h += row["cnt"]

            for row in conn.execute(
                "SELECT ecosystem, verdict, COUNT(*) as cnt "
                "FROM supply_chain_events GROUP BY ecosystem, verdict"
            ):
                eco = row["ecosystem"] or "unknown"
                ecosystem_total[eco] += row["cnt"]
                if row["verdict"] == "block":
                    ecosystem_blocked[eco] += row["cnt"]

            for row in conn.execute(
                "SELECT package_name, ecosystem, ioc_id, COUNT(*) as cnt "
                "FROM supply_chain_events WHERE verdict='block' "
                "GROUP BY package_name ORDER BY cnt DESC LIMIT 20"
            ):
                name = row["package_name"] or ""
                pkg_blocks[name] += row["cnt"]
                pkg_ecosystem[name] = row["ecosystem"] or ""
                if row["ioc_id"] and name not in pkg_ioc:
                    pkg_ioc[name] = row["ioc_id"]

            for row in conn.execute(
                "SELECT ts, package_name, ecosystem, score, signals_json, verdict "
                "FROM supply_chain_events WHERE verdict IN ('block','warn') "
                "ORDER BY ts DESC LIMIT 60"
            ):
                try:
                    sigs = json.loads(row["signals_json"] or "[]")
                except Exception:
                    sigs = []
                recent_blocks.append({
                    "ts": _relative_time_store(row["ts"]) if row["ts"] else "",
                    "package": row["package_name"] or "",
                    "ecosystem": row["ecosystem"] or "",
                    "score": row["score"] or 0,
                    "verdict": row["verdict"] or "block",
                    "reason": sigs[0]["description"][:80] if sigs else "",
                })
        except Exception:
            pass
        finally:
            conn.close()

    recent_blocks.sort(key=lambda x: x.get("ts", ""), reverse=False)
    recent_blocks = recent_blocks[:30]

    top_blocked = sorted(pkg_blocks, key=lambda k: pkg_blocks[k], reverse=True)[:10]

    return {
        "kpis": {
            "checkedPackages24h": checked_24h,
            "blockedPackages24h": blocked_24h,
            "warnedPackages24h": warned_24h,
        },
        "ecosystemBreakdown": [
            {
                "ecosystem": eco,
                "total": ecosystem_total[eco],
                "blocked": ecosystem_blocked.get(eco, 0),
            }
            for eco in sorted(ecosystem_total, key=lambda k: ecosystem_total[k], reverse=True)
        ],
        "topBlockedPackages": [
            {
                "name": name,
                "ecosystem": pkg_ecosystem.get(name, ""),
                "count": pkg_blocks[name],
                "iocId": pkg_ioc.get(name, ""),
            }
            for name in top_blocked
        ],
        "recentBlocks": recent_blocks,
    }
