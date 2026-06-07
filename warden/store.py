from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


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
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event))
        handle.write("\n")
    return log_path


def read_session_events(workspace: Path, session_id: str) -> List[Dict[str, Any]]:
    log_path = session_log_path(workspace, session_id)
    with log_path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle.read().splitlines() if line.strip()]


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
                ioc_id TEXT,
                recommended_version TEXT,
                session_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sc_ts ON supply_chain_events(ts);
            CREATE INDEX IF NOT EXISTS idx_sc_verdict ON supply_chain_events(verdict);
            CREATE INDEX IF NOT EXISTS idx_sc_session ON supply_chain_events(session_id);
            """
        )
        # Backfill columns on pre-existing DBs (idempotent: ignore if column exists)
        for ddl in (
            "ALTER TABLE supply_chain_events ADD COLUMN recommended_version TEXT",
            "ALTER TABLE supply_chain_events ADD COLUMN session_id TEXT",
        ):
            try:
                connection.execute(ddl)
            except sqlite3.OperationalError:
                pass
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


def _absolute_time_store(ts: str) -> str:
    """Return a compact absolute UTC timestamp (YYYY-MM-DD HH:MM:SS) for tooltips."""
    if not ts:
        return ""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def _ts_pair(ts: str) -> Dict[str, str]:
    """Return ``{"rel": "2h ago", "abs": "2026-06-06 14:23:05 UTC"}`` for a ts."""
    return {"rel": _relative_time_store(ts) if ts else "", "abs": _absolute_time_store(ts)}


def _extract_mcp_or_tool(raw_json: str) -> Optional[Dict[str, str]]:
    """Identify whether an event was an MCP server call or a skill/tool call.

    Returns ``None`` for hook-event noise (Pre/PostToolUse without an MCP
    server or a recognised tool name).  Otherwise returns
    ``{"kind": "mcp"|"skill"|"tool", "name": str}``.
    """
    if not raw_json:
        return None
    try:
        raw = json.loads(raw_json)
    except Exception:
        return None
    meta = raw.get("metadata") or {}

    mcp_server = raw.get("mcp_server") or meta.get("mcp_server")
    if mcp_server:
        return {"kind": "mcp", "name": str(mcp_server)}

    tool_name = meta.get("tool_name") or (raw.get("metadata", {}) or {}).get("tool_name") or ""
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        server = tool_name[len("mcp__"):].split("__", 1)[0]
        return {"kind": "mcp", "name": server}
    if tool_name == "Skill":
        # The skill name lives inside the raw payload's tool_input.
        skill_name = ""
        try:
            skill_name = (raw.get("metadata", {}).get("raw", {})
                          .get("tool_input", {}).get("skill", ""))
        except Exception:
            pass
        return {"kind": "skill", "name": skill_name or "Skill"}
    if tool_name in {"Bash", "Read", "Edit", "MultiEdit", "Write",
                     "WebFetch", "WebSearch", "Grep", "Glob", "Task"}:
        return {"kind": "tool", "name": tool_name}
    return None


def _connect_ro(db_path: Path):
    """Open a SQLite DB read-only; returns None if unavailable."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _migrate_sc_columns(db_path: Path) -> None:
    """Backfill any newly-added supply_chain_events columns onto an old DB.

    Idempotent: if the column already exists, sqlite raises OperationalError
    and we move on.  This lets the dashboard read pre-existing data without
    requiring an immunity-cli write to trigger initialize_database.
    """
    if not db_path.exists():
        return
    try:
        conn = sqlite3.connect(db_path)
        try:
            for ddl in (
                "ALTER TABLE supply_chain_events ADD COLUMN recommended_version TEXT",
                "ALTER TABLE supply_chain_events ADD COLUMN session_id TEXT",
            ):
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


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
    threats_prev_acc = [0]  # boxed so nested scopes can mutate
    agent_blocks: Counter = Counter()
    tool_breakdown: Counter = Counter()
    mcp_acc: Dict[str, Dict[str, Any]] = {}    # real MCP servers
    skill_acc: Dict[str, Dict[str, Any]] = {}  # claude skills

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

            # ── Threats by category (24h) ─────────────────────────────────
            # Join findings to their triggering event so we filter on the
            # event's actual timestamp.  For supply-chain findings (which
            # have no event_index), fall back to the session's updated_at.
            for row in conn.execute(
                """
                SELECT f.category, COUNT(*) as cnt
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE COALESCE(e.ts, s.updated_at) >= datetime('now', ?)
                GROUP BY f.category
                """,
                (f"-{hours} hours",),
            ):
                dash_cat = _CATEGORY_MAP.get(row["category"] or "", "dangerous_command")
                threats_by_category[dash_cat] += row["cnt"]

            # Prior 24h window — for delta calculation.
            for row in conn.execute(
                """
                SELECT COUNT(*) as cnt
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE COALESCE(e.ts, s.updated_at) >= datetime('now', ?)
                  AND COALESCE(e.ts, s.updated_at) <  datetime('now', ?)
                """,
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ):
                threats_prev_acc[0] += row["cnt"] or 0

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

            # ── Agent blocked commands (24h, per-finding event) ───────────
            # Counts each finding once by joining to its specific event via
            # event_index — older join double-counted across the session.
            for row in conn.execute(
                """
                SELECT s.agent, COUNT(*) as blocked
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE COALESCE(e.ts, s.updated_at) >= datetime('now', ?)
                GROUP BY s.agent
                """,
                (f"-{hours} hours",),
            ):
                agent = row["agent"] or "unknown"
                agent_blocks[agent] += row["blocked"] or 0

            # ── Tool call breakdown (built-in tools only; MCP/skills below) ──
            # Skip supply_chain events so they don't show up next to Bash/Read.
            for row in conn.execute(
                "SELECT type, COUNT(*) as count FROM events "
                "WHERE type != 'supply_chain' GROUP BY type"
            ):
                label = _TYPE_LABEL.get(row["type"] or "", row["type"] or "other")
                tool_breakdown[label] += row["count"] or 0

            # ── Top patterns (last_seen = finding's specific event) ──────
            # Use event_index to find the finding's event, then read its ts.
            for row in conn.execute(
                """
                SELECT f.title, f.category, f.severity,
                       COUNT(*) as count,
                       MAX(COALESCE(e.ts, s.updated_at)) as last_seen_ts
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                                  AND e.id = (
                                    SELECT id FROM events
                                    WHERE session_id = f.session_id
                                    ORDER BY id LIMIT 1 OFFSET COALESCE(f.event_index, 0)
                                  )
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
                        "lastSeenAbs": "",
                        "lastSeenTs": "",
                    }
                patterns_acc[title]["count"] += row["count"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > patterns_acc[title]["lastSeenTs"]:
                    patterns_acc[title]["lastSeenTs"] = ts
                    patterns_acc[title]["lastSeen"] = _relative_time_store(ts) if ts else ""
                    patterns_acc[title]["lastSeenAbs"] = _absolute_time_store(ts) if ts else ""

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
                ts_raw = row["ts"] or ""
                live_events_raw.append({
                    "ts": _relative_time_store(ts_raw) or "—",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "agent": row["agent"] or "unknown",
                    "action": ": ".join(action_parts) if action_parts else "event",
                    "verdict": row["verdict"] or "allowed",
                    "severity": (row["severity"] or "low").lower(),
                })

            # ── Top sessions by blocks (full ID, agent, source) ──────────
            for row in conn.execute(
                """
                SELECT f.session_id as sid, s.agent, s.source,
                       COUNT(f.finding_id) as blocked,
                       MAX(COALESCE(e.ts, s.updated_at)) as last_seen_ts
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                GROUP BY f.session_id
                ORDER BY blocked DESC LIMIT 10
                """
            ):
                sid = row["sid"] or "unknown"
                if sid not in top_users_acc:
                    top_users_acc[sid] = {
                        "sessionId": sid,
                        "agent": row["agent"] or "unknown",
                        "source": row["source"] or "agent",
                        "blocked": 0,
                        "lastSeen": "", "lastSeenAbs": "", "lastSeenTs": "",
                    }
                top_users_acc[sid]["blocked"] += row["blocked"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > top_users_acc[sid]["lastSeenTs"]:
                    top_users_acc[sid]["lastSeenTs"] = ts
                    top_users_acc[sid]["lastSeen"] = _relative_time_store(ts) if ts else ""
                    top_users_acc[sid]["lastSeenAbs"] = _absolute_time_store(ts) if ts else ""

            # ── Top MCP servers + skills (parse raw_json — hook events
            #    like Pre/PostToolUse are filtered out so the chart shows
            #    real server / skill names instead of hook noise) ────────
            for row in conn.execute(
                """
                SELECT e.raw_json, s.agent, f.finding_id IS NOT NULL as blocked
                FROM events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id
                                    AND f.event_index = (
                                      SELECT COUNT(*) FROM events e2
                                      WHERE e2.session_id = e.session_id
                                        AND e2.id < e.id
                                    )
                WHERE e.type != 'supply_chain'
                  AND e.ts >= datetime('now', ?)
                LIMIT 5000
                """,
                (f"-{hours} hours",),
            ):
                info = _extract_mcp_or_tool(row["raw_json"] or "")
                if info is None or info["kind"] == "tool":
                    continue
                acc = mcp_acc if info["kind"] == "mcp" else skill_acc
                key = info["name"]
                if key not in acc:
                    acc[key] = {"name": key, "type": info["kind"], "calls": 0, "blocked": 0}
                acc[key]["calls"] += 1
                if row["blocked"]:
                    acc[key]["blocked"] += 1

            # ── Severity breakdown (24h, gated on the finding's event ts) ─
            for row in conn.execute(
                """
                SELECT f.severity, COUNT(*) as cnt
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events e ON e.session_id = f.session_id
                WHERE COALESCE(e.ts, s.updated_at) >= datetime('now', ?)
                GROUP BY f.severity
                """,
                (f"-{hours} hours",),
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

    # MCP + skills merged for the chart — MCP first (typically higher signal),
    # then skills, capped at 15 entries.
    combined = (
        sorted(mcp_acc.values(),   key=lambda x: x["calls"], reverse=True) +
        sorted(skill_acc.values(), key=lambda x: x["calls"], reverse=True)
    )
    top_mcp_and_skills = combined[:15]

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
                "threats": _pct_delta(sum(threats_out.values()), threats_prev_acc[0]),
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
        "topSessionsByBlocks": top_users,
        "topMcpAndSkills": top_mcp_and_skills,
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
                "SELECT session_id, agent, source, risk_score, findings_count, "
                "started_at, updated_at, workspace_path FROM sessions LIMIT 5000"
            ):
                rows.append({
                    "sessionId": row["session_id"] or "",
                    "agent": row["agent"] or "unknown",
                    "source": row["source"] or "agent",
                    "riskScore": row["risk_score"] or 0,
                    "findingsCount": row["findings_count"] or 0,
                    "startedAt": _relative_time_store(row["started_at"]) if row["started_at"] else "",
                    "startedAtAbs": _absolute_time_store(row["started_at"] or ""),
                    "updatedAt": _relative_time_store(row["updated_at"]) if row["updated_at"] else "",
                    "updatedAtAbs": _absolute_time_store(row["updated_at"] or ""),
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
            # The triggering event for a finding is identified by event_index
            # (its 0-based position in the session's event list). Resolve it
            # via a correlated subquery so we get the actual command/prompt
            # rather than MAX(...) across the whole session.
            for row in conn.execute(
                f"""
                SELECT f.finding_id, f.session_id, f.title, f.category,
                       f.severity, f.evidence, f.event_index, s.agent,
                       te.ts          as trig_ts,
                       te.type        as trig_type,
                       te.command_text as trig_cmd,
                       te.path_text    as trig_path,
                       te.url_text     as trig_url,
                       te.content_text as trig_content,
                       te.agent_event  as trig_hook,
                       s.updated_at    as session_updated
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN events te ON te.id = (
                    SELECT id FROM events
                    WHERE session_id = f.session_id
                    ORDER BY id LIMIT 1 OFFSET COALESCE(f.event_index, 0)
                )
                {where}
                ORDER BY COALESCE(te.ts, s.updated_at) DESC
                LIMIT 5000
                """,
                params,
            ):
                ts_raw = row["trig_ts"] or row["session_updated"] or ""
                trig_kind = (row["trig_type"] or "").strip() or row["trig_hook"] or ""
                trig_detail = (row["trig_cmd"] or row["trig_path"] or row["trig_url"]
                              or row["trig_content"] or "")
                rows.append({
                    "id": (row["finding_id"] or "")[:20],
                    "sessionId": row["session_id"] or "",
                    "title": row["title"] or "Unknown",
                    "category": _CATEGORY_MAP.get(row["category"] or "", "dangerous_command"),
                    "severity": (row["severity"] or "low").lower(),
                    "evidence": (row["evidence"] or "")[:800],
                    "agent": row["agent"] or "unknown",
                    "ts": _relative_time_store(ts_raw) if ts_raw else "",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "_tsRaw": ts_raw,
                    "trigger": {
                        "kind": trig_kind,
                        "detail": (trig_detail or "")[:1200],
                    },
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
                ts_raw = row["ts"] or ""
                rows.append({
                    "ts": _relative_time_store(ts_raw) if ts_raw else "",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "_tsRaw": ts_raw,
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
    recommendations: Optional[Dict[str, str]] = None,
) -> None:
    """Record immunity CLI scoring results into the warden DB. Fail-open.

    ``recommendations`` maps ``spec.raw`` → safe version string so the
    dashboard can show "blocked X, suggested Y" instead of just "blocked X".
    """
    import uuid as _uuid
    recommendations = recommendations or {}
    try:
        db_path = initialize_database(workspace)
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()

            n_blocked = sum(1 for v in verdicts if v.verdict == "block")
            n_warned = sum(1 for v in verdicts if v.verdict == "warn")
            n_allowed = sum(1 for v in verdicts if v.verdict == "allow")
            n_findings = n_blocked + n_warned
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
                    json.dumps({
                        "ecosystem": ecosystem,
                        "installCmd": install_cmd,
                        "allowed": n_allowed,
                        "blocked": n_blocked,
                        "warned": n_warned,
                    }),
                ),
            )

            for v in verdicts:
                ioc_id = next(
                    (s.id[len("ioc_"):] for s in v.signals if s.id.startswith("ioc_")),
                    None,
                )
                recommended = recommendations.get(v.spec.raw, "") or ""
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
                            "recommended": recommended,
                        }),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO supply_chain_events (
                        ts, workspace_path, ecosystem, package_name, package_version,
                        install_cmd, verdict, score, signals_json, ioc_id,
                        recommended_version, session_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts, str(workspace), ecosystem,
                        v.spec.name,
                        getattr(v.spec, "version", None) or getattr(v.meta, "version", None) or "",
                        install_cmd,
                        v.verdict,
                        v.score,
                        json.dumps([
                            {"id": s.id, "points": s.points, "description": s.description}
                            for s in v.signals
                        ]),
                        ioc_id,
                        recommended,
                        session_id,
                    ),
                )

                if v.verdict in ("block", "warn"):
                    has_ioc = any(s.id.startswith("ioc_") for s in v.signals)
                    severity = "CRITICAL" if has_ioc else ("HIGH" if v.score >= 60 else "MEDIUM")
                    title = f"{v.verdict.upper()}: {v.spec.raw} [{ecosystem}] score {v.score}"
                    evidence_parts = ["; ".join(s.description for s in v.signals[:3])]
                    if recommended:
                        evidence_parts.append(f"Suggested safe version: {recommended}")
                    evidence_parts.append(f"Triggered by: {install_cmd}")
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
                            title,
                            " | ".join(evidence_parts),
                        ),
                    )

            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


_ADVISORY_RE = re.compile(r"(GHSA-[0-9a-z-]+|CVE-\d{4}-\d{4,}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)", re.IGNORECASE)


def _extract_advisory_ids(signals_json: str) -> List[str]:
    """Pull GHSA/CVE/MAL/PYSEC/RUSTSEC IDs out of a signals_json blob."""
    if not signals_json:
        return []
    ids: List[str] = []
    seen: set = set()
    try:
        for sig in json.loads(signals_json) or []:
            for match in _ADVISORY_RE.findall(str(sig.get("description", ""))):
                up = match.upper()
                if up not in seen:
                    seen.add(up)
                    ids.append(up)
    except Exception:
        pass
    return ids


def get_supply_chain_stats(hours: int = 24) -> Dict[str, Any]:
    """Aggregate supply chain enforcement data across all registered workspaces."""
    from collections import Counter

    workspaces = list_registered_workspaces()

    checked_24h = 0
    allowed_24h = 0
    blocked_24h = 0
    warned_24h = 0
    ecosystem_total: Counter = Counter()
    ecosystem_blocked: Counter = Counter()
    pkg_blocks: Counter = Counter()
    pkg_ecosystem: Dict[str, str] = {}
    pkg_ioc: Dict[str, str] = {}
    recent_rows: List[Dict[str, Any]] = []   # raw rows for later sort/format
    session_acc: Dict[str, Dict[str, Any]] = {}

    for ws in workspaces:
        db_path = get_db_path(ws)
        _migrate_sc_columns(db_path)
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
                elif v == "allow":
                    allowed_24h += row["cnt"]
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

            # Recent blocks + warnings with full enrichment.
            for row in conn.execute(
                """
                SELECT ts, package_name, package_version, ecosystem, score,
                       signals_json, verdict, install_cmd,
                       COALESCE(recommended_version, '') as recommended,
                       COALESCE(session_id, '') as session_id, ioc_id
                FROM supply_chain_events
                WHERE verdict IN ('block','warn')
                ORDER BY ts DESC
                LIMIT 60
                """
            ):
                try:
                    sigs = json.loads(row["signals_json"] or "[]")
                except Exception:
                    sigs = []
                # The "reason" is the highest-impact signal — the original
                # code just took sigs[0] which often was a low-weight
                # informational signal like "maintainer data unavailable".
                top_sig = max(sigs, key=lambda s: s.get("points", 0), default=None)
                recent_rows.append({
                    "tsRaw": row["ts"] or "",
                    "package": row["package_name"] or "",
                    "version": row["package_version"] or "",
                    "ecosystem": row["ecosystem"] or "",
                    "score": row["score"] or 0,
                    "verdict": row["verdict"] or "block",
                    "reason": (top_sig.get("description", "")[:120] if top_sig else ""),
                    "installCmd": row["install_cmd"] or "",
                    "recommended": row["recommended"] or "",
                    "advisoryIds": _extract_advisory_ids(row["signals_json"] or ""),
                    "iocId": row["ioc_id"] or "",
                    "sessionId": row["session_id"] or "",
                })

            # Per-session install activity in the 24h window.
            for row in conn.execute(
                """
                SELECT session_id,
                       ecosystem,
                       MAX(install_cmd) as install_cmd,
                       MIN(ts) as started,
                       MAX(ts) as last_seen,
                       SUM(CASE WHEN verdict='allow' THEN 1 ELSE 0 END) as allowed,
                       SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END) as blocked,
                       SUM(CASE WHEN verdict='warn'  THEN 1 ELSE 0 END) as warned,
                       COUNT(*) as total
                FROM supply_chain_events
                WHERE ts >= datetime('now', ?)
                  AND session_id IS NOT NULL AND session_id != ''
                GROUP BY session_id, install_cmd
                ORDER BY last_seen DESC
                LIMIT 25
                """,
                (f"-{hours} hours",),
            ):
                sid = row["session_id"] or "—"
                key = (sid, row["install_cmd"] or "")
                if key in session_acc:
                    continue
                session_acc[key] = {
                    "sessionId": sid,
                    "ecosystem": row["ecosystem"] or "",
                    "installCmd": row["install_cmd"] or "",
                    "allowed": row["allowed"] or 0,
                    "blocked": row["blocked"] or 0,
                    "warned": row["warned"] or 0,
                    "total": row["total"] or 0,
                    "lastSeen": _relative_time_store(row["last_seen"]) if row["last_seen"] else "",
                    "lastSeenAbs": _absolute_time_store(row["last_seen"] or ""),
                    "_tsRaw": row["last_seen"] or "",
                }
        except Exception:
            pass
        finally:
            conn.close()

    # Sort recent rows by raw ts (the old code sorted by relative-time string
    # which interleaved "12m ago" with "2h ago" arbitrarily) then format.
    recent_rows.sort(key=lambda r: r["tsRaw"], reverse=True)
    recent_blocks = [
        {
            "ts": _relative_time_store(r["tsRaw"]) if r["tsRaw"] else "",
            "tsAbs": _absolute_time_store(r["tsRaw"]),
            "package": r["package"],
            "version": r["version"],
            "ecosystem": r["ecosystem"],
            "score": r["score"],
            "verdict": r["verdict"],
            "reason": r["reason"],
            "installCmd": r["installCmd"],
            "recommended": r["recommended"],
            "advisoryIds": r["advisoryIds"],
            "iocId": r["iocId"],
            "sessionId": r["sessionId"],
        }
        for r in recent_rows[:30]
    ]

    by_session = sorted(
        session_acc.values(),
        key=lambda s: s.get("_tsRaw") or "",
        reverse=True,
    )[:15]
    for s in by_session:
        s.pop("_tsRaw", None)

    top_blocked = sorted(pkg_blocks, key=lambda k: pkg_blocks[k], reverse=True)[:10]

    return {
        "kpis": {
            "checkedPackages24h": checked_24h,
            "allowedPackages24h": allowed_24h,
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
        "installsBySession": by_session,
    }
