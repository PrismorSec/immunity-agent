from __future__ import annotations

import json
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
