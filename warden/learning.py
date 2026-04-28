"""Tier 3 — Session-Based Learning for Warden.

Mines historical session data to propose new detection rules, track false
positives, and detect evasion attempts where structurally similar commands
bypass existing rules.

Usage:
    warden learn                 # propose new rules from session history
    warden learn --apply ID      # accept a candidate rule into project policy
"""
from __future__ import annotations

import json
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from warden.store import get_db_path, initialize_database


# ── Schema migration ───────────────────────────────────────────────────────

_LEARNING_DDL = """
CREATE TABLE IF NOT EXISTS dismissals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    evidence TEXT,
    dismissed_at TEXT NOT NULL,
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_dismissals_rule ON dismissals(rule_id);

CREATE TABLE IF NOT EXISTS candidate_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposed_at TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    rule_json TEXT NOT NULL,
    source TEXT,
    confidence REAL DEFAULT 0.5,
    support_count INTEGER DEFAULT 1,
    sample_evidence TEXT
);

CREATE TABLE IF NOT EXISTS evasion_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    blocked_rule_id TEXT NOT NULL,
    blocked_command TEXT,
    evading_command TEXT,
    similarity_score REAL,
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evasion_session ON evasion_attempts(session_id);
"""


def initialize_learning_tables(connection: sqlite3.Connection) -> None:
    """Add learning tables to an existing warden.db connection."""
    connection.executescript(_LEARNING_DDL)


# ── Command normalization ──────────────────────────────────────────────────

# Patterns for shell substitution forms
_SUBST_BACKTICK = re.compile(r"`[^`]*`")
_SUBST_DOLLAR = re.compile(r"\$\([^)]*\)")
_SUBST_BRACE = re.compile(r"\$\{[^}]*\}")
_WHITESPACE = re.compile(r"\s+")
_SHELL_SPLIT = re.compile(r"\s*(?:;|&&|\|\||[|])\s*")


def normalize_command_structure(command: str) -> str:
    """Normalize a shell command for structural comparison.

    Strips quoting, replaces substitutions with a placeholder, collapses
    whitespace, and sorts arguments within each pipeline stage.
    """
    s = command.strip()

    # Replace all substitution forms with a placeholder
    s = _SUBST_BACKTICK.sub("__SUBST__", s)
    s = _SUBST_DOLLAR.sub("__SUBST__", s)
    s = _SUBST_BRACE.sub("__SUBST__", s)

    # Strip quotes
    s = s.replace('"', "").replace("'", "")

    # Collapse whitespace
    s = _WHITESPACE.sub(" ", s).strip()

    # Tokenize on shell metacharacters and normalize each segment
    segments = _SHELL_SPLIT.split(s)
    normalized_segments = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split()
        if not parts:
            continue
        # Keep the base command first, sort remaining args
        base = parts[0]
        args = sorted(parts[1:])
        normalized_segments.append(" ".join([base] + args))

    return " | ".join(normalized_segments)


def _tokenize(normalized: str) -> set:
    """Split a normalized command into a set of tokens."""
    return set(normalized.split())


def command_structural_similarity(cmd_a: str, cmd_b: str) -> float:
    """Compute Jaccard similarity between two commands after normalization.

    Returns a float between 0.0 (completely different) and 1.0 (identical).
    """
    norm_a = normalize_command_structure(cmd_a)
    norm_b = normalize_command_structure(cmd_b)

    tokens_a = _tokenize(norm_a)
    tokens_b = _tokenize(norm_b)

    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def _base_command(command: str) -> str:
    """Extract the first command name from a shell string."""
    normalized = normalize_command_structure(command)
    first_segment = normalized.split(" | ")[0] if " | " in normalized else normalized
    parts = first_segment.split()
    return parts[0] if parts else ""


# ── Dismissal tracking ─────────────────────────────────────────────────────

def record_dismissal(
    workspace: Path,
    session_id: str,
    rule_id: str,
    evidence: str,
    reason: str,
) -> None:
    """Record that a finding was dismissed or allowlisted."""
    db_path = initialize_database(workspace)
    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        conn.execute(
            "INSERT INTO dismissals (session_id, rule_id, evidence, dismissed_at, reason) VALUES (?, ?, ?, ?, ?)",
            (session_id, rule_id, evidence[:4000] if evidence else "",
             datetime.now(timezone.utc).isoformat(), reason),
        )
        conn.commit()
    finally:
        conn.close()


# ── Evasion detection ──────────────────────────────────────────────────────

_EVASION_THRESHOLD = 0.6


def detect_evasion(
    workspace: Path,
    session_id: str,
    event: Dict[str, Any],
    current_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Check if a passing shell command is structurally similar to a recently blocked one.

    Only runs when the event has no findings (it passed policy checks).
    Returns a list of HIGH-severity findings if evasion is detected.
    """
    if current_findings:
        return []

    command = event.get("command", "")
    if not command:
        return []

    base = _base_command(command)
    if not base:
        return []

    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)

        # Get recently blocked commands from this session
        rows = conn.execute(
            """
            SELECT e.command_text, f.finding_id, f.title, f.category
            FROM events e
            JOIN findings f ON e.session_id = f.session_id
            WHERE e.session_id = ?
              AND e.type = 'shell'
              AND e.command_text IS NOT NULL
              AND e.command_text != ''
            ORDER BY e.id DESC
            LIMIT 50
            """,
            (session_id,),
        ).fetchall()

        evasion_findings = []
        for blocked_cmd, finding_id, title, category in rows:
            if not blocked_cmd:
                continue

            # Must share the same base command
            if _base_command(blocked_cmd) != base:
                continue

            similarity = command_structural_similarity(command, blocked_cmd)
            if similarity >= _EVASION_THRESHOLD:
                # Record the evasion attempt
                conn.execute(
                    """
                    INSERT INTO evasion_attempts
                        (session_id, blocked_rule_id, blocked_command, evading_command, similarity_score, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (session_id, finding_id, blocked_cmd[:4000], command[:4000],
                     similarity, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()

                evasion_findings.append({
                    "id": f"{session_id}:evasion-{len(evasion_findings)}",
                    "severity": "HIGH",
                    "category": category or "evasion",
                    "title": f"Possible evasion of: {title}",
                    "evidence": f"Command '{command[:200]}' is {similarity:.0%} similar to blocked '{blocked_cmd[:200]}'",
                    "ruleId": "evasion-detection",
                    "action": "block",
                })
                break  # One match is enough

        return evasion_findings
    finally:
        conn.close()


# ── Pattern mining ─────────────────────────────────────────────────────────

# Sensitive command prefixes that warrant attention even without a rule match
_SENSITIVE_COMMANDS = {
    "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "rsync",
    "chmod", "chown", "chgrp", "sudo", "su", "doas",
    "docker", "podman", "kubectl",
    "pip", "pip3", "npm", "yarn", "gem", "cargo",
    "eval", "exec", "source",
}


def mine_patterns(workspace: Path, min_support: int = 3) -> List[Dict[str, Any]]:
    """Find recurring command patterns across sessions that have no rule coverage.

    Returns candidate rule dicts for commands that appear >= min_support times
    and involve sensitive operations.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        # Get all shell events that have no associated finding.
        # A finding's event_index corresponds to the event's position
        # within its session (0-based row number by id order).
        rows = conn.execute(
            """
            SELECT e.command_text, e.session_id
            FROM events e
            WHERE e.type = 'shell'
              AND e.command_text IS NOT NULL
              AND e.command_text != ''
              AND NOT EXISTS (
                  SELECT 1 FROM findings f
                  WHERE f.session_id = e.session_id
                    AND f.evidence LIKE '%' || SUBSTR(e.command_text, 1, 40) || '%'
              )
            """,
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return []

    # Group by normalized structure
    structure_groups: Dict[str, List[Tuple[str, str]]] = {}
    for cmd, sid in rows:
        norm = normalize_command_structure(cmd)
        structure_groups.setdefault(norm, []).append((cmd, sid))

    candidates = []
    for norm, entries in structure_groups.items():
        if len(entries) < min_support:
            continue

        base = _base_command(entries[0][0])
        if base not in _SENSITIVE_COMMANDS:
            continue

        # Build a candidate rule
        sample = entries[0][0]
        escaped = re.escape(base)
        candidate = {
            "id": f"learned-{base}-{len(candidates)}",
            "severity": "MEDIUM",
            "category": "learned_pattern",
            "title": f"Recurring uncovered pattern: {base} (seen {len(entries)} times)",
            "event_types": ["shell"],
            "fields": ["command"],
            "patterns": [f"(?:^|\\s|;|&|\\|){escaped}\\b"],
            "action": "warn",
            "enabled": True,
        }
        candidates.append({
            "rule": candidate,
            "source": "pattern_mining",
            "confidence": min(0.9, 0.3 + (len(entries) * 0.1)),
            "support_count": len(entries),
            "sample_evidence": sample[:500],
            "sessions": list({sid for _, sid in entries}),
        })

    return candidates


# ── False positive tracking ────────────────────────────────────────────────

def track_false_positives(workspace: Path, threshold: int = 5) -> List[Dict[str, Any]]:
    """Find rules that have been dismissed more than threshold times.

    Returns a list of dicts with rule_id, dismissal_count, and recommendation.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            """
            SELECT rule_id, COUNT(*) as cnt,
                   GROUP_CONCAT(DISTINCT reason) as reasons,
                   GROUP_CONCAT(evidence, '|||') as evidences
            FROM dismissals
            GROUP BY rule_id
            HAVING cnt >= ?
            ORDER BY cnt DESC
            """,
            (threshold,),
        ).fetchall()
    finally:
        conn.close()

    results = []
    for rule_id, count, reasons, evidences in rows:
        sample_evidence = (evidences or "").split("|||")[:3]
        results.append({
            "rule_id": rule_id,
            "dismissal_count": count,
            "reasons": reasons,
            "sample_evidence": sample_evidence,
            "recommendation": (
                f"Rule '{rule_id}' has been dismissed {count} times. "
                "Consider lowering severity or adding an allowlist entry."
            ),
        })

    return results


# ── Rule refinement proposals ──────────────────────────────────────────────

def propose_rule_refinements(workspace: Path) -> List[Dict[str, Any]]:
    """Analyze evasion attempts and propose broader regex patterns.

    For each evasion where similarity > threshold, suggest a pattern that
    catches both the original blocked command and the evading variant.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            """
            SELECT blocked_rule_id, blocked_command, evading_command, similarity_score
            FROM evasion_attempts
            WHERE similarity_score >= ?
            ORDER BY detected_at DESC
            LIMIT 100
            """,
            (_EVASION_THRESHOLD,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return []

    # Group by blocked_rule_id
    by_rule: Dict[str, List[Tuple[str, str, float]]] = {}
    for rule_id, blocked, evading, score in rows:
        by_rule.setdefault(rule_id, []).append((blocked, evading, score))

    refinements = []
    for rule_id, attempts in by_rule.items():
        # Find common structural elements between blocked and evading commands
        blocked_norms = {normalize_command_structure(b) for b, _, _ in attempts}
        evading_norms = {normalize_command_structure(e) for _, e, _ in attempts}

        all_tokens = set()
        for n in blocked_norms | evading_norms:
            all_tokens.update(_tokenize(n))

        # The base command is the anchor for the refined pattern
        base = _base_command(attempts[0][0])
        if not base:
            continue

        refinements.append({
            "rule_id": rule_id,
            "evasion_count": len(attempts),
            "avg_similarity": sum(s for _, _, s in attempts) / len(attempts),
            "suggestion": (
                f"Broaden patterns for rule '{rule_id}' to catch shell substitution "
                f"variants (backticks, $(), ${{}}) around '{base}'. "
                f"Seen {len(attempts)} evasion attempt(s)."
            ),
            "sample_blocked": attempts[0][0][:200],
            "sample_evading": attempts[0][1][:200],
        })

    return refinements


# ── Candidate rule persistence ─────────────────────────────────────────────

def save_candidate_rules(workspace: Path, candidates: List[Dict[str, Any]]) -> int:
    """Persist mined candidate rules to the database. Returns count saved."""
    if not candidates:
        return 0

    db_path = initialize_database(workspace)
    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for c in candidates:
            conn.execute(
                """
                INSERT INTO candidate_rules
                    (proposed_at, status, rule_json, source, confidence, support_count, sample_evidence)
                VALUES (?, 'pending', ?, ?, ?, ?, ?)
                """,
                (now, json.dumps(c["rule"]), c["source"],
                 c["confidence"], c["support_count"], c.get("sample_evidence", "")),
            )
            count += 1
        conn.commit()
        return count
    finally:
        conn.close()


def list_candidate_rules(workspace: Path, status: str = "pending") -> List[Dict[str, Any]]:
    """List candidate rules by status."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            """
            SELECT id, proposed_at, status, rule_json, source, confidence, support_count, sample_evidence
            FROM candidate_rules
            WHERE status = ?
            ORDER BY confidence DESC, support_count DESC
            """,
            (status,),
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row[0],
            "proposed_at": row[1],
            "status": row[2],
            "rule": json.loads(row[3]),
            "source": row[4],
            "confidence": row[5],
            "support_count": row[6],
            "sample_evidence": row[7],
        }
        for row in rows
    ]


def accept_candidate_rule(workspace: Path, candidate_id: int) -> Optional[Dict[str, Any]]:
    """Mark a candidate rule as accepted and return it for policy insertion."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return None

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        row = conn.execute(
            "SELECT rule_json FROM candidate_rules WHERE id = ? AND status = 'pending'",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE candidate_rules SET status = 'accepted' WHERE id = ?",
            (candidate_id,),
        )
        conn.commit()
        return json.loads(row[0])
    finally:
        conn.close()


def reject_candidate_rule(workspace: Path, candidate_id: int) -> bool:
    """Mark a candidate rule as rejected."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return False

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        cursor = conn.execute(
            "UPDATE candidate_rules SET status = 'rejected' WHERE id = ? AND status = 'pending'",
            (candidate_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ── Report formatting ──────────────────────────────────────────────────────

_BOLD = "\033[1m"
_NC = "\033[0m"
_CYAN = "\033[0;36m"
_YELLOW = "\033[1;33m"
_GREEN = "\033[0;32m"
_DIM = "\033[37m"


def format_learning_report(
    candidates: List[Dict[str, Any]],
    false_positives: List[Dict[str, Any]],
    refinements: List[Dict[str, Any]],
) -> str:
    """Format learning results for terminal display."""
    lines: List[str] = []

    lines.append(f"\n{_BOLD}Warden Learning Report{_NC}")
    lines.append("=" * 60)

    # Pattern mining results
    lines.append(f"\n{_CYAN}Pattern Mining — Candidate Rules{_NC}")
    if candidates:
        for c in candidates:
            rule = c["rule"]
            lines.append(
                f"  [{c.get('id', c['rule'].get('id', '?'))}] {rule['title']}"
            )
            lines.append(
                f"       Confidence: {c['confidence']:.0%}  |  "
                f"Support: {c['support_count']}  |  Source: {c['source']}"
            )
            if c.get("sample_evidence"):
                lines.append(f"       Sample: {c['sample_evidence'][:100]}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No new patterns found.{_NC}")
        lines.append("")

    # False positive tracking
    lines.append(f"{_YELLOW}False Positive Tracking{_NC}")
    if false_positives:
        for fp in false_positives:
            lines.append(f"  Rule: {fp['rule_id']}  |  Dismissed: {fp['dismissal_count']}x")
            lines.append(f"       {fp['recommendation']}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No false positive patterns detected.{_NC}")
        lines.append("")

    # Evasion refinements
    lines.append(f"{_CYAN}Evasion-Based Refinements{_NC}")
    if refinements:
        for r in refinements:
            lines.append(
                f"  Rule: {r['rule_id']}  |  "
                f"Evasions: {r['evasion_count']}  |  "
                f"Avg similarity: {r['avg_similarity']:.0%}"
            )
            lines.append(f"       {r['suggestion']}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No evasion patterns detected.{_NC}")
        lines.append("")

    # Summary
    total = len(candidates) + len(false_positives) + len(refinements)
    if total > 0:
        lines.append(f"{_GREEN}Total insights: {total}{_NC}")
        lines.append(f"Use {_BOLD}warden learn --apply ID{_NC} to accept a candidate rule.")
    else:
        lines.append(f"{_DIM}No actionable insights. Collect more session data.{_NC}")

    lines.append("")
    return "\n".join(lines)
