"""Lethal-trifecta red/blue tool-category crossover primitive.

Tools split into two buckets:

  * red  — untrusted-content tools that ingest attacker-influenceable input
           (read_email, WebFetch, web search, externally-shared docs, PDFs of
           uncertain origin).
  * blue — critical-action tools that send / publish / destroy outside a sandbox
           (send_email, delete_records, PR creation, outbound HTTP, chat posts,
           file writes outside the workspace).

A session may make any number of same-category calls. The first call from the
*second* category, once a session has already used the first, is a dangerous
crossover: an untrusted red read can carry a prompt injection that drives a blue
action. ``PolicyEngine.evaluate`` consults this module to detect that crossover
from the session's prior tool-use history and block it before it executes.

This module owns the swappable *detection* (classification + per-session ledger);
``policy_engine`` owns *enforcement* (emitting the finding). Detection can later
be swapped (strict crossover → risk scoring) without touching enforcement.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, Optional

RED = "red"
BLUE = "blue"

# ── Built-in defaults ─────────────────────────────────────────────────────────
# (matcher, match_type, category). Kept in sync with the enterprise premium
# catalog (feed/tool-categories.json) so the capability degrades safely to these
# defaults when no signed catalog / org override is present. Order matters: the
# first matching entry wins, so exact names precede globs.
TOOL_CATEGORY_DEFAULTS = [
    # RED — untrusted content
    ("WebFetch", "exact", RED),
    ("WebSearch", "exact", RED),
    ("mcp__*__read_email", "glob", RED),
    ("mcp__*__list_emails", "glob", RED),
    ("mcp__*__read_calendar", "glob", RED),
    ("mcp__*__get_issue", "glob", RED),
    ("mcp__*__read_channel", "glob", RED),
    ("mcp__*__read_document", "glob", RED),
    ("mcp__*__*fetch*", "glob", RED),
    ("mcp__*__*scrape*", "glob", RED),
    # BLUE — critical action
    ("mcp__*__send_email", "glob", BLUE),
    ("mcp__*__post_message", "glob", BLUE),
    ("mcp__*__create_pull_request", "glob", BLUE),
    ("mcp__*__upload_file", "glob", BLUE),
    ("mcp__*__execute_sql", "glob", BLUE),
    ("mcp__*__*delete*", "glob", BLUE),
    ("mcp__*__*create*", "glob", BLUE),
]

# Event types that, absent an explicit/default match, imply a bucket. Used only
# when inference is enabled — a best-effort fallback so uncategorized tools are
# not silently uncovered.
_RED_EVENT_TYPES = {"tool_result", "memory", "subagent_spawn", "file_read"}
_BLUE_EVENT_TYPES = {"file_write", "shell"}
# Finding categories that unambiguously mark a critical (blue) action.
_BLUE_FINDING_CATEGORIES = {
    "destructive_command",
    "secret_exfiltration",
    "db_modification",
    "remote_execution",
}


def _matches(tool_name: str, matcher: str, match_type: str) -> bool:
    if not tool_name:
        return False
    if match_type == "exact":
        return tool_name == matcher
    if match_type == "glob":
        return fnmatch.fnmatchcase(tool_name, matcher)
    if match_type == "regex":
        import re
        try:
            return re.search(matcher, tool_name) is not None
        except re.error:
            return False
    return False


def _tool_name(event: Dict[str, Any]) -> str:
    meta = event.get("metadata") or {}
    return str(meta.get("tool_name") or event.get("tool_name") or "")


def classify_tool_category(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tc_settings: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Classify a tool call as 'red', 'blue', or None (neutral).

    Resolution order: explicit org map → built-in defaults → event-type/finding
    inference. Returns None when nothing applies (the call is ignored by the
    crossover check).
    """
    tc = tc_settings or {}
    tool_name = _tool_name(event)

    # 1. Explicit org/catalog map: {tool_or_glob: 'red'|'blue'}.
    mapping = tc.get("map") or {}
    if isinstance(mapping, dict):
        # exact first, then glob, for determinism
        if tool_name in mapping and mapping[tool_name] in (RED, BLUE):
            return mapping[tool_name]
        for pat, cat in mapping.items():
            if cat in (RED, BLUE) and _matches(tool_name, pat, "glob"):
                return cat

    # 2. Built-in defaults.
    if tc.get("defaults_enabled", True):
        for matcher, match_type, cat in TOOL_CATEGORY_DEFAULTS:
            if _matches(tool_name, matcher, match_type):
                return cat

    # 3. Inference (best-effort fallback).
    if tc.get("inference_enabled", True):
        fcats = finding_categories or set()
        if fcats & _BLUE_FINDING_CATEGORIES:
            return BLUE
        if event_type == "network":
            # A fetch that returns content is untrusted ingest (red); a bare
            # outbound call with no response is egress (blue).
            return RED if event.get("response") else BLUE
        if event_type in _BLUE_EVENT_TYPES:
            return BLUE
        if event_type in _RED_EVENT_TYPES:
            return RED

    return None


class CategoryLedger:
    """Per-session record of which trifecta categories a session has used.

    Persisted across hook invocations (each hook call is a separate process) as
    JSON under the central data dir, mirroring ``policy_engine._TaintStore``.
    """

    def __init__(self, workspace: Path, session_id: str) -> None:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
        from prismor.runtime.store import get_data_dir

        self._path = get_data_dir(workspace) / "trifecta" / f"{safe}.json"
        self.red: bool = False
        self.blue: bool = False
        self.first_red: Optional[Dict[str, Any]] = None
        self.first_blue: Optional[Dict[str, Any]] = None
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.red = bool(data.get("red", False))
            self.blue = bool(data.get("blue", False))
            self.first_red = data.get("first_red")
            self.first_blue = data.get("first_blue")
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(
                    {
                        "red": self.red,
                        "blue": self.blue,
                        "first_red": self.first_red,
                        "first_blue": self.first_blue,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    def crosses(self, category: str) -> Optional[Dict[str, Any]]:
        """If `category` is the OPPOSITE of one already seen this session, return
        the first-seen opposing entry (the crossover partner); else None."""
        if category == RED and self.blue:
            return self.first_blue
        if category == BLUE and self.red:
            return self.first_red
        return None

    def record(self, category: str, index: int, tool: str) -> None:
        entry = {"index": index, "tool": tool}
        if category == RED and not self.red:
            self.red = True
            self.first_red = entry
            self._save()
        elif category == BLUE and not self.blue:
            self.blue = True
            self.first_blue = entry
            self._save()
