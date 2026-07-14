"""Tool-combination governance — customizable tags + forbidden combinations.

The generalized "lethal trifecta": tools carry one or more customizable **tags**,
and an org declares **incompatible** tag sets that must not co-occur within a
single session. The tool call that *completes* a forbidden combination is blocked
before it executes, from the session's prior tool-use history.

Red/blue is just the default instance: two tags ``untrusted_content`` (reads
attacker-influenceable input) and ``critical_action`` (sends / publishes /
destroys externally), with one incompatible set ``[untrusted_content,
critical_action]``. Orgs can define any tags and any N-tag combinations (e.g. a
three-condition ``[untrusted_content, private_data, external_comms]``).

This module owns the swappable *detection* (tagging + per-session ledger);
``policy_engine`` owns *enforcement* (emitting the finding). Detection can be
swapped (strict combination now, risk scoring later) without touching
enforcement.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Default tag vocabulary (the red/blue pair, in PDF language).
UNTRUSTED = "untrusted_content"
CRITICAL = "critical_action"

# ── Built-in default tagging ──────────────────────────────────────────────────
# (matcher, match_type, [tags]). Kept in sync with the enterprise premium catalog
# so the capability degrades safely to these defaults when no signed catalog /
# org override is present. Every matching entry's tags are unioned.
TOOL_TAG_DEFAULTS = [
    # untrusted-content ingest
    ("WebFetch", "exact", [UNTRUSTED]),
    ("WebSearch", "exact", [UNTRUSTED]),
    ("mcp__*__read_email", "glob", [UNTRUSTED]),
    ("mcp__*__list_emails", "glob", [UNTRUSTED]),
    ("mcp__*__read_calendar", "glob", [UNTRUSTED]),
    ("mcp__*__get_issue", "glob", [UNTRUSTED]),
    ("mcp__*__read_channel", "glob", [UNTRUSTED]),
    ("mcp__*__read_document", "glob", [UNTRUSTED]),
    ("mcp__*__*fetch*", "glob", [UNTRUSTED]),
    ("mcp__*__*scrape*", "glob", [UNTRUSTED]),
    # critical action
    ("mcp__*__send_email", "glob", [CRITICAL]),
    ("mcp__*__post_message", "glob", [CRITICAL]),
    ("mcp__*__create_pull_request", "glob", [CRITICAL]),
    ("mcp__*__upload_file", "glob", [CRITICAL]),
    ("mcp__*__execute_sql", "glob", [CRITICAL]),
    ("mcp__*__*delete*", "glob", [CRITICAL]),
    ("mcp__*__*create*", "glob", [CRITICAL]),
]

# Default incompatible set when the policy declares none (the red/blue rule).
DEFAULT_INCOMPATIBLE = [[UNTRUSTED, CRITICAL]]

# Inference fallback: event types → an implied tag.
_UNTRUSTED_EVENT_TYPES = {"tool_result", "memory", "subagent_spawn", "file_read"}
_CRITICAL_EVENT_TYPES = {"file_write", "shell"}
_CRITICAL_FINDING_CATEGORIES = {
    "destructive_command",
    "secret_exfiltration",
    "db_modification",
    "remote_execution",
}


def _as_list(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return []


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
    # A bare mapping entry with no explicit type: treat as glob if it has wildcard
    # metacharacters, else exact.
    if any(c in matcher for c in "*?["):
        return fnmatch.fnmatchcase(tool_name, matcher)
    return tool_name == matcher


def _tool_name(event: Dict[str, Any]) -> str:
    meta = event.get("metadata") or {}
    return str(meta.get("tool_name") or event.get("tool_name") or "")


def normalize_incompatible(raw: Any) -> List[Set[str]]:
    """Coerce the policy's ``incompatible`` list into a list of tag sets.
    Falls back to the default red/blue pair when unset/empty."""
    out: List[Set[str]] = []
    if isinstance(raw, (list, tuple)):
        for item in raw:
            tags = {str(t) for t in _as_list(item)}
            if len(tags) >= 2:  # a single-tag "set" can never be a combination
                out.append(tags)
    if not out:
        out = [set(s) for s in DEFAULT_INCOMPATIBLE]
    return out


def classify_tool_tags(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tt_settings: Optional[Dict[str, Any]] = None,
) -> Set[str]:
    """Return the set of tags for a tool call.

    Resolution: explicit org map → built-in defaults → event/finding inference.
    Each tier unions all matching entries; the first non-empty tier wins.
    """
    tt = tt_settings or {}
    tool_name = _tool_name(event)
    tags: Set[str] = set()

    # 1. Explicit org/catalog map: {tool_or_glob: tag | [tags]}.
    mapping = tt.get("tags") or {}
    if isinstance(mapping, dict):
        if tool_name in mapping:
            tags |= set(_as_list(mapping[tool_name]))
        for pat, val in mapping.items():
            if pat != tool_name and _matches(tool_name, pat, "auto"):
                tags |= set(_as_list(val))
    if tags:
        return tags

    # 2. Built-in defaults.
    if tt.get("defaults_enabled", True):
        for matcher, match_type, deftags in TOOL_TAG_DEFAULTS:
            if _matches(tool_name, matcher, match_type):
                tags |= set(deftags)
        if tags:
            return tags

    # 3. Inference (best-effort fallback).
    if tt.get("inference_enabled", True):
        fcats = finding_categories or set()
        if fcats & _CRITICAL_FINDING_CATEGORIES:
            tags.add(CRITICAL)
        if event_type == "network":
            tags.add(UNTRUSTED if event.get("response") else CRITICAL)
        elif event_type in _CRITICAL_EVENT_TYPES:
            tags.add(CRITICAL)
        elif event_type in _UNTRUSTED_EVENT_TYPES:
            tags.add(UNTRUSTED)

    return tags


class TagLedger:
    """Per-session record of which tags a session has used and the tool that
    first introduced each. Persisted across hook invocations (each hook call is a
    separate process) as JSON under the central data dir, like ``_TaintStore``.
    """

    def __init__(self, workspace: Path, session_id: str) -> None:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
        from prismor.runtime.store import get_data_dir

        self._path = get_data_dir(workspace) / "trifecta" / f"{safe}.json"
        # tag -> {"index": int, "tool": str}  (first call that introduced the tag)
        self.seen: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            s = data.get("seen")
            if isinstance(s, dict):
                self.seen = s
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({"seen": self.seen}, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def completes(
        self, new_tags: Set[str], incompatible: List[Set[str]], current_index: int = 1 << 62
    ) -> Optional[Dict[str, Any]]:
        """If this call's ``new_tags`` complete a forbidden set that the session
        had not yet fully covered by PRIOR calls, return details of the completed
        combination; else None. The completing call is the one to block.

        Only tags introduced at an index < ``current_index`` count as prior. This
        is deliberate: the caller may re-record the current event (an idempotent
        pre-pass over session history runs before the authoritative decision), so
        the current call's own tag can already be in ``seen`` at ``current_index``
        — it must still be treated as "new", not "already seen"."""
        seen_tags = {
            t for t, info in self.seen.items()
            if isinstance(info, dict) and info.get("index", -1) < current_index
        }
        union = seen_tags | set(new_tags)
        best: Optional[Dict[str, Any]] = None
        for forbidden in incompatible:
            if forbidden <= union and not (forbidden <= seen_tags) and (forbidden & new_tags):
                introduced = {t: self.seen[t] for t in forbidden if t in seen_tags}
                cand = {
                    "set": sorted(forbidden),
                    "this_call_tags": sorted(forbidden & set(new_tags)),
                    "introduced_by": introduced,
                }
                # Prefer the largest completed set for the clearest message.
                if best is None or len(cand["set"]) > len(best["set"]):
                    best = cand
        return best

    def record(self, new_tags: Set[str], index: int, tool: str) -> None:
        changed = False
        for tag in new_tags:
            if tag not in self.seen:
                self.seen[tag] = {"index": index, "tool": tool}
                changed = True
        if changed:
            self._save()
