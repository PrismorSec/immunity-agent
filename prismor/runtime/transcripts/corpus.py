"""Export replayed events as a labelled rule-testing corpus.

Rules are currently exercised against hand-written cases, which say what an
author imagined an agent would do. History says what agents actually did. This
turns a sweep into fixtures: events that fired a rule become positives for that
rule, events that fired nothing become negatives.

**Redaction is mandatory here.** Every other consumer of replayed events reaches
the store through `save_session_snapshot`, which runs `_recloak_event` on the
way in. This path writes files directly, so it inherits none of that and must
scrub explicitly — a corpus is exactly the kind of artifact that ends up
committed to a repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.transcripts.driver import SweepResult

#: Keys whose values are scrubbed of home-directory paths and secret-shaped
#: tokens before being written.
_TEXT_KEYS = (
    "command",
    "path",
    "url",
    "content",
    "prompt",
    "response",
    "stdout",
    "stderr",
)

_HOME_RE = re.compile(re.escape(os.path.expanduser("~")))


@dataclass
class CorpusStats:
    positives: int = 0
    negatives: int = 0
    rules: Dict[str, int] = field(default_factory=dict)
    output_dir: Optional[Path] = None


def _secret_pattern():
    from prismor.runtime.cli import _SECRET_PATTERNS

    return _SECRET_PATTERNS


def redact_text(text: str) -> str:
    if not text:
        return text
    scrubbed = _HOME_RE.sub("~", str(text))
    return _secret_pattern().sub("<REDACTED-SECRET>", scrubbed)


def redact_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Scrub an event for durable, shareable storage.

    Three layers, because each catches what the others miss: enrolled cloaking
    secrets by exact value, home-directory paths (which leak the operator's
    username), and generic secret-shaped tokens by pattern.
    """
    from prismor.runtime.store import _recloak_event

    try:
        cleaned = _recloak_event(dict(event))
    except Exception:
        cleaned = dict(event)

    return _scrub(cleaned)


#: Dropped rather than redacted. `raw` is the verbatim upstream payload — it
#: duplicates every normalized field and is the likeliest place for an
#: unscrubbed copy of a secret to survive a targeted pass.
_DROP_KEYS = frozenset({"raw", "memory_files"})

#: Structural values that must survive verbatim for a fixture to be usable.
_STRUCTURAL_KEYS = frozenset({"type", "agent", "agent_event", "ts", "session_id"})


def _scrub(value: Any, key: str = "") -> Any:
    """Recursively redact every string reachable from an event.

    An earlier version scrubbed only a fixed list of top-level text keys, which
    missed `metadata.cwd` — a field that contains the operator's home directory
    on essentially every event. Walking the whole structure means a newly added
    field is redacted by default rather than leaking until someone notices.
    """
    if isinstance(value, dict):
        return {
            k: _scrub(v, k) for k, v in value.items() if k not in _DROP_KEYS
        }
    if isinstance(value, list):
        return [_scrub(item, key) for item in value]
    if isinstance(value, str) and key not in _STRUCTURAL_KEYS:
        return redact_text(value)
    return value


def _fixture_name(event: Dict[str, Any]) -> str:
    blob = json.dumps(event, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def export_corpus(
    result: SweepResult,
    output_dir: Path,
    *,
    negatives_per_rule: int = 3,
    max_per_rule: int = 50,
) -> CorpusStats:
    """Write ``<out>/<ruleId>/positive/*.json`` and ``<out>/_negative/*.json``.

    Positives are deduplicated by content hash, so a command an agent ran fifty
    times contributes one fixture rather than fifty near-identical ones.
    """
    stats = CorpusStats(output_dir=output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    seen: set = set()
    negatives_written = 0
    negative_budget = max(0, negatives_per_rule) * max(1, len(result.sessions))

    for session in result.sessions:
        blocked = {b.get("eventIndex") for b in session.would_block}
        by_index: Dict[int, List[Dict[str, Any]]] = {}
        for finding in session.findings:
            index = finding.get("eventIndex")
            if isinstance(index, int):
                by_index.setdefault(index, []).append(finding)

        for index, findings in by_index.items():
            for finding in findings:
                rule = str(finding.get("ruleId") or "unknown")
                if stats.rules.get(rule, 0) >= max_per_rule:
                    continue
                event = (
                    session.events[index]
                    if 0 <= index < len(session.events)
                    else None
                )
                record = {
                    "ruleId": rule,
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "wouldBlock": index in blocked,
                    "agent": session.agent,
                    "evidence": redact_text(str(finding.get("evidence") or ""))[:2000],
                    "event": redact_event(event) if isinstance(event, dict) else None,
                }
                digest = _fixture_name(record)
                if digest in seen:
                    continue
                seen.add(digest)
                target = output_dir / rule / "positive"
                target.mkdir(parents=True, exist_ok=True)
                (target / f"{digest}.json").write_text(
                    json.dumps(record, indent=2, default=str), encoding="utf-8"
                )
                stats.positives += 1
                stats.rules[rule] = stats.rules.get(rule, 0) + 1

        if negatives_written >= negative_budget:
            continue
        for index, event in enumerate(session.clean_events or []):
            if negatives_written >= negative_budget:
                break
            record = {
                "ruleId": None,
                "expect": "no-finding",
                "agent": session.agent,
                "event": redact_event(event),
            }
            digest = _fixture_name(record)
            if digest in seen:
                continue
            seen.add(digest)
            target = output_dir / "_negative"
            target.mkdir(parents=True, exist_ok=True)
            (target / f"{digest}.json").write_text(
                json.dumps(record, indent=2, default=str), encoding="utf-8"
            )
            stats.negatives += 1
            negatives_written += 1

    return stats


def format_corpus(stats: CorpusStats) -> str:
    lines = ["", "Corpus export", ""]
    lines.append(f"  {stats.positives:>5}  positive fixtures across {len(stats.rules)} rules")
    lines.append(f"  {stats.negatives:>5}  negative fixtures")
    lines.append(f"  ->    {stats.output_dir}")
    lines.append("")
    if stats.rules:
        lines.append("  Top rules by fixture count")
        for rule, count in sorted(stats.rules.items(), key=lambda kv: -kv[1])[:10]:
            lines.append(f"    {rule:<34} {count:>4}")
        lines.append("")
    lines.append(
        "  Events are scrubbed of enrolled secrets, home paths, and\n"
        "  secret-shaped tokens. Review before committing anywhere public."
    )
    lines.append("")
    return "\n".join(lines)
