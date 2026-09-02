"""Adapter contract for reading an agent's on-disk session transcripts.

Prismor's detection engine is time-agnostic: `PolicyEngine.evaluate` takes an
event and returns findings, with no notion of whether that event arrived from a
live hook a millisecond ago or from a JSONL file written three weeks ago. Until
now the only thing that ever fed it was the hook dispatcher, so Prismor's
knowledge started the moment `install-hooks` ran.

Every supported agent already writes a complete record of what it did to disk.
An adapter's only job is to turn those records into the *same hook-shaped
payloads* the live dispatcher receives, so `hooks.normalize_payload` can produce
byte-identical events. Adapters deliberately do not build events themselves —
routing through the live normalizer is what guarantees replayed detection can
never drift from live detection.

Adding an agent is roughly forty lines: say where the files live, say which
files are yours, and yield one payload per tool call. See `adapters/claude.py`
for the reference implementation.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any, ClassVar, Dict, Iterator, List, Optional, Protocol, Tuple,
    runtime_checkable,
)


@dataclass
class DiscoveredSession:
    """One transcript file found on disk, before it has been parsed."""

    agent: str
    path: Path
    session_id: str
    #: Epoch seconds of the file's last write. Used for `--since` filtering
    #: before any parsing happens, so a 90-day sweep never opens a file it is
    #: going to discard.
    mtime: float
    #: Set when the adapter could name the workspace the session ran in.
    workspace: Optional[Path] = None

    @property
    def size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0


#: Fields that discriminate a record's kind across the supported transcript
#: formats. Their VALUES are schema tags ("assistant", "summary",
#: "function_call"), not user content, so they are safe to report.
_SHAPE_KEYS = ("type", "role", "kind", "event")

#: Longest discriminator value echoed back. Guards against a value that is
#: really content sneaking into a report.
_SHAPE_VALUE_MAX = 40


def record_shape(record: Dict[str, Any]) -> str:
    """A short, content-free description of why a record could be unrecognised.

    Reported back to the user so a silent transcript can be triaged without
    anyone handing over the transcript itself (issue #346). Emits a
    discriminator such as ``type=summary`` when the record has one, else the
    sorted top-level field names, which is what an adapter would have keyed on.
    """
    for key in _SHAPE_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value:
            if len(value) > _SHAPE_VALUE_MAX:
                return f"{key}=<{len(value)} chars>"
            return f"{key}={value}"
    keys = sorted(k for k in record.keys() if isinstance(k, str))[:6]
    return f"keys={','.join(keys)}" if keys else "empty-record"


@dataclass
class ParseStats:
    """Per-file parse accounting, surfaced so a silent adapter is detectable.

    An adapter that yields zero payloads for a non-empty file is the failure
    mode that matters most here: the sweep looks like it worked and quietly
    protects nothing. `--strict` turns that into a non-zero exit.
    """

    records_read: int = 0
    payloads_emitted: int = 0
    malformed_lines: int = 0
    skipped_records: int = 0
    errors: List[str] = field(default_factory=list)
    #: Record shape -> how many records of that shape emitted nothing. A bare
    #: count told a user their transcripts were silent but not *what* about
    #: them did not match, which is untriageable without handing over personal
    #: transcripts (issue #346). Keys are schema only -- a discriminator value
    #: like `type=summary` and top-level field NAMES -- never field values.
    skip_reasons: Dict[str, int] = field(default_factory=dict)

    #: Bound on distinct shapes tracked per file; the rest fold into `other`.
    MAX_SKIP_REASONS: ClassVar[int] = 12

    def note_skip(self, reason: str) -> None:
        self.skipped_records += 1
        if reason not in self.skip_reasons and len(self.skip_reasons) >= self.MAX_SKIP_REASONS:
            reason = "other"
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def merge(self, other: "ParseStats") -> None:
        self.records_read += other.records_read
        self.payloads_emitted += other.payloads_emitted
        self.malformed_lines += other.malformed_lines
        self.skipped_records += other.skipped_records
        self.errors.extend(other.errors)
        for reason, count in other.skip_reasons.items():
            if reason not in self.skip_reasons and len(self.skip_reasons) >= self.MAX_SKIP_REASONS:
                reason = "other"
            self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + count

    @property
    def looks_silent(self) -> bool:
        return self.records_read > 0 and self.payloads_emitted == 0

    @property
    def top_skip_reasons(self) -> List[Tuple[str, int]]:
        """Skip shapes, most common first."""
        return sorted(self.skip_reasons.items(), key=lambda kv: (-kv[1], kv[0]))


@runtime_checkable
class TranscriptAdapter(Protocol):
    """Reads one agent's transcripts and yields hook-shaped payloads.

    Implementations must be side-effect free: a sweep reads history and must
    never write to the agent's own state, mutate config, or perform network I/O.
    """

    #: Agent key. Must match the name `hooks.normalize_payload` dispatches on,
    #: because the driver hands payloads straight to it.
    agent: str

    #: Human-readable name for reports.
    label: str

    def roots(self) -> List[Path]:
        """Directories that may contain this agent's transcripts.

        Non-existent paths are fine — the driver filters them. Honor the
        agent's own home-override environment variable here.
        """
        ...

    def discover(self) -> Iterator[DiscoveredSession]:
        """Yield every transcript file belonging to this agent."""
        ...

    def payloads(self, session: DiscoveredSession) -> Iterator[Dict[str, Any]]:
        """Yield hook-shaped payloads, oldest first.

        Each payload must carry at minimum a `hook_event_name` naming a
        *pre-action* event (`PreToolUse`, `UserPromptSubmit`, …). `should_block`
        early-returns on anything else via `_is_pre_action`, so a payload
        labelled with a post-action name silently reports zero would-blocks.
        """
        ...


class JsonlAdapter:
    """Base for the common case: line-delimited JSON, one record per line.

    Every agent verified so far writes JSONL with a discriminated record type
    and the tool call nested somewhere inside. Subclasses supply `roots`, a
    file glob, and a `record_to_payloads` mapping; this class handles walking,
    decoding, malformed-line tolerance, and stats.
    """

    agent: str = ""
    label: str = ""
    #: Glob applied beneath each root.
    pattern: str = "**/*.jsonl"

    # -- discovery -------------------------------------------------------

    def roots(self) -> List[Path]:  # pragma: no cover - overridden
        raise NotImplementedError

    def session_id_for(self, path: Path) -> str:
        """Stable id for a transcript file.

        Defaults to the filename stem, which every verified agent uses as its
        session identifier. Overriding matters only when the id lives inside
        the file. The id is the store's primary key, and
        `save_session_snapshot` is INSERT-OR-REPLACE keyed on it, so a stable
        id is exactly what makes re-running a sweep idempotent.
        """
        return path.stem

    def workspace_for(self, path: Path) -> Optional[Path]:
        return None

    def discover(self) -> Iterator[DiscoveredSession]:
        seen: set = set()
        for root in self.roots():
            if not root.exists() or not root.is_dir():
                continue
            for candidate in sorted(root.glob(self.pattern)):
                if not candidate.is_file():
                    continue
                try:
                    resolved = candidate.resolve()
                except OSError:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    mtime = candidate.stat().st_mtime
                except OSError:
                    continue
                yield DiscoveredSession(
                    agent=self.agent,
                    path=candidate,
                    session_id=self.session_id_for(candidate),
                    mtime=mtime,
                    workspace=self.workspace_for(candidate),
                )

    # -- parsing ---------------------------------------------------------

    def record_to_payloads(
        self, record: Dict[str, Any], session: DiscoveredSession
    ) -> Iterator[Dict[str, Any]]:  # pragma: no cover - overridden
        raise NotImplementedError

    def iter_records(self, session: DiscoveredSession, stats: ParseStats) -> Iterator[Dict[str, Any]]:
        """Stream decoded records, tolerating malformed lines.

        Transcript formats are undocumented and drift between agent releases.
        A single bad line must never abort a 101 MB sweep, so decode failures
        are counted rather than raised; `--strict` inspects the count.
        """
        try:
            handle = session.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            stats.errors.append(f"{session.path}: {exc}")
            return
        with handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    stats.malformed_lines += 1
                    continue
                if not isinstance(record, dict):
                    stats.malformed_lines += 1
                    continue
                stats.records_read += 1
                yield record

    def payloads(self, session: DiscoveredSession) -> Iterator[Dict[str, Any]]:
        stats = ParseStats()
        for payload in self.payloads_with_stats(session, stats):
            yield payload

    def payloads_with_stats(
        self, session: DiscoveredSession, stats: ParseStats
    ) -> Iterator[Dict[str, Any]]:
        for record in self.iter_records(session, stats):
            try:
                emitted = list(self.record_to_payloads(record, session))
            except Exception as exc:  # defensive: never let one record kill a sweep
                stats.errors.append(f"{session.path}: {type(exc).__name__}: {exc}")
                continue
            if not emitted:
                stats.note_skip(record_shape(record))
                continue
            for payload in emitted:
                stats.payloads_emitted += 1
                yield payload


def home() -> Path:
    return Path(os.path.expanduser("~"))


def env_root(var: str, default: Path) -> Path:
    """Resolve an agent's home-override env var, falling back to `default`."""
    raw = os.environ.get(var)
    if not raw:
        return default
    return Path(os.path.expanduser(raw))
