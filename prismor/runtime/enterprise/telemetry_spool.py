"""Offline spool for control-plane telemetry — at-least-once upload.

The ``prismor`` sink (sinks.py) uploads telemetry records synchronously and
best-effort. When the control plane is unreachable (offline laptop, cold DB,
outage), records used to be dropped. Instead they are appended here — a JSONL
file at ``$PRISMOR_HOME/telemetry-spool.jsonl`` — and drained into the next
successful upload, so org observability survives outages without ever
blocking or retrying on the hot path.

Properties:

* **Bounded.** The spool keeps at most ``SPOOL_MAX_RECORDS`` records (oldest
  dropped first); a runaway outage can't grow an unbounded file.
* **Concurrent-safe.** Hook invocations from parallel agent processes
  serialize on an ``fcntl`` lock around every read-modify-write.
* **Privacy-preserving.** Records are spooled *after* the telemetry redaction
  boundary (prismor/runtime/telemetry.py), so the file never contains anything that
  wasn't already cleared to leave the machine.
* **Best-effort.** Every function swallows OSError — a broken spool degrades
  to the old drop-on-failure behavior, never to a blocked tool call.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List

from prismor.runtime.enterprise import identity as _identity

SPOOL_MAX_RECORDS = 1000
# Age cap (audit #20 / privacy F-7): spooled telemetry must not linger on a
# developer's laptop beyond the org's retention window. Records older than this
# are dropped on the next append/drain. Override via env; 0 disables.
try:
    SPOOL_MAX_AGE_DAYS = float(os.environ.get("PRISMOR_SPOOL_MAX_AGE_DAYS", "30") or 30)
except ValueError:
    SPOOL_MAX_AGE_DAYS = 30.0


def _fresh(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop records older than SPOOL_MAX_AGE_DAYS (by their ISO ``ts``)."""
    if SPOOL_MAX_AGE_DAYS <= 0:
        return records
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=SPOOL_MAX_AGE_DAYS)
    out: List[Dict[str, Any]] = []
    for r in records:
        ts = r.get("ts")
        try:
            t = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else None
        except ValueError:
            t = None
        if t is None or t >= cutoff:
            out.append(r)
    return out


def spool_path() -> Path:
    return _identity.prismor_home() / "telemetry-spool.jsonl"


@contextmanager
def _locked(path: Path) -> Iterator[Any]:
    """Hold an exclusive advisory lock on ``<spool>.lock`` for a read-modify-write.

    Via the one guarded implementation: a bare ``import fcntl`` here raised
    ImportError on Windows, where the module does not exist.
    """
    from prismor.runtime.store import file_lock
    with file_lock(path):
        yield None


def _read_records(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
    except OSError:
        return []
    return records


def _write_records(path: Path, records: List[Dict[str, Any]]) -> None:
    if not records:
        try:
            path.unlink()
        except OSError:
            pass
        return
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    os.replace(tmp, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def append(records: List[Dict[str, Any]]) -> None:
    """Spool records for a later upload, keeping at most SPOOL_MAX_RECORDS
    (oldest dropped first). Never raises."""
    if not records:
        return
    path = spool_path()
    try:
        with _locked(path):
            existing = _read_records(path)
            merged = _fresh(existing + records)[-SPOOL_MAX_RECORDS:]
            _write_records(path, merged)
    except OSError:
        pass


def drain(limit: int) -> List[Dict[str, Any]]:
    """Remove and return up to ``limit`` of the oldest spooled records.

    Callers must re-``append`` them if the upload fails. Never raises.
    """
    if limit <= 0:
        return []
    path = spool_path()
    if not path.exists():
        return []
    try:
        with _locked(path):
            records = _fresh(_read_records(path))
            if not records:
                _write_records(path, [])
                return []
            taken, rest = records[:limit], records[limit:]
            _write_records(path, rest)
            return taken
    except OSError:
        return []


def pending_count() -> int:
    """Number of records waiting in the spool (for status display). Never raises."""
    path = spool_path()
    if not path.exists():
        return 0
    return len(_read_records(path))
