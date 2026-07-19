"""Local pause/resume for the Prismor runtime.

`prismor pause` suspends local screening and enforcement WITHOUT uninstalling
the hooks. The hook dispatcher short-circuits to "allow" for every tool call,
but keeps emitting a lightweight heartbeat so the control plane shows the
machine as *paused* — a deliberate, attributable, time-boxed state — rather
than letting it silently go idle, which is the failure mode of just deleting
the hooks (indistinguishable from a closed laptop).

State lives in a single JSON marker at ``~/.prismor/pause.json``, mirroring the
revocation-marker pattern in ``enterprise/identity.py``. A ``--for`` window
makes the pause self-expire (checked on the hot path in :func:`active_state`),
so protection heals itself even if ``prismor resume`` is never run.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_SCHEMA = "prismor.runtime.pause.v1"

# Don't upload a paused heartbeat more than once per this many seconds, so a
# burst of tool calls while paused doesn't hammer the control plane. Matches
# the ~30s policy-refresh debounce cadence.
_BEAT_DEBOUNCE_SECONDS = 30.0


def prismor_home() -> Path:
    """Return the Prismor home dir, honoring $PRISMOR_HOME (default ~/.prismor)."""
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


def pause_path() -> Path:
    return prismor_home() / "pause.json"


def parse_duration(text: str) -> int:
    """Parse a human duration into seconds: ``30m`` / ``2h`` / ``90s`` / ``1d``.
    A bare number is read as minutes. Raises ``ValueError`` on anything else."""
    s = (text or "").strip().lower()
    if not s:
        raise ValueError("empty duration")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] in units:
        value = float(s[:-1])  # raises ValueError on garbage like "abcm"
        return int(value * units[s[-1]])
    return int(float(s) * 60)  # bare number = minutes


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def set_paused(duration_seconds: Optional[int] = None, reason: str = "", by: str = "") -> Dict[str, Any]:
    """Write the pause marker. ``duration_seconds=None`` pauses indefinitely.
    Returns the record written."""
    now = _now()
    record: Dict[str, Any] = {
        "schema": _SCHEMA,
        "paused": True,
        "at": now,
        "until": (now + duration_seconds) if duration_seconds else None,
        "reason": (reason or "")[:300],
        "by": (by or "")[:120],
        "last_beat": 0.0,
    }
    home = prismor_home()
    home.mkdir(parents=True, exist_ok=True)
    path = pause_path()
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return record


def clear_paused() -> bool:
    """Remove the pause marker (resume). Returns True if one existed. Never raises."""
    path = pause_path()
    try:
        if path.exists():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def _read_raw() -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(pause_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data.get("paused") else None
    except (OSError, ValueError):
        return None


def active_state() -> Optional[Dict[str, Any]]:
    """The pause record if this machine is currently paused, else None.

    If a ``--for`` window has elapsed the marker is cleared (auto-resume) and
    None is returned, so the caller falls through to normal screening. Never
    raises."""
    rec = _read_raw()
    if rec is None:
        return None
    until = rec.get("until")
    if until is not None:
        try:
            if _now() >= float(until):
                clear_paused()
                return None
        except (TypeError, ValueError):
            pass
    return rec


def is_paused() -> bool:
    return active_state() is not None


def beat(agent: Optional[str] = None, state: Optional[Dict[str, Any]] = None) -> bool:
    """Emit a debounced "paused" heartbeat so the control plane keeps this
    device's ``lastSeenAt`` fresh and flags it as paused. No-op when not
    enrolled, inside the debounce window, or on any error. Returns True iff it
    uploaded a record."""
    rec = state or active_state()
    if rec is None:
        return False
    now = _now()
    try:
        last_beat = float(rec.get("last_beat") or 0)
    except (TypeError, ValueError):
        last_beat = 0.0
    if now - last_beat < _BEAT_DEBOUNCE_SECONDS:
        return False

    # Gate on enrollment before any network work — a personal (unenrolled)
    # machine reports nowhere, so there's nothing to heartbeat.
    try:
        from prismor.runtime.enterprise import identity as _identity
        if not _identity.is_enrolled():
            return False
    except Exception:
        return False

    until = rec.get("until")
    record = {
        "schema": "prismor.runtime.telemetry.v1",
        "event_id": "evt_" + uuid.uuid4().hex,
        "ts": _iso(now),
        "type": "paused_heartbeat",
        "verdict": "observed",
        "title": "Prismor paused locally",
        "agent": agent or None,
        "count": 1,
        "redacted": True,
        "detail": {
            "paused": True,
            "pausedAt": _iso(float(rec.get("at") or now)),
            "pausedUntil": _iso(float(until)) if until else None,
            "reason": rec.get("reason") or None,
        },
    }
    try:
        from prismor.runtime.sinks import upload_telemetry
        upload_telemetry([record])
    except Exception:
        return False

    # Note the beat so the next tool calls stay debounced. Best-effort: a write
    # failure just means we heartbeat again sooner, which is harmless.
    try:
        rec["last_beat"] = now
        path = pause_path()
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        path.chmod(0o600)
    except OSError:
        pass
    return True
