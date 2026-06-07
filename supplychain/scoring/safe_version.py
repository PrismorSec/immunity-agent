"""Recommend a known-safe stable version when an install is blocked.

Strategy: enumerate stable releases from the registry, drop pre-releases
and anything younger than ``MIN_AGE_DAYS`` (so freshly-pushed bad
versions never get recommended), then batch-query OSV to find the
newest version with zero known vulnerabilities.

Designed for agentic use — the recommendation has to be a version the
agent can actually pin without a human babysitting it. We pick *stable
and proven*, not *latest*.

Fails closed-ish: returns None when we can't confidently identify a
clean version. Callers should treat that as "no recommendation" rather
than "any version is fine".
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from supplychain.scoring.osv_lookup import batch_has_vulns

MIN_AGE_DAYS = 14
MAX_CANDIDATES = 15
_TIMEOUT = 4


@dataclass
class SafeVersion:
    version: str
    age_days: int
    reason: str  # short human-readable rationale


# ── Version-string helpers ───────────────────────────────────────────────────

_STABLE_RE = re.compile(r"^\d+(?:\.\d+)*$")


def _is_stable(version: str) -> bool:
    """A stable version is digits-and-dots only (no a/b/rc/dev/+local)."""
    return bool(_STABLE_RE.match(version))


def _version_key(version: str) -> Tuple[int, ...]:
    """Tuple form for comparison; non-numeric segments collapse to 0."""
    parts: List[int] = []
    for seg in version.split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _age_days(date_str: str) -> Optional[int]:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


# ── Registry version listings ────────────────────────────────────────────────

def _http_get(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "immunity-agent/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _list_npm_versions(name: str) -> Dict[str, Optional[int]]:
    """Return {version: age_days_or_None} for an npm package."""
    encoded = name.replace("/", "%2F")
    data = _http_get(f"https://registry.npmjs.org/{encoded}")
    if not data:
        return {}
    times = data.get("time") or {}
    out: Dict[str, Optional[int]] = {}
    for version in (data.get("versions") or {}):
        out[version] = _age_days(times.get(version, ""))
    return out


def _list_pypi_versions(name: str) -> Dict[str, Optional[int]]:
    """Return {version: age_days_or_None} for a PyPI package.

    Skips releases with no files (yanked-only) and uses the earliest
    upload time across files in a release as that release's age.
    """
    data = _http_get(f"https://pypi.org/pypi/{name}/json")
    if not data:
        return {}
    out: Dict[str, Optional[int]] = {}
    for version, files in (data.get("releases") or {}).items():
        if not files:
            continue
        # Skip if every file is yanked.
        if all(f.get("yanked") for f in files):
            continue
        uploads = [
            f.get("upload_time_iso_8601") or f.get("upload_time")
            for f in files
        ]
        uploads = [u for u in uploads if u]
        age = _age_days(min(uploads)) if uploads else None
        out[version] = age
    return out


_NPM_ECOSYSTEMS = {"npm", "pnpm", "yarn", "bun"}
_PYPI_ECOSYSTEMS = {"pip", "uv"}


def _list_versions(name: str, ecosystem: str) -> Dict[str, Optional[int]]:
    """Dispatch to the right registry lister at call time.

    Resolving the lister per call (rather than via a module-level dict)
    keeps the indirection mockable — tests can patch
    ``_list_npm_versions`` directly.
    """
    if ecosystem in _NPM_ECOSYSTEMS:
        return _list_npm_versions(name)
    if ecosystem in _PYPI_ECOSYSTEMS:
        return _list_pypi_versions(name)
    return {}


# ── Recommendation ──────────────────────────────────────────────────────────

def recommend_safe_version(
    name: str,
    ecosystem: str,
    exclude_version: str = "",
) -> Optional[SafeVersion]:
    """Find the newest stable version with no known OSV vulnerabilities.

    Returns None when:
      - the ecosystem isn't supported,
      - the registry is unreachable,
      - no stable version older than MIN_AGE_DAYS exists,
      - every checked candidate has known vulns (don't guess — bail).
    """
    versions = _list_versions(name, ecosystem)
    if not versions:
        return None

    # Build candidate pool: stable only, old enough to have weathered
    # initial bug reports, and not the version we just blocked.
    candidates: List[Tuple[str, int]] = []
    for version, age in versions.items():
        if version == exclude_version:
            continue
        if not _is_stable(version):
            continue
        if age is None or age < MIN_AGE_DAYS:
            continue
        candidates.append((version, age))

    if not candidates:
        return None

    # Newest first.
    candidates.sort(key=lambda vt: _version_key(vt[0]), reverse=True)
    top = candidates[:MAX_CANDIDATES]

    # One batch call to OSV for all candidates.
    vuln_map = batch_has_vulns(name, ecosystem, [v for v, _ in top])

    for version, age in top:
        if vuln_map.get(version, True):
            continue
        return SafeVersion(
            version=version,
            age_days=age,
            reason=f"newest stable release with no known CVEs (published {age}d ago)",
        )

    return None
