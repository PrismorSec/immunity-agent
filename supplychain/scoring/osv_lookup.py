"""OSV.dev vulnerability lookup — version-aware, ecosystem-scoped.

Replaces the old NVD keyword-search approach. OSV's /v1/query endpoint
filters to vulnerabilities affecting the exact installed version in the
right ecosystem, eliminating CPE parsing, keyword collisions, and
version-blind matches in one move.

Also surfaces malicious-package advisories (MAL-* IDs from the OSV
malicious-packages corpus) that NVD does not track.

Fails open: returns [] on any network or parse error.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Map our internal ecosystem labels to OSV's ecosystem identifiers.
# See https://ossf.github.io/osv-schema/#defined-ecosystems
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "pip": "PyPI",
    "uv": "PyPI",
    "cargo": "crates.io",
    "go": "Go",
    "gem": "RubyGems",
    "maven": "Maven",
}

_CACHE: Dict[str, tuple] = {}  # key -> (expire_time, result)
_CACHE_TTL = 300


def _cache_get(key: str) -> Optional[List[Dict[str, Any]]]:
    if key in _CACHE:
        expire, result = _CACHE[key]
        if time.monotonic() < expire:
            return result
        del _CACHE[key]
    return None


def _cache_set(key: str, result: List[Dict[str, Any]]) -> None:
    _CACHE[key] = (time.monotonic() + _CACHE_TTL, result)


def _osv_ecosystem(ecosystem: str) -> Optional[str]:
    return _ECOSYSTEM_MAP.get(ecosystem)


def _post_json(url: str, body: Dict[str, Any], timeout: int = 4) -> Optional[dict]:
    """POST JSON to OSV; return parsed response or None on any failure."""
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "immunity-agent/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _classify_severity(vuln: Dict[str, Any]) -> str:
    """Pick a severity tier from an OSV vuln record.

    Order of preference:
      1. MAL-* IDs (malicious-packages corpus) → critical.
      2. database_specific.severity (GHSA text severity).
      3. CVSS vector impact metrics — rough heuristic, not a full calculator.
      4. Default "medium" so a confirmed-vulnerable version is never silent.
    """
    vid = vuln.get("id", "")
    if vid.startswith("MAL-"):
        return "critical"

    db = vuln.get("database_specific") or {}
    text = str(db.get("severity") or "").lower()
    if text in ("critical", "high", "medium", "low"):
        return text

    for sev in vuln.get("severity") or []:
        vector = str(sev.get("score") or "")
        if "CVSS" not in vector:
            continue
        n_high_impact = vector.count(":H")
        network = "AV:N" in vector
        if network and n_high_impact >= 3:
            return "critical"
        if network and n_high_impact >= 1:
            return "high"
        if n_high_impact >= 1:
            return "medium"
        return "low"

    return "medium"


def _format_title(vuln: Dict[str, Any]) -> str:
    vid = vuln.get("id", "OSV")
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        # Fallback to first line of details.
        details = (vuln.get("details") or "").strip().splitlines()
        summary = details[0] if details else ""
    if not summary:
        return vid
    if len(summary) > 80:
        summary = summary[:77] + "..."
    return f"{vid}: {summary}"


def _is_malicious(vuln: Dict[str, Any]) -> bool:
    if vuln.get("id", "").startswith("MAL-"):
        return True
    db = vuln.get("database_specific") or {}
    return str(db.get("type") or "").upper() == "MALICIOUS_LIBRARY"


def fetch_vulns(
    package_name: str,
    ecosystem: str,
    version: str = "",
) -> List[Dict[str, Any]]:
    """Query OSV for vulnerabilities affecting `package_name` at `version`.

    Returns a list of {id, severity, title, malicious} dicts, already
    filtered to the right ecosystem and (when version is given) the
    affected version range.
    """
    osv_eco = _osv_ecosystem(ecosystem)
    if not osv_eco or not package_name:
        return []

    cache_key = f"{osv_eco}:{package_name}:{version}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    query: Dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": osv_eco},
    }
    if version:
        query["version"] = version

    data = _post_json(OSV_QUERY_URL, query)
    if not data:
        _cache_set(cache_key, [])
        return []

    out: List[Dict[str, Any]] = []
    for vuln in data.get("vulns") or []:
        if vuln.get("withdrawn"):
            continue
        out.append({
            "id": vuln.get("id", ""),
            "severity": _classify_severity(vuln),
            "title": _format_title(vuln),
            "malicious": _is_malicious(vuln),
        })

    _cache_set(cache_key, out)
    return out


def batch_has_vulns(
    package_name: str,
    ecosystem: str,
    versions: List[str],
) -> Dict[str, bool]:
    """Batch-check which versions have any known vulnerabilities.

    Returns {version: has_vulns}. Versions not in the response (or on
    network failure) are reported as having vulns — safer to skip an
    unknown version than to recommend something we couldn't verify.
    """
    osv_eco = _osv_ecosystem(ecosystem)
    if not osv_eco or not versions:
        return {v: True for v in versions}

    body = {
        "queries": [
            {"package": {"name": package_name, "ecosystem": osv_eco}, "version": v}
            for v in versions
        ]
    }
    data = _post_json(OSV_BATCH_URL, body, timeout=5)
    if not data:
        return {v: True for v in versions}

    results = data.get("results") or []
    out: Dict[str, bool] = {}
    for v, result in zip(versions, results):
        vulns = result.get("vulns") or []
        out[v] = bool(vulns)
    # Anything missing from the response stays marked as vulnerable.
    for v in versions:
        out.setdefault(v, True)
    return out
