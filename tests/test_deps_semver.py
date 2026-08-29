"""Lockfile-aware advisory matching and floating-range detection."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from prismor.runtime.deps import (
    _read_npm_lockfile,
    check_against_feed,
    check_floating_ranges,
    parse_dependencies,
    scan_workspace,
)


def _write_pkg(ws: Path, dep_name: str, range_str: str) -> None:
    (ws / "package.json").write_text(json.dumps({
        "name": "fixture", "version": "0.0.0",
        "dependencies": {dep_name: range_str},
    }))


def _write_lock(ws: Path, dep_name: str, pinned: str) -> None:
    (ws / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture", "version": "0.0.0"},
            f"node_modules/{dep_name}": {"version": pinned, "resolved": "https://x", "integrity": "sha512-x"},
        },
    }))


def _feed(name: str, affected: str) -> dict:
    return {"advisories": [{
        "type": "dependency_vulnerability",
        "id": "CVE-X",
        "severity": "HIGH",
        "title": f"{name} CVE",
        "affected": [affected],
    }]}


def test_lockfile_pins_safe_version(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "^4.17.0")
    _write_lock(tmp_path, "lodash", "4.17.21")
    result = scan_workspace(tmp_path, _feed("lodash", "lodash<=4.17.20"))
    assert result["feed_matches"] == []


def test_lockfile_pins_vulnerable_version(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "^4.17.0")
    _write_lock(tmp_path, "lodash", "4.17.0")
    result = scan_workspace(tmp_path, _feed("lodash", "lodash<=4.17.20"))
    assert len(result["feed_matches"]) == 1
    assert result["feed_matches"][0]["matched_deps"][0]["name"] == "lodash"


def test_no_lockfile_floating_range_lowerbound(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "^4.17.0")
    result = scan_workspace(tmp_path, _feed("lodash", "lodash<=4.17.20"))
    assert len(result["feed_matches"]) == 1


def test_exact_pin_safe(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "4.17.21")
    result = scan_workspace(tmp_path, _feed("lodash", "lodash<=4.17.20"))
    assert result["feed_matches"] == []


def test_star_range_flagged_as_floating(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "*")
    _write_lock(tmp_path, "lodash", "4.17.21")
    result = scan_workspace(tmp_path, {"advisories": []})
    names = {f["name"] for f in result["floating_ranges"]}
    assert "lodash" in names


def test_caret_with_lockfile_is_low_severity(tmp_path: Path) -> None:
    _write_pkg(tmp_path, "lodash", "^4.17.21")
    _write_lock(tmp_path, "lodash", "4.17.21")
    findings = check_floating_ranges(tmp_path, _read_npm_lockfile(tmp_path))
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["pinned_version"] == "4.17.21"


def test_empty_version_falls_back_to_name_only(tmp_path: Path) -> None:
    """supplychain/cli.py passes version='' — must still match by name."""
    deps = [{"name": "lodash", "version": "", "ecosystem": ""}]
    matches = check_against_feed(deps, _feed("lodash", "lodash<=4.17.20"))
    assert len(matches) == 1


def test_parse_package_json_uses_lockfile_pin(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    _write_pkg(tmp_path, "lodash", "^4.17.0")
    from prismor.runtime.deps import _parse_package_json
    deps = _parse_package_json(pkg.read_text(), lockfile_map={"lodash": "4.17.21"})
    assert deps == [{
        "name": "lodash",
        "version": "4.17.21",
        "ecosystem": "npm",
        "range": "^4.17.0",
        "pinned_via_lock": True,
    }]


# ── IOC database wiring (independent of the signed advisory feed) ────────────
# Regression: the shipped feed carries 0 dependency_vulnerability advisories,
# so `prismor deps` matched nothing. It now also consults supplychain.ioc, so a
# known-malicious pinned package is flagged even with an empty feed.

def test_deps_flags_known_ioc_with_empty_feed(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nmistralai==2.4.6\nguardrails-ai==0.10.1\n"
    )
    result = scan_workspace(tmp_path, feed={"advisories": []})
    matched = {m["matched_deps"][0]["name"]: m for m in result["feed_matches"]}
    assert "mistralai" in matched, result["feed_matches"]
    assert "guardrails-ai" in matched
    # exact pip pin -> CRITICAL exact-version match, not a name-only HIGH
    assert matched["mistralai"]["severity"] == "critical"
    assert "2.4.6" in matched["mistralai"]["affected"]


def test_deps_ioc_no_false_positive_on_safe_version(tmp_path):
    # 2.4.5 is the legitimate release; only 2.4.6 is compromised.
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nmistralai==2.4.5\n")
    result = scan_workspace(tmp_path, feed={"advisories": []})
    assert result["feed_matches"] == [], result["feed_matches"]


def test_deps_flags_ioc_npm_range(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "fixture", "version": "0.0.0",
        "dependencies": {"@mistralai/mistralai": "2.2.4"},
    }))
    result = scan_workspace(tmp_path, feed={"advisories": []})
    names = {m["matched_deps"][0]["name"] for m in result["feed_matches"]}
    assert "@mistralai/mistralai" in names, result["feed_matches"]
