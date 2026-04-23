"""Dependency-to-feed correlation for Prismor Warden.

Scans workspace manifest files, extracts dependency names and versions,
and cross-references them against the threat feed's dependency_vulnerability
advisories.

Usage (from CLI):
    warden deps              # scan current workspace
    warden deps --json       # machine-readable output
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Manifest file patterns (kept in sync with default_policy.yaml).
_MANIFEST_GLOBS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "requirements-*.txt": "pip",
    "requirements_*.txt": "pip",
    "pyproject.toml": "pip",
    "Gemfile": "gem",
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
}

# Patterns for lockfiles paired with their manifests.
_LOCKFILE_PAIRS: Dict[str, List[str]] = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "requirements.txt": ["requirements.txt"],  # pip has no standard lockfile
    "pyproject.toml": ["poetry.lock", "uv.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "pom.xml": [],  # Maven has no standard lockfile
}


def find_manifests(workspace: Path) -> List[Dict[str, Any]]:
    """Find dependency manifest files in the workspace.

    Returns list of {path, type, ecosystem}.
    """
    results: List[Dict[str, Any]] = []
    for pattern, ecosystem in _MANIFEST_GLOBS.items():
        for match in workspace.glob(pattern):
            if match.is_file() and ".git" not in match.parts:
                results.append({
                    "path": match,
                    "name": match.name,
                    "ecosystem": ecosystem,
                })
    return results


def check_lockfile_presence(workspace: Path) -> List[Dict[str, Any]]:
    """Check that lockfiles exist alongside manifests.

    Returns list of {manifest, missing_lockfiles, severity, message}.
    """
    findings: List[Dict[str, Any]] = []
    for pattern, lockfiles in _LOCKFILE_PAIRS.items():
        if not lockfiles:
            continue
        for manifest in workspace.glob(pattern):
            if not manifest.is_file() or ".git" in manifest.parts:
                continue
            parent = manifest.parent
            has_lock = any((parent / lf).exists() for lf in lockfiles)
            if not has_lock:
                findings.append({
                    "manifest": str(manifest),
                    "missing_lockfiles": lockfiles,
                    "severity": "MEDIUM",
                    "message": (
                        f"{manifest.name} has no lockfile — dependency versions "
                        f"are not pinned (expected one of: {', '.join(lockfiles)})"
                    ),
                })
    return findings


def parse_dependencies(manifest: Path, ecosystem: str) -> List[Dict[str, str]]:
    """Extract dependency names and versions from a manifest file.

    Returns list of {name, version, ecosystem}.
    """
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError:
        return []

    if ecosystem == "npm":
        return _parse_package_json(text)
    elif ecosystem == "pip":
        if manifest.name == "pyproject.toml":
            return _parse_pyproject_toml(text)
        return _parse_requirements_txt(text)
    elif ecosystem == "go":
        return _parse_go_mod(text)
    elif ecosystem == "cargo":
        return _parse_cargo_toml(text)
    return []


def _parse_package_json(text: str) -> List[Dict[str, str]]:
    """Parse package.json dependencies."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    deps: List[Dict[str, str]] = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            deps.append({"name": name, "version": str(version), "ecosystem": "npm"})
    return deps


def _parse_requirements_txt(text: str) -> List[Dict[str, str]]:
    """Parse requirements.txt (simple format)."""
    deps: List[Dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle name==version, name>=version, name~=version, bare name
        match = re.match(r'^([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[\d.]+)?', line)
        if match:
            name = match.group(1)
            version = (match.group(2) or "").strip()
            deps.append({"name": name, "version": version, "ecosystem": "pip"})
    return deps


def _parse_pyproject_toml(text: str) -> List[Dict[str, str]]:
    """Parse pyproject.toml dependencies (simple regex, no TOML parser)."""
    deps: List[Dict[str, str]] = []
    # Match lines like: "requests>=2.28", "flask", etc. inside dependencies array
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^dependencies\s*=\s*\[', stripped):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            # Extract package spec from quoted string
            match = re.match(r'^["\']([A-Za-z0-9_.-]+)\s*([><=!~].*?)?["\']', stripped)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": (match.group(2) or "").strip(),
                    "ecosystem": "pip",
                })
    return deps


def _parse_go_mod(text: str) -> List[Dict[str, str]]:
    """Parse go.mod require blocks."""
    deps: List[Dict[str, str]] = []
    in_require = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append({"name": parts[0], "version": parts[1], "ecosystem": "go"})
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                deps.append({"name": parts[1], "version": parts[2], "ecosystem": "go"})
    return deps


def _parse_cargo_toml(text: str) -> List[Dict[str, str]]:
    """Parse Cargo.toml [dependencies] section."""
    deps: List[Dict[str, str]] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[dependencies\]', stripped, re.IGNORECASE):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("["):
                in_deps = False
                continue
            if not stripped or stripped.startswith("#"):
                continue
            # name = "version" or name = { version = "..." }
            match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"', stripped)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "cargo"})
            else:
                # name = { version = "..." }
                match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]*)"', stripped)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "cargo"})
    return deps


def check_against_feed(
    deps: List[Dict[str, str]],
    feed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Match dependency names against threat feed advisories.

    Returns list of matches with advisory details.
    """
    advisories = feed.get("advisories", [])
    # Filter to dependency_vulnerability type only
    dep_advisories = [a for a in advisories if a.get("type") == "dependency_vulnerability"]

    matches: List[Dict[str, Any]] = []
    dep_names = {d["name"].lower() for d in deps}

    for advisory in dep_advisories:
        affected = advisory.get("affected", [])
        for affected_str in affected:
            # Extract package name from CPE-like strings: "package<=version"
            pkg_name = re.split(r'[<>=!]', affected_str)[0].strip().lower()
            if pkg_name in dep_names:
                matching_deps = [d for d in deps if d["name"].lower() == pkg_name]
                matches.append({
                    "advisory_id": advisory.get("id", ""),
                    "severity": advisory.get("severity", "unknown"),
                    "title": advisory.get("title", ""),
                    "affected": affected_str,
                    "action": advisory.get("action", ""),
                    "matched_deps": matching_deps,
                })

    return matches


def scan_workspace(
    workspace: Path,
    feed: Dict[str, Any],
) -> Dict[str, Any]:
    """Full workspace dependency scan.

    Returns {manifests, dependencies, feed_matches, lockfile_issues}.
    """
    manifests = find_manifests(workspace)
    all_deps: List[Dict[str, str]] = []
    for m in manifests:
        deps = parse_dependencies(m["path"], m["ecosystem"])
        all_deps.extend(deps)

    feed_matches = check_against_feed(all_deps, feed)
    lockfile_issues = check_lockfile_presence(workspace)

    return {
        "manifests": [{"path": str(m["path"]), "ecosystem": m["ecosystem"]} for m in manifests],
        "dependencies": len(all_deps),
        "feed_matches": feed_matches,
        "lockfile_issues": lockfile_issues,
    }
