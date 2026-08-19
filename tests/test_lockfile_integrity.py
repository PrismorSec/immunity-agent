"""check_lockfile_integrity must not flag npm's normal flat/hoisted
transitive-dependency layout as "lockfile injection". A real lockfile
commonly has dozens of top-level node_modules/<name> entries that are
NOT direct dependencies in package.json but ARE reachable through the
real dependency graph (npm dedupes/hoists whenever there's no version
conflict). Before the reachability fix, every one of those was flagged
as HIGH "lockfile injection" — in this session's live experiment, a
real Next.js app produced ~404 such findings, almost all false
positives, burying the rare genuine signal.
"""
from __future__ import annotations

import json
from pathlib import Path

from prismor.runtime.deps import _reachable_lockfile_names, check_lockfile_integrity


def _write_pkg(ws: Path, dependencies: dict) -> None:
    (ws / "package.json").write_text(json.dumps({
        "name": "fixture", "version": "0.0.0", "dependencies": dependencies,
    }))


def _write_lock(ws: Path, packages: dict) -> None:
    (ws / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": packages,
    }))


def _registry_entry(version: str, dependencies: dict | None = None) -> dict:
    entry = {
        "version": version,
        "resolved": f"https://registry.npmjs.org/x/-/x-{version}.tgz",
        "integrity": "sha512-fake==",
    }
    if dependencies is not None:
        entry["dependencies"] = dependencies
    return entry


def test_hoisted_transitive_dep_not_flagged_as_injection(tmp_path: Path) -> None:
    """express -> accepts -> negotiator, all hoisted flat, none of them
    are direct dependencies except express — only express is declared."""
    _write_pkg(tmp_path, {"express": "4.18.2"})
    _write_lock(tmp_path, {
        "": {"name": "fixture", "dependencies": {"express": "4.18.2"}},
        "node_modules/express": _registry_entry("4.18.2", {"accepts": "~1.3.8"}),
        "node_modules/accepts": _registry_entry("1.3.8", {"negotiator": "0.6.3"}),
        "node_modules/negotiator": _registry_entry("0.6.3", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    injection = [f for f in findings if f["issue"] == "lockfile-injection"]
    assert injection == []


def test_genuinely_unreachable_entry_still_flagged(tmp_path: Path) -> None:
    _write_pkg(tmp_path, {"express": "4.18.2"})
    _write_lock(tmp_path, {
        "": {"name": "fixture", "dependencies": {"express": "4.18.2"}},
        "node_modules/express": _registry_entry("4.18.2", {}),
        "node_modules/totally-unrelated-pkg": _registry_entry("9.9.9", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    injection = [f for f in findings if f["issue"] == "lockfile-injection"]
    assert len(injection) == 1
    assert "totally-unrelated-pkg" in injection[0]["message"]
    assert injection[0]["severity"] == "HIGH"


def test_deeply_nested_reachability_resolved(tmp_path: Path) -> None:
    """a -> b -> c -> d, four hops deep, all hoisted flat — d must still
    be recognized as reachable, not flagged."""
    _write_pkg(tmp_path, {"a": "1.0.0"})
    _write_lock(tmp_path, {
        "": {"name": "fixture", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _registry_entry("1.0.0", {"b": "1.0.0"}),
        "node_modules/b": _registry_entry("1.0.0", {"c": "1.0.0"}),
        "node_modules/c": _registry_entry("1.0.0", {"d": "1.0.0"}),
        "node_modules/d": _registry_entry("1.0.0", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    assert [f for f in findings if f["issue"] == "lockfile-injection"] == []


def test_nested_lockfile_path_entries_always_skipped(tmp_path: Path) -> None:
    """A genuinely nested path (node_modules/a/node_modules/b, npm's
    non-hoisted form when versions conflict) is skipped outright,
    independent of reachability."""
    _write_pkg(tmp_path, {"a": "1.0.0"})
    _write_lock(tmp_path, {
        "": {"name": "fixture", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _registry_entry("1.0.0", {}),
        "node_modules/a/node_modules/b": _registry_entry("2.0.0", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    assert [f for f in findings if f["issue"] == "lockfile-injection"] == []


def test_unverifiable_reachability_downgrades_to_info(tmp_path: Path) -> None:
    """A lockfile whose entries carry no `dependencies` field at all
    (foreign/older shape) can't have reachability computed — report the
    softer, explicitly-unverified signal instead of asserting injection
    for an entry that ISN'T the declared dependency itself."""
    _write_pkg(tmp_path, {"express": "4.18.2"})
    _write_lock(tmp_path, {
        "": {"name": "fixture"},
        "node_modules/express": {"version": "4.18.2"},  # no "dependencies" key anywhere
        "node_modules/negotiator": {"version": "0.6.3"},  # undeclared, unverifiable
    })
    findings = check_lockfile_integrity(tmp_path)
    injection = [f for f in findings if f["issue"] == "lockfile-injection"]
    info = [f for f in findings if f["issue"] == "undeclared-direct-entry"]
    assert injection == []
    assert len(info) == 1
    assert info[0]["severity"] == "INFO"
    assert "negotiator" in info[0]["message"]


def test_reachable_names_helper_directly() -> None:
    packages = {
        "node_modules/a": {"dependencies": {"b": "1.0.0"}},
        "node_modules/b": {"dependencies": {"c": "1.0.0"}},
        "node_modules/c": {"dependencies": {}},
        "node_modules/orphan": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"a"}, packages)
    assert reachable == {"a", "b", "c"}
    assert "orphan" not in reachable


def test_reachable_names_helper_returns_none_without_declared() -> None:
    assert _reachable_lockfile_names(set(), {"node_modules/a": {"dependencies": {}}}) is None


def test_reachable_names_helper_returns_none_without_dependency_metadata() -> None:
    assert _reachable_lockfile_names({"a"}, {"node_modules/a": {"version": "1.0.0"}}) is None


def test_audit_pass_message_does_not_imply_cve_freedom(tmp_path: Path) -> None:
    """The audit's lockfile-presence PASS line must not read as a
    vulnerability-free verdict — it only verifies lockfiles exist."""
    from prismor.runtime.audit import _check_lockfile_presence

    _write_pkg(tmp_path, {"express": "4.18.2"})
    _write_lock(tmp_path, {
        "": {"name": "fixture", "dependencies": {"express": "4.18.2"}},
        "node_modules/express": _registry_entry("4.18.2", {}),
    })
    findings = _check_lockfile_presence(tmp_path)
    passes = [f for f in findings if f.severity == "PASS"]
    assert len(passes) == 1
    assert "does not mean" in passes[0].message
    assert "checked live" in passes[0].message


def test_reachable_names_follows_nested_node_modules_edges() -> None:
    """Regression for #289.

    Reproduces the reported shape: jackspeak is required only by a nested
    copy of glob, which is itself required only by a nested copy under
    rimraf. Ignoring nested edges leaves jackspeak unreachable, and an
    ordinary hoisted transitive gets reported as lockfile injection.
    """
    packages = {
        "node_modules/rimraf": {"dependencies": {"glob": "^10.0.0"}},
        "node_modules/rimraf/node_modules/glob": {"dependencies": {"jackspeak": "^2.0.0"}},
        "node_modules/jackspeak": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"rimraf"}, packages)
    assert reachable is not None
    assert "jackspeak" in reachable, "hoisted transitive reached only via a nested edge"
    assert reachable == {"rimraf", "glob", "jackspeak"}


def test_reachable_names_unions_edges_across_nesting_depths() -> None:
    """The same package at two depths may pin different dependency sets;
    either is a real route, so the union is what reachability means."""
    packages = {
        "node_modules/glob": {"dependencies": {"minimatch": "1"}},
        "node_modules/rimraf": {"dependencies": {"glob": "1"}},
        "node_modules/rimraf/node_modules/glob": {"dependencies": {"jackspeak": "1"}},
        "node_modules/minimatch": {"dependencies": {}},
        "node_modules/jackspeak": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"rimraf"}, packages)
    assert reachable == {"rimraf", "glob", "minimatch", "jackspeak"}


def test_reachable_names_still_excludes_a_genuine_orphan() -> None:
    """The nested fix must not make everything reachable — a package no
    edge points at is still injection."""
    packages = {
        "node_modules/a": {"dependencies": {"b": "1"}},
        "node_modules/a/node_modules/b": {"dependencies": {}},
        "node_modules/injected": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"a"}, packages)
    assert reachable == {"a", "b"}
    assert "injected" not in reachable


def test_reachable_names_handles_scoped_packages_when_nested() -> None:
    packages = {
        "node_modules/pkg": {"dependencies": {"@scope/child": "1"}},
        "node_modules/pkg/node_modules/@scope/child": {"dependencies": {"leaf": "1"}},
        "node_modules/leaf": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"pkg"}, packages)
    assert "@scope/child" in reachable
    assert "leaf" in reachable
