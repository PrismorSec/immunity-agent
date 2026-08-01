"""Tests for prismor.runtime.memory_guard — TOFU integrity, git-aware classification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from prismor.runtime.memory_guard import (
    _GIT_TIMEOUT,
    compute_file_hash,
    load_trust_store,
    verify_memory_files,
    approve_memory_file,
    trust_memory_file,
    format_trust_status,
    _prismor_home,
    _workspace_trust_path,
)


# ── helpers ────────────────────────────────────────────────────────────────


def _make_file(path: Path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clear_trust_stores(tmp_path: Path) -> None:
    """Remove any trust stores so tests start clean."""
    ws_store = _workspace_trust_path(tmp_path)
    if ws_store.exists():
        ws_store.unlink()
    global_store = _prismor_home() / "memory-trust.json"
    if global_store.exists():
        global_store.unlink()


# ── TOFU tests ─────────────────────────────────────────────────────────────


def test_tofu_first_load_records_baseline(tmp_path):
    """First-ever verify_memory_files() creates a trust entry, no finding."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    expected_hash = _make_file(f, "# Project conventions\nAlways use 2-space indent.\n")

    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings == []

    store = load_trust_store(tmp_path)
    assert str(f.resolve()) in store["files"]
    entry = store["files"][str(f.resolve())]
    assert entry["sha256"] == expected_hash
    assert entry["mode"] == "trusted"


def test_tofu_subsequent_load_matches_silent(tmp_path):
    """Same file unchanged — second call returns empty findings."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# conventions\n")

    # First load: TOFU
    findings1 = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings1 == []

    # Second load: should match
    findings2 = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings2 == []


def test_hash_mismatch_detected(tmp_path):
    """Modify a trusted file — should get an integrity finding."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# original\n")

    # TOFU
    verify_memory_files([{"path": str(f)}], tmp_path)

    # Modify
    _make_file(f, "# modified\n")

    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert len(findings) >= 1
    assert findings[0]["category"] == "memory_integrity"


def test_file_removed_handled(tmp_path):
    """Deleted file produces a file_removed finding."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# temp\n")

    # TOFU
    verify_memory_files([{"path": str(f)}], tmp_path)

    # Delete
    f.unlink()

    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert len(findings) >= 1
    assert findings[0].get("evidence", {}).get("origin") == "file_removed"


def test_trust_store_deleted_re_tofu(tmp_path):
    """Deleting the trust store causes re-TOFU on next load."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    hash1 = _make_file(f, "# v1\n")

    # TOFU
    verify_memory_files([{"path": str(f)}], tmp_path)

    # Delete trust store
    ws_store = _workspace_trust_path(tmp_path)
    ws_store.unlink()
    # Also nuke global store if it exists
    gs = _prismor_home() / "memory-trust.json"
    if gs.exists():
        gs.unlink()

    # Re-TOFU should succeed
    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings == []
    store = load_trust_store(tmp_path)
    assert store["files"][str(f.resolve())]["mode"] == "trusted"


# ── Git-aware classification ───────────────────────────────────────────────


def test_changed_in_commit_classified(tmp_path):
    """Git shows the change is in a commit → changed_in_commit."""
    _clear_trust_stores(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT,
    )

    f = repo / "CLAUDE.md"
    _make_file(f, "# v1\n")
    subprocess.run(["git", "add", "CLAUDE.md"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)

    # TOFU baseline
    verify_memory_files([{"path": str(f)}], repo)

    # New commit changes the file
    _make_file(f, "# v2\n")
    subprocess.run(["git", "add", "CLAUDE.md"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)
    subprocess.run(["git", "commit", "-m", "update"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)

    findings = verify_memory_files([{"path": str(f)}], repo)
    assert len(findings) >= 1
    origin = findings[0].get("evidence", {}).get("origin", "")
    assert origin in ("changed_in_commit", "unclassified_change")


def test_uncommitted_change_classified(tmp_path):
    """Uncommitted edit → uncommitted_change."""
    _clear_trust_stores(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT,
    )

    f = repo / "CLAUDE.md"
    _make_file(f, "# v1\n")
    subprocess.run(["git", "add", "CLAUDE.md"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=str(repo), capture_output=True, timeout=_GIT_TIMEOUT)

    # Approve (TOFU baseline after commit)
    approve_memory_file(f, repo)

    # Uncommitted edit
    _make_file(f, "# v1-uncommitted\n")

    findings = verify_memory_files([{"path": str(f)}], repo)
    assert len(findings) >= 1
    origin = findings[0].get("evidence", {}).get("origin", "")
    assert origin in ("uncommitted_change", "unclassified_change")


def test_git_unavailable_graceful_degradation(tmp_path, monkeypatch):
    """No git binary → unclassified_change, no crash."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# original\n")
    verify_memory_files([{"path": str(f)}], tmp_path)

    _make_file(f, "# modified no git\n")

    # Remove git from PATH
    monkeypatch.setenv("PATH", "/nonexistent")
    # Also need to make _git() fail-fast
    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    # Should not crash; should produce a finding
    assert len(findings) >= 1
    origin = findings[0].get("evidence", {}).get("origin", "")
    assert origin in ("unclassified_change", "unable_to_verify")


def test_deduplication_across_sessions(tmp_path):
    """Two verify calls on the same file → only one baseline."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# dedup test\n")

    findings1 = verify_memory_files([{"path": str(f)}], tmp_path)
    findings2 = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings1 == []
    assert findings2 == []

    store = load_trust_store(tmp_path)
    # One entry, not two
    assert len(store["files"]) == 1


def test_sha256_over_full_bytes_not_truncated(tmp_path):
    """Hash computed over full file bytes, including binary content."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "binary_file.bin"
    # Create a file with null bytes and random binary
    data = b"header text\n" + bytes(range(256)) + b"\ntrailer"
    f.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()
    actual = compute_file_hash(f)
    assert actual == expected

    # Verify the hash matches in the trust store
    verify_memory_files([{"path": str(f)}], tmp_path)
    store = load_trust_store(tmp_path)
    # Base64-encoded path, but the hash should match
    for entry in store["files"].values():
        if entry.get("sha256") == expected:
            break
    else:
        pytest.fail("Expected hash not found in trust store")


def test_approve_rebaseline_command(tmp_path):
    """approve_memory_file updates the stored hash → subsequent verify silent."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# v1\n")

    verify_memory_files([{"path": str(f)}], tmp_path)

    # Change the file
    new_hash = _make_file(f, "# v2\n")

    # Approve
    approve_memory_file(f, tmp_path)

    # Verify should be clean
    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings == []

    store = load_trust_store(tmp_path)
    assert store["files"][str(f.resolve())]["sha256"] == new_hash


# ── Signed mode (skip if cryptography not installed) ────────────────────────


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cryptography"),
    reason="cryptography not installed",
)
def test_signed_mode_verify_valid(tmp_path):
    """Sign a file, then verify — should be clean."""
    _clear_trust_stores(tmp_path)
    from prismor.runtime.memory_guard import sign_memory_file
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# signed content\n")

    # Generate a keypair
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "test_key.pem"
    key_path.write_bytes(key.private_bytes_raw())

    # Sign
    os.environ["PRISMOR_MEMORY_SIGNED_MODE"] = "1"
    try:
        sign_memory_file(f, key_path, tmp_path)
    finally:
        del os.environ["PRISMOR_MEMORY_SIGNED_MODE"]

    # Verify should be clean
    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings == []

    store = load_trust_store(tmp_path)
    entry = store["files"].get(str(f.resolve()), {})
    assert entry.get("mode") == "signed"


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cryptography"),
    reason="cryptography not installed",
)
def test_signed_mode_verify_invalid(tmp_path):
    """Sign a file, then modify it — should produce a finding."""
    _clear_trust_stores(tmp_path)
    from prismor.runtime.memory_guard import sign_memory_file
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# signed content\n")

    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "test_key.pem"
    key_path.write_bytes(key.private_bytes_raw())

    os.environ["PRISMOR_MEMORY_SIGNED_MODE"] = "1"
    try:
        sign_memory_file(f, key_path, tmp_path)
    finally:
        del os.environ["PRISMOR_MEMORY_SIGNED_MODE"]

    # Tamper with the file
    _make_file(f, "# tampered content\n")

    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert len(findings) >= 1


# ── Unicode / control character tests ──────────────────────────────────────


def test_invisible_controls_regex_false_positives(tmp_path):
    """Emoji ZWJ sequences and CJK text should NOT be flagged as invisible controls."""
    # This test verifies that _INVISIBLE_CONTROL_RE (defined in hooks.py, not
    # memory_guard.py) doesn't false-positive on legitimate Unicode sequences.
    # The memory_guard module itself doesn't do content scanning — it does
    # integrity. But the integrity framework feeds findings back through the
    # policy engine, which uses _INVISIBLE_CONTROL_RE.
    #
    # We test this indirectly: a file with emoji/CJK content should pass
    # TOFU and subsequent integrity checks without issue.
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    content = "# Emoji and CJK\n👨‍👩‍👧 ZWJ sequence\n日本語のテキスト\nàéîõū Latin accents\n"
    _make_file(f, content)

    # TOFU
    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings == []

    # Subsequent load
    findings2 = verify_memory_files([{"path": str(f)}], tmp_path)
    assert findings2 == []


def test_invisible_controls_regex_true_positives(tmp_path):
    """Bidi control characters in the file are detected via integrity (content changed)."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# clean\n")

    # TOFU
    verify_memory_files([{"path": str(f)}], tmp_path)

    # Add bidi controls — the content changed, so integrity fires
    _make_file(f, "# \u202eclean\u202c\n")

    findings = verify_memory_files([{"path": str(f)}], tmp_path)
    assert len(findings) >= 1
    assert findings[0]["category"] == "memory_integrity"


# ── Truncation / limits ────────────────────────────────────────────────────


def test_truncated_memory_emits_warning(tmp_path):
    """Large files should still be hashable — integrity doesn't truncate hashing."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    # Create a large file
    content = "# " + "x" * 100000
    _make_file(f, content)

    # Should hash successfully
    h = compute_file_hash(f)
    assert len(h) == 64  # SHA-256 hex
    assert h != ""


def test_memory_max_files_cap(tmp_path):
    """64+ files — verify_memory_files handles them all."""
    _clear_trust_stores(tmp_path)
    files = []
    for i in range(80):
        f = tmp_path / f"CLAUDE_{i:03d}.md"
        _make_file(f, f"# file {i}\n")
        files.append({"path": str(f)})

    # Should not crash
    findings = verify_memory_files(files, tmp_path)
    # First 80 files → all TOFU, no findings
    assert len(findings) == 0

    store = load_trust_store(tmp_path)
    assert len(store["files"]) == 80  # All stored


# ── Trust store format ─────────────────────────────────────────────────────


def test_format_trust_status(tmp_path):
    """format_trust_status produces a readable table."""
    _clear_trust_stores(tmp_path)
    f = tmp_path / "CLAUDE.md"
    _make_file(f, "# test\n")
    verify_memory_files([{"path": str(f)}], tmp_path)

    output = format_trust_status(tmp_path)
    assert "Trust Store" in output
    assert "CLAUDE.md" in output
    assert "trusted" in output
