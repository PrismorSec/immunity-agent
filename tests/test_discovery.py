"""Tests for local-host AI discovery (enterprise/discovery.py).

Verifies the host sweep classifies agents as present / governed / ungoverned
from files on disk, that a Prismor marker in a config flips an agent to
governed, and that the summary counts the shadow-AI (ungoverned) total.

Isolated with a fake home + workspace; no real machine state is read.
Run: python3 -m pytest tests/test_discovery.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))


@pytest.fixture()
def fake_host(tmp_path, monkeypatch):
    """A fake $HOME with no agents, plus a workspace. Patches Path.home() so
    both discovery.py and scanner.py resolve to the temp home."""
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    for mod in ("prismor.runtime.enterprise.discovery", "prismor.runtime.scanner"):
        sys.modules.pop(mod, None)
    from prismor.runtime.enterprise import discovery
    return discovery, home, ws


def _write(path: Path, text: str = "{}") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_empty_host_finds_nothing(fake_host):
    discovery, home, ws = fake_host
    report = discovery.discover(ws)
    assert report["summary"]["present"] == 0
    assert report["summary"]["ungoverned"] == 0
    assert all(not a["present"] for a in report["agents"])


def test_ungoverned_agent_is_flagged(fake_host):
    discovery, home, ws = fake_host
    # A Claude install with a config but NO prismor hooks.
    _write(home / ".claude" / "settings.json", '{"hooks": {}}')
    report = discovery.discover(ws)
    claude = next(a for a in report["agents"] if a["agent"] == "claude")
    assert claude["present"] and not claude["governed"]
    assert report["summary"]["ungoverned"] == 1
    assert report["summary"]["governed"] == 0


def test_governed_marker_flips_to_governed(fake_host):
    discovery, home, ws = fake_host
    _write(home / ".claude" / "settings.json",
           '{"hooks": {"PreToolUse": [{"command": "python -m prismor.runtime hook-dispatch"}]}}')
    report = discovery.discover(ws)
    claude = next(a for a in report["agents"] if a["agent"] == "claude")
    assert claude["present"] and claude["governed"]
    assert report["summary"]["governed"] == 1
    assert report["summary"]["ungoverned"] == 0


def test_cli_presence_without_config_counts(fake_host):
    """An agent dir on disk (~/.codex) counts as present even with no config
    file yet, so a fresh install still shows up as ungoverned."""
    discovery, home, ws = fake_host
    (home / ".codex").mkdir()
    report = discovery.discover(ws)
    codex = next(a for a in report["agents"] if a["agent"] == "codex")
    assert codex["present"] and not codex["governed"]


def test_mixed_host_summary(fake_host):
    discovery, home, ws = fake_host
    _write(home / ".claude" / "settings.json", '{"hooks": {"PreToolUse": ["prismor hook-dispatch"]}}')
    _write(home / ".codex" / "config.toml", 'model = "gpt"\n')  # present, ungoverned
    (home / ".hermes").mkdir()  # present via CLI marker, ungoverned
    report = discovery.discover(ws)
    s = report["summary"]
    assert s["present"] == 3
    assert s["governed"] == 1
    assert s["ungoverned"] == 2


def test_workspace_config_marker(fake_host):
    """A project-level config with the marker governs that agent too."""
    discovery, home, ws = fake_host
    _write(ws / ".mcp.json", '{"note": "installed via prismor install-hooks"}')
    report = discovery.discover(ws)
    claude = next(a for a in report["agents"] if a["agent"] == "claude")
    assert claude["present"] and claude["governed"]
