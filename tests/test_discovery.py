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


def test_directory_valued_config_can_be_governed(fake_host):
    """Nine registry entries point at a directory, not a file. Reading one
    raises IsADirectoryError, which used to swallow into governed=False — so
    those agents reported as shadow no matter how they were configured, and
    that verdict rides in the signed attestation bundle."""
    discovery, home, ws = fake_host
    plugins = home / ".config" / "opencode" / "plugins"
    _write(plugins / "prismor.js", "// prismor hook-dispatch bridge\n")
    report = discovery.discover(ws)
    opencode = next(a for a in report["agents"] if a["agent"] == "opencode")
    assert opencode["present"] and opencode["governed"]


def test_directory_without_marker_stays_ungoverned(fake_host):
    discovery, home, ws = fake_host
    plugins = home / ".config" / "opencode" / "plugins"
    _write(plugins / "other.js", "// unrelated plugin\n")
    report = discovery.discover(ws)
    opencode = next(a for a in report["agents"] if a["agent"] == "opencode")
    assert opencode["present"] and not opencode["governed"]


def test_glob_config_paths_are_expanded(fake_host):
    """Registry paths like `cli-agents/*.json` were exists()-checked verbatim,
    so a glob could never match and those agents were undetectable."""
    discovery, home, ws = fake_host
    _write(ws / ".amazonq" / "cli-agents" / "default.json",
           '{"hooks": {"preToolUse": "prismor hook-dispatch"}}')
    report = discovery.discover(ws)
    amazonq = next((a for a in report["agents"] if a["agent"] == "amazon-q"), None)
    assert amazonq is not None, "amazon-q missing from the sweep"
    assert amazonq["present"] and amazonq["governed"]


def test_workspace_config_marker(fake_host):
    """A project-level config with the marker governs that agent too."""
    discovery, home, ws = fake_host
    _write(ws / ".mcp.json", '{"note": "installed via prismor install-hooks"}')
    report = discovery.discover(ws)
    claude = next(a for a in report["agents"] if a["agent"] == "claude")
    assert claude["present"] and claude["governed"]


def test_hook_at_the_installers_path_counts_as_governed(fake_host):
    """Regression: `discover --fix` installed Cursor's global hook to
    ~/.cursor/hooks.json, but this sweep only ever inspected ~/.cursor/mcp.json
    (the registry lists no user-scope hook path for Cursor). So a freshly
    hooked Cursor reported as ungoverned forever, and --fix claimed a fix the
    next discover contradicted. Governed must be judged against the paths the
    INSTALLER writes, not only the ones discovery happens to enumerate."""
    discovery, home, ws = fake_host
    _write(home / ".cursor" / "mcp.json", '{"mcpServers": {}}')
    report = discovery.discover(ws)
    cursor = next(a for a in report["agents"] if a["agent"] == "cursor")
    assert cursor["present"] and not cursor["governed"]

    _write(home / ".cursor" / "hooks.json",
           '{"hooks": [{"command": "python -m prismor.runtime.immunity_cli hook-dispatch"}]}')
    report = discovery.discover(ws)
    cursor = next(a for a in report["agents"] if a["agent"] == "cursor")
    assert cursor["governed"], "a hooked agent must not read as shadow"


def test_project_scope_hook_also_counts(fake_host):
    discovery, home, ws = fake_host
    _write(home / ".cursor" / "mcp.json", '{"mcpServers": {}}')
    _write(ws / ".cursor" / "hooks.json",
           '{"hooks": [{"command": "prismor hook-dispatch"}]}')
    report = discovery.discover(ws)
    assert next(a for a in report["agents"] if a["agent"] == "cursor")["governed"]


def test_an_unhookable_agent_never_reads_as_governed(fake_host):
    """Regression: hooks._config_path falls through to the Windsurf path for
    any agent it does not recognise, so asking about warp/trae/antigravity
    returned Windsurf's answer. Every unhookable agent inherited Windsurf's
    hook status and reported as GOVERNED, inflating fleet coverage with
    agents Prismor cannot govern at all."""
    discovery, home, ws = fake_host
    # Windsurf present AND hooked.
    _write(home / ".codeium" / "windsurf" / "mcp_config.json", '{"mcpServers": {}}')
    _write(ws / ".windsurf" / "hooks.json",
           '{"hooks": [{"command": "prismor hook-dispatch"}]}')
    # An agent with no hook surface, merely present.
    (home / ".warp").mkdir(parents=True, exist_ok=True)
    (home / ".trae").mkdir(parents=True, exist_ok=True)

    report = discovery.discover(ws)
    by = {a["agent"]: a for a in report["agents"]}
    assert by["windsurf"]["governed"], "windsurf really is hooked"
    for unhookable in ("warp", "trae"):
        if unhookable in by and by[unhookable]["present"]:
            assert not by[unhookable]["governed"], (
                f"{unhookable} has no hook surface and must never read as governed")


def test_hook_installed_refuses_an_unknown_agent(fake_host):
    from prismor.runtime import hooks
    discovery, home, ws = fake_host
    _write(ws / ".windsurf" / "hooks.json",
           '{"hooks": [{"command": "prismor hook-dispatch"}]}')
    assert hooks.hook_installed("windsurf", "project", ws) is True
    # Same path, different agent name — must not borrow the answer.
    assert hooks.hook_installed("warp", "project", ws) is False
    assert hooks.hook_installed("not-a-real-agent", "project", ws) is False
