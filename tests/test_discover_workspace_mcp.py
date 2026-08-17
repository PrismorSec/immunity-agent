"""Repo-local MCP config is executable authority, not project metadata.

A server declared inside the workspace arrives with the code — a clone, a
branch, a pull request, a dependency's example directory. Whoever can land a
file in the repo names the command the agent will spawn, and that process
inherits the developer's environment. Discovery has to tell "the user asked for
this server" apart from "the checkout did", and only the config's location
carries that distinction.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import discover as disc  # noqa: E402
from prismor.runtime.discover import (  # noqa: E402
    McpRecord,
    _is_workspace_scoped,
    _score_mcp,
    discover_mcp,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    yield


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A checkout that is not the home directory."""
    home = tmp_path / "home"
    ws = tmp_path / "work" / "checkout"
    (ws / ".git").mkdir(parents=True)
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return ws


def _write_mcp(ws: Path, name: str, cfg: dict, rel: str = ".mcp.json") -> Path:
    path = ws / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {name: cfg}}))
    return path


# ── location classification ──────────────────────────────────────────────────

def test_config_inside_the_workspace_is_workspace_scoped(workspace):
    assert _is_workspace_scoped(workspace / ".mcp.json", workspace) is True
    assert _is_workspace_scoped(workspace / ".vscode" / "mcp.json", workspace) is True
    assert _is_workspace_scoped(workspace / ".cursor" / "mcp.json", workspace) is True


def test_user_config_is_not_workspace_scoped(workspace):
    assert _is_workspace_scoped(Path.home() / ".claude.json", workspace) is False
    assert _is_workspace_scoped(Path.home() / ".gemini" / "settings.json",
                                workspace) is False


def test_home_as_workspace_never_counts(tmp_path, monkeypatch):
    """Agent run from ~: everything would qualify, so the signal must go quiet."""
    home = tmp_path / "home"
    home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    assert _is_workspace_scoped(home / ".mcp.json", home) is False
    assert _is_workspace_scoped(home / ".vscode" / "mcp.json", home) is False


def test_workspace_above_home_never_counts(tmp_path, monkeypatch):
    home = tmp_path / "home" / "user"
    home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    assert _is_workspace_scoped(home / ".mcp.json", tmp_path / "home") is False


def test_missing_paths_do_not_raise(workspace):
    assert _is_workspace_scoped(workspace / "nope" / "mcp.json", workspace) is True
    assert _is_workspace_scoped(Path("/definitely/not/here.json"), workspace) is False


# ── scoring ──────────────────────────────────────────────────────────────────

def _record(**kw):
    base = dict(name="s", agent="claude-code", source="/w/.mcp.json")
    base.update(kw)
    return McpRecord(**base)


def test_repo_supplied_command_is_high_risk():
    rec = _record(command=["node", "./scripts/mcp-server.js"], workspace_scoped=True)
    _score_mcp(rec, {})

    assert rec.risk == "high"
    assert "declared by a file in this workspace" in rec.findings[0]
    assert "runs with your environment" in rec.findings[0]


def test_repo_supplied_remote_endpoint_is_medium_risk():
    rec = _record(url="https://mcp.example.com/mcp", remote=True,
                  workspace_scoped=True)
    _score_mcp(rec, {})

    assert rec.risk == "medium"
    assert "travels with the checkout" in rec.findings[0]


def test_user_declared_command_is_not_escalated():
    rec = _record(command=["node", "server.js"], workspace_scoped=False)
    _score_mcp(rec, {})

    assert rec.risk == "none"
    assert rec.findings == []


def test_the_gateway_entry_itself_is_exempt():
    """Pointing at Prismor is the governed outcome, not a risk."""
    rec = _record(command=["prismor", "mcp-gateway"], workspace_scoped=True,
                  is_gateway=True)
    _score_mcp(rec, {})

    assert rec.risk == "none"
    assert rec.findings == []


def test_repo_local_reason_is_listed_first():
    """It explains the others: the whole file is attacker-supplied."""
    rec = _record(command=["node", "s.js"], url="https://x.example.com",
                  remote=True, workspace_scoped=True)
    _score_mcp(rec, {})

    assert rec.findings[0].startswith("declared by a file in this workspace")


# ── end to end ───────────────────────────────────────────────────────────────

def test_discover_flags_a_repo_local_stdio_server(workspace, monkeypatch):
    _write_mcp(workspace, "planted", {"command": "node",
                                      "args": ["./.hidden/mcp.js"]})
    records = {r.name: r for r in discover_mcp(workspace)}

    assert "planted" in records, "repo-local server was not discovered at all"
    rec = records["planted"]
    assert rec.workspace_scoped is True
    assert rec.risk == "high"
    assert any("declared by a file in this workspace" in f for f in rec.findings)


def test_discover_leaves_user_scoped_servers_alone(workspace, monkeypatch):
    """A server the developer added themselves must not become a warning."""
    user_cfg = Path.home() / ".mcp.json"
    user_cfg.parent.mkdir(parents=True, exist_ok=True)
    user_cfg.write_text(json.dumps({"mcpServers": {
        "mine": {"command": "node", "args": ["server.js"]}}}))

    records = {r.name: r for r in discover_mcp(workspace)}
    rec = records.get("mine")
    if rec is not None:      # only asserted when this path is scanned at all
        assert rec.workspace_scoped is False
        assert rec.risk != "high"


def test_record_serializes_the_new_field(workspace):
    from dataclasses import asdict

    _write_mcp(workspace, "planted", {"command": "node", "args": ["x.js"]})
    records = discover_mcp(workspace)
    payload = [asdict(r) for r in records]

    assert any(r["workspace_scoped"] for r in payload)
    assert json.loads(json.dumps({"mcp": payload}))   # report-shaped, serializable
