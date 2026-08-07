"""Tests for the shadow-AI inventory (runtime/discover.py).

Covers the two surfaces ``enterprise/discovery.py`` does not: MCP servers not
routed through the gateway, and provider credentials not registered with Cloak.
Plus the redaction layer, which matters more than the inventory itself — MCP
server URLs routinely carry the caller's key in a path segment, and this report
is rendered to a terminal and serialized to JSON.

Isolated with a fake home + workspace; no real machine state is read.
Run: python3 -m pytest tests/test_discover_shadow.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))


@pytest.fixture()
def fake_host(tmp_path, monkeypatch):
    """A fake $HOME with no agents, plus a workspace, with Cloak and the
    gateway pointed somewhere empty so nothing reads the real machine."""
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PRISMOR_HOME", str(home / ".prismor"))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(home / ".prismor" / "secrets"))
    for mod in ("prismor.runtime.discover", "prismor.runtime.scanner",
                "prismor.runtime.enterprise.discovery"):
        sys.modules.pop(mod, None)
    from prismor.runtime import discover
    # No gateway config unless a test writes one.
    monkeypatch.setattr(discover, "_gateway_servers", lambda: set())
    return discover, home, ws


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(text, encoding="utf-8")


# ── redaction ────────────────────────────────────────────────────────────────

def test_redact_url_masks_credential_path_segment(fake_host):
    discover, _, _ = fake_host
    url = "https://mcp.example.dev/mcp/prism_agent_ae35779540e0c918f6baadadfa47908"
    out = discover.redact_url(url)
    assert "prism_agent_ae35779540e0c918f6baadadfa47908" not in out
    assert out.startswith("https://mcp.example.dev/mcp/")
    assert "<redacted>" in out


def test_redact_url_masks_query_and_userinfo(fake_host):
    discover, _, _ = fake_host
    out = discover.redact_url("https://u:pw@x.dev/mcp?api_key=abc123def456&mode=fast")
    assert "pw" not in out.split("@")[0].replace("https://", "") or "<redacted>" in out
    assert "abc123def456" not in out
    assert "mode=fast" in out  # non-secret params survive


def test_redact_leaves_benign_paths_alone(fake_host):
    """Over-redaction would make the report useless — these must survive."""
    discover, _, _ = fake_host
    assert discover.redact_url("https://developers.openai.com/mcp") == \
        "https://developers.openai.com/mcp"
    assert discover.redact_command(["npx", "-y", "get-an-expert-agent@latest"]) == \
        ["npx", "-y", "get-an-expert-agent@latest"]
    assert discover.redact_command(["/usr/local/bin/node_repl"]) == \
        ["/usr/local/bin/node_repl"]


def test_redact_masks_jwt_and_base64_tokens(fake_host):
    """Bearer tokens on MCP endpoints are usually JWTs or base64 blobs, and
    neither matches the plain token pattern — dots and +/= break it."""
    import base64
    discover, _, _ = fake_host
    jwt = ".".join([
        base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("="),
        base64.urlsafe_b64encode(b'{"sub":"1234567890"}').decode().rstrip("="),
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ])
    blob = base64.b64encode(b"secret+token/value==1234567890abcdefghij").decode()
    for token in (jwt, blob):
        out = discover.redact_url("https://x.dev/mcp/" + token)
        assert token not in out, f"{token[:16]}... survived redaction"
        assert "<redacted>" in out


def test_redact_command_masks_flag_values(fake_host):
    discover, _, _ = fake_host
    out = discover.redact_command(
        ["server", "--api-key", "sk-abcdef0123456789abcdef", "--port", "8080"])
    assert "sk-abcdef0123456789abcdef" not in out
    assert "8080" in out


def test_mcp_record_never_carries_the_raw_url(fake_host):
    """Redaction must happen at record construction, not at render time."""
    discover, home, ws = fake_host
    secret = "prism_agent_ae35779540e0c918f6baadadfa47908"
    _write(ws / ".mcp.json",
           {"mcpServers": {"remote": {"url": f"https://x.dev/mcp/{secret}"}}})
    records = discover.discover_mcp(ws)
    assert records, "expected the workspace .mcp.json server to be found"
    assert secret not in json.dumps([r.__dict__ for r in records])


# ── MCP inventory ────────────────────────────────────────────────────────────

def test_ungoverned_mcp_server_is_shadow(fake_host):
    discover, home, ws = fake_host
    _write(ws / ".mcp.json",
           {"mcpServers": {"weather": {"command": "npx", "args": ["weather-mcp"]}}})
    records = discover.discover_mcp(ws)
    weather = next(r for r in records if r.name == "weather")
    assert weather.shadow and not weather.managed


def test_gateway_routed_server_is_governed(fake_host, monkeypatch):
    discover, home, ws = fake_host
    monkeypatch.setattr(discover, "_gateway_servers", lambda: {"weather"})
    _write(ws / ".mcp.json",
           {"mcpServers": {"weather": {"command": "npx", "args": ["weather-mcp"]}}})
    records = discover.discover_mcp(ws)
    weather = next(r for r in records if r.name == "weather")
    assert weather.managed and not weather.shadow


def test_gateway_entry_is_not_its_own_shadow_finding(fake_host):
    """The gateway proxy entry itself must not be counted as a shadow server."""
    discover, home, ws = fake_host
    _write(ws / ".mcp.json", {"mcpServers": {
        "prismor-gateway": {"command": "prismor", "args": ["mcp-gateway", "serve"]}}})
    records = discover.discover_mcp(ws)
    gw = next(r for r in records if r.name == "prismor-gateway")
    assert gw.is_gateway and not gw.shadow


def test_remote_server_floors_at_medium_risk(fake_host):
    discover, home, ws = fake_host
    _write(ws / ".mcp.json", {"mcpServers": {"remote": {"url": "https://x.dev/mcp"}}})
    remote = next(r for r in discover.discover_mcp(ws) if r.name == "remote")
    assert remote.remote and remote.risk in ("medium", "high")


# ── credentials ──────────────────────────────────────────────────────────────

def test_env_key_without_cloak_is_shadow(fake_host, monkeypatch):
    discover, home, ws = fake_host
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key-0123456789")
    creds = discover.discover_credentials(ws, scan_files=False)
    entry = next(c for c in creds if c.location == "ANTHROPIC_API_KEY")
    assert entry.provider == "anthropic" and entry.shadow


def test_cloaked_key_is_governed(fake_host, monkeypatch):
    discover, home, ws = fake_host
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key-0123456789")
    monkeypatch.setattr(discover, "_cloak_names", lambda: {"openai_api_key"})
    creds = discover.discover_credentials(ws, scan_files=False)
    entry = next(c for c in creds if c.location == "OPENAI_API_KEY")
    assert entry.managed and not entry.shadow


def test_credential_records_carry_no_value(fake_host, monkeypatch):
    discover, home, ws = fake_host
    secret = "sk-ant-do-not-leak-0123456789abcdef"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    creds = discover.discover_credentials(ws, scan_files=False)
    assert secret not in json.dumps([c.__dict__ for c in creds])


def test_empty_env_var_is_not_reported(fake_host, monkeypatch):
    discover, home, ws = fake_host
    monkeypatch.setenv("GROQ_API_KEY", "   ")
    creds = discover.discover_credentials(ws, scan_files=False)
    assert not any(c.location == "GROQ_API_KEY" for c in creds)


# ── report ───────────────────────────────────────────────────────────────────

def test_coverage_is_none_when_nothing_governable(fake_host, monkeypatch):
    """A clean machine must read as 'nothing to govern', not a false 100%."""
    discover, home, ws = fake_host
    monkeypatch.setattr(discover, "discover_agents", lambda w: [])
    monkeypatch.setattr(discover, "discover_mcp", lambda w: [])
    monkeypatch.setattr(discover, "discover_credentials",
                        lambda w, scan_files=True: [])
    assert discover.build_report(ws)["summary"]["coverage"] is None


def test_report_counts_shadow_across_all_three_surfaces(fake_host, monkeypatch):
    discover, home, ws = fake_host
    monkeypatch.setenv("MISTRAL_API_KEY", "not-a-real-key-0123456789")
    _write(ws / ".mcp.json",
           {"mcpServers": {"weather": {"command": "npx", "args": ["weather-mcp"]}}})
    report = discover.build_report(ws)
    summary = report["summary"]
    assert summary["mcp_shadow"] >= 1
    assert summary["credentials_shadow"] >= 1
    assert summary["coverage"] is not None and summary["coverage"] < 100


def test_agents_delegate_to_the_attested_sweep(fake_host, monkeypatch):
    """The agent half must come from enterprise.discovery so this view and the
    signed attestation bundle can never disagree."""
    discover, home, ws = fake_host
    called = {}

    def fake_discover(workspace):
        called["hit"] = True
        return {"agents": [{"agent": "claude", "present": True, "governed": False,
                            "seen": False, "last_seen": None,
                            "config_paths": [str(home / ".claude" / "settings.json")]}],
                "summary": {}}

    from prismor.runtime.enterprise import discovery as _discovery
    monkeypatch.setattr(_discovery, "discover", fake_discover)
    records = discover.discover_agents(ws)
    assert called.get("hit")
    assert [r.id for r in records] == ["claude"]
    assert records[0].shadow
