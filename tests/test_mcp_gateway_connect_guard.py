"""The gateway must screen a remote upstream before it dials it.

`initialize` and `tools/list` run automatically at startup, with the gateway's
own network position, before any tool call exists to evaluate. If policy is
only consulted at tools/call time then registering a server is itself an
execution path — pointing an upstream at an internal address reaches it during
discovery and the tool surface never has to be used at all.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import egress as egress_mod  # noqa: E402
from prismor.runtime.egress import Destination, EgressPolicy  # noqa: E402
from prismor.runtime.mcp_gateway import (  # noqa: E402
    Gateway,
    UpstreamError,
    UpstreamHttp,
    UpstreamSpec,
    make_upstream,
)
from prismor.runtime.runtime import Decision  # noqa: E402


REMOTE = UpstreamSpec(name="linear", url="https://mcp.linear.app/mcp",
                      transport="http")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    yield


@pytest.fixture
def no_socket(monkeypatch):
    """Any actual outbound connection fails the test loudly."""
    opened = []

    def _boom(*args, **kwargs):
        opened.append(args[0] if args else None)
        raise AssertionError("gateway opened a socket before policy allowed it")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    return opened


# ── the guard fires before the socket ────────────────────────────────────────

def test_denied_upstream_is_refused_before_any_connection(no_socket):
    def guard(spec):
        raise UpstreamError(f"refused: {spec.name}")

    up = UpstreamHttp(REMOTE, None, guard)

    with pytest.raises(UpstreamError, match="refused: linear"):
        up.request("initialize", {})
    assert no_socket == []


def test_notifications_are_guarded_too(no_socket):
    """notify() posts as well; an unguarded path is an unguarded path."""
    def guard(spec):
        raise UpstreamError("refused")

    up = UpstreamHttp(REMOTE, None, guard)
    up.notify("notifications/initialized", {})   # swallows UpstreamError by design

    assert no_socket == []


def test_allowed_upstream_connects(monkeypatch):
    calls = []

    class _Resp:
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b'{"jsonrpc":"2.0","id":"gw-1","result":{"ok":true}}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=None: calls.append(req.full_url) or _Resp())
    up = UpstreamHttp(REMOTE, None, lambda spec: None)

    assert up.request("initialize", {}) == {"ok": True}
    assert calls == ["https://mcp.linear.app/mcp"]


def test_stdio_upstreams_get_no_guard():
    """A local command has no URL to screen; the guard must not be wired in."""
    spec = UpstreamSpec(name="local", command=["true"], transport="stdio")
    up = make_upstream(spec, None, lambda s: None)

    assert up.guard is None


# ── the Gateway's own guard ──────────────────────────────────────────────────

def _gateway(tmp_path, monkeypatch, mode="enforce"):
    gateway = Gateway([REMOTE], workspace=tmp_path, mode=mode)
    monkeypatch.setattr(gateway, "_send", lambda msg: None)
    return gateway


def test_gateway_guard_blocks_on_a_blocking_decision(tmp_path, monkeypatch, no_socket):
    monkeypatch.setattr(
        "prismor.runtime.runtime.evaluate_tool_call",
        lambda **k: Decision(allow=False, blocking={
            "severity": "high",
            "title": "Outbound request to destination not on the egress allowlist",
            "ruleId": "egress-allowlist"}))
    gateway = _gateway(tmp_path, monkeypatch)

    with pytest.raises(UpstreamError) as exc:
        gateway.upstreams[0].request("tools/list", {})

    assert "refused before connect" in str(exc.value)
    assert "egress-allowlist" in str(exc.value)
    assert no_socket == []


def test_guard_screens_the_url_as_a_network_event(tmp_path, monkeypatch, no_socket):
    seen = []

    def _eval(**kwargs):
        seen.append(kwargs["event"])
        return Decision(allow=False, blocking={"title": "denied"})

    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gateway = _gateway(tmp_path, monkeypatch)

    with pytest.raises(UpstreamError):
        gateway.upstreams[0].request("initialize", {})

    assert len(seen) == 1
    event = seen[0]
    # A network event carrying the URL is what the egress policy screens.
    assert event["type"] == "network"
    assert event["url"] == "https://mcp.linear.app/mcp"
    assert event["agent_event"] == "PreToolUse"
    assert event["metadata"]["tool_name"] == "mcp__linear__connect"


def test_verdict_is_memoized_per_upstream(tmp_path, monkeypatch, no_socket):
    calls = []

    def _eval(**kwargs):
        calls.append(kwargs)
        return Decision(allow=False, blocking={"title": "denied"})

    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gateway = _gateway(tmp_path, monkeypatch)
    up = gateway.upstreams[0]

    for _ in range(4):
        with pytest.raises(UpstreamError):
            up.request("tools/list", {})

    assert len(calls) == 1, "policy re-run on every JSON-RPC message"


def test_allowed_upstream_is_evaluated_once_then_left_alone(tmp_path, monkeypatch):
    calls = []

    class _Resp:
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b'{"jsonrpc":"2.0","id":"gw-1","result":{}}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _Resp())
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: calls.append(k) or Decision(allow=True))
    gateway = _gateway(tmp_path, monkeypatch)
    up = gateway.upstreams[0]
    up.request("initialize", {})
    up.request("tools/list", {})

    assert len(calls) == 1


def test_observe_mode_does_not_block(tmp_path, monkeypatch):
    """Observe mode reports; it does not sever the connection."""
    class _Resp:
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b'{"jsonrpc":"2.0","id":"gw-1","result":{}}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _Resp())
    # observe-mode decisions carry findings but no `blocking`
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: Decision(allow=True))
    gateway = _gateway(tmp_path, monkeypatch, mode="observe")

    assert gateway.upstreams[0].request("initialize", {}) == {}


# ── the policy that actually backs it ────────────────────────────────────────

def test_egress_policy_denies_a_gateway_url_aimed_at_imds(monkeypatch):
    """End to end on the policy side: the event the guard builds gets denied."""
    monkeypatch.setattr(egress_mod, "_raw_resolve",
                        lambda h: ("169.254.169.254",) if h == "mcp.evil.test" else ())
    egress_mod._resolve_cache.clear()
    pol = EgressPolicy.from_settings({"egress": {
        "enabled": True, "mode": "enforce", "default": "allow",
        "deny": [{"host": "169.254.0.0/16", "reason": "link-local"}],
    }}, source="remote")

    event = {"type": "network", "url": "https://mcp.evil.test/mcp"}
    findings = pol.evaluate(event, 0, default_mode="enforce")

    assert len(findings) == 1
    assert findings[0]["action"] == "block"
    assert pol.verdict(Destination("mcp.evil.test", scheme="https"))[0] == "deny"
    egress_mod._resolve_cache.clear()
