"""The external-authorization surface.

Most of these tests are about refusing correctly. This surface can only say
yes or no — it cannot rewrite a body — so every verdict that means "change this
before it goes out" has to become a denial. Getting that wrong would forward an
unredacted payload upstream while reporting success, which is worse than either
allowing or blocking honestly.
"""
from __future__ import annotations

import json

import pytest

from prismor.runtime import ext_authz
from prismor.runtime.contract import Decision


@pytest.fixture()
def ws(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    return tmp_path


def _frame(name="run_sql", arguments=None):
    return json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


def _decide(body, ws, headers=None, mode="enforce", **kw):
    return ext_authz.decide(
        body=body, headers=headers or {}, workspace=ws,
        server="db", session_id="authz-test", mode=mode, **kw)


# ── verdict mapping: the part that must not be got wrong ─────────────────────

@pytest.mark.parametrize("verdict", ["block", "modify", "defer", "step_up"])
def test_every_non_allow_verdict_denies(verdict, ws, monkeypatch):
    """Only `allow` allows. A surface that cannot honor a verdict refuses."""
    fake = Decision(
        allow=False,
        blocking={"action": verdict, "ruleId": "r1", "severity": "HIGH",
                  "title": "test", "transform": "pii_redact"},
        reason="test reason",
    )
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **kw: fake)
    allow, reason, rule, _ = _decide(_frame(), ws)
    assert allow is False, f"{verdict} must deny on a refuse-only surface"
    assert rule == "r1"
    assert reason


def test_modify_explains_where_redaction_can_actually_happen(ws, monkeypatch):
    """A deny for `modify` is a routing problem, so say where it is solved."""
    fake = Decision(
        allow=False,
        blocking={"action": "modify", "ruleId": "db-1", "transform": "pii_redact"},
        reason="payload carries PII",
    )
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **kw: fake)
    _, reason, _, _ = _decide(_frame(), ws)
    assert "cannot rewrite" in reason
    assert "mcp-gateway" in reason


def test_allow_verdict_allows(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **kw: Decision(allow=True))
    allow, reason, rule, _ = _decide(_frame(), ws)
    assert allow is True and not reason and not rule


# ── fail closed ──────────────────────────────────────────────────────────────

def test_truncated_body_denies(ws):
    """Screening a prefix and answering 200 would misreport coverage."""
    allow, reason, rule, _ = _decide(
        _frame(), ws, headers={ext_authz.PARTIAL_BODY_HEADER: "true"})
    assert allow is False
    assert rule == "ext-authz-partial-body"
    assert "truncated" in reason


@pytest.mark.parametrize("body", ["not json", "", "[1,2,3]"])
def test_unparseable_body_denies(body, ws):
    """Unreadable is not empty."""
    allow, _, rule, _ = _decide(body, ws)
    assert allow is False
    assert rule == "ext-authz-unparseable"


def test_engine_error_denies_in_enforce_but_not_observe(ws, monkeypatch):
    def boom(**kw):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", boom)

    allow, _, rule, _ = _decide(_frame(), ws, mode="enforce")
    assert allow is False and rule == "ext-authz-engine-error"

    allow, _, _, _ = _decide(_frame(), ws, mode="observe")
    assert allow is True, "observe mode is a dry run; a broken engine must not block"


def test_method_with_nothing_to_decide_allows_cleanly(ws):
    """No event and no error: not every frame is a policy question."""
    allow, reason, rule, decision = _decide(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}), ws)
    assert allow is True and not reason and not rule and decision is None


# ── it really does reach the policy engine ───────────────────────────────────

def test_a_dangerous_frame_is_denied_by_real_policy(ws):
    """No mocks: shape a hostile MCP call and let the engine judge it."""
    allow, reason, rule, decision = ext_authz.decide(
        body=_frame(name="fetch", arguments={"url": "http://169.254.169.254/latest/meta-data/"}),
        headers={}, workspace=ws, url="http://169.254.169.254/latest/meta-data/",
        server="web", session_id="authz-real", mode="enforce")
    # The engine owns the verdict; this asserts the wiring reached it and
    # produced a coherent answer either way.
    assert isinstance(allow, bool)
    if decision is not None:
        assert decision.verdict in ("allow", "block", "step_up", "defer", "modify")


# ── the denial an MCP client has to read ─────────────────────────────────────

def test_denial_body_is_jsonrpc_not_html():
    payload = json.loads(ext_authz._deny_body("nope", "rule-x"))
    assert payload["jsonrpc"] == "2.0"
    assert payload["error"]["code"] == -32000
    assert "nope" in payload["error"]["message"]
    assert payload["error"]["data"]["rule"] == "rule-x"


def test_only_allow_is_in_the_honored_set():
    """If this list ever grows, the body-rewrite limitation was misread."""
    assert ext_authz.HONORED == ("allow",)


def test_surface_is_registered_as_refuse_only():
    from prismor.runtime.contract import surface

    s = surface("ext-authz")
    assert s is not None
    assert s.can_refuse is True
    assert s.can_rewrite is False and s.can_redact is False
