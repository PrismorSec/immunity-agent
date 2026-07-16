"""Server-side scope synthesis for enrolled devices.

An org can standardise scoping on one model instead of each machine using its
own ANTHROPIC_API_KEY (or, with no key, silently dropping to keyword
heuristics). The device asks; the org decides whether to answer.

The fallback behaviour is the part that matters: this runs in the
UserPromptSubmit hook, in front of a developer, so nothing here may raise or
hang — an unavailable control plane must simply mean "scope locally".
"""
from __future__ import annotations

import json

import pytest

# Assembled rather than written literally: a bare @@SECRET:...@@ in this file
# is a live cloak placeholder, and the tooling that reads it will try to
# resolve a secret that does not exist.
_PLACEHOLDER = "@@" + "SECRET:AWS_KEY" + "@@"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    # Keep the local Anthropic path out of these tests entirely.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield


def _enrolled(monkeypatch, enrolled=True):
    from prismor.runtime.enterprise import identity as ident
    monkeypatch.setattr(ident, "is_enrolled", lambda: enrolled)
    monkeypatch.setattr(ident, "load_identity", lambda: {
        "device_key": "dk_test", "api_base": "https://prismor.test",
    })
    monkeypatch.setattr(ident, "api_base", lambda: "https://prismor.test")


class _Resp:
    def __init__(self, body):
        self._b = json.dumps(body).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _mock_http(monkeypatch, body=None, boom=None):
    """Capture the outbound request; return ``body`` or raise ``boom``."""
    seen = {}
    import urllib.request

    def fake_urlopen(req, timeout=None):
        seen['url'] = req.full_url
        seen['auth'] = req.headers.get('Authorization')
        seen['payload'] = json.loads(req.data.decode())
        seen['timeout'] = timeout
        if boom:
            raise boom
        return _Resp(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return seen


RULES = {"allowed_tools": ["Read"], "allowed_paths": ["**"], "deny_tools": ["Bash"], "deny_network": True}


# ── The remote path ────────────────────────────────────────────────────────

def test_enrolled_device_uses_the_control_plane(tmp_path, monkeypatch):
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    seen = _mock_http(monkeypatch, {"ok": True, "rules": RULES})
    out = scoped_agent.synthesize_scoped_rules(
        goal="read the config", available_tools=["Bash", "Read"], workspace=tmp_path)
    assert out["allowed_tools"] == ["Read"]
    assert seen['url'] == "https://prismor.test/api/scope"
    assert seen['auth'] == "Bearer dk_test"
    assert seen['payload']["goal"] == "read the config"


def test_unenrolled_device_never_calls_out(tmp_path, monkeypatch):
    """An un-enrolled machine must not phone home about its prompts at all."""
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch, enrolled=False)
    called = {"n": 0}
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    out = scoped_agent.synthesize_scoped_rules(
        goal="read the config", available_tools=["Bash", "Read"], workspace=tmp_path)
    assert called["n"] == 0
    assert out is not None  # fell back locally


def test_context_only_sent_when_given(tmp_path, monkeypatch):
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    seen = _mock_http(monkeypatch, {"ok": True, "rules": RULES})
    scoped_agent.synthesize_scoped_rules(goal="g", available_tools=["Read"], workspace=tmp_path)
    assert "context" not in seen['payload']

    seen2 = _mock_http(monkeypatch, {"ok": True, "rules": RULES})
    scoped_agent.synthesize_scoped_rules(
        goal="g", available_tools=["Read"], workspace=tmp_path,
        context=[{"role": "user", "text": "hi"}])
    assert seen2['payload']["context"] == [{"role": "user", "text": "hi"}]


# ── Falling back ───────────────────────────────────────────────────────────

def test_org_declining_falls_back_locally(tmp_path, monkeypatch):
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    _mock_http(monkeypatch, {"ok": False, "reason": "disabled", "rules": None})
    out = scoped_agent.synthesize_scoped_rules(
        goal="read the config", available_tools=["Bash", "Read"], workspace=tmp_path)
    assert out is not None


def test_unreachable_control_plane_falls_back(tmp_path, monkeypatch):
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    _mock_http(monkeypatch, boom=OSError("connection refused"))
    out = scoped_agent.synthesize_scoped_rules(
        goal="read the config", available_tools=["Bash", "Read"], workspace=tmp_path)
    assert out is not None


def test_garbage_response_falls_back(tmp_path, monkeypatch):
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    _mock_http(monkeypatch, {"ok": True, "rules": {"nonsense": 1}})
    out = scoped_agent.synthesize_scoped_rules(
        goal="read the config", available_tools=["Bash", "Read"], workspace=tmp_path)
    assert out is not None and "allowed_tools" in out


def test_request_is_time_boxed(tmp_path, monkeypatch):
    """It sits in front of the developer's prompt; an unbounded wait is a hang."""
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    seen = _mock_http(monkeypatch, {"ok": True, "rules": RULES})
    scoped_agent.synthesize_scoped_rules(goal="g", available_tools=["Read"], workspace=tmp_path)
    assert seen['timeout'] and seen['timeout'] <= 20


# ── The invariant survives the round trip ──────────────────────────────────

def test_cloak_invariant_reapplied_to_remote_rules(tmp_path, monkeypatch):
    """A server that dropped Bash would otherwise self-block the cloaking flow."""
    from prismor.runtime import scoped_agent
    _enrolled(monkeypatch)
    _mock_http(monkeypatch, {"ok": True, "rules": {
        "allowed_tools": ["Read"], "allowed_paths": ["**"],
        "deny_tools": ["Bash"], "deny_network": True,
    }})
    out = scoped_agent.synthesize_scoped_rules(
        goal=f"deploy using {_PLACEHOLDER}", available_tools=["Bash", "Read"],
        workspace=tmp_path)
    assert "Bash" in out["allowed_tools"]
    assert "Bash" not in out["deny_tools"]
    assert out["deny_network"] is False
