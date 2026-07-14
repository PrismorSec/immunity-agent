"""Tool-combination governance — unit + end-to-end tests (customizable tags).

Covers the tagging + per-session ledger (prismor.runtime.trifecta) and the
forbidden-combination enforcement wired into PolicyEngine.evaluate.
"""
import uuid

import pytest

from prismor.runtime.trifecta import (
    UNTRUSTED, CRITICAL, classify_tool_tags, TagLedger, normalize_incompatible,
    TOOL_TAG_DEFAULTS,
)
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.policy_engine import (
    _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES,
)


def _ev(tool, etype, **extra):
    e = {"type": etype, "agent_event": "PreToolUse", "metadata": {"tool_name": tool}}
    e.update(extra)
    return e


# ── tagging ───────────────────────────────────────────────────────────────────

def test_explicit_tags_win_and_support_lists():
    tt = {"tags": {"mcp__Custom__x": ["private_data", "external_comms"]}}
    assert classify_tool_tags(_ev("mcp__Custom__x", "tool_result"), "tool_result", set(), tt) == \
        {"private_data", "external_comms"}


def test_glob_tag_mapping():
    tt = {"tags": {"mcp__*__read_customers": "private_data"}}
    assert classify_tool_tags(_ev("mcp__crm__read_customers", "tool_result"), "tool_result", set(), tt) == \
        {"private_data"}


def test_builtin_defaults():
    assert classify_tool_tags(_ev("WebFetch", "network"), "network", set(), {}) == {UNTRUSTED}
    assert classify_tool_tags(_ev("mcp__Gmail__send_email", "network"), "network", set(), {}) == {CRITICAL}


def test_inference_fallback():
    tt = {"defaults_enabled": False}
    assert classify_tool_tags(_ev("w", "file_write"), "file_write", set(), tt) == {CRITICAL}
    assert classify_tool_tags(_ev("r", "tool_result"), "tool_result", set(), tt) == {UNTRUSTED}
    assert classify_tool_tags(_ev("x", "shell"), "shell", {"destructive_command"}, tt) == {CRITICAL}


def test_neutral_returns_empty():
    tt = {"defaults_enabled": False, "inference_enabled": False}
    assert classify_tool_tags(_ev("mystery", "prompt"), "prompt", set(), tt) == set()


def test_defaults_and_normalize_incompatible():
    for _, _, tags in TOOL_TAG_DEFAULTS:
        assert tags and all(isinstance(t, str) for t in tags)
    # unset -> default red/blue pair; single-tag "sets" dropped
    assert normalize_incompatible(None) == [{UNTRUSTED, CRITICAL}]
    assert normalize_incompatible([["a"]]) == [{UNTRUSTED, CRITICAL}]
    assert normalize_incompatible([["a", "b"], ["c", "d", "e"]]) == [{"a", "b"}, {"c", "d", "e"}]


# ── ledger ────────────────────────────────────────────────────────────────────

def test_ledger_completes_two_tag(tmp_path):
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    rules = [{"a", "b"}]
    assert led.completes({"a"}, rules, 0) is None        # only 1 of 2 present
    led.record({"a"}, 0, "toolA")
    done = led.completes({"b"}, rules, 1)                 # 2nd call (index 1) completes it
    assert done and done["set"] == ["a", "b"] and done["this_call_tags"] == ["b"]
    assert done["introduced_by"]["a"]["tool"] == "toolA"


def test_ledger_completes_three_tag_and_persists(tmp_path):
    sid = "s-" + uuid.uuid4().hex
    rules = [{"a", "b", "c"}]
    led = TagLedger(tmp_path, sid)
    led.record({"a"}, 0, "tA"); led.record({"b"}, 1, "tB")
    # a fresh instance reloads state (separate process in real use)
    led2 = TagLedger(tmp_path, sid)
    assert led2.completes({"a"}, rules, 2) is None        # 'a' already prior, no new completion
    assert led2.completes({"c"}, rules, 2)["set"] == ["a", "b", "c"]  # 'c' (index 2) completes the trio


def test_completes_ignores_current_index_rerecord(tmp_path):
    # The current call's tag may already be recorded at current_index (pre-pass) —
    # it must still count as new, not "already seen".
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    led.record({"a"}, 0, "tA")
    led.record({"b"}, 1, "tB")            # simulate pre-pass recording current call's tag
    done = led.completes({"b"}, [{"a", "b"}], 1)  # authoritative pass, same index 1
    assert done and done["set"] == ["a", "b"]


# ── end-to-end enforcement ────────────────────────────────────────────────────

def _workspace(tmp_path, mode, tags=None, incompatible=None):
    import yaml
    ws = tmp_path / f"ws-{mode}-{uuid.uuid4().hex[:6]}"
    (ws / ".prismor").mkdir(parents=True)
    policy = {"version": "1.0", "settings": {"tool_tags": {
        "enabled": True, "mode": mode,
        "tags": tags or {"mcp__Gmail__read_email": ["untrusted_content"],
                         "mcp__Gmail__send_email": ["critical_action"]},
        "incompatible": incompatible or [["untrusted_content", "critical_action"]],
    }}}
    (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(policy))
    return ws


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))


def _call(ws, sid, tool, etype="network"):
    return evaluate_tool_call(event=_ev(tool, etype), workspace=ws, agent="claude",
                              mode="enforce", session_id=sid, persist=True)


def test_combination_blocks_in_enforce(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_all_untrusted_allowed(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    assert _call(ws, sid, "WebFetch", "network").allow is True


def test_three_tag_rule_blocks_on_completion(tmp_path):
    tags = {"mcp__web__fetch": ["untrusted_content"],
            "mcp__crm__read": ["private_data"],
            "mcp__x__post": ["external_comms"]}
    rule = [["untrusted_content", "private_data", "external_comms"]]
    ws = _workspace(tmp_path, "enforce", tags=tags, incompatible=rule)
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__web__fetch", "tool_result").allow is True   # 1/3
    assert _call(ws, sid, "mcp__crm__read", "tool_result").allow is True    # 2/3
    d = _call(ws, sid, "mcp__x__post", "network")                           # 3/3 completes
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_observe_logs_but_does_not_block(tmp_path):
    ws = _workspace(tmp_path, "observe")
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "mcp__Gmail__read_email", "tool_result")
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is True
    assert any(f.get("category") == "lethal_trifecta" for f in d.findings)


def test_floor_protected():
    assert "tool-category-crossover" in _NON_OVERRIDABLE_RULE_IDS
    assert "lethal_trifecta" in _CORE_BLOCK_CATEGORIES
