"""Lethal-trifecta red/blue crossover — unit + end-to-end tests.

Covers the classifier and per-session ledger (prismor.runtime.trifecta) and the
crossover enforcement wired into PolicyEngine.evaluate via evaluate_tool_call.
"""
import uuid

import pytest

from prismor.runtime.trifecta import (
    RED, BLUE, classify_tool_category, CategoryLedger, TOOL_CATEGORY_DEFAULTS,
)
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.policy_engine import (
    _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES,
)


def _ev(tool, etype, **extra):
    e = {"type": etype, "agent_event": "PreToolUse", "metadata": {"tool_name": tool}}
    e.update(extra)
    return e


# ── classifier ────────────────────────────────────────────────────────────────

def test_classify_explicit_map_wins():
    tc = {"map": {"mcp__Custom__thing": "blue"}}
    assert classify_tool_category(_ev("mcp__Custom__thing", "tool_result"), "tool_result", set(), tc) == BLUE


def test_classify_builtin_defaults():
    assert classify_tool_category(_ev("WebFetch", "network"), "network", set(), {}) == RED
    assert classify_tool_category(_ev("mcp__Gmail__send_email", "network"), "network", set(), {}) == BLUE
    assert classify_tool_category(_ev("mcp__Gmail__read_email", "tool_result"), "tool_result", set(), {}) == RED


def test_classify_inference_fallback():
    tc = {"defaults_enabled": False}  # force inference
    assert classify_tool_category(_ev("some_writer", "file_write"), "file_write", set(), tc) == BLUE
    assert classify_tool_category(_ev("some_reader", "tool_result"), "tool_result", set(), tc) == RED
    # a finding category that marks a critical action → blue
    assert classify_tool_category(_ev("x", "shell"), "shell", {"destructive_command"}, tc) == BLUE


def test_classify_neutral_returns_none():
    tc = {"defaults_enabled": False, "inference_enabled": False}
    assert classify_tool_category(_ev("mystery", "prompt"), "prompt", set(), tc) is None


def test_defaults_are_all_red_or_blue():
    for _, _, cat in TOOL_CATEGORY_DEFAULTS:
        assert cat in (RED, BLUE)


# ── ledger ────────────────────────────────────────────────────────────────────

def test_ledger_crosses_and_persists(tmp_path):
    sid = "sess-" + uuid.uuid4().hex
    led = CategoryLedger(tmp_path, sid)
    assert led.crosses(RED) is None and led.crosses(BLUE) is None
    led.record(RED, 0, "read_email")
    assert led.crosses(RED) is None            # same category never crosses
    assert led.crosses(BLUE) == {"index": 0, "tool": "read_email"}  # opposite crosses
    # a fresh instance reloads persisted state (separate process in real use)
    led2 = CategoryLedger(tmp_path, sid)
    assert led2.red is True and led2.crosses(BLUE)["tool"] == "read_email"


# ── end-to-end enforcement ────────────────────────────────────────────────────

def _workspace(tmp_path, mode):
    ws = tmp_path / f"ws-{mode}"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(
        "version: '1.0'\n"
        "settings:\n"
        "  tool_categories:\n"
        "    enabled: true\n"
        f"    mode: {mode}\n"
        "    map:\n"
        "      mcp__Gmail__read_email: red\n"
        "      mcp__Gmail__send_email: blue\n"
    )
    return ws


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    # Ledger lives in the central data dir ($PRISMOR_HOME) — isolate per test.
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))


def _call(ws, sid, tool, etype="network"):
    return evaluate_tool_call(
        event=_ev(tool, etype), workspace=ws, agent="claude",
        mode="enforce", session_id=sid, persist=True,
    )


def test_crossover_blocks_in_enforce(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    d1 = _call(ws, sid, "mcp__Gmail__read_email", "tool_result")   # red
    assert d1.allow is True
    d2 = _call(ws, sid, "mcp__Gmail__send_email", "network")       # blue → crossover
    assert d2.allow is False
    assert d2.blocking and d2.blocking["category"] == "lethal_trifecta"


def test_all_red_session_allowed(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    assert _call(ws, sid, "WebFetch", "network").allow is True     # red default
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True


def test_all_blue_session_allowed(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__send_email", "network").allow is True
    assert _call(ws, sid, "mcp__github__create_pull_request", "tool_result").allow is True


def test_observe_mode_logs_but_does_not_block(tmp_path):
    ws = _workspace(tmp_path, "observe")
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "mcp__Gmail__read_email", "tool_result")        # red
    d2 = _call(ws, sid, "mcp__Gmail__send_email", "network")       # blue → crossover, logged
    assert d2.allow is True                                        # observe never blocks
    assert any(f.get("category") == "lethal_trifecta" for f in d2.findings)


def test_crossover_is_floor_protected():
    assert "tool-category-crossover" in _NON_OVERRIDABLE_RULE_IDS
    assert "lethal_trifecta" in _CORE_BLOCK_CATEGORIES
