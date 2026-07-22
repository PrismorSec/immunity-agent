#!/usr/bin/env python3
"""Tool-combination governance — live enforcement demo (customizable tags).

Drives crafted tool-call sequences through the REAL Prismor decision path
(``prismor.runtime.runtime.evaluate_tool_call`` — the same function the Claude
Code hook and every adapter funnel into) and prints ALLOW / BLOCK per call.

Tools carry customizable TAGS; a session may not COMPLETE a forbidden tag set
(``incompatible``). The call that completes one is blocked before it executes.
Red/blue is just the default rule [untrusted_content, critical_action]; you can
define any tags and any N-tag combination (see scenario 4, a 3-tag rule).

Run via demo.sh (sets PYTHONPATH), or:
    PYTHONPATH=/path/to/prismor python3 examples/lethal-trifecta/demo.py
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

from prismor.runtime.runtime import evaluate_tool_call

RUN = uuid.uuid4().hex[:8]  # salt session ids so each run starts from a clean ledger

_TTY = os.isatty(1)
def _c(code, s): return f"\033[{code}m{s}\033[0m" if _TTY else s
BOLD = lambda s: _c("1", s)
DIM = lambda s: _c("2", s)
GREEN = lambda s: _c("32", s)
TAGCOL = lambda s: _c("36", s)


def make_workspace(mode: str, tags: dict, incompatible: list,
                   rules: list | None = None) -> Path:
    ws = Path(tempfile.mkdtemp(prefix=f"trifecta-{mode}-"))
    (ws / ".prismor").mkdir(parents=True, exist_ok=True)
    tt = {
        "enabled": True,
        "mode": mode,               # observe | enforce
        "detector": "strict_combination",
        "defaults_enabled": True,
        "inference_enabled": True,
        "tags": tags,               # {} -> rely on built-in defaults
        "incompatible": incompatible,
    }
    if rules is not None:
        tt["rules"] = rules         # tag-rule expressions (policy as code)
    policy = {"version": "1.0", "settings": {"tool_tags": tt}}
    try:
        import yaml
        (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(policy))
    except Exception:
        (ws / ".prismor" / "policy.yaml").write_text(json.dumps(policy))
    return ws


def ev(tool: str, etype: str, **extra) -> dict:
    e = {"type": etype, "agent_event": "PreToolUse", "metadata": {"tool_name": tool}}
    e.update(extra)
    return e


CALLS = {
    "read_email": ev("mcp__Gmail__read_email", "tool_result", response="<inbox body>"),
    "read_cal":   ev("mcp__Gcal__read_calendar", "tool_result", response="<invite>"),
    "web_fetch":  ev("WebFetch", "network", url="https://example.com/doc", response="<page>"),
    "send_email": ev("mcp__Gmail__send_email", "network", url="https://gmail.googleapis.com/send"),
    "create_pr":  ev("mcp__github__create_pull_request", "tool_result", response="<pr>"),
    "post_msg":   ev("mcp__slack__post_message", "network", url="https://slack.com/api/chat.postMessage"),
    # scenario 4 (custom 3-tag rule):
    "fetch_page": ev("mcp__web__fetch_page", "tool_result", response="<scraped page>"),
    "read_cust":  ev("mcp__crm__read_customers", "tool_result", response="<customer rows>"),
    "post_ext":   ev("mcp__slack__post_external", "network", url="https://hooks.slack.com/x"),
}
NAME = {
    "read_email": "read_email", "read_cal": "read_calendar", "web_fetch": "WebFetch",
    "send_email": "send_email", "create_pr": "create_pull_request", "post_msg": "post_message",
    "fetch_page": "web.fetch_page", "read_cust": "crm.read_customers", "post_ext": "slack.post_external",
}


def run_session(title: str, ws: Path, sid: str, steps: list) -> None:
    print(BOLD(f"\n{title}"))
    for i, key in enumerate(steps, 1):
        d = evaluate_tool_call(
            event=dict(CALLS[key]), workspace=ws, agent="claude",
            mode="enforce", session_id=f"{RUN}-{sid}", persist=True,
        )
        crossover = next((f for f in d.findings if f.get("category") == "lethal_trifecta"), None)
        if not d.allow:
            verdict, note = _c("41;97", " BLOCK "), "  <- blocked BEFORE execution (terminal)"
        elif crossover:
            verdict, note = _c("43;30", " OBSERVE "), "  <- combination logged, not blocked (observe)"
        else:
            verdict, note = GREEN(" ALLOW "), ""
        print(f"  [{i}] {NAME[key]:<20} {verdict}{note}")
        if crossover:
            print(DIM(f"        {crossover['title']}"))


def main() -> int:
    print(BOLD("=== Prismor tool-combination governance — live enforcement ==="))
    print(DIM("  tags are customizable; a session may not complete a forbidden tag set"))

    # Default red/blue rule: [untrusted_content, critical_action], built-in tags.
    ws_enf = make_workspace("enforce", {}, [["untrusted_content", "critical_action"]])
    ws_obs = make_workspace("observe", {}, [["untrusted_content", "critical_action"]])

    # Custom 3-tag rule with custom tags — shows the model is not limited to red/blue.
    three_tags = {
        "mcp__web__fetch_page": ["untrusted_content"],
        "mcp__crm__read_customers": ["private_data"],
        "mcp__slack__post_external": ["external_comms"],
    }
    ws_3 = make_workspace(
        "enforce", three_tags,
        [["untrusted_content", "private_data", "external_comms"]])

    run_session("1. Inbox exfil — read_email then send_email  [rule: untrusted+critical]",
                ws_enf, "inbox", ["read_email", "send_email"])
    run_session("2. Benign all-untrusted session — email, calendar, web",
                ws_enf, "allred", ["read_email", "read_cal", "web_fetch"])
    run_session("3. Benign all-critical session — send, PR, post",
                ws_enf, "allblue", ["send_email", "create_pr", "post_msg"])
    run_session("4. Custom 3-TAG rule — fetch, read customers, THEN post externally",
                ws_3, "three", ["fetch_page", "read_cust", "post_ext"])
    run_session("5. Same as #1 but OBSERVE-first — logs, does not block",
                ws_obs, "observe", ["read_email", "send_email"])

    # ORDERED rule (tag-rule expression): critical FIRST is fine; only a
    # critical action AFTER untrusted content fires.
    ws_ord = make_workspace(
        "enforce", {}, [],
        rules=["untrusted_content then critical_action -> block"])
    run_session('6. ORDERED rule "untrusted then critical" — send, read, send',
                ws_ord, "ordered", ["send_email", "read_email", "send_email"])

    # WARN rule: same sequence logs a finding but never blocks, even in enforce.
    ws_warn = make_workspace(
        "enforce", {}, [],
        rules=["untrusted_content then critical_action -> warn"])
    run_session('7. WARN rule — same sequence, logged but never blocked',
                ws_warn, "warn", ["read_email", "send_email"])

    print(BOLD("\n=== summary ==="))
    print("  same-tag sessions (#2, #3) stay frictionless — no blocks.")
    print("  the call that COMPLETES a forbidden set is blocked (#1 = 2-tag, #4 = 3-tag).")
    print("  observe mode (#5) logs the combination without blocking (safe rollout).")
    print("  ordered rules (#6) allow critical-first patterns; only untrusted->critical fires.")
    print("  warn rules (#7) log the finding but never block, even in enforce.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
