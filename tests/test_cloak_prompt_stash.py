"""Tests for the sanitized-prompt stash in userprompt-guard.sh.

Claude Code cannot rewrite a prompt from a UserPromptSubmit hook, so when the
guard detects a secret it blocks and stashes the sanitized prompt. The user's
next clean message in the same session then reloads the stash as
`additionalContext`, so nobody has to re-paste. These tests exercise the
block -> stash -> reload lifecycle in isolation.

Run:  python3 tests/test_cloak_prompt_stash.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

_HOME = Path(tempfile.mkdtemp(prefix="prismor-test-"))
_SECRETS = _HOME / "secrets"
_SECRETS.mkdir(parents=True)
_STASH = _HOME / "prompt_stash"
os.environ["PRISMOR_HOME"] = str(_HOME)
os.environ["PRISMOR_SECRETS_DIR"] = str(_SECRETS)
os.environ["PRISMOR_PROMPT_STASH_DIR"] = str(_STASH)

_GUARD = _REPO / "prismor" / "runtime" / "cloaking" / "hooks" / "userprompt-guard.sh"
# Synthetic JWT-shaped canary, assembled at runtime so no literal token sits in
# this file (the cloaking Write guard would otherwise vault it).
_JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJDQU5BUlkiLCJpYXQiOjB9",
                 "CANARYsignatureCANARYsignature"])
_PROMPT = f"curl https://example.test/api -b '__session={_JWT}' why does this 401?"

_passed = 0
_failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  PASS  {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}  {detail}")


def run(prompt: str, session: str = "sess-A") -> dict | None:
    payload = {"prompt": prompt, "cwd": str(_HOME), "session_id": session}
    proc = subprocess.run(["bash", str(_GUARD)], input=json.dumps(payload),
                          capture_output=True, text=True, env=os.environ)
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def blocked(res) -> bool:
    return bool(res) and res.get("decision") == "block"


def context_of(res) -> str:
    return ((res or {}).get("hookSpecificOutput") or {}).get("additionalContext", "")


def test_block_stashes_sanitized():
    res = run(_PROMPT)
    check("secret prompt is blocked", blocked(res), str(res))
    reason = res.get("reason", "") if res else ""
    check("raw value absent from block reason", _JWT not in reason)
    check("reason mentions auto-load", "load it automatically" in reason, reason[:200])
    stash = _STASH / "sess-A"
    check("stash file written", stash.is_file())
    body = stash.read_text() if stash.is_file() else ""
    check("stash holds sanitized prompt", "@@SECRET:auto_" in body and _JWT not in body, body[:200])
    check("stash is 0600", stash.is_file() and (stash.stat().st_mode & 0o777) == 0o600)


def test_followup_reloads_and_clears():
    res = run("go", session="sess-A")
    ctx = context_of(res)
    check("follow-up gets additionalContext", bool(ctx), str(res)[:200])
    check("context carries sanitized prompt", "@@SECRET:auto_" in ctx and "why does this 401?" in ctx)
    check("context never carries raw value", _JWT not in ctx)
    check("stash consumed", not (_STASH / "sess-A").exists())
    res2 = run("and then?", session="sess-A")
    check("second follow-up injects nothing", res2 is None, str(res2))


def test_stash_is_per_session():
    run(_PROMPT, session="sess-B")
    res = run("hello", session="sess-C")
    check("other session sees no stash", res is None, str(res))
    check("sess-B stash still present", (_STASH / "sess-B").is_file())
    res = run("go", session="sess-B")
    check("owning session reloads", "@@SECRET:auto_" in context_of(res))


def test_reblock_overwrites_stash_without_reload():
    run(_PROMPT, session="sess-D")
    res = run(_PROMPT + " (again)", session="sess-D")
    check("re-sent raw prompt is blocked again", blocked(res))
    body = (_STASH / "sess-D").read_text()
    check("stash updated to latest sanitized prompt", "(again)" in body and _JWT not in body)
    res = run("ok", session="sess-D")
    check("reload after re-block carries latest", "(again)" in context_of(res))


def test_pasted_sanitized_prompt_not_duplicated():
    res = run(_PROMPT, session="sess-E")
    sanitized = res["reason"].split("---\n")[1].rstrip("\n-")
    res = run(sanitized, session="sess-E")
    check("pasting sanitized prompt passes clean", res is None, str(res)[:200])
    check("stash cleared after paste", not (_STASH / "sess-E").exists())


def test_expired_stash_is_dropped():
    run(_PROMPT, session="sess-F")
    old = time.time() - 7200
    os.utime(_STASH / "sess-F", (old, old))
    res = run("go", session="sess-F")
    check("expired stash not injected", res is None, str(res))
    check("expired stash removed", not (_STASH / "sess-F").exists())


def test_allow_bypass_still_reloads():
    run(_PROMPT, session="sess-G")
    res = run("!!allow just checking", session="sess-G")
    check("!!allow follow-up still reloads stash", "@@SECRET:auto_" in context_of(res))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        print(f"{fn.__name__}:")
        fn()
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)
