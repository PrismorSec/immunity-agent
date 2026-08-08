"""Async human-in-the-loop approval for headless STEP_UP actions.

Interactive coding agents (Claude/Copilot) render a STEP_UP verdict as an inline
"ask" prompt at the hook boundary (see cli.py). A *headless* framework agent — an
OpenAI Agents / LangChain / CrewAI / browser-use worker running unattended — has
no human at the keyboard, so Phase 1 fails those closed to DENY.

This module is the Phase 2 path: on a STEP_UP verdict, the in-process adapter
posts a pending **approval request** to the control plane and blocks, polling
until an org admin approves or denies (or a timeout elapses). Approve → the tool
call proceeds; deny/timeout/any error → fail closed (blocked). The wait happens
inside the adapter's own long-lived process, so unlike the short-lived hook it
can genuinely pause the action.

Control-plane contract:
  POST {api}/api/approvals            (device bearer) → {id, status}
  GET  {api}/api/approvals/{id}       (device bearer) → {id, status}
Statuses: ``pending`` | ``approved`` | ``denied`` | ``expired``.

Failure posture: never raise into the tool path. Not enrolled, network error,
or timeout all resolve to "not approved" so the caller fails closed. Tunables:
``PRISMOR_APPROVAL_TIMEOUT`` (s, default 300) and ``PRISMOR_APPROVAL_POLL``
(s, default 3).
"""
from __future__ import annotations

from prismor.runtime.http_ua import user_agent as _http_user_agent

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

DEFAULT_TIMEOUT = 300.0
DEFAULT_POLL = 3.0
_PENDING = "pending"
_APPROVED = "approved"
_DECIDED = {"approved", "denied", "expired"}


def _timeout() -> float:
    try:
        return max(1.0, float(os.environ.get("PRISMOR_APPROVAL_TIMEOUT", DEFAULT_TIMEOUT)))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


def _poll_interval() -> float:
    try:
        return max(0.5, float(os.environ.get("PRISMOR_APPROVAL_POLL", DEFAULT_POLL)))
    except (TypeError, ValueError):
        return DEFAULT_POLL


def enabled() -> bool:
    """Master switch for headless approvals (``PRISMOR_APPROVALS``).

    Defaults to on. Set ``PRISMOR_APPROVALS=0`` (or ``false``/``off``/``no``)
    to disable escalation entirely: a STEP_UP verdict is then not posted to the
    control plane and the caller fails closed - exactly the posture of an
    unenrolled install. Per-guard opt-out is available via the adapters'
    ``approvals=False`` keyword; this env var is the fleet-wide override.
    """
    val = str(os.environ.get("PRISMOR_APPROVALS", "1")).strip().lower()
    return val not in ("0", "false", "off", "no")


def step_up_finding(decision: Any) -> Optional[Dict[str, Any]]:
    """The blocking finding iff it is a STEP_UP verdict, else None."""
    blocking = getattr(decision, "blocking", None)
    if isinstance(blocking, dict) and str(blocking.get("action") or "").lower() == "step_up":
        return blocking
    return None


def _fingerprint(session_id: str, tool: str, evidence_hash: str) -> str:
    """Stable id for one logical action, so repeated attempts of the same call
    coalesce onto one approval request instead of spamming the queue."""
    raw = f"{session_id}\x1f{tool}\x1f{evidence_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _headers(ident: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ident.get('device_key')}",
    }


def _post_request(ident: Dict[str, Any], body: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = f"{base}/api/approvals"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=_headers(ident), method="POST"
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _get_status(ident: Dict[str, Any], approval_id: str, timeout: float) -> Optional[str]:
    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = f"{base}/api/approvals/{approval_id}"
    req = urllib.request.Request(url, headers=_headers(ident), method="GET")
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return str(data.get("status") or "").lower() or None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _audit_outcome(
    body: Dict[str, Any],
    *,
    status: str,
    approval_id: Optional[str],
    agent: str,
    session_id: str,
) -> None:
    """Record the human-approval outcome on the signed audit trail.

    Best-effort: the approval decision itself is already final; the trail
    write must never change it or raise into the tool path."""
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if _audit.enabled():
            _audit.append_approval_record(
                status=status,
                approval_id=approval_id,
                tool=str(body.get("tool") or ""),
                rule_id=body.get("rule_id"),
                severity=body.get("severity"),
                reason=str(body.get("reason") or ""),
                fingerprint=str(body.get("fingerprint") or ""),
                agent=agent,
                session_id=session_id,
            )
    except Exception:
        pass


def await_step_up(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
) -> bool:
    """Post an approval request for a STEP_UP finding and block until decided.

    Returns True only on an explicit ``approved``. Not enrolled, denied, expired,
    timeout, or any error → False (the caller must fail closed). Safe to call for
    any decision — a no-op returning False when the verdict is not STEP_UP.
    Every resolved request (approved/denied/expired/timeout/request_failed) is
    recorded on the signed audit trail.
    """
    finding = step_up_finding(decision)
    if finding is None or not enabled():
        return False
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return False  # no control plane to approve through → fail closed

    tool = str(finding.get("toolName") or (event or {}).get("type") or "tool")
    body = {
        "fingerprint": _fingerprint(session_id, tool, str(finding.get("evidence_hash") or finding.get("evidenceHash") or "")),
        "tool": tool,
        "reason": str(finding.get("title") or "policy step-up"),
        "rule_id": finding.get("ruleId"),
        "severity": finding.get("severity"),
        "session_id": session_id or None,
        "agent": agent or None,
    }

    def _record(status: str, approval_id: Optional[str] = None) -> None:
        _audit_outcome(
            body, status=status, approval_id=approval_id,
            agent=agent, session_id=session_id,
        )

    poll_timeout = min(10.0, _poll_interval() + 5.0)
    created = _post_request(ident, body, timeout=poll_timeout)
    if not created or not created.get("id"):
        _record("request_failed")
        return False
    approval_id = str(created["id"])
    if str(created.get("status") or "").lower() == _APPROVED:
        _record("approved", approval_id)
        return True

    deadline = _monotonic() + _timeout()
    interval = _poll_interval()
    while _monotonic() < deadline:
        time.sleep(interval)
        status = _get_status(ident, approval_id, timeout=poll_timeout)
        if status == _APPROVED:
            _record("approved", approval_id)
            return True
        if status in _DECIDED:  # denied / expired
            _record(status, approval_id)
            return False
    _record("timeout", approval_id)
    return False  # timed out → fail closed


async def await_step_up_async(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
) -> bool:
    """Event-loop-safe :func:`await_step_up`.

    The sync poll loop sleeps for up to ``PRISMOR_APPROVAL_TIMEOUT`` seconds;
    called directly from an ``async def`` tool wrapper it would park the entire
    event loop - stalling every concurrent tool, LLM stream, and (for
    browser-use) the CDP socket - until a human decides. This variant runs the
    wait in a worker thread instead, so the loop keeps servicing. Same
    contract: True only on an explicit approval, everything else False.
    """
    if step_up_finding(decision) is None or not enabled():
        return False
    import asyncio

    return await asyncio.to_thread(
        await_step_up, decision, event=event, agent=agent, session_id=session_id
    )


def _monotonic() -> float:
    return time.monotonic()
