"""Shared tool-call evaluation pipeline.

Every adapter — coding-agent hooks (``cli.py hook-dispatch``), in-process
framework SDK adapters (``adapters/``), and the MCP proxy — funnels a single
normalized event through :func:`evaluate_tool_call`. It runs the policy engine,
session-scoped rules, IAM, cross-call learning correlation, persists the event,
forwards telemetry to sinks, records the enterprise heartbeat, and returns a
:class:`Decision` describing whether the call may proceed.

Keeping this in one place means a production framework agent gets the exact same
policy, observe/enforce semantics, and per-user attribution a local coding agent
already gets — the caller only differs in how it renders the decision (exit-2,
a JSON permission object, or a raised exception).
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.hooks import legacy_should_block, should_block
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.store import (
    append_session_event,
    persist_runtime_findings,
    read_session_events,
    save_session_snapshot,
)


@dataclass
class Decision:
    """Outcome of evaluating one tool call."""

    allow: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    blocking: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    subject: Optional[Subject] = None
    # Engine kept so callers that need post-decision config (e.g. the Claude
    # sandbox rewrite path) don't have to re-instantiate it.
    engine: Optional[PolicyEngine] = None


def _apply_rule_exemptions(
    findings: List[Dict[str, Any]],
    rule_exemptions: Optional[List[Dict[str, Any]]],
    *,
    session_id: str,
    subject: Optional[Subject],
) -> List[Dict[str, Any]]:
    """Relax or downgrade findings per admin-granted, signed rule exemptions.

    Each exemption is ``{ruleId, scope (user|device|session), scopeId, action
    (allow|flag), expires?}``, matched at eval time against the current context.
    ``allow`` drops the matched finding (the call proceeds, nothing recorded);
    ``flag`` downgrades it to observe (reported as a warning, but non-blocking).

    Core protections are never exemptable: a floor rule id / core block category
    (and the agent kill-switch) is left untouched regardless of any exemption.
    """
    if not rule_exemptions:
        return findings
    from prismor.runtime.policy_engine import _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    user_id = subject.user_id if subject else None
    device_id = None
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        device_id = ident.get("device_id") if ident else None
    except Exception:
        device_id = None

    def _matches(ex: Dict[str, Any], rule_id: str) -> bool:
        if str(ex.get("ruleId") or "") != rule_id:
            return False
        exp = ex.get("expires")
        if exp and str(exp) < now_iso:
            return False
        scope, scope_id = ex.get("scope"), ex.get("scopeId")
        if scope == "user":
            return bool(user_id) and scope_id == user_id
        if scope == "device":
            return bool(device_id) and scope_id == device_id
        if scope == "session":
            return bool(session_id) and scope_id == session_id
        return False

    out: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = str(f.get("ruleId") or "")
        category = f.get("category")
        # Floor + admin kill-switch are never relaxable.
        if (rule_id in _NON_OVERRIDABLE_RULE_IDS
                or category in _CORE_BLOCK_CATEGORIES
                or category == "agent-control"):
            out.append(f)
            continue
        match = next((ex for ex in rule_exemptions if isinstance(ex, dict) and _matches(ex, rule_id)), None)
        if match is None:
            out.append(f)
        elif str(match.get("action") or "allow") == "flag":
            # Keep the finding (auditable warning), but strip its ability to block.
            downgraded = {**f, "mode": "observe", "exempted": "flag"}
            out.append(downgraded)
        # action == "allow": drop the finding entirely.
    return out


def _block_reason(finding: Dict[str, Any]) -> str:
    parts = [f"[{finding.get('severity', 'high')}] {finding.get('title', 'blocked')}"]
    if finding.get("evidence"):
        parts.append(str(finding["evidence"]))
    if finding.get("remediation"):
        parts.append(f"Recommended fix: {finding['remediation']}")
    return "\n".join(parts)


def evaluate_tool_call(
    *,
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    mode: str = "enforce",
    session_id: str = "",
    repo_root: Optional[Path] = None,
    subject: Optional[Subject] = None,
    persist: bool = True,
    agent_name: str = "",
) -> Decision:
    """Evaluate one normalized tool-call ``event`` against active policy.

    Args:
        event: canonical event (``type``, ``agent``, ``agent_event``, ...).
        workspace: workspace whose policy + session store apply.
        agent: agent/framework id (telemetry + heartbeat tagging).
        mode: ``enforce`` blocks on enforce-mode findings; ``observe`` is a local
            dry-run kill-switch (the control plane can still force enforce per rule).
        session_id: session to append to / read history from.
        repo_root: repo root for analysis (defaults to ``workspace``).
        subject: resolved end-user principal; if ``None`` it is resolved from
            ``PRISMOR_SUBJECT`` / device identity so single-user installs are unchanged.
        persist: append the event + write a session snapshot (set ``False`` for
            pure pre-checks like ``immunity check``).

    Returns:
        A :class:`Decision`. ``allow`` is ``False`` only when a finding's effective
        mode is enforce; callers may further downgrade to observe (e.g. a local
        dry-run kill-switch).
    """
    repo_root = repo_root or workspace
    subject = subject or resolve_subject()
    # Normalise agent_name: default to the framework id for backward compat.
    _agent_name = agent_name or agent

    # Stamp principal and agent identity onto the event.
    meta = event.setdefault("metadata", {})
    if "subject" not in meta:
        meta["subject"] = subject.as_dict()
    meta.setdefault("agent_name", _agent_name)

    if persist:
        append_session_event(workspace, session_id, event)
        events = read_session_events(workspace, session_id)
        try:
            from prismor.runtime.cli import analyze_events  # lazy: avoid import cycle
            analysis = analyze_events(
                events, repo_root=repo_root, workspace=workspace, session_id=session_id
            )
            save_session_snapshot(
                workspace=workspace,
                session_id=session_id,
                agent=agent,
                agent_name=_agent_name,
                source="hook",
                repo_url=None,
                events=events,
                analysis=analysis,
            )
        except Exception as exc:  # best-effort; never block on analysis failure
            sys.stderr.write(f"[prismor] analysis error: {exc}\n")
    else:
        events = [event]

    engine = PolicyEngine(workspace=workspace)

    # Resolve per-agent control (kill-switch, mode override, IAM profile).
    # Runs AFTER engine construction so the org's remote controls — carried in
    # the verified signed policy's settings.agent_controls, managed workspaces
    # only — merge with the local agents.yaml (tighten-only: see agents.py).
    _control = None
    try:
        from prismor.runtime.agents import resolve_agent_control, record_seen, make_disabled_finding
        _control = resolve_agent_control(
            _agent_name, workspace,
            remote_controls=getattr(engine, "agent_controls", None),
        )
        # Throttled auto-registration — once per agent per process.
        record_seen(_agent_name, framework=agent, workspace=workspace)
        # Per-agent mode override: takes precedence over the caller's mode.
        if _control.mode:
            mode = _control.mode
    except Exception as _exc:
        sys.stderr.write(f"[prismor] agent control error: {_exc}\n")

    # Only the current event drives the real-time decision (stale prior findings
    # must not block an unrelated event — see cli.py hook-dispatch rationale).
    # Timed from here through exemptions: the guard-evaluation duration reported
    # in telemetry (excludes session persistence/analysis above).
    _guard_t0 = time.perf_counter()
    _session_seq = len(events) - 1
    findings = engine.evaluate(event, _session_seq, session_id=session_id, subject=subject)

    # Codex cannot mutate Bash input or scrub Bash output from hooks. Block
    # literal cloak placeholders/read leaks before they execute, and persist the
    # finding so the dashboard explains the decision.
    if agent == "codex":
        try:
            from prismor.runtime.cloaking.runtime import codex_cloak_finding
            cloak_finding = codex_cloak_finding(event, session_id)
            if cloak_finding:
                findings.append(cloak_finding)
        except Exception as exc:
            sys.stderr.write(f"[prismor] codex cloak guard error: {exc}\n")

    # Session-scoped rules.
    try:
        from prismor.runtime.scoped_agent import load_scoped_rules, check_scoped_rules
        scoped = load_scoped_rules(workspace, session_id)
        if scoped is not None:
            sr_finding = check_scoped_rules(scoped, event, session_id=session_id)
            if sr_finding:
                findings.append(sr_finding)
    except Exception as exc:
        sys.stderr.write(f"[prismor] scoped enforcement error: {exc}\n")

    # Per-agent kill-switch: inject a CRITICAL finding when the agent is disabled.
    # This runs before IAM so the disabled state always wins.
    if _control is not None and not _control.enabled:
        try:
            from prismor.runtime.agents import make_disabled_finding
            findings.insert(0, make_disabled_finding(
                _agent_name, session_id, disabled_by=_control.disabled_by))
        except Exception as exc:
            sys.stderr.write(f"[prismor] kill-switch error: {exc}\n")

    # Per-agent / global tool-tag deny list (operator-set from the dashboard's
    # Tool Call panel). Resolves the tool tag the same way scoped rules do, so
    # arbitrary MCP tags (e.g. mcp__node_repl__js) work verbatim. Tagged
    # agent-control so it blocks in observe mode too — an explicit deny is an
    # operator decision, not a passive detection.
    if _control is not None and getattr(_control, "deny_tools", ()):  # noqa: SIM102
        try:
            from prismor.runtime.scoped_agent import _resolve_tool_name
            from prismor.runtime.agents import make_agent_tool_deny_finding
            _tname = _resolve_tool_name(event)
            if _tname and _tname in _control.deny_tools:
                findings.append(make_agent_tool_deny_finding(_agent_name, _tname, session_id))
        except Exception as exc:
            sys.stderr.write(f"[prismor] tool-deny error: {exc}\n")

    # Org signed-policy tool denies (settings.tool_denies, set by an admin from
    # the Prismor web console). Same tool-tag matcher; scope decides whether
    # this event is covered. Device-scoped entries are pre-filtered to this
    # device server-side, so org/device always apply here; agent/session match
    # on the event's agent name / session id. Blocks regardless of mode.
    _org_denies = getattr(engine, "tool_denies", None)
    if _org_denies:
        try:
            from prismor.runtime.scoped_agent import _resolve_tool_name
            from prismor.runtime.agents import make_agent_tool_deny_finding
            _otn = _resolve_tool_name(event)
            if _otn:
                for _d in _org_denies:
                    if not isinstance(_d, dict) or _d.get("action", "deny") != "deny":
                        continue
                    if _d.get("tool") != _otn:
                        continue
                    _scope = _d.get("scope") or "org"
                    _sid = _d.get("scopeId")
                    _hit = (
                        _scope in ("org", "device")
                        or (_scope == "agent" and _sid == _agent_name)
                        or (_scope == "session" and _sid == session_id)
                    )
                    if _hit:
                        findings.append(make_agent_tool_deny_finding(
                            _agent_name, _otn, session_id,
                            scope_label=f"org {_scope}", rule_id="org-tool-deny"))
                        break
        except Exception as exc:
            sys.stderr.write(f"[prismor] org tool-deny error: {exc}\n")

    # IAM named-identity enforcement (now subject-aware + per-agent profile).
    try:
        from prismor.runtime.iam import check_iam
        iam_finding = check_iam(
            workspace=workspace,
            event=event,
            session_id=session_id,
            subject=subject,
            agent_profile=_control.iam_profile if _control else None,
            remote_controls=getattr(engine, "subject_controls", None),
        )
        if iam_finding:
            findings.append(iam_finding)
    except Exception as exc:
        sys.stderr.write(f"[prismor] IAM enforcement error: {exc}\n")

    # Cross-call learning correlation on otherwise-clean shell events.
    if not findings and event.get("type") == "shell":
        for fn_name in ("detect_evasion", "detect_staged_execution"):
            try:
                from prismor.runtime import learning
                detector = getattr(learning, fn_name)
                extra = detector(workspace, session_id, event, findings)
                if extra:
                    findings.extend(extra)
            except Exception as exc:
                sys.stderr.write(f"[prismor] {fn_name} error: {exc}\n")

    # Per-event rule exemptions (admin-granted, signed): relax ("allow", drop the
    # finding) or downgrade ("flag", warn but don't block) a rule for the current
    # user / device / session. Applied after ALL findings are gathered, so it can
    # also relax scoped-agent denials — but never a core/floor protection.
    try:
        findings = _apply_rule_exemptions(
            findings, getattr(engine, "rule_exemptions", None),
            session_id=session_id, subject=subject,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] rule-exemption error: {exc}\n")

    _eval_ms = int((time.perf_counter() - _guard_t0) * 1000)

    if persist and findings:
        try:
            persist_runtime_findings(workspace, session_id, findings, _session_seq)
        except Exception as exc:
            sys.stderr.write(f"[prismor] finding persistence error: {exc}\n")

    _dispatch_telemetry(
        engine=engine,
        findings=findings,
        event=event,
        workspace=workspace,
        agent=agent,
        agent_name=_agent_name if _agent_name != agent else None,
        mode=mode,
        session_id=session_id,
        subject=subject,
        eval_ms=_eval_ms,
        session_seq=_session_seq,
    )

    # Per-call inspected-volume heartbeat (org observability), managed repos only.
    if getattr(engine, "workspace_managed", False):
        try:
            from prismor.runtime.enterprise import heartbeat
            heartbeat.record_call(
                agent=agent,
                agent_name=_agent_name if _agent_name != agent else "",
                session_id=session_id,
            )
            heartbeat.maybe_flush()
        except Exception:
            pass

    blocking = should_block(findings, event)
    if blocking is None and mode == "enforce" and getattr(engine, "is_legacy_policy", False):
        blocking = legacy_should_block(findings, event, engine.block_categories)

    # Per-agent observe override: if the effective mode was downgraded to observe
    # (by the agent registry), suppress blocking even when policy findings say enforce.
    # Kill-switch (agent-control category) is exempt — it always blocks.
    if blocking is not None and mode == "observe":
        if blocking.get("category") != "agent-control":
            blocking = None

    # Tamper-evident signed audit trail: one chained + signed record per
    # evaluated call — every verdict, not just findings — so the local trail
    # is complete (see enterprise/audit_trail.py). Best-effort by default (a
    # skipped record is a detectable seq gap); PRISMOR_AUDIT_STRICT=1 fails
    # the action closed when the record cannot be written.
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if _audit.enabled():
            _audit.append_action_record(
                event=event,
                findings=findings,
                blocking=blocking,
                workspace=workspace,
                agent=agent,
                agent_name=_agent_name,
                session_id=session_id,
                subject=subject.as_dict(),
                mode=mode,
                eval_ms=_eval_ms,
            )
    except Exception as exc:
        sys.stderr.write(f"[prismor] audit trail error: {exc}\n")
        if os.environ.get("PRISMOR_AUDIT_STRICT", "").lower() in ("1", "true", "yes", "on"):
            blocking = {
                "action": "block",
                "severity": "critical",
                "category": "agent-control",
                "ruleId": "audit-trail-strict",
                "title": "Audit trail write failed — action blocked (PRISMOR_AUDIT_STRICT=1)",
            }
            return Decision(
                allow=False,
                findings=findings,
                blocking=blocking,
                reason=_block_reason(blocking),
                subject=subject,
                engine=engine,
            )

    return Decision(
        allow=blocking is None,
        findings=findings,
        blocking=blocking,
        reason=_block_reason(blocking) if blocking else None,
        subject=subject,
        engine=engine,
    )


def _dispatch_telemetry(
    *,
    engine: PolicyEngine,
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    agent_name: Optional[str] = None,
    mode: str,
    session_id: str,
    subject: Subject,
    eval_ms: Optional[int] = None,
    session_seq: Optional[int] = None,
) -> None:
    """Forward findings to configured sinks before the blocking decision so a
    SIEM sees every event, including blocked ones. Best-effort."""
    if not (getattr(engine, "outputs", None) and findings):
        return
    try:
        from prismor.runtime.sinks import dispatch as sink_dispatch
        exm = getattr(engine, "active_exemption", None)
        policy_scope = (
            f"repo_exemption:{exm.get('id')}"
            if isinstance(exm, dict) and exm.get("id")
            else "org"
        )
        repo = None
        if getattr(engine, "workspace_managed", False):
            try:
                from prismor.runtime.enterprise import workspace_scope as ws
                repo = ws.detect_git_remote(workspace)
            except Exception:
                repo = None
        sink_dispatch(
            findings,
            engine.outputs,
            extra={
                "session_id": session_id,
                "agent": agent,
                # Instance label (adapter `name=`), distinct from the framework
                # id above — lets the org dashboard tell "checkout-bot" apart
                # from every other agent on the same framework.
                "agent_name": agent_name,
                "mode": mode,
                "workspace": str(workspace),
                "policy_scope": policy_scope,
                "repo": repo,
                "subject": subject.as_dict(),
                # Guard-eval duration + on-device session position, surfaced in
                # the org dashboard's event inspector / latency KPIs.
                "eval_ms": eval_ms,
                "session_seq": session_seq,
            },
            raw_event=event,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] sink dispatch error: {exc}\n")
