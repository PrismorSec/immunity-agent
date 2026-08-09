"""prismor/runtime/inference_hook.py — transcript-turn evaluation channel.

Prismor's local hook screens one *tool call* on the box where the agent runs.
This module screens one *prompt turn* from a transcript handed to us by a model
provider before the model sees it — the enforcement channel that reaches cloud
surfaces and unmanaged devices, where no local hook exists.

It is a front-end onto the pipeline that already exists, not a second engine.
A transcript is fanned out into the same canonical events the local hook emits
(``prompt`` / ``shell`` / ``file_read`` / ``file_write`` / ``network`` /
``tool_result``), each is run through ``evaluate_tool_call``, and the per-event
Decisions are reduced to one turn verdict.

Three things differ from the local channel and are handled here:

1. **No local box.** Session taint normally lives in a per-session file. Here
   the provider re-sends the whole transcript every turn, so taint is
   reconstructed by replaying it into one shared in-memory store
   (``InMemoryTaintStore``) — stateless, with no cross-tenant state to leak.
2. **Coarser grain.** The verdict covers the turn, not a single call. Any event
   that denies denies the turn (``deny`` wins), and the reasons are aggregated.
3. **Binary verdict.** Prismor's five actions collapse to allow/deny. ``block``
   denies; ``step_up``/``defer`` deny *now* and queue for out-of-band approval;
   ``modify`` cannot be expressed (the prompt is not ours to rewrite) and is
   resolved per the channel's configured policy, always logged.

The HTTP surface, auth, timeout and fail posture live in
``inference_hook_server.py``; everything here is pure and directly testable.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from prismor.runtime.policy_engine import InMemoryTaintStore
from prismor.runtime.principal import resolve_subject
from prismor.runtime.runtime import evaluate_tool_call

AGENT_ID = "inference-hook"

# Categories this channel denies on even when the active policy only rates them
# observe/warn. The local channel can afford to warn — a developer is watching a
# terminal and the tool call is still in front of them. Here there is no
# terminal and no second chance: the turn either reaches the model or it does
# not. These are the exposures that make the channel worth deploying, so they
# are its floor, and an operator can widen or narrow it per org via
# ``deny_categories`` (see ChannelConfig).
DEFAULT_DENY_CATEGORIES = frozenset({
    "pii_exposure",
    "secret_exfiltration",
    "secret_access",
    "prompt_injection",
    "prompt_injection_semantic",
})

# Per-event cap on scanned text. A transcript grows without bound across a long
# conversation while the latency budget does not, and the rules are regex over
# the text — so the tail of a pathological blob costs real milliseconds and
# finds nothing new. Truncation is reported on the verdict rather than hidden.
MAX_EVENT_CHARS = 200_000
MAX_TRANSCRIPT_CHARS = 2_000_000


# ── Configuration ───────────────────────────────────────────────────────────

@dataclass
class ChannelConfig:
    """Per-org posture for this channel.

    ``fail_open`` is the consequential one. This server sits on the critical
    path of a user's prompt: if it is slow or down, fail-closed means the user's
    model stops working, and fail-open means the org is briefly unguarded. There
    is no default that is right for everyone, so the default is the safe one
    (closed) and it is an explicit org decision to change it.
    """

    org_id: str = ""
    fail_open: bool = False
    deny_categories: frozenset = DEFAULT_DENY_CATEGORIES
    # Total wall-clock budget for one turn evaluation, inside the provider's own
    # few-second window. Exceeding it is a timeout, resolved by fail posture.
    timeout_s: float = 3.0
    mode: str = "enforce"
    # How to resolve verdicts that this channel's binary contract cannot carry.
    # "deny" is the safe reading of "the policy wanted something other than a
    # plain allow"; an org that finds that too blunt can set "allow".
    step_up_verdict: str = "deny"
    defer_verdict: str = "deny"
    modify_verdict: str = "deny"
    # Queue step_up/defer to the approvals control plane as we deny, so the
    # decision reaches a human even though this request cannot wait for one.
    enqueue_approvals: bool = True
    max_transcript_chars: int = MAX_TRANSCRIPT_CHARS
    workspace: Optional[Path] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], *, org_id: str = "") -> "ChannelConfig":
        cfg = cls(org_id=org_id or str(raw.get("org_id") or ""))
        if "fail_open" in raw:
            cfg.fail_open = bool(raw["fail_open"])
        cats = raw.get("deny_categories")
        if isinstance(cats, (list, tuple, set)):
            cfg.deny_categories = frozenset(str(c) for c in cats)
        if raw.get("timeout_s") is not None:
            try:
                cfg.timeout_s = max(0.1, float(raw["timeout_s"]))
            except (TypeError, ValueError):
                pass
        if raw.get("max_transcript_chars") is not None:
            try:
                cfg.max_transcript_chars = max(0, int(raw["max_transcript_chars"]))
            except (TypeError, ValueError):
                pass
        if raw.get("mode") in ("enforce", "observe"):
            cfg.mode = str(raw["mode"])
        for key in ("step_up_verdict", "defer_verdict", "modify_verdict"):
            if raw.get(key) in ("deny", "allow"):
                setattr(cfg, key, str(raw[key]))
        if "enqueue_approvals" in raw:
            cfg.enqueue_approvals = bool(raw["enqueue_approvals"])
        if raw.get("workspace"):
            cfg.workspace = Path(str(raw["workspace"]))
        return cfg


class ConfigError(ValueError):
    """The channel config file is present but unusable."""


def load_config_file(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read the multi-org channel config, or ``{}`` when none is set.

    Shape::

        {"defaults": {...}, "orgs": {"<org_id>": {"api_key": "...", ...}}}

    Raises ConfigError on a malformed file rather than falling back to
    defaults: a config that silently half-applies is how an org ends up
    fail-open without anyone choosing it.
    """
    raw_path = path or os.environ.get("PRISMOR_INFERENCE_HOOK_CONFIG")
    if not raw_path:
        return {}
    p = Path(raw_path)
    if not p.exists():
        raise ConfigError(f"channel config not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"channel config is not valid JSON ({p}): {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"channel config must be a JSON object ({p})")
    return data


def resolve_config(
    org_id: str,
    *,
    file_config: Optional[Dict[str, Any]] = None,
    workspace: Optional[Path] = None,
) -> ChannelConfig:
    """Merge defaults with this org's overrides into one ChannelConfig."""
    data = file_config if file_config is not None else load_config_file()
    merged: Dict[str, Any] = dict(data.get("defaults") or {})
    orgs = data.get("orgs")
    if isinstance(orgs, dict) and org_id and isinstance(orgs.get(org_id), dict):
        merged.update(orgs[org_id])
    cfg = ChannelConfig.from_dict(merged, org_id=org_id)
    if cfg.workspace is None:
        cfg.workspace = workspace
    return cfg


# ── Transcript → canonical events ───────────────────────────────────────────

def _blocks(content: Any) -> List[Dict[str, Any]]:
    """Normalize a message ``content`` to a list of typed blocks.

    Accepts the string shorthand and the block-array form, so the fan-out does
    not care which the provider sent.
    """
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, dict):
        return [content]
    if isinstance(content, (list, tuple)):
        out: List[Dict[str, Any]] = []
        for item in content:
            if isinstance(item, str):
                out.append({"type": "text", "text": item})
            elif isinstance(item, dict):
                out.append(item)
        return out
    return []


def _block_text(block: Dict[str, Any]) -> str:
    """Best-effort text of a block, whatever the provider called the field."""
    for key in ("text", "content", "value"):
        val = block.get(key)
        if isinstance(val, str) and val:
            return val
    # A tool_result's content is itself a block list in the Messages shape.
    val = block.get("content")
    if isinstance(val, (list, tuple)):
        return "\n".join(_block_text(b) for b in _blocks(val))
    if val is not None and not isinstance(val, str):
        return json.dumps(val, default=str)
    return ""


def _truncate(text: str, limit: int = MAX_EVENT_CHARS) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _base_event(*, session_id: str, agent_event: str, index: int) -> Dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": AGENT_ID,
        "agent_event": agent_event,
        "metadata": {
            "framework": AGENT_ID,
            "channel": "inference_hook",
            "transcript_index": index,
        },
    }


def _tool_use_event(
    block: Dict[str, Any],
    *,
    session_id: str,
    index: int,
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    """Normalize a ``tool_use`` block via the existing Claude hook normalizer.

    The transcript's tool names are the same names the local Claude hook sees
    (Bash / Read / Edit / WebFetch / mcp__server__tool / ...), so rather than
    keep a second mapping in sync — and quietly diverge from it — this
    synthesizes the payload shape ``_normalize_claude`` already understands and
    reuses it wholesale, MCP classification included.
    """
    from prismor.runtime.hooks import _normalize_claude

    name = str(block.get("name") or "")
    if not name:
        return None
    tool_input = block.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {"input": tool_input} if tool_input is not None else {}

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": name,
        "tool_input": tool_input,
        "session_id": session_id,
    }
    try:
        event = _normalize_claude(payload, session_id, workspace)
    except Exception as exc:  # a malformed block must not sink the whole turn
        sys.stderr.write(f"[prismor] inference-hook: tool_use normalize failed ({name}): {exc}\n")
        return None
    event["agent"] = AGENT_ID
    meta = event.setdefault("metadata", {})
    meta["framework"] = AGENT_ID
    meta["channel"] = "inference_hook"
    meta["transcript_index"] = index
    meta["tool_use_id"] = block.get("id")
    # `raw` carries the synthetic payload we just built; drop it so the event
    # doesn't ship a duplicate copy of the tool input into telemetry.
    meta.pop("raw", None)
    return event


@dataclass
class FanOut:
    events: List[Dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    dropped_chars: int = 0


def fan_out(
    transcript: Dict[str, Any],
    *,
    session_id: str,
    workspace: Path,
    max_transcript_chars: int = MAX_TRANSCRIPT_CHARS,
) -> FanOut:
    """Turn one inference-hook request body into canonical Prismor events.

    Ordering is transcript order, which is what makes the taint replay in
    ``evaluate_turn`` correct: a poisoned ``tool_result`` is evaluated before
    the ``network`` call it should escalate.
    """
    out = FanOut()
    budget = max(0, int(max_transcript_chars))
    spent = 0

    def _spend(text: str) -> tuple[str, bool]:
        nonlocal spent
        if not text:
            return "", False
        remaining = budget - spent
        if remaining <= 0:
            out.truncated = True
            out.dropped_chars += len(text)
            return "", True
        clipped, was_cut = _truncate(text, min(MAX_EVENT_CHARS, remaining))
        if was_cut:
            out.truncated = True
            out.dropped_chars += len(text) - len(clipped)
        spent += len(clipped)
        return clipped, was_cut

    index = 0

    # The system prompt is instruction text the model will act on; a tampered
    # one is exactly the injection this channel exists to catch.
    system = transcript.get("system")
    system_text = "\n".join(_block_text(b) for b in _blocks(system)).strip()
    if system_text:
        text, _ = _spend(system_text)
        if text:
            ev = _base_event(session_id=session_id, agent_event="UserPromptSubmit", index=index)
            ev["metadata"]["source"] = "system"
            out.events.append({**ev, "type": "prompt", "prompt": text})
            index += 1

    for message in transcript.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "")
        for block in _blocks(message.get("content")):
            btype = str(block.get("type") or ("text" if "text" in block else ""))

            if btype == "tool_use":
                ev = _tool_use_event(block, session_id=session_id, index=index, workspace=workspace)
                if ev is not None:
                    out.events.append(ev)
                    index += 1
                continue

            if btype == "tool_result":
                text, _ = _spend(_block_text(block))
                if not text:
                    continue
                # Pre-action even though the tool already ran: nothing here has
                # reached the model *this* turn, and should_block() only
                # considers pre-action events. The turn is the action.
                ev = _base_event(session_id=session_id, agent_event="PreToolUse", index=index)
                ev["metadata"]["tool_use_id"] = block.get("tool_use_id")
                out.events.append({**ev, "type": "tool_result", "content": text})
                index += 1
                continue

            text, _ = _spend(_block_text(block))
            if not text:
                continue
            if role == "assistant":
                # Model output is not a user prompt; route it as tool_result so
                # the untrusted-content rules apply without it being mistaken
                # for a human instruction in telemetry.
                ev = _base_event(session_id=session_id, agent_event="PreToolUse", index=index)
                ev["metadata"]["source"] = "assistant"
                out.events.append({**ev, "type": "tool_result", "content": text})
            else:
                ev = _base_event(session_id=session_id, agent_event="UserPromptSubmit", index=index)
                ev["metadata"]["source"] = role or "user"
                out.events.append({**ev, "type": "prompt", "prompt": text})
            index += 1

    # Attachments ride alongside the messages and are the highest-yield place to
    # find a pasted spreadsheet full of card numbers.
    for att in transcript.get("attachments") or []:
        if isinstance(att, str):
            att = {"text": att}
        if not isinstance(att, dict):
            continue
        text, _ = _spend(_block_text(att) or str(att.get("text") or ""))
        if not text:
            continue
        ev = _base_event(session_id=session_id, agent_event="UserPromptSubmit", index=index)
        ev["metadata"]["source"] = "attachment"
        ev["metadata"]["attachment_name"] = att.get("name") or att.get("filename")
        out.events.append({**ev, "type": "prompt", "prompt": text})
        index += 1

    return out


# ── Verdict ─────────────────────────────────────────────────────────────────

@dataclass
class TurnVerdict:
    allow: bool
    reason: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    blocking: Optional[Dict[str, Any]] = None
    # "policy" (a rule decided), "fail_closed"/"fail_open" (we could not),
    # or "empty" (nothing to screen).
    basis: str = "policy"
    events_evaluated: int = 0
    truncated: bool = False
    approval_id: Optional[str] = None
    downgraded_action: Optional[str] = None
    eval_ms: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "allow": self.allow,
            "reason": self.reason,
            "basis": self.basis,
            "findings": self.findings,
            "blocking": self.blocking,
            "events_evaluated": self.events_evaluated,
            "truncated": self.truncated,
            "approval_id": self.approval_id,
            "downgraded_action": self.downgraded_action,
            "eval_ms": self.eval_ms,
        }


def _channel_blocking(
    findings: Sequence[Dict[str, Any]],
    deny_categories: frozenset,
) -> Optional[Dict[str, Any]]:
    """First finding this channel denies on beyond the engine's own verdict.

    The engine already returned ``allow`` for these — they are observe/warn
    under the active policy. This is the channel floor described on
    DEFAULT_DENY_CATEGORIES, not a second opinion about the rule itself.
    """
    if not deny_categories:
        return None
    for finding in findings:
        if finding.get("contextInert"):
            continue
        if str(finding.get("category") or "") in deny_categories:
            return finding
    return None


def _reason_for(finding: Dict[str, Any]) -> str:
    """A user-facing sentence. Evidence is deliberately left out — it is the
    matched secret or card number, and this string is shown to the end user and
    logged by the provider."""
    severity = str(finding.get("severity") or "high").upper()
    title = str(finding.get("title") or "policy violation")
    rule = finding.get("ruleId")
    suffix = f" ({rule})" if rule else ""
    return f"[{severity}] {title}{suffix}"


def evaluate_turn(
    transcript: Dict[str, Any],
    *,
    config: ChannelConfig,
    session_id: str = "",
    subject: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> TurnVerdict:
    """Screen one prompt turn. Never raises — see ``basis`` on the result.

    Every event of the transcript shares one in-memory taint store, so the
    session state the local channel keeps on disk is reconstructed by replay
    for the life of this call and then discarded.
    """
    import time

    t0 = time.perf_counter()
    ws = workspace or config.workspace or Path.cwd()
    sid = session_id or str(transcript.get("session_id") or transcript.get("sessionId") or "")

    fan = fan_out(
        transcript,
        session_id=sid,
        workspace=ws,
        max_transcript_chars=config.max_transcript_chars,
    )
    if not fan.events:
        return TurnVerdict(
            allow=True, basis="empty", truncated=fan.truncated,
            reason=None, eval_ms=int((time.perf_counter() - t0) * 1000),
        )

    taint = InMemoryTaintStore()
    resolved_subject = resolve_subject(subject) if subject else None

    all_findings: List[Dict[str, Any]] = []
    blocking: Optional[Dict[str, Any]] = None

    for event in fan.events:
        decision = evaluate_tool_call(
            event=event,
            workspace=ws,
            agent=AGENT_ID,
            agent_name=AGENT_ID,
            mode=config.mode,
            session_id=sid,
            subject=resolved_subject,
            # No local session store to append to, and no snapshot worth
            # writing: the provider owns the session, and persisting here
            # would put another tenant's transcript on our disk.
            persist=False,
            # The "workspace" here is shared server infrastructure, not one
            # developer's project: registering every tenant's agents into its
            # inventory would both mix them together and put a disk write on
            # the request path.
            register_agent=False,
            taint_store=taint,
        )
        all_findings.extend(decision.findings)
        # Deny wins, and the first denial is the one we explain. Evaluation
        # continues so the receipt records everything the turn tripped, not
        # just the first thing — the operator reviewing a block wants the
        # whole picture.
        if blocking is None and decision.blocking is not None:
            blocking = decision.blocking

    if blocking is None:
        blocking = _channel_blocking(all_findings, config.deny_categories)

    verdict = TurnVerdict(
        allow=True,
        findings=all_findings,
        blocking=blocking,
        events_evaluated=len(fan.events),
        truncated=fan.truncated,
    )

    if blocking is not None:
        action = str(blocking.get("action") or "block").lower()
        verdict.allow = _map_action(action, config) == "allow"
        verdict.reason = None if verdict.allow else _reason_for(blocking)
        if action in ("step_up", "defer", "modify"):
            verdict.downgraded_action = action
            if action == "modify":
                # The prompt is the provider's to send, not ours to rewrite, so
                # a modify verdict has nowhere to go on this channel. Logged
                # loudly: a policy silently losing its remediation is worse
                # than a policy that denies.
                sys.stderr.write(
                    f"[prismor] inference-hook: 'modify' is not expressible on this "
                    f"channel; resolved as {config.modify_verdict} "
                    f"(rule {blocking.get('ruleId')})\n"
                )
        if action in ("step_up", "defer") and config.enqueue_approvals:
            verdict.approval_id = _enqueue(blocking, session_id=sid)

    verdict.eval_ms = int((time.perf_counter() - t0) * 1000)
    return verdict


def _map_action(action: str, config: ChannelConfig) -> str:
    """Prismor's five actions onto this channel's two."""
    if action == "step_up":
        return config.step_up_verdict
    if action == "defer":
        return config.defer_verdict
    if action == "modify":
        return config.modify_verdict
    return "deny"  # block, and anything unrecognized: enforce means stop


def _enqueue(finding: Dict[str, Any], *, session_id: str) -> Optional[str]:
    """Queue a step_up/defer for out-of-band approval. Best-effort by design:
    the turn is already denied, so a failed enqueue costs the user a retry, not
    their safety."""
    try:
        from prismor.runtime.enterprise import approvals
        return approvals.enqueue_step_up(
            finding, agent=AGENT_ID, session_id=session_id, timeout=1.0,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] inference-hook: approval enqueue failed: {exc}\n")
        return None


def fail_verdict(config: ChannelConfig, reason: str) -> TurnVerdict:
    """The verdict for "we could not decide" — timeout, crash, bad config."""
    if config.fail_open:
        return TurnVerdict(allow=True, basis="fail_open", reason=None)
    return TurnVerdict(
        allow=False,
        basis="fail_closed",
        reason="Security screening is unavailable, so this request was blocked.",
    )
