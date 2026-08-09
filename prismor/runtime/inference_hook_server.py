"""prismor/runtime/inference_hook_server.py — HTTP surface for the turn channel.

Serves ``POST /v1/inference-hook``: a model provider hands us the transcript it
is about to send to the model, and we answer allow or deny inside a few-second
budget. The evaluation itself lives in ``inference_hook.py``; this file owns the
things that only matter because the caller is remote and multi-tenant:

* **Per-org auth.** Each org gets its own key, and the org is resolved *from the
  key*, not from a body field — otherwise any valid caller could ask for another
  org's posture by changing a string.
* **A hard timeout.** We sit on the critical path of somebody's prompt. Blowing
  the provider's window degrades their model for every user in the org, so the
  budget is enforced here rather than hoped for.
* **A defined fail posture.** Never a naked 500. Every path — bad JSON, crash,
  timeout, unusable config — resolves to the org's configured posture, which
  defaults to fail-closed.

This is the stdlib server, which is right for a sidecar and for running the
channel end to end locally. Hosting it as a real multi-tenant service on the
critical path wants an ASGI app and a front door with TLS termination, rate
limiting, and autoscaling; the evaluation core is deliberately framework-free
so that move is a re-host, not a rewrite.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple

from prismor.runtime.inference_hook import (
    AGENT_ID,
    ChannelConfig,
    ConfigError,
    TurnVerdict,
    evaluate_turn,
    fail_verdict,
    load_config_file,
    resolve_config,
)

# Body larger than this is refused unread. A transcript is text; anything at
# this size is a mistake or an attempt to tie the process up allocating.
MAX_BODY_BYTES = 32 * 1024 * 1024


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def _resolve_org(
    presented_key: str,
    file_config: Dict[str, Any],
    fallback_key: Optional[str],
) -> Tuple[bool, str]:
    """Authenticate a bearer key and return ``(ok, org_id)``.

    The org is derived from whichever key matched, so a caller cannot name an
    org it does not hold the key for. Comparison is constant-time on every
    branch — an early return on length or prefix would leak key material by
    timing just as surely as ``==`` would.
    """
    ok = False
    org_id = ""
    orgs = file_config.get("orgs")
    if isinstance(orgs, dict):
        for candidate_org, settings in orgs.items():
            if not isinstance(settings, dict):
                continue
            key = settings.get("api_key")
            if not key:
                continue
            if hmac.compare_digest(str(key), presented_key) and not ok:
                ok, org_id = True, str(candidate_org)
    if fallback_key and hmac.compare_digest(str(fallback_key), presented_key) and not ok:
        # Single-tenant deployment: one key, no org registry.
        ok, org_id = True, str(file_config.get("default_org_id") or "")
    return ok, org_id


class InferenceHookHandler(BaseHTTPRequestHandler):
    workspace: Path = Path.cwd()
    file_config: Dict[str, Any] = {}
    fallback_key: Optional[str] = None
    config_error: Optional[str] = None
    # Bounded pool so a burst cannot spawn unbounded evaluation threads. Each
    # request still gets its own worker; the queue is what absorbs the burst,
    # and the per-request timeout is what keeps the queue from growing forever.
    pool: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=16)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        pass  # per-request logging belongs in telemetry, not stderr

    # ── plumbing ────────────────────────────────────────────────────────────

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_verdict(self, verdict: TurnVerdict, *, org_id: str = "") -> None:
        """Emit the provider-facing verdict.

        The contract's exact field names are not something we control, so the
        binary answer is stated three compatible ways (``decision``, ``allow``,
        ``action``) and the reason under both the plain and the explicit
        user-facing name. Prismor's own detail is nested under ``prismor`` where
        it cannot collide with the contract.
        """
        reason = verdict.reason or ""
        self._send_json({
            "decision": "allow" if verdict.allow else "deny",
            "allow": verdict.allow,
            "action": "allow" if verdict.allow else "deny",
            "reason": reason,
            "user_facing_reason": reason,
            "prismor": {
                "basis": verdict.basis,
                "rule_id": (verdict.blocking or {}).get("ruleId"),
                "category": (verdict.blocking or {}).get("category"),
                "severity": (verdict.blocking or {}).get("severity"),
                "finding_count": len(verdict.findings),
                "events_evaluated": verdict.events_evaluated,
                "transcript_truncated": verdict.truncated,
                "approval_id": verdict.approval_id,
                "downgraded_action": verdict.downgraded_action,
                "eval_ms": verdict.eval_ms,
                "org_id": org_id or None,
                "channel": "inference_hook",
            },
        })

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            # Liveness only — deliberately unauthenticated and free of org
            # detail so a load balancer can poll it.
            self._send_json({
                "status": "degraded" if self.config_error else "ok",
                "channel": "inference_hook",
                "ts": datetime.now(timezone.utc).isoformat(),
            }, status=200 if not self.config_error else 503)
        else:
            self._send_json({"error": "not found"}, 404)

    # ── the endpoint ────────────────────────────────────────────────────────

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?")[0] != "/v1/inference-hook":
            self._send_json({"error": "not found"}, 404)
            return

        # A config we could not parse means we do not know anybody's posture,
        # including whether they chose fail-open. Deny and say so.
        if self.config_error:
            self._send_verdict(TurnVerdict(
                allow=False, basis="fail_closed",
                reason="Security screening is unavailable, so this request was blocked.",
            ))
            return

        presented = ""
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
        ok, org_id = _resolve_org(presented, self.file_config, self.fallback_key)
        if not ok:
            # 401 rather than a deny verdict: this is not a policy outcome, and
            # a misconfigured caller should see an auth error, not think its
            # transcripts are being screened and blocked.
            self._send_json({"error": "unauthorized"}, 401)
            return

        cfg = resolve_config(org_id, file_config=self.file_config, workspace=self.workspace)

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self._send_json({"error": "payload too large"}, 413)
            return

        try:
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except Exception as exc:
            # An unparseable body is an unscreenable one. Fail posture, not 400:
            # a caller that can't be understood must not be allowed through just
            # because the failure was its fault.
            sys.stderr.write(f"[prismor] inference-hook: bad request body: {exc}\n")
            self._send_verdict(fail_verdict(cfg, f"bad request body: {exc}"), org_id=org_id)
            return

        session_id = str(
            body.get("session_id") or body.get("sessionId")
            or body.get("conversation_id") or ""
        )
        subject = (
            self.headers.get("X-Prismor-Subject")
            or (str(body.get("subject")) if body.get("subject") else None)
        )

        future = self.pool.submit(
            evaluate_turn, body,
            config=cfg, session_id=session_id, subject=subject, workspace=self.workspace,
        )
        try:
            verdict = future.result(timeout=cfg.timeout_s)
        except FutureTimeout:
            # The work keeps running on its pool thread; we stop waiting on it.
            # Cancelling mid-evaluation would leave the receipt half-written.
            future.cancel()
            sys.stderr.write(
                f"[prismor] inference-hook: evaluation exceeded {cfg.timeout_s}s "
                f"(org={org_id or 'default'}) — applying fail posture\n"
            )
            verdict = fail_verdict(cfg, "evaluation timed out")
        except Exception as exc:
            sys.stderr.write(f"[prismor] inference-hook: evaluation error: {exc}\n")
            verdict = fail_verdict(cfg, f"evaluation error: {exc}")

        self._send_verdict(verdict, org_id=org_id)
        _record_receipt(verdict, org_id=org_id, session_id=session_id, workspace=self.workspace)


def _record_receipt(
    verdict: TurnVerdict,
    *,
    org_id: str,
    session_id: str,
    workspace: Path,
) -> None:
    """Append one signed turn record to the audit trail.

    Signed with this host's key and carrying a null ``device_id``: there is no
    enrolled device on this path, so the record attests that *this service*
    reached this verdict, not that a known machine did. That is genuinely weaker
    non-repudiation than the local channel and is left visible in the record
    rather than papered over.

    Runs after the response is written — the provider is waiting, and a receipt
    is not worth latency on their critical path.
    """
    try:
        from prismor.runtime.enterprise import audit_trail
        if not audit_trail.enabled():
            return
        event = {
            "type": "prompt",
            "agent_event": "UserPromptSubmit",
            "session_id": session_id,
            "metadata": {
                "channel": "inference_hook",
                "org_id": org_id or None,
                "attestation": "service",
                "basis": verdict.basis,
                "events_evaluated": verdict.events_evaluated,
                "transcript_truncated": verdict.truncated,
                "approval_id": verdict.approval_id,
                "downgraded_action": verdict.downgraded_action,
            },
        }
        audit_trail.append_action_record(
            event=event,
            findings=verdict.findings,
            blocking=verdict.blocking,
            workspace=workspace,
            agent=AGENT_ID,
            agent_name=AGENT_ID,
            session_id=session_id,
            subject={"org_id": org_id} if org_id else {},
            mode="enforce",
            eval_ms=verdict.eval_ms,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] inference-hook: receipt write failed: {exc}\n")


def _preflight(workspace: Path) -> None:
    """Warn about local-only assumptions that do not survive being hosted.

    The semantic guard's ``hybrid`` mode shells out to a local Claude CLI. On a
    developer's laptop that is the point; on a hosted box there is no CLI and no
    per-user session, so it would fail every call and silently degrade the guard
    to nothing. ``api`` mode is the hosted equivalent.
    """
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        cfg = PolicyEngine(workspace=workspace).semantic_guard_config or {}
        if not cfg.get("enabled"):
            return
        mode = str(cfg.get("mode", "hybrid")).lower()
        if mode == "hybrid":
            print(
                "[prismor] warning: semantic_guard.mode is 'hybrid', which shells out to a "
                "local Claude CLI that does not exist on a hosted host.\n"
                "[prismor]          Set settings.semantic_guard.mode to 'api' (needs "
                "ANTHROPIC_API_KEY) or 'heuristic' for this channel."
            )
        elif mode == "api" and not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "[prismor] warning: semantic_guard.mode is 'api' but ANTHROPIC_API_KEY is "
                "unset — the guard will fall back to the heuristic signature bank."
            )
    except Exception:
        pass


def run_inference_hook_server(
    host: str = "127.0.0.1",
    port: int = 7072,
    workspace: Optional[Path] = None,
    api_key: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> None:
    """Start the inference-hook server (blocking)."""
    ws = workspace or Path.cwd()
    InferenceHookHandler.workspace = ws
    InferenceHookHandler.fallback_key = api_key or os.environ.get("PRISMOR_INFERENCE_HOOK_KEY") or None

    try:
        InferenceHookHandler.file_config = load_config_file(config_path)
        InferenceHookHandler.config_error = None
    except ConfigError as exc:
        # Serve anyway, denying everything: a security server that exits on a
        # config typo takes the org's Claude down with it, and a running server
        # that says why is easier to diagnose than a crashed one.
        InferenceHookHandler.file_config = {}
        InferenceHookHandler.config_error = str(exc)
        sys.stderr.write(f"[prismor] inference-hook: {exc}\n")
        sys.stderr.write("[prismor] inference-hook: serving in fail-closed mode until fixed.\n")

    orgs = InferenceHookHandler.file_config.get("orgs")
    org_count = len(orgs) if isinstance(orgs, dict) else 0
    if not InferenceHookHandler.fallback_key and org_count == 0 and not InferenceHookHandler.config_error:
        sys.stderr.write(
            "[prismor] inference-hook: no credentials configured — every request will 401.\n"
            "[prismor] inference-hook: pass --api-key, set PRISMOR_INFERENCE_HOOK_KEY, or "
            "register orgs in --config.\n"
        )

    _preflight(ws)

    server = _ThreadingHTTPServer((host, port), InferenceHookHandler)
    print(f"[prismor] inference-hook server listening on http://{host}:{port}")
    print(f"[prismor] workspace: {ws}")
    print(f"[prismor] orgs registered: {org_count}"
          + (" (+ single-key fallback)" if InferenceHookHandler.fallback_key else ""))
    print(f"[prismor] POST /v1/inference-hook  →  transcript → allow/deny")
    print(f"[prismor] GET  /health             →  liveness check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] inference-hook server stopped.")
    finally:
        InferenceHookHandler.pool.shutdown(wait=False)


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Prismor inference-hook security server")
    _p.add_argument("--port", type=int, default=7072)
    _p.add_argument("--host", default="127.0.0.1")
    _p.add_argument("--workspace", default=None)
    _p.add_argument("--api-key", default=None)
    _p.add_argument("--config", default=None)
    _a = _p.parse_args()
    run_inference_hook_server(
        host=_a.host, port=_a.port,
        workspace=Path(_a.workspace) if _a.workspace else None,
        api_key=_a.api_key,
        config_path=Path(_a.config) if _a.config else None,
    )
