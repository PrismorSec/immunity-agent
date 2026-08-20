"""External-authorization surface: a proxy asks Prismor for a verdict.

Prismor governs the agent side — the hook in the coding agent, the gateway in
front of its MCP servers. That leaves the traffic a production proxy is already
carrying: MCP calls crossing a service mesh, where there is no agent process to
hook. Rather than build a proxy, Prismor answers one: any proxy implementing the
standard external-authorization callout can delegate its per-request decision
here, and the same policy.yaml that governs a developer's Claude Code governs
the fleet's MCP traffic.

The protocol
------------
A proxy POSTs the client's request (headers, and the body when it is configured
to buffer one) to this server. **200 means allow; any other status denies.**
Both the widely-implemented HTTP and gRPC callouts share that shape; this module
implements the HTTP one, which needs no extra dependency.

What this surface can and cannot do
-----------------------------------
It can refuse. It cannot rewrite a request body — no external-authorization
callout can, in either protocol: the allow path carries header and query
mutations only. That single fact decides the verdict mapping below, because a
`modify` verdict means "this payload is only safe once redacted", and a surface
that answers 200 without performing the redaction has shipped the unredacted
payload upstream while reporting success. So `modify` denies here. Same for
`defer`, whose adjudication does not fit inside a synchronous callout that
proxies default to timing out in a few hundred milliseconds.

Fail closed, specifically
-------------------------
Three things deny that might naively look like "nothing to see":

* A body that does not parse. Unreadable is not empty.
* A **truncated** body. Proxies cap how much they buffer and flag the overflow;
  screening the first N bytes and answering 200 is a lie about coverage.
* An engine error while in enforce mode, matching the gateway's rule.

A request carrying no body at all is different: with body buffering switched off
there is nothing to screen, and this server says so loudly at startup rather
than silently allowing everything forever.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple

from prismor.runtime import mcp_shape
from prismor.runtime.contract import ALLOW, Decision
from prismor.runtime.principal import resolve_subject

SURFACE_ID = "ext-authz"
AUTHZ_AGENT = "mcp-proxy"

#: Header a proxy sets when it buffered only part of the client body.
PARTIAL_BODY_HEADER = "x-envoy-auth-partial-body"

#: Verdicts this surface can actually carry out. Everything else denies — see
#: the module docstring; the allow path of an authorization callout cannot
#: rewrite a body, so `modify` cannot be honored and must not be faked.
HONORED = (ALLOW,)

_DENY_STATUS = 403


def _deny_body(reason: str, rule_id: str = "") -> bytes:
    """A JSON-RPC error, so an MCP client renders the refusal rather than
    choking on an HTML error page."""
    message = f"Blocked by Prismor: {reason}" if reason else "Blocked by Prismor"
    payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32000, "message": message},
    }
    if rule_id:
        payload["error"]["data"] = {"rule": rule_id}
    return json.dumps(payload).encode()


def decide(
    *,
    body: Any,
    headers: Dict[str, str],
    workspace: Path,
    url: str = "",
    server: str = "",
    session_id: str = "",
    mode: str = "enforce",
    subject_str: Optional[str] = None,
    eval_lock: Optional[threading.Lock] = None,
) -> Tuple[bool, str, str, Optional[Decision]]:
    """Authorize one proxied request.

    Returns ``(allow, reason, rule_id, decision)``. Pure enough to test without
    a socket, which is how the verdict-mapping tests below reach it.
    """
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}

    # A truncated body would mean screening a prefix and reporting on the whole.
    if str(lower.get(PARTIAL_BODY_HEADER, "")).lower() == "true":
        return (False,
                "request body was truncated by the proxy before Prismor saw it; "
                "raise the proxy's max request bytes so the full payload is screened",
                "ext-authz-partial-body", None)

    event, err = mcp_shape.shape_request_event(
        body=body, url=url, server=server, session_id=session_id,
        agent=AUTHZ_AGENT, surface_id=SURFACE_ID,
        metadata={"http_host": lower.get("host", ""), "http_path": lower.get("path", "")},
    )

    if err:
        return False, f"unscreenable request: {err}", "ext-authz-unparseable", None

    if event is None:
        # A method with nothing to decide (ping, notifications). Not every
        # frame is a policy question.
        return True, "", "", None

    try:
        from prismor.runtime.runtime import evaluate_tool_call
        lock = eval_lock or threading.Lock()
        with lock:
            decision = evaluate_tool_call(
                event=event,
                workspace=workspace,
                agent=AUTHZ_AGENT,
                mode=mode,
                session_id=session_id,
                subject=resolve_subject(subject_str),
                # Shared infrastructure, not one developer's project: keep the
                # per-tenant agent inventory and the session snapshot off the
                # request path (see evaluate_tool_call's docstring).
                persist=False,
                register_agent=False,
            )
    except Exception as exc:
        sys.stderr.write(f"[prismor-authz] evaluation error: {exc}\n")
        if mode == "enforce":
            return (False, f"policy evaluation failed ({exc}); denied (fail-closed)",
                    "ext-authz-engine-error", None)
        return True, "", "", None

    if decision.verdict in HONORED:
        return True, "", "", decision

    rule = decision.rule_id or ""
    if decision.verdict == "modify":
        # The policy asked for a redacted payload. This surface cannot produce
        # one, and answering 200 would forward the unredacted body while
        # reporting success.
        return (False,
                f"{decision.reason or 'payload requires redaction'} "
                "(an authorization callout cannot rewrite a request body — "
                "route this traffic through `prismor mcp-gateway` to redact "
                "instead of deny)",
                rule, decision)
    if decision.verdict == "defer":
        return (False,
                f"{decision.reason or 'action requires deeper adjudication'} "
                "(cannot adjudicate inside a synchronous authorization callout)",
                rule, decision)
    if decision.verdict == "step_up":
        return (False,
                f"{decision.reason or 'action requires human approval'} "
                "(no approval channel on this surface)",
                rule, decision)
    return False, decision.reason or "blocked by policy", rule, decision


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AuthzHandler(BaseHTTPRequestHandler):
    workspace: Path = Path.cwd()
    api_key: Optional[str] = None
    mode: str = "enforce"
    server_name_header: str = "host"
    # Serialized like the gateway: the taint ledger depends on session
    # ordering, and interleaved evaluations could let the completing call of a
    # forbidden pair slip past it.
    eval_lock = threading.Lock()
    seen_body = False

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _send(self, status: int, body: bytes = b"", extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, json.dumps({
                "status": "ok",
                "surface": SURFACE_ID,
                "mode": self.mode,
                "body_seen": AuthzHandler.seen_body,
                "ts": datetime.now(timezone.utc).isoformat(),
            }).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        # The proxy forwards the CLIENT's path, so this server must answer on
        # whatever path the original request used rather than a path of its own.
        if self.api_key:
            presented = self.headers.get("X-Prismor-Authz-Key", "")
            if not presented or not hmac.compare_digest(presented, self.api_key):
                self._send(401, b'{"error":"unauthorized"}')
                return

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        if raw:
            AuthzHandler.seen_body = True

        headers = {k: v for k, v in self.headers.items()}
        host = self.headers.get("Host", "") or ""
        server = host.split(":")[0].split(".")[0] if host else "proxy"

        if not raw:
            # Nothing to screen. Allow, but make the gap visible: a deployment
            # that never buffers a body is running an authorization server that
            # cannot see what it is authorizing.
            sys.stderr.write(
                "[prismor-authz] request carried no body — nothing to screen. "
                "Enable request-body buffering on the proxy "
                "(with_request_body / includeRequestBody) or this surface "
                "cannot inspect MCP tool calls.\n")
            self._send(200, b"", {"x-prismor-verdict": "allow-no-body"})
            return

        allow, reason, rule, _decision = decide(
            body=raw,
            headers=headers,
            workspace=self.workspace,
            url=f"https://{host}{self.headers.get('Path', '') or self.path}",
            server=server,
            session_id=self.headers.get("X-Prismor-Session", "") or f"authz-{os.getpid()}",
            mode=self.mode,
            subject_str=self.headers.get("X-Prismor-Subject"),
            eval_lock=AuthzHandler.eval_lock,
        )

        if allow:
            # Provenance for the upstream, when the proxy is configured to
            # forward these (allowed_upstream_headers).
            self._send(200, b"", {"x-prismor-verdict": "allow"})
            return

        sys.stderr.write(f"[prismor-authz] deny rule={rule or '-'}: {reason}\n")
        self._send(_DENY_STATUS, _deny_body(reason, rule),
                   {"x-prismor-verdict": "deny", "x-prismor-rule": rule or "-"})


def run_authz_server(
    host: str = "127.0.0.1",
    port: int = 7072,
    workspace: Optional[Path] = None,
    api_key: Optional[str] = None,
    mode: str = "enforce",
) -> None:
    """Start the external-authorization server (blocking)."""
    ws = workspace or Path.cwd()
    AuthzHandler.workspace = ws
    AuthzHandler.mode = mode
    AuthzHandler.api_key = api_key or os.environ.get("PRISMOR_AUTHZ_KEY") or None

    server = _ThreadingHTTPServer((host, port), AuthzHandler)
    if host not in ("127.0.0.1", "localhost", "::1") and not AuthzHandler.api_key:
        print("[prismor] WARNING: binding beyond localhost with NO key — anyone "
              "who can reach this port can evaluate against your policy. "
              "Pass --api-key or set PRISMOR_AUTHZ_KEY.")
    print(f"[prismor] authz-server listening on http://{host}:{port} (mode={mode})")
    print(f"[prismor] workspace: {ws}")
    print("[prismor] POST <any path>  ->  200 allow / 403 deny")
    print("[prismor] GET  /health     ->  liveness + whether a body has ever been seen")
    print("[prismor] NOTE: enable request-body buffering on the proxy, and raise "
          "its callout timeout above the default — policy evaluation is not a "
          "sub-millisecond operation.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] authz-server stopped.")
