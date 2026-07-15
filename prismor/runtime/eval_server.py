"""prismor/runtime/eval_server.py — HTTP evaluation endpoint for non-Python adapters.

Exposes the Prismor policy pipeline as a local HTTP service so TypeScript,
Go, or any other language can call evaluate_tool_call without embedding the
Python runtime.

Usage:
    immunity eval-server [--port 7071] [--host 127.0.0.1] [--workspace .]

Endpoints:
    POST /v1/evaluate   → evaluate a tool call, return allow/block decision
    GET  /health        → {"status": "ok", "ts": "<iso>"}

Request body (POST /v1/evaluate):
    {
      "tool_name":  "run_shell",        # required
      "arguments":  {"command": "..."},  # required — tool arguments as object
      "event_type": "shell",             # optional, default "shell"
      "agent":      "vercel-ai",         # optional, default "sdk"
      "mode":       "enforce",           # optional, default "enforce"
      "session_id": "req-abc123",        # optional
      "subject":    "user:alice",        # optional — user:<id> or user=x;team=y
      "agent_name": "support-bot",       # optional — per-instance name (enables kill-switch + control)
      "workspace":  "/path/to/project"   # optional, overrides server default
    }

    X-Prismor-Agent-Name header also accepted (takes precedence over body field).

Response:
    {
      "allow":    false,
      "reason":   "[HIGH] destructive-command matched ...",
      "findings": [...],
      "subject":  {"user_id": "alice", "team_id": null, ...}
    }

Non-2xx on server errors only. Policy denials are always 200 with allow=false.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Optional

from prismor.runtime.principal import resolve_subject
from prismor.runtime.runtime import evaluate_tool_call

_TYPE_FIELD = {
    "shell":      "command",
    "file_read":  "path",
    "file_write": "path",
    "network":    "url",
    "prompt":     "content",
    "tool_result":"content",
}


def _build_event(
    *,
    tool_name: str,
    arguments: dict,
    event_type: str,
    agent: str,
    session_id: str,
    subject_str: Optional[str],
    available_tools: Optional[list[str]] = None,
) -> dict:
    field = _TYPE_FIELD.get(event_type, "command")
    # Serialize arguments to a single value string (values only — for regex matching)
    value = " ".join(str(v) for v in arguments.values() if v is not None).strip()
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: value,
        "metadata": {
            "tool_name": tool_name,
            "framework": agent,
            "args": list(arguments.values()),
            "kwargs": arguments,
            "subject": subject_str,
            "available_tools": available_tools or [],
        },
    }


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class EvalHandler(BaseHTTPRequestHandler):
    workspace: Path = Path.cwd()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # silence per-request logs; server startup message is printed separately

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Prismor-Subject, X-Warden-Subject")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/evaluate":
            self._send_json({"error": "not found"}, 404)
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except Exception as exc:
            self._send_json({"error": f"invalid JSON: {exc}"}, 400)
            return

        tool_name = body.get("tool_name")
        if not tool_name:
            self._send_json({"error": "tool_name is required"}, 400)
            return

        arguments: dict = body.get("arguments", {})
        event_type: str = body.get("event_type", "shell")
        agent: str = body.get("agent", "sdk")
        mode: str = body.get("mode", "enforce")
        session_id: str = body.get("session_id", f"eval-{os.getpid()}")
        # Agent name: prefer X-Prismor-Agent-Name header, then body field.
        # X-Warden-Agent-Name is accepted for backward compatibility with
        # clients built before the Prismor rename.
        agent_name: str = (
            self.headers.get("X-Prismor-Agent-Name")
            or self.headers.get("X-Warden-Agent-Name")
            or body.get("agent_name", "")
        )

        # Subject: prefer X-Prismor-Subject header, then body field
        # (X-Warden-Subject accepted for backward compatibility).
        subject_str: Optional[str] = (
            self.headers.get("X-Prismor-Subject")
            or self.headers.get("X-Warden-Subject")
            or body.get("subject")
        )
        subject = resolve_subject(subject_str)

        # Workspace: prefer body field, then server default
        ws_str: Optional[str] = body.get("workspace")
        workspace = Path(ws_str) if ws_str else self.workspace

        event = _build_event(
            tool_name=tool_name,
            arguments=arguments,
            event_type=event_type,
            agent=agent,
            session_id=session_id,
            subject_str=subject_str,
            available_tools=[str(t) for t in body.get("available_tools", []) if t][:200]
            if isinstance(body.get("available_tools"), list) else [],
        )

        try:
            decision = evaluate_tool_call(
                event=event,
                workspace=workspace,
                agent=agent,
                agent_name=agent_name,
                mode=mode,
                session_id=session_id,
                subject=subject,
            )
        except Exception as exc:
            self._send_json({"error": f"evaluation error: {exc}"}, 500)
            return

        self._send_json({
            "allow":    decision.allow,
            "reason":   decision.reason,
            "findings": decision.findings,
            "blocking": decision.blocking,
            "subject":  decision.subject.as_dict() if decision.subject else None,
        })


def run_eval_server(
    host: str = "127.0.0.1",
    port: int = 7071,
    workspace: Optional[Path] = None,
) -> None:
    """Start the evaluation HTTP server (blocking)."""
    ws = workspace or Path.cwd()
    EvalHandler.workspace = ws

    server = _ThreadingHTTPServer((host, port), EvalHandler)
    print(f"[prismor] eval-server listening on http://{host}:{port}")
    print(f"[prismor] workspace: {ws}")
    print(f"[prismor] POST /v1/evaluate  →  tool call → Decision")
    print(f"[prismor] GET  /health       →  liveness check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] eval-server stopped.")


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Prismor HTTP evaluation server")
    _p.add_argument("--port", type=int, default=7071)
    _p.add_argument("--host", default="127.0.0.1")
    _p.add_argument("--workspace", default=None)
    _a = _p.parse_args()
    run_eval_server(host=_a.host, port=_a.port,
                    workspace=Path(_a.workspace) if _a.workspace else None)
