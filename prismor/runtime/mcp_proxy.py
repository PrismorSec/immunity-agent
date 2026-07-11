"""prismor/runtime/mcp_proxy.py — MCP proxy firewall for any MCP-speaking agent.

Sits in front of a downstream MCP server, intercepts ``tools/call`` JSON-RPC
methods, evaluates them with :func:`evaluate_tool_call`, and either:

* **deny** — return an MCP ``isError`` result (or JSON-RPC error) without
  forwarding the call, or
* **allow** — forward the request to the upstream server and return its response.

Everything else (``initialize``, ``tools/list``, notifications, …) is
pass-through.

Transports
----------
**stdio** (primary)::

    prismor mcp-proxy --stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp

Wire as the MCP server command in Claude Code / Cursor / etc. so the agent
talks to Prismor; Prismor talks to the real server on a child stdio pipe.

**HTTP** (sidecar)::

    prismor mcp-proxy --upstream http://127.0.0.1:9000 --port 8080

Listen for JSON-RPC POSTs and proxy to ``--upstream``.

Message framing on stdio supports both Content-Length headers (LSP-style) and
newline-delimited JSON.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from prismor.runtime.principal import resolve_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call

# JSON-RPC / MCP constants
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INTERNAL_ERROR = -32603
MCP_TOOLS_CALL = "tools/call"

# Heuristic: map common tool argument keys → canonical event fields
_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


# ── Event construction ───────────────────────────────────────────────────────


def infer_event_type(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Best-effort map of MCP tool name/args → Prismor event type."""
    name = (tool_name or "").lower()
    args = arguments if isinstance(arguments, dict) else {}

    if any(k in args for k in ("command", "cmd", "shell", "script")):
        return "shell"
    if any(k in args for k in ("url", "uri", "href", "endpoint")):
        return "network"
    path_keys = ("path", "file_path", "filePath", "filename", "file", "target")
    if any(k in args for k in path_keys):
        write_tokens = ("write", "edit", "create", "delete", "unlink", "rm", "move", "rename", "patch")
        if any(t in name for t in write_tokens):
            return "file_write"
        return "file_read"
    if any(t in name for t in ("bash", "shell", "exec", "run_command", "terminal")):
        return "shell"
    if any(t in name for t in ("fetch", "http", "request", "browse", "web_")):
        return "network"
    # Default: shell so destructive-command / secret-exfil rules match on arg text
    return "shell"


def _payload_value(event_type: str, arguments: Dict[str, Any]) -> str:
    """Flatten tool arguments into the string the policy engine matches on."""
    args = arguments if isinstance(arguments, dict) else {}
    if event_type == "shell":
        for k in ("command", "cmd", "shell", "script"):
            if args.get(k) is not None:
                return str(args[k])
    if event_type in ("file_read", "file_write"):
        for k in ("path", "file_path", "filePath", "filename", "file", "target"):
            if args.get(k) is not None:
                return str(args[k])
    if event_type == "network":
        for k in ("url", "uri", "href", "endpoint"):
            if args.get(k) is not None:
                return str(args[k])
    # Fallback: join all values (eval_server style)
    return " ".join(str(v) for v in args.values() if v is not None).strip()


def build_event_from_tools_call(
    *,
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    session_id: str = "",
    agent: str = "mcp-proxy",
    subject_str: Optional[str] = None,
    event_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a canonical Prismor event from an MCP ``tools/call`` params object."""
    args = dict(arguments or {})
    etype = event_type or infer_event_type(tool_name, args)
    field = _TYPE_FIELD.get(etype, "command")
    value = _payload_value(etype, args)
    event: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": etype,
        field: value,
        "metadata": {
            "tool_name": tool_name,
            "framework": "mcp-proxy",
            "args": list(args.values()),
            "kwargs": args,
            "mcp_method": MCP_TOOLS_CALL,
        },
    }
    if subject_str:
        event["metadata"]["subject"] = subject_str
    # file_write may also carry content for injection rules
    if etype == "file_write" and "content" in args:
        event["content"] = str(args.get("content") or "")
    return event


# ── Decision → MCP response ──────────────────────────────────────────────────


def deny_result(req_id: Any, reason: str, *, as_jsonrpc_error: bool = False) -> Dict[str, Any]:
    """Build a tools/call response that signals the call was blocked.

    Default is the MCP-native shape (``result.isError = true``) so clients that
    only surface tool errors still show the denial. ``as_jsonrpc_error`` uses a
    JSON-RPC error object instead.
    """
    text = f"Blocked by Prismor: {reason}" if reason else "Blocked by Prismor"
    if as_jsonrpc_error:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": JSONRPC_INVALID_REQUEST,
                "message": text,
                "data": {"source": "prismor", "blocked": True},
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
        },
    }


def evaluate_tools_call(
    *,
    params: Dict[str, Any],
    workspace: Path,
    mode: str = "enforce",
    session_id: str = "",
    subject: Optional[str] = None,
    agent: str = "mcp-proxy",
    agent_name: str = "",
    persist: bool = True,
) -> Decision:
    """Run policy evaluation for one MCP tools/call params object."""
    tool_name = str(params.get("name") or params.get("tool") or "")
    raw_args = params.get("arguments")
    if raw_args is None:
        raw_args = params.get("args") or {}
    if not isinstance(raw_args, dict):
        try:
            raw_args = dict(raw_args)  # type: ignore[arg-type]
        except Exception:
            raw_args = {"value": raw_args}

    event = build_event_from_tools_call(
        tool_name=tool_name,
        arguments=raw_args,
        session_id=session_id,
        agent=agent,
        subject_str=subject,
    )
    return evaluate_tool_call(
        event=event,
        workspace=workspace,
        agent=agent,
        agent_name=agent_name or agent,
        mode=mode,
        session_id=session_id,
        subject=resolve_subject(subject),
        persist=persist,
    )


def maybe_intercept_tools_call(
    message: Dict[str, Any],
    *,
    workspace: Path,
    mode: str = "enforce",
    session_id: str = "",
    subject: Optional[str] = None,
    agent: str = "mcp-proxy",
    agent_name: str = "",
    persist: bool = True,
    as_jsonrpc_error: bool = False,
) -> Optional[Dict[str, Any]]:
    """If ``message`` is a tools/call that should be denied, return a response.

    Returns ``None`` when the message should be forwarded upstream (not a
    tools/call, observe-only allow, or evaluation allows the call).
    """
    if not isinstance(message, dict):
        return None
    if message.get("method") != MCP_TOOLS_CALL:
        return None
    # Notifications (no id) for tools/call are unusual; still evaluate but only
    # suppress when enforce-deny — there is no response channel for notifications.
    params = message.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    try:
        decision = evaluate_tools_call(
            params=params,
            workspace=workspace,
            mode=mode,
            session_id=session_id,
            subject=subject,
            agent=agent,
            agent_name=agent_name,
            persist=persist,
        )
    except Exception as exc:
        # Fail closed for tools/call only when mode is enforce — a broken
        # evaluator should not silently allow dangerous tools.
        if mode == "enforce" and "id" in message:
            return deny_result(
                message.get("id"),
                f"evaluation error: {exc}",
                as_jsonrpc_error=as_jsonrpc_error,
            )
        return None

    if decision.allow:
        return None
    if "id" not in message:
        # Notification — cannot return a response; best-effort drop.
        return {"_prismor_drop": True}
    return deny_result(
        message.get("id"),
        decision.reason or "policy denied",
        as_jsonrpc_error=as_jsonrpc_error,
    )


# ── Framing ──────────────────────────────────────────────────────────────────


def encode_message(obj: Dict[str, Any], *, framing: str = "content-length") -> bytes:
    """Serialize a JSON-RPC object for the wire."""
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "ndjson":
        return body + b"\n"
    # Content-Length (LSP / classic MCP stdio)
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def _read_content_length_message(stream: BinaryIO) -> Optional[Dict[str, Any]]:
    """Read one Content-Length framed message. Returns None on EOF."""
    headers: Dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None  # EOF mid-headers
        if line in (b"\r\n", b"\n"):
            break
        try:
            text = line.decode("ascii", errors="replace").rstrip("\r\n")
        except Exception:
            text = str(line)
        if ":" in text:
            k, v = text.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    length_s = headers.get("content-length")
    if not length_s:
        return None
    try:
        length = int(length_s)
    except ValueError:
        return None
    body = stream.read(length)
    if not body or len(body) < length:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def _read_ndjson_message(stream: BinaryIO) -> Optional[Dict[str, Any]]:
    """Read one newline-delimited JSON object. Returns None on EOF."""
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line.decode("utf-8"))
        except Exception:
            # Skip garbage lines rather than dying
            continue


class MessageReader:
    """Auto-detect Content-Length vs NDJSON from the first message."""

    def __init__(self, stream: BinaryIO, framing: str = "auto") -> None:
        self.stream = stream
        self.framing = framing  # auto | content-length | ndjson
        self._detected = framing if framing != "auto" else None

    def read(self) -> Optional[Dict[str, Any]]:
        if self._detected is None:
            # Peek first non-empty byte
            peek = self.stream.peek(1) if hasattr(self.stream, "peek") else b""
            # BufferedReader has peek; otherwise try reading one byte via buffer
            if not peek:
                # Fall back: read a line and decide
                line = self.stream.readline()
                if not line:
                    return None
                if line.lower().startswith(b"content-length:"):
                    self._detected = "content-length"
                    # Re-parse: we consumed the first header line
                    headers = {"content-length": line.split(b":", 1)[1].strip().decode()}
                    while True:
                        hline = self.stream.readline()
                        if not hline or hline in (b"\r\n", b"\n"):
                            break
                        if b":" in hline:
                            k, v = hline.split(b":", 1)
                            headers[k.decode().strip().lower()] = v.strip().decode()
                    length = int(headers["content-length"])
                    body = self.stream.read(length)
                    return json.loads(body.decode("utf-8"))
                self._detected = "ndjson"
                line = line.strip()
                if not line:
                    return self.read()
                return json.loads(line.decode("utf-8"))
            if peek[:1] in (b"C", b"c"):
                self._detected = "content-length"
            else:
                self._detected = "ndjson"

        if self._detected == "content-length":
            return _read_content_length_message(self.stream)
        return _read_ndjson_message(self.stream)


def write_message(stream: BinaryIO, obj: Dict[str, Any], *, framing: str = "content-length") -> None:
    data = encode_message(obj, framing=framing)
    stream.write(data)
    stream.flush()


# ── stdio proxy ──────────────────────────────────────────────────────────────


class ProxyConfig:
    """Runtime options for the MCP proxy."""

    def __init__(
        self,
        *,
        workspace: Path,
        mode: str = "enforce",
        session_id: str = "",
        subject: Optional[str] = None,
        agent: str = "mcp-proxy",
        agent_name: str = "",
        persist: bool = True,
        as_jsonrpc_error: bool = False,
        framing: str = "auto",
    ) -> None:
        self.workspace = workspace
        self.mode = mode
        self.session_id = session_id or f"mcp-proxy-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.subject = subject
        self.agent = agent
        self.agent_name = agent_name
        self.persist = persist
        self.as_jsonrpc_error = as_jsonrpc_error
        self.framing = framing


def _handle_client_message(
    msg: Dict[str, Any],
    cfg: ProxyConfig,
    upstream_in: BinaryIO,
    client_out: BinaryIO,
    out_framing: str,
) -> None:
    """Process one client→upstream message (intercept or forward)."""
    intercepted = maybe_intercept_tools_call(
        msg,
        workspace=cfg.workspace,
        mode=cfg.mode,
        session_id=cfg.session_id,
        subject=cfg.subject,
        agent=cfg.agent,
        agent_name=cfg.agent_name,
        persist=cfg.persist,
        as_jsonrpc_error=cfg.as_jsonrpc_error,
    )
    if intercepted is not None:
        if intercepted.get("_prismor_drop"):
            return
        write_message(client_out, intercepted, framing=out_framing)
        return
    write_message(upstream_in, msg, framing=out_framing)


def run_stdio_proxy(
    upstream_cmd: Sequence[str],
    *,
    cfg: ProxyConfig,
    client_in: Optional[BinaryIO] = None,
    client_out: Optional[BinaryIO] = None,
    env: Optional[Dict[str, str]] = None,
) -> int:
    """Bridge client stdio ↔ upstream process, intercepting tools/call.

    Returns the upstream process exit code (or 1 on proxy-side failure).
    """
    if not upstream_cmd:
        sys.stderr.write("[prismor] mcp-proxy: upstream command required after --\n")
        return 2

    cin = client_in or sys.stdin.buffer
    cout = client_out or sys.stdout.buffer

    try:
        proc = subprocess.Popen(
            list(upstream_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface upstream logs
            env=env or os.environ.copy(),
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"[prismor] mcp-proxy: failed to start upstream: {exc}\n")
        return 1

    assert proc.stdin is not None and proc.stdout is not None

    # Framing: auto-detect on client; use same framing toward upstream after detect
    client_reader = MessageReader(cin, framing=cfg.framing)
    # Upstream often uses the same framing as the client; default content-length
    # until we know — for NDJSON-only servers we re-detect from first client msg.
    upstream_framing = "content-length" if cfg.framing == "auto" else cfg.framing
    client_framing = upstream_framing
    stop = threading.Event()

    def _upstream_to_client() -> None:
        # Forward raw bytes from upstream stdout to client to preserve framing
        try:
            assert proc.stdout is not None
            while not stop.is_set():
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                cout.write(chunk)
                cout.flush()
        except Exception as exc:
            sys.stderr.write(f"[prismor] mcp-proxy: upstream→client error: {exc}\n")
        finally:
            stop.set()

    relay = threading.Thread(target=_upstream_to_client, name="mcp-proxy-relay", daemon=True)
    relay.start()

    sys.stderr.write(
        f"[prismor] mcp-proxy stdio → {' '.join(upstream_cmd)}\n"
        f"[prismor] workspace={cfg.workspace} mode={cfg.mode} session={cfg.session_id}\n"
    )

    exit_code = 0
    try:
        while not stop.is_set():
            msg = client_reader.read()
            if msg is None:
                break
            # Lock framing once detected
            if client_reader._detected:
                client_framing = client_reader._detected
                upstream_framing = client_reader._detected
            _handle_client_message(msg, cfg, proc.stdin, cout, upstream_framing)
    except KeyboardInterrupt:
        exit_code = 130
    except Exception as exc:
        sys.stderr.write(f"[prismor] mcp-proxy: client→upstream error: {exc}\n")
        exit_code = 1
    finally:
        stop.set()
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        relay.join(timeout=1)
        if proc.returncode is not None and exit_code == 0:
            exit_code = proc.returncode
    return exit_code


# ── HTTP proxy ───────────────────────────────────────────────────────────────


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def _http_forward(upstream: str, body: bytes, headers: Dict[str, str]) -> Tuple[int, bytes, str]:
    """POST body to upstream; return (status, body, content_type)."""
    req = Request(
        upstream,
        data=body,
        method="POST",
        headers={
            "Content-Type": headers.get("Content-Type", "application/json"),
            "Accept": headers.get("Accept", "application/json, text/event-stream"),
        },
    )
    try:
        with urlopen(req, timeout=120) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except HTTPError as exc:
        return exc.code, exc.read() if exc.fp else b"", "application/json"
    except URLError as exc:
        err = json.dumps({"jsonrpc": "2.0", "id": None, "error": {
            "code": JSONRPC_INTERNAL_ERROR,
            "message": f"upstream unreachable: {exc.reason}",
        }}).encode()
        return 502, err, "application/json"


def run_http_proxy(
    *,
    upstream: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    cfg: ProxyConfig,
) -> None:
    """Listen for JSON-RPC POSTs, intercept tools/call, forward the rest."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Prismor-Subject")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/health", "/"):
                body = json.dumps({
                    "status": "ok",
                    "service": "prismor-mcp-proxy",
                    "upstream": upstream,
                    "ts": datetime.now(timezone.utc).isoformat(),
                }).encode()
                self._send(200, body)
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                msg = json.loads(raw.decode("utf-8") or "{}")
            except Exception as exc:
                self._send(400, json.dumps({"error": f"invalid JSON: {exc}"}).encode())
                return

            # Batch support: array of messages
            if isinstance(msg, list):
                out: List[Any] = []
                for item in msg:
                    if not isinstance(item, dict):
                        continue
                    resp = maybe_intercept_tools_call(
                        item,
                        workspace=cfg.workspace,
                        mode=cfg.mode,
                        session_id=cfg.session_id,
                        subject=self.headers.get("X-Prismor-Subject") or cfg.subject,
                        agent=cfg.agent,
                        agent_name=cfg.agent_name,
                        persist=cfg.persist,
                        as_jsonrpc_error=cfg.as_jsonrpc_error,
                    )
                    if resp is not None and not resp.get("_prismor_drop"):
                        out.append(resp)
                    else:
                        # Forward single item — for batch, forward whole batch is simpler
                        # but would re-evaluate. Forward the original single request.
                        status, body, ctype = _http_forward(
                            upstream,
                            json.dumps(item).encode(),
                            dict(self.headers),
                        )
                        try:
                            out.append(json.loads(body.decode("utf-8")))
                        except Exception:
                            out.append({"jsonrpc": "2.0", "id": item.get("id"), "error": {
                                "code": JSONRPC_INTERNAL_ERROR,
                                "message": f"upstream status {status}",
                            }})
                self._send(200, json.dumps(out).encode())
                return

            if not isinstance(msg, dict):
                self._send(400, b'{"error":"expected JSON object"}')
                return

            subject = self.headers.get("X-Prismor-Subject") or cfg.subject
            intercepted = maybe_intercept_tools_call(
                msg,
                workspace=cfg.workspace,
                mode=cfg.mode,
                session_id=cfg.session_id,
                subject=subject,
                agent=cfg.agent,
                agent_name=cfg.agent_name,
                persist=cfg.persist,
                as_jsonrpc_error=cfg.as_jsonrpc_error,
            )
            if intercepted is not None:
                if intercepted.get("_prismor_drop"):
                    self._send(204, b"")
                    return
                self._send(200, json.dumps(intercepted).encode())
                return

            status, body, ctype = _http_forward(upstream, raw, dict(self.headers))
            self._send(status, body, ctype)

    server = _ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write(
        f"[prismor] mcp-proxy HTTP http://{host}:{port} → {upstream}\n"
        f"[prismor] workspace={cfg.workspace} mode={cfg.mode}\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[prismor] mcp-proxy stopped.\n")


def run_mcp_proxy(
    *,
    upstream_cmd: Optional[Sequence[str]] = None,
    upstream_url: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    workspace: Optional[Path] = None,
    mode: str = "enforce",
    session_id: str = "",
    subject: Optional[str] = None,
    agent_name: str = "",
    persist: bool = True,
    as_jsonrpc_error: bool = False,
    framing: str = "auto",
) -> int:
    """CLI entry: stdio mode if ``upstream_cmd``, else HTTP if ``upstream_url``."""
    ws = (workspace or Path.cwd()).resolve()
    cfg = ProxyConfig(
        workspace=ws,
        mode=mode,
        session_id=session_id,
        subject=subject,
        agent_name=agent_name,
        persist=persist,
        as_jsonrpc_error=as_jsonrpc_error,
        framing=framing,
    )

    if upstream_cmd:
        return run_stdio_proxy(upstream_cmd, cfg=cfg)
    if upstream_url:
        run_http_proxy(upstream=upstream_url, host=host, port=port, cfg=cfg)
        return 0

    sys.stderr.write(
        "[prismor] mcp-proxy: provide --stdio -- <cmd…> or --upstream <url>\n"
    )
    return 2
