"""Prismor MCP Gateway — a single MCP server that fronts all of a user's MCP servers.

The user's agent (Claude Code, Cursor, any MCP client) is configured with ONE
stdio MCP server: ``prismor mcp-gateway``. The gateway aggregates the user's
downstream MCP servers (read from an ``mcpServers``-shaped config), exposes
their tools to the client namespaced as ``<server>__<tool>``, and becomes the
single enforcement point:

  * every ``tools/call`` is evaluated by ``evaluate_tool_call`` before it is
    forwarded (tool denies, trifecta tag crossover, IAM, policy rules), and
  * every tool *result* is re-evaluated as a ``tool_result`` event (prompt
    injection / poisoned content) before it is returned to the model.

Naming subtlety (the one correctness trap in this design): the client sees
``github__create_issue`` and its client (e.g. Claude Code) will prefix that
with its own MCP tag (``mcp__prismor__github__create_issue``). Internally the
gateway builds policy events with ``tool_name = mcp__github__create_issue`` —
the *real* server name — so trifecta defaults (``mcp__*__send_email``), org
tool denies, and control-plane matchers all fire on the actual server, not on
the gateway's alias. Routing never string-parses names: a cached
rewritten-name -> (upstream, original-name) map is authoritative, so ``__`` in
downstream tool names cannot misroute.

Denials are returned as MCP tool results with ``isError: true`` (the model can
read the reason and adapt); JSON-RPC errors are reserved for protocol failures
(unknown tool, dead upstream).

Transport: newline-delimited JSON-RPC over stdio on the client side; stdio
subprocesses or streamable-HTTP/SSE (stdlib urllib) on the upstream side. No
third-party dependencies — the runtime's floor is Python 3.8 and its only dep
is pyyaml, which the official MCP SDK would break.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from prismor.runtime.hooks import _extract_mcp_response_text, _mcp_endpoint_meta

PROTOCOL_VERSION_FALLBACK = "2025-03-26"
GATEWAY_AGENT = "mcp-gateway"
REQUEST_TIMEOUT = 30.0
CALL_TIMEOUT = 300.0


def _gateway_version() -> str:
    try:
        from importlib.metadata import version
        return version("prismor")
    except Exception:
        return "0"


# ── config ───────────────────────────────────────────────────────────────────

@dataclass
class UpstreamSpec:
    name: str
    command: Optional[List[str]] = None
    env: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""       # "stdio" | "http" | "sse" (informational)
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def remote(self) -> bool:
        return bool(self.url)


class GatewayConfigError(ValueError):
    pass


def load_gateway_config(path: Path) -> List[UpstreamSpec]:
    """Load downstream servers from a ``.mcp.json``-shaped config.

    Accepts both ``{"mcpServers": {...}}`` (Claude Code / Claude Desktop /
    Cursor — users move their existing block over verbatim) and a
    prismor-native ``{"servers": {...}}``.
    """
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise GatewayConfigError(f"gateway config not found: {path}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise GatewayConfigError(f"gateway config is not valid JSON: {path}: {exc}")
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise GatewayConfigError(
            f"no servers found in {path} (expected an 'mcpServers' object)")
    specs: List[UpstreamSpec] = []
    for name, cfg in servers.items():
        specs.append(_spec_from_entry(str(name), cfg if isinstance(cfg, dict) else {}))
    return specs


def _spec_from_entry(name: str, cfg: Dict[str, Any]) -> UpstreamSpec:
    meta = _mcp_endpoint_meta(cfg)
    if meta["url"]:
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        return UpstreamSpec(name=name, url=meta["url"],
                            transport=meta["transport"] or "http",
                            headers=dict(headers or {}))
    command = cfg.get("command")
    if isinstance(command, str):
        argv = [command] + [str(a) for a in cfg.get("args") or []]
    elif isinstance(command, list):
        argv = [str(a) for a in command] + [str(a) for a in cfg.get("args") or []]
    else:
        raise GatewayConfigError(f"server '{name}' has neither a url nor a command")
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    return UpstreamSpec(name=name, command=argv, transport="stdio",
                        env={str(k): str(v) for k, v in (env or {}).items()})


def parse_inline_server(value: str) -> UpstreamSpec:
    """Parse a ``--server name=<url|command>`` value."""
    name, sep, rest = value.partition("=")
    if not sep or not name.strip() or not rest.strip():
        raise GatewayConfigError(f"--server expects name=<url|command>, got: {value!r}")
    rest = rest.strip()
    if rest.startswith(("http://", "https://")):
        return UpstreamSpec(name=name.strip(), url=rest, transport="http")
    return UpstreamSpec(name=name.strip(), command=shlex.split(rest), transport="stdio")


# ── upstream clients ─────────────────────────────────────────────────────────

class UpstreamError(RuntimeError):
    def __init__(self, message: str, code: int = -32603):
        super().__init__(message)
        self.code = code


class Upstream:
    """One downstream MCP server."""

    def __init__(self, spec: UpstreamSpec,
                 on_notification: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.spec = spec
        self.on_notification = on_notification

    def initialize(self, client_params: Dict[str, Any]) -> Dict[str, Any]:
        result = self.request("initialize", client_params, timeout=REQUEST_TIMEOUT)
        self.notify("notifications/initialized", {})
        return result

    def request(self, method: str, params: Dict[str, Any],
                timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
        raise NotImplementedError

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class UpstreamStdio(Upstream):
    def __init__(self, spec: UpstreamSpec,
                 on_notification: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        super().__init__(spec, on_notification)
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()          # serialize writes to stdin
        self._pending: Dict[str, "_PendingReply"] = {}
        self._counter = 0
        self._reader: Optional[threading.Thread] = None

    def _ensure_started(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        env = dict(os.environ)
        env.update(self.spec.env)
        kwargs: Dict[str, Any] = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        try:
            self._proc = subprocess.Popen(
                self.spec.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                env=env,
                text=True,
                bufsize=1,
                **kwargs,
            )
        except OSError as exc:
            raise UpstreamError(
                f"failed to start MCP server '{self.spec.name}': {exc}")
        self._reader = threading.Thread(
            target=self._read_loop, name=f"mcp-up-{self.spec.name}", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            msg_id = msg.get("id")
            if msg_id is not None and ("result" in msg or "error" in msg):
                pending = self._pending.pop(str(msg_id), None)
                if pending is not None:
                    pending.resolve(msg)
            elif msg_id is not None and msg.get("method"):
                # Server-initiated request (sampling/roots/...). The gateway is
                # a tools aggregator and cannot broker these back to the client
                # without id remapping — refuse rather than hang the upstream.
                self._write({"jsonrpc": "2.0", "id": msg_id,
                             "error": {"code": -32601,
                                       "message": "prismor-gateway: server-initiated requests are not supported"}})
            elif msg.get("method") and self.on_notification is not None:
                try:
                    self.on_notification(msg["method"], msg.get("params") or {})
                except Exception:
                    pass
        # EOF: upstream died — fail everything still in flight.
        for pending in list(self._pending.values()):
            pending.resolve({"error": {"code": -32603,
                                       "message": f"MCP server '{self.spec.name}' exited"}})
        self._pending.clear()

    def _write(self, msg: Dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise UpstreamError(f"MCP server '{self.spec.name}' is not running")
        with self._lock:
            try:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                raise UpstreamError(f"MCP server '{self.spec.name}' pipe closed")

    def request(self, method: str, params: Dict[str, Any],
                timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
        self._ensure_started()
        self._counter += 1
        req_id = f"gw-{self._counter}"
        pending = _PendingReply()
        self._pending[req_id] = pending
        try:
            self._write({"jsonrpc": "2.0", "id": req_id,
                         "method": method, "params": params})
        except UpstreamError:
            self._pending.pop(req_id, None)
            raise
        msg = pending.wait(timeout)
        if msg is None:
            self._pending.pop(req_id, None)
            raise UpstreamError(
                f"MCP server '{self.spec.name}' timed out on {method}")
        if "error" in msg:
            err = msg["error"] or {}
            raise UpstreamError(str(err.get("message") or "upstream error"),
                                code=int(err.get("code") or -32603))
        return msg.get("result") or {}

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        self._ensure_started()
        try:
            self._write({"jsonrpc": "2.0", "method": method, "params": params})
        except UpstreamError:
            pass

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None or proc.poll() is not None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except Exception:
            pass
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass


class _PendingReply:
    def __init__(self) -> None:
        self._event = threading.Event()
        self._msg: Optional[Dict[str, Any]] = None

    def resolve(self, msg: Dict[str, Any]) -> None:
        self._msg = msg
        self._event.set()

    def wait(self, timeout: float) -> Optional[Dict[str, Any]]:
        self._event.wait(timeout)
        return self._msg


class UpstreamHttp(Upstream):
    """Streamable-HTTP upstream via stdlib urllib.

    POSTs each JSON-RPC message; understands both ``application/json`` and
    ``text/event-stream`` responses (the streamable-HTTP spec allows either).
    Notifications delivered on the SSE stream are surfaced through
    ``on_notification``. The ``Mcp-Session-Id`` response header is echoed on
    subsequent requests.
    """

    def __init__(self, spec: UpstreamSpec,
                 on_notification: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        super().__init__(spec, on_notification)
        self._session_id: Optional[str] = None
        self._counter = 0
        self._lock = threading.Lock()

    def _post(self, body: Dict[str, Any], timeout: float,
              want_reply: bool) -> Optional[Dict[str, Any]]:
        import urllib.request
        import urllib.error
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            # urllib's default Python-urllib/x.y UA is rejected outright by
            # common CDNs/WAFs (Cloudflare returns 403) — identify honestly.
            "User-Agent": "prismor-gateway/" + _gateway_version(),
        }
        headers.update(self.spec.headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(
            self.spec.url, data=json.dumps(body).encode("utf-8"),
            headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self._session_id = sid
                if not want_reply:
                    return None
                ctype = (resp.headers.get("Content-Type") or "").lower()
                raw = resp.read().decode("utf-8", errors="replace")
                if "text/event-stream" in ctype:
                    return self._parse_sse(raw, str(body.get("id")))
                if not raw.strip():
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise UpstreamError(
                f"MCP server '{self.spec.name}' HTTP {exc.code}: {exc.reason}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise UpstreamError(f"MCP server '{self.spec.name}' unreachable: {exc}")

    def _parse_sse(self, raw: str, want_id: str) -> Optional[Dict[str, Any]]:
        reply: Optional[Dict[str, Any]] = None
        data_lines: List[str] = []
        for line in raw.splitlines() + [""]:
            if line.startswith("data:"):
                data_lines.append(line[len("data:"):].strip())
                continue
            if line.strip() == "" and data_lines:
                try:
                    msg = json.loads("\n".join(data_lines))
                except (json.JSONDecodeError, ValueError):
                    msg = None
                data_lines = []
                if not isinstance(msg, dict):
                    continue
                if str(msg.get("id")) == want_id and ("result" in msg or "error" in msg):
                    reply = msg
                elif msg.get("method") and msg.get("id") is None \
                        and self.on_notification is not None:
                    try:
                        self.on_notification(msg["method"], msg.get("params") or {})
                    except Exception:
                        pass
        return reply

    def request(self, method: str, params: Dict[str, Any],
                timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
        with self._lock:
            self._counter += 1
            req_id = f"gw-{self._counter}"
        msg = self._post({"jsonrpc": "2.0", "id": req_id,
                          "method": method, "params": params},
                         timeout=timeout, want_reply=True)
        if msg is None:
            raise UpstreamError(
                f"MCP server '{self.spec.name}' returned no reply to {method}")
        if "error" in msg:
            err = msg["error"] or {}
            raise UpstreamError(str(err.get("message") or "upstream error"),
                                code=int(err.get("code") or -32603))
        return msg.get("result") or {}

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        try:
            self._post({"jsonrpc": "2.0", "method": method, "params": params},
                       timeout=REQUEST_TIMEOUT, want_reply=False)
        except UpstreamError:
            pass


def make_upstream(spec: UpstreamSpec,
                  on_notification: Optional[Callable[[str, Dict[str, Any]], None]] = None
                  ) -> Upstream:
    if spec.remote:
        return UpstreamHttp(spec, on_notification)
    return UpstreamStdio(spec, on_notification)


# ── gateway ──────────────────────────────────────────────────────────────────

@dataclass
class _Route:
    upstream: Upstream
    server: str        # real downstream server name (event namespace)
    tool: str          # original un-namespaced tool name
    # Tags the server self-declares on the tool definition (_meta.prismor.tags,
    # _meta.tags, or annotations["prismor/tags"]) — consumed by trifecta
    # classification below the explicit org map (admin always wins).
    meta_tags: List[str] = field(default_factory=list)


_META_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")
_META_TAG_CAP = 8


def _extract_meta_tags(tool: Dict[str, Any]) -> List[str]:
    """Pull self-declared tags off an upstream tool definition, sanitized:
    lowercase, tag charset only, capped. Untrusted input — never let a server
    smuggle arbitrary strings into policy findings."""
    raw: Any = None
    meta = tool.get("_meta")
    if isinstance(meta, dict):
        pris = meta.get("prismor")
        if isinstance(pris, dict):
            raw = pris.get("tags")
        if raw is None:
            raw = meta.get("tags")
    if raw is None:
        ann = tool.get("annotations")
        if isinstance(ann, dict):
            raw = ann.get("prismor/tags")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    out: List[str] = []
    for item in raw:
        tag = str(item).strip().lower()
        if tag and _META_TAG_RE.match(tag) and tag not in out:
            out.append(tag)
        if len(out) >= _META_TAG_CAP:
            break
    return out


class Gateway:
    def __init__(self, specs: List[UpstreamSpec], *, workspace: Path,
                 mode: str = "enforce", namespace: str = "plain",
                 session_id: str = ""):
        if not specs:
            raise GatewayConfigError("no upstream MCP servers configured")
        names = [s.name for s in specs]
        if len(set(names)) != len(names):
            raise GatewayConfigError(f"duplicate upstream server names: {names}")
        self.workspace = workspace
        self.mode = mode
        # Single-upstream shim mode may skip renaming; the aggregator must
        # namespace to keep tool names collision-free across servers.
        self.namespace = "plain" if (namespace == "none" and len(specs) > 1) else namespace
        # A stable session id makes sessions resumable across gateway restarts
        # (hosted deployments restore the session store + trifecta ledger from
        # durable storage — a fresh id each boot would orphan that state and
        # reset the crossover ledger, reopening the wait-out-the-restart bypass).
        self.session_id = session_id or ("mcp-" + uuid.uuid4().hex[:12])
        self.agent_name = GATEWAY_AGENT
        self.upstreams: List[Upstream] = [
            make_upstream(s, self._make_notification_handler(s.name)) for s in specs
        ]
        self._routes: Dict[str, _Route] = {}
        self._routes_lock = threading.Lock()
        self._stdout_lock = threading.Lock()
        self._eval_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=8,
                                            thread_name_prefix="mcp-gw")
        self._initialized = False
        self._client_protocol = PROTOCOL_VERSION_FALLBACK

    # ── serve loop ───────────────────────────────────────────────────────

    def serve_stdio(self) -> int:
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                self._dispatch(msg)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()
        return 0

    def close(self) -> None:
        self._executor.shutdown(wait=False)
        for up in self.upstreams:
            try:
                up.close()
            except Exception:
                pass

    def _send(self, msg: Dict[str, Any]) -> None:
        with self._stdout_lock:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def _reply(self, req_id: Any, result: Dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _reply_error(self, req_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": code, "message": message}})

    def _dispatch(self, msg: Dict[str, Any]) -> None:
        method = msg.get("method")
        req_id = msg.get("id")
        if not method:
            return
        if req_id is None:
            self._handle_notification(method, msg.get("params") or {})
            return
        params = msg.get("params") or {}
        if method == "initialize":
            self._handle_initialize(req_id, params)
        elif method == "tools/list":
            self._handle_tools_list(req_id, params)
        elif method == "tools/call":
            # Claude Code issues concurrent tool calls; handle off-loop so one
            # slow upstream doesn't head-of-line-block the others.
            self._executor.submit(self._handle_tools_call_safe, req_id, params)
        elif method == "ping":
            self._reply(req_id, {})
        else:
            # Tools-only aggregation: resources/prompts are never advertised in
            # the initialize capabilities, so a compliant client won't ask.
            self._reply_error(req_id, -32601, f"method not supported by prismor-gateway: {method}")

    def _handle_notification(self, method: str, params: Dict[str, Any]) -> None:
        if method == "notifications/initialized":
            self._initialized = True
            return
        # cancellation / progress from the client — fan out best-effort.
        for up in self.upstreams:
            try:
                up.notify(method, params)
            except Exception:
                pass

    # ── initialize ───────────────────────────────────────────────────────

    def _handle_initialize(self, req_id: Any, params: Dict[str, Any]) -> None:
        client_info = params.get("clientInfo") or {}
        if isinstance(client_info, dict) and client_info.get("name"):
            # Feeds per-agent controls (kill switch, forced mode) in
            # evaluate_tool_call, so an admin can target e.g. "claude-code".
            self.agent_name = str(client_info["name"])
        self._client_protocol = str(
            params.get("protocolVersion") or PROTOCOL_VERSION_FALLBACK)
        for up in self.upstreams:
            try:
                up.initialize(params)
            except UpstreamError as exc:
                sys.stderr.write(
                    f"[prismor-gateway] upstream '{up.spec.name}' failed to initialize: {exc}\n")
        self._reply(req_id, {
            "protocolVersion": self._client_protocol,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "prismor-gateway",
                           "version": _gateway_version()},
        })

    # ── tools/list ───────────────────────────────────────────────────────

    def _client_tool_name(self, server: str, tool: str) -> str:
        if self.namespace == "none":
            return tool
        return f"{server}__{tool}"

    def _handle_tools_list(self, req_id: Any, params: Dict[str, Any]) -> None:
        tools: List[Dict[str, Any]] = []
        routes: Dict[str, _Route] = {}
        for up in self.upstreams:
            try:
                result = up.request("tools/list", {}, timeout=REQUEST_TIMEOUT)
            except UpstreamError as exc:
                sys.stderr.write(
                    f"[prismor-gateway] tools/list failed for '{up.spec.name}': {exc}\n")
                continue
            for tool in result.get("tools") or []:
                if not isinstance(tool, dict) or not tool.get("name"):
                    continue
                original = str(tool["name"])
                exposed = self._client_tool_name(up.spec.name, original)
                routes[exposed] = _Route(upstream=up, server=up.spec.name,
                                         tool=original,
                                         meta_tags=_extract_meta_tags(tool))
                entry = dict(tool)
                entry["name"] = exposed
                if self.namespace != "none":
                    desc = str(tool.get("description") or "")
                    entry["description"] = f"[{up.spec.name}] {desc}".strip()
                tools.append(entry)
        with self._routes_lock:
            self._routes = routes
        self._reply(req_id, {"tools": tools})

    # ── tools/call (the enforcement point) ───────────────────────────────

    def _handle_tools_call_safe(self, req_id: Any, params: Dict[str, Any]) -> None:
        try:
            self._handle_tools_call(req_id, params)
        except UpstreamError as exc:
            self._reply_error(req_id, exc.code, str(exc))
        except Exception as exc:  # never kill the serve loop from a worker
            self._reply_error(req_id, -32603, f"prismor-gateway internal error: {exc}")

    def _handle_tools_call(self, req_id: Any, params: Dict[str, Any]) -> None:
        name = str(params.get("name") or "")
        arguments = params.get("arguments")
        with self._routes_lock:
            route = self._routes.get(name)
        if route is None:
            self._reply_error(req_id, -32602, f"unknown tool: {name}")
            return

        # Keep org-managed policy fresh on the hot path (debounced ~30s;
        # no-op when not enrolled). Mirrors the hook-dispatch handler.
        try:
            from prismor.runtime.enterprise import remote_policy as _remote
            _remote.check_and_refresh()
        except Exception:
            pass

        # Pre-call evaluation.
        decision = self._evaluate(self._build_call_event(route, arguments))
        if decision is not None:
            from prismor.runtime.runtime import log_observe_findings
            log_observe_findings(decision, mode=self.mode, tool_name=name)
        if decision is not None and decision.blocking is not None:
            self._reply(req_id, _blocked_result("Blocked by Prismor",
                                                decision.blocking))
            return

        result = route.upstream.request(
            "tools/call", {"name": route.tool, "arguments": arguments},
            timeout=CALL_TIMEOUT)

        # Post-call: the response is untrusted content — scan before the model
        # ever sees it (prompt injection, poisoned tool output, secrets).
        decision = self._evaluate(self._build_result_event(route, result))
        if decision is not None:
            from prismor.runtime.runtime import log_observe_findings
            log_observe_findings(decision, mode=self.mode, tool_name=name)
        if decision is not None and decision.blocking is not None:
            self._reply(req_id, _blocked_result(
                "[Prismor] response withheld", decision.blocking))
            return

        self._reply(req_id, result)

    def _evaluate(self, event: Dict[str, Any]):
        """Run one event through the shared runtime pipeline.

        Serialized: the trifecta TagLedger depends on session ordering, and
        interleaved evaluations of concurrent calls could let the completing
        call of a forbidden tag pair slip past the ledger check.
        """
        try:
            from prismor.runtime.runtime import evaluate_tool_call
            with self._eval_lock:
                return evaluate_tool_call(
                    event=event,
                    workspace=self.workspace,
                    agent=GATEWAY_AGENT,
                    mode=self.mode,
                    session_id=self.session_id,
                    agent_name=self.agent_name,
                )
        except Exception as exc:
            # Fail open on engine *errors* only in observe mode; in enforce
            # mode a broken engine must not silently wave calls through.
            sys.stderr.write(f"[prismor-gateway] evaluation error: {exc}\n")
            if self.mode == "enforce":
                raise UpstreamError(
                    f"prismor-gateway: policy evaluation failed ({exc}); "
                    "call denied (fail-closed)")
            return None

    # ── event builders ───────────────────────────────────────────────────

    def _event_base(self, route: _Route, agent_event: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            "cwd": str(self.workspace),
            # The REAL server name — matches trifecta globs, tool denies,
            # and control-plane parseToolName. See module docstring.
            "tool_name": f"mcp__{route.server}__{route.tool}",
        }
        if route.meta_tags:
            # Server-declared tags ride on the event; trifecta consumes them
            # as a classification tier below the explicit org map.
            metadata["meta_tags"] = list(route.meta_tags)
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "agent": GATEWAY_AGENT,
            "agent_event": agent_event,
            "metadata": metadata,
        }

    def _build_call_event(self, route: _Route, arguments: Any) -> Dict[str, Any]:
        base = self._event_base(route, "PreToolUse")
        try:
            args_text = json.dumps(arguments, default=str)
        except Exception:
            args_text = str(arguments)
        mcp_meta = {"mcp_server": route.server, "mcp_tool": route.tool}
        spec = route.upstream.spec
        if spec.remote:
            # Remote server: route through the network path so the egress
            # allowlist, secret-in-args, and taint escalation rules apply.
            return {**base, "type": "network", "url": spec.url,
                    "outbound_payload": args_text, **mcp_meta}
        return {**base, "type": "tool_result", "response": args_text, **mcp_meta}

    def _build_result_event(self, route: _Route, result: Any) -> Dict[str, Any]:
        base = self._event_base(route, "PostToolUse")
        event = {**base, "type": "tool_result",
                 "response": _extract_mcp_response_text(result),
                 "mcp_server": route.server, "mcp_tool": route.tool}
        spec = route.upstream.spec
        if spec.remote:
            event["url"] = spec.url
        return event

    # ── upstream notifications ───────────────────────────────────────────

    def _make_notification_handler(self, server: str) -> Callable[[str, Dict[str, Any]], None]:
        def _handler(method: str, params: Dict[str, Any]) -> None:
            if method == "notifications/tools/list_changed":
                # Route map is rebuilt on the client's next tools/list.
                with self._routes_lock:
                    self._routes = {}
                self._send({"jsonrpc": "2.0", "method": method, "params": params})
            elif method.startswith("notifications/"):
                # progress / logging — pass through untouched (tokens are
                # client-allocated and unambiguous).
                self._send({"jsonrpc": "2.0", "method": method, "params": params})
        return _handler


def _blocked_result(prefix: str, blocking: Dict[str, Any]) -> Dict[str, Any]:
    parts = [f"{prefix}: [{blocking.get('severity', 'high')}] "
             f"{blocking.get('title', 'policy violation')}"]
    if blocking.get("ruleId"):
        parts[0] += f" (rule: {blocking['ruleId']})"
    if blocking.get("evidence"):
        parts.append(str(blocking["evidence"]))
    if blocking.get("remediation"):
        parts.append(f"Recommended fix: {blocking['remediation']}")
    return {"content": [{"type": "text", "text": "\n".join(parts)}],
            "isError": True}


# ── install / uninstall helper ───────────────────────────────────────────────

DEFAULT_GATEWAY_CONFIG = Path.home() / ".prismor" / "mcp-gateway.json"


# Top-level keys an MCP server block is declared under. ``mcpServers`` is the
# Claude Code / Claude Desktop / Cursor / Windsurf / Cline spelling; ``servers``
# is VS Code's. Anything else — Zed's ``context_servers``, Codex's TOML — is
# left alone rather than guessed at: this function rewrites files the developer
# owns, so an unrecognised shape must mean "don't touch", never "assume".
_MCP_BLOCK_KEYS = ("mcpServers", "servers")


@dataclass
class MigrationResult:
    """What happened to one config file."""

    path: Path
    #: migrated | skipped | failed
    status: str
    moved: int = 0
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "migrated"


def _gateway_entry() -> Dict[str, Any]:
    return {"command": "prismor",
            "args": ["mcp-gateway", "--config", str(DEFAULT_GATEWAY_CONFIG)]}


def _absorb(servers: Dict[str, Any]) -> int:
    """Merge servers into the gateway config. Returns how many moved."""
    DEFAULT_GATEWAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    existing: Dict[str, Any] = {}
    if DEFAULT_GATEWAY_CONFIG.exists():
        try:
            existing = (json.loads(DEFAULT_GATEWAY_CONFIG.read_text(encoding="utf-8"))
                        .get("mcpServers") or {})
        except (json.JSONDecodeError, ValueError, OSError):
            existing = {}
    moved = {k: v for k, v in servers.items() if k != "prismor"}
    existing.update(moved)
    DEFAULT_GATEWAY_CONFIG.write_text(
        json.dumps({"mcpServers": existing}, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(DEFAULT_GATEWAY_CONFIG, 0o600)  # may hold tokens in env blocks
    except OSError:
        pass
    return len(moved)


def migrate_config(path: Path) -> MigrationResult:
    """Move one config file's MCP servers behind the gateway.

    Everything in the file that is not the server block is preserved verbatim —
    these are live configs carrying the developer's own settings, and a
    migration that dropped an unrelated key would be a far worse bug than the
    ungoverned server it set out to fix. The original is kept alongside as
    ``<name>.bak`` before anything is written.
    """
    if not path.exists():
        return MigrationResult(path, "skipped", detail="file no longer exists")
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return MigrationResult(path, "failed", detail=f"not valid JSON: {exc}")
    except OSError as exc:
        return MigrationResult(path, "failed", detail=str(exc))
    if not isinstance(data, dict):
        return MigrationResult(path, "skipped", detail="not a JSON object")

    key = next((k for k in _MCP_BLOCK_KEYS
                if isinstance(data.get(k), dict) and data.get(k)), None)
    if key is None:
        return MigrationResult(
            path, "skipped",
            detail="no recognised MCP server block (mcpServers/servers)")

    servers = data[key]
    if list(servers.keys()) == ["prismor"]:
        return MigrationResult(path, "skipped", detail="already behind the gateway")

    moved = _absorb(servers)
    if not moved:
        return MigrationResult(path, "skipped", detail="nothing to move")

    backup = Path(str(path) + ".bak")
    try:
        backup.write_text(raw, encoding="utf-8")
    except OSError as exc:
        # No backup, no rewrite. Losing the original is not an acceptable
        # trade for governing a server.
        return MigrationResult(path, "failed", detail=f"could not write backup: {exc}")

    data[key] = {"prismor": _gateway_entry()}
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        return MigrationResult(path, "failed", detail=str(exc))
    return MigrationResult(path, "migrated", moved=moved,
                           detail=f"moved {moved} server(s); backup at {backup}")


def migrate_configs(paths: Iterable[Path]) -> List[MigrationResult]:
    """Migrate several configs. One bad file never stops the rest."""
    seen: set = set()
    out: List[MigrationResult] = []
    for path in paths:
        try:
            key = str(Path(path).resolve())
        except (OSError, ValueError):
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(migrate_config(Path(path)))
    return out


def install_gateway(workspace: Path) -> str:
    """Move the workspace ``.mcp.json`` servers behind the gateway.

    Scope is deliberately this one file. ``migrate_configs`` handles the wider
    sweep (Claude Desktop, Cursor, VS Code …); broadening this entry point
    would mean ``prismor mcp-gateway install`` silently rewriting configs the
    developer did not point it at.
    """
    mcp_json = workspace / ".mcp.json"
    if not mcp_json.exists():
        return f"No .mcp.json found in {workspace} — nothing to install."
    result = migrate_config(mcp_json)
    if result.status == "failed":
        raise GatewayConfigError(f"{mcp_json}: {result.detail}")
    if result.status == "skipped":
        if "already behind the gateway" in result.detail:
            return "Gateway already installed (only the prismor entry remains)."
        return f"{mcp_json} has no mcpServers — nothing to install."
    return (f"Moved {result.moved} server(s) into {DEFAULT_GATEWAY_CONFIG}.\n"
            f"{mcp_json} now routes through the Prismor gateway "
            f"(backup: {mcp_json.with_suffix('.json.bak')}).")


def uninstall_gateway(workspace: Path) -> str:
    """Restore ``.mcp.json`` from the backup written by :func:`install_gateway`."""
    mcp_json = workspace / ".mcp.json"
    backup = mcp_json.with_suffix(".json.bak")
    if not backup.exists():
        return f"No backup found at {backup} — nothing to restore."
    mcp_json.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
    backup.unlink()
    return f"Restored {mcp_json} from backup. Gateway config left at {DEFAULT_GATEWAY_CONFIG}."


# ── CLI entrypoint ───────────────────────────────────────────────────────────

# Interpreters/launchers that say nothing about WHICH server this is. The
# server name feeds every policy matcher (mcp__<name>__<tool>), so shim mode
# must not name an upstream "python3" or "npx".
_LAUNCHERS = {"python", "python3", "node", "npx", "bunx", "uv", "uvx", "deno", "sh", "bash"}


def _shim_name(argv: List[str]) -> str:
    for token in argv:
        stem = Path(token).stem.lower()
        if stem in _LAUNCHERS or token.startswith("-"):
            continue
        name = Path(token).stem
        if name:
            return name
    return "upstream"


def _install_everywhere(workspace: Path) -> str:
    """Migrate every MCP config ``discover`` can find on this machine.

    Uses discovery's own enumeration rather than a second list, so the set of
    files this rewrites is exactly the set the sweep reports as ungoverned —
    two lists would drift, and the gap would be servers reported as shadow that
    nothing can ever fix.
    """
    try:
        from prismor.runtime.discover import discover_mcp
    except Exception as exc:  # pragma: no cover - import guard
        return f"Could not enumerate MCP configs: {exc}"
    sources = []
    for record in discover_mcp(workspace):
        if record.is_gateway or record.managed or not record.source:
            continue
        sources.append(Path(record.source))
    if not sources:
        return "No ungoverned MCP servers found — nothing to install."

    results = migrate_configs(sources)
    lines = []
    total = 0
    for r in results:
        if r.ok:
            total += r.moved
            lines.append(f"  migrated  {r.path}  ({r.moved} server(s))")
        elif r.status == "failed":
            lines.append(f"  FAILED    {r.path}  — {r.detail}")
        else:
            lines.append(f"  skipped   {r.path}  — {r.detail}")
    head = (f"Moved {total} server(s) into {DEFAULT_GATEWAY_CONFIG} "
            f"from {sum(1 for r in results if r.ok)} config file(s).")
    return head + "\n" + "\n".join(lines)


def run_gateway(args, workspace: Path) -> int:
    """Entry point for ``prismor mcp-gateway`` (called from cli.main)."""
    action = getattr(args, "action", None) or "serve"
    if action == "install":
        if getattr(args, "all", False):
            print(_install_everywhere(workspace))
            return 0
        print(install_gateway(workspace))
        return 0
    if action == "uninstall":
        print(uninstall_gateway(workspace))
        return 0

    specs: List[UpstreamSpec] = []
    if getattr(args, "upstream", None):
        value = args.upstream.strip()
        if value.startswith(("http://", "https://")):
            specs.append(UpstreamSpec(name="upstream", url=value, transport="http"))
        else:
            argv = shlex.split(value)
            specs.append(UpstreamSpec(name=_shim_name(argv),
                                      command=argv, transport="stdio"))
    for inline in getattr(args, "server", None) or []:
        specs.append(parse_inline_server(inline))
    if not specs:
        config = getattr(args, "config", None)
        path = Path(config).expanduser() if config else DEFAULT_GATEWAY_CONFIG
        specs = load_gateway_config(path)

    gateway = Gateway(specs, workspace=workspace,
                      mode=getattr(args, "mode", "observe") or "observe",
                      namespace=getattr(args, "namespace", "plain") or "plain",
                      session_id=(getattr(args, "session_id", "") or
                                  os.environ.get("PRISMOR_SESSION_ID", "")))

    def _shutdown(signum, frame):  # noqa: ARG001
        gateway.close()
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, OSError):
        pass  # not the main thread / unsupported platform

    sys.stderr.write(
        f"[prismor-gateway] serving {len(specs)} upstream server(s) "
        f"session={gateway.session_id} mode={gateway.mode}\n")
    return gateway.serve_stdio()
