"""Prismor LLM Gateway — governed egress for model API traffic.

The MCP gateway (``prismor/runtime/mcp_gateway.py``) governs the *tool* lane:
one connector in front of every MCP server. This module is the *model* lane —
a local HTTP proxy that agents point at instead of ``api.anthropic.com`` /
``api.openai.com``. Together they are the two data-plane lanes of
``prismor gateway``.

What passing through here buys, none of which the agent has to opt into:

  * **Policy.** Every request is evaluated by ``evaluate_tool_call`` — the
    same engine the PreToolUse hooks run — as a ``network`` event carrying the
    outbound payload, so the egress allowlist, secret-in-payload rules, and
    taint escalation all apply with no new policy surface to configure.
  * **Credential brokering.** The client sends a placeholder (or nothing at
    all); the real provider key is resolved here, server-side, and never has
    to exist on the developer's machine. See ``resolve_upstream_auth``.
  * **Metering.** Token counts and cost are extracted from the provider's own
    usage accounting and attributed to session/agent/subject, then flushed as
    ``llm_usage`` telemetry records — the same uploader the finding records
    and activity heartbeats already use.
  * **Response scanning.** The completion is re-evaluated as a ``tool_result``
    event before it reaches the caller, so a poisoned upstream (or a
    compromised provider account) cannot inject directives into context.

Design constraints inherited from the runtime: stdlib only (the floor is
Python 3.8 and the sole dependency is pyyaml), fail-closed in enforce mode,
and never block the hot path on the control plane — usage flushes are
debounced and spooled exactly like every other telemetry record.

Streaming is a first-class path, not an afterthought: agent traffic is
overwhelmingly SSE, and a proxy that only handled buffered JSON would be
useless in practice. Streamed bytes are relayed to the client as they arrive
(no added latency, no buffering the whole completion) while a tap accumulates
just enough to recover the usage block and the assistant text for scanning.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

GATEWAY_AGENT = "llm-gateway"
DEFAULT_PORT = 8787
UPSTREAM_TIMEOUT = 600.0
# Bound how much of a request/response body we hand to the policy engine.
# Prompts are unbounded in principle; scanning the first 256 KiB catches
# injected directives and secret material without turning a long context
# window into an O(MB) regex sweep on every call.
SCAN_CAP = 256 * 1024


# ── providers ────────────────────────────────────────────────────────────────

@dataclass
class ProviderSpec:
    """How to reach one model provider and how to read its usage accounting."""
    name: str
    base_url: str
    # Header carrying the provider credential, and how the value is formatted.
    auth_header: str
    auth_format: str            # "{key}" or "Bearer {key}"
    env_keys: Tuple[str, ...]   # env vars searched, in order, for the key
    # Path prefixes this provider claims when the gateway is multiplexing
    # several providers on one port.
    path_prefixes: Tuple[str, ...]


_PROVIDERS: Dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic",
        base_url="https://api.anthropic.com",
        auth_header="x-api-key",
        auth_format="{key}",
        env_keys=("ANTHROPIC_API_KEY",),
        path_prefixes=("/v1/messages", "/v1/complete"),
    ),
    "openai": ProviderSpec(
        name="openai",
        base_url="https://api.openai.com",
        auth_header="Authorization",
        auth_format="Bearer {key}",
        env_keys=("OPENAI_API_KEY",),
        path_prefixes=("/v1/chat/completions", "/v1/responses", "/v1/embeddings"),
    ),
}


class LlmGatewayError(RuntimeError):
    pass


def resolve_provider(name: str) -> ProviderSpec:
    spec = _PROVIDERS.get(name.strip().lower())
    if spec is None:
        raise LlmGatewayError(
            f"unknown provider {name!r} (known: {', '.join(sorted(_PROVIDERS))})")
    return spec


def provider_for_path(path: str) -> Optional[ProviderSpec]:
    """Pick a provider from the request path when multiplexing.

    Explicit ``/<provider>/...`` prefixes win; otherwise the native API path
    is matched so an SDK pointed at the gateway with only its base URL changed
    works untouched.
    """
    clean = path.split("?", 1)[0]
    for name, spec in _PROVIDERS.items():
        if clean == f"/{name}" or clean.startswith(f"/{name}/"):
            return spec
    for spec in _PROVIDERS.values():
        for prefix in spec.path_prefixes:
            if clean.startswith(prefix):
                return spec
    return None


def strip_provider_prefix(path: str, spec: ProviderSpec) -> str:
    if path == f"/{spec.name}":
        return "/"
    if path.startswith(f"/{spec.name}/"):
        return path[len(spec.name) + 1:]
    return path


# ── credential brokering ─────────────────────────────────────────────────────

# A client may send a Cloak placeholder instead of a real key. Resolving it
# here is what lets a laptop hold no provider credentials at all.
_PLACEHOLDER_RE = re.compile(r"^@@SECRET:([A-Za-z0-9_.\-]+)@@$")


def resolve_upstream_auth(spec: ProviderSpec,
                          client_value: Optional[str]) -> Optional[str]:
    """Resolve the credential actually sent upstream.

    Order: a Cloak placeholder from the client is resolved through the local
    Cloak store; otherwise the gateway's own environment supplies the key; a
    real key passed by the client is honoured last so existing setups keep
    working. Returning ``None`` means "send nothing" — the upstream will
    reject it, which is the correct, loud failure.
    """
    if client_value:
        match = _PLACEHOLDER_RE.match(client_value.strip())
        if match:
            resolved = _lookup_cloak_secret(match.group(1))
            if resolved:
                return resolved
            raise LlmGatewayError(
                f"secret placeholder '{match.group(1)}' could not be resolved")
    for env_key in spec.env_keys:
        value = os.environ.get(env_key)
        if value:
            return value
    return client_value or None


def _lookup_cloak_secret(name: str) -> Optional[str]:
    """Resolve a placeholder through the runtime's Cloak store, if present."""
    try:
        from prismor.runtime.cloaking import store as _store  # type: ignore
    except Exception:
        return None
    for attr in ("get_secret", "lookup", "resolve"):
        fn = getattr(_store, attr, None)
        if callable(fn):
            try:
                value = fn(name)
            except Exception:
                continue
            if value:
                return str(value)
    return None


# ── usage accounting ─────────────────────────────────────────────────────────

@dataclass
class Usage:
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return (self.input_tokens + self.output_tokens
                + self.cache_read_tokens + self.cache_write_tokens)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model or None,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_tokens": self.total_tokens,
        }


# USD per 1M tokens, matched by longest model-id prefix. Deliberately a small
# static table with a conservative fallback: the gateway's job is attribution
# and trend, not invoicing, and a stale price is far better than no cost
# signal at all. Overridable per deployment via `pricing` in the config file.
_DEFAULT_PRICING: Dict[str, Tuple[float, float]] = {
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "gpt-5": (1.25, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "o3": (2.0, 8.0),
}
_FALLBACK_PRICE = (1.0, 5.0)


def estimate_cost_usd(usage: Usage,
                      pricing: Optional[Dict[str, Tuple[float, float]]] = None
                      ) -> float:
    table = pricing or _DEFAULT_PRICING
    model = (usage.model or "").lower()
    best: Optional[Tuple[float, float]] = None
    best_len = -1
    for prefix, price in table.items():
        if prefix.lower() in model and len(prefix) > best_len:
            best, best_len = price, len(prefix)
    price_in, price_out = best or _FALLBACK_PRICE
    # Cache reads bill at a fraction of input; cache writes at a premium.
    billed_in = usage.input_tokens + usage.cache_write_tokens * 1.25 \
        + usage.cache_read_tokens * 0.1
    return round(
        (billed_in / 1_000_000.0) * price_in
        + (usage.output_tokens / 1_000_000.0) * price_out, 6)


def extract_usage(provider: str, body: bytes) -> Usage:
    """Read the provider's own usage block out of a buffered JSON response."""
    usage = Usage()
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return usage
    if not isinstance(data, dict):
        return usage
    usage.model = str(data.get("model") or "")
    raw = data.get("usage")
    if not isinstance(raw, dict):
        return usage
    return _fill_usage(usage, provider, raw)


def _fill_usage(usage: Usage, provider: str, raw: Dict[str, Any]) -> Usage:
    def _int(key: str) -> int:
        value = raw.get(key)
        return int(value) if isinstance(value, (int, float)) else 0

    if provider == "anthropic":
        usage.input_tokens = _int("input_tokens") or usage.input_tokens
        usage.output_tokens = _int("output_tokens") or usage.output_tokens
        usage.cache_read_tokens = (_int("cache_read_input_tokens")
                                   or usage.cache_read_tokens)
        usage.cache_write_tokens = (_int("cache_creation_input_tokens")
                                    or usage.cache_write_tokens)
    else:
        usage.input_tokens = _int("prompt_tokens") or usage.input_tokens
        usage.output_tokens = _int("completion_tokens") or usage.output_tokens
        details = raw.get("prompt_tokens_details")
        if isinstance(details, dict):
            cached = details.get("cached_tokens")
            if isinstance(cached, (int, float)):
                usage.cache_read_tokens = int(cached)
    return usage


class StreamTap:
    """Accumulate usage + assistant text from an SSE stream as it is relayed.

    The bytes go to the client untouched and unbuffered; this only watches
    them go past. Text capture is capped so a long completion cannot grow the
    proxy's memory without bound.
    """

    def __init__(self, provider: str, cap: int = SCAN_CAP):
        self.provider = provider
        self.usage = Usage()
        self.cap = cap
        self._text: List[str] = []
        self._text_len = 0
        self._buf = b""

    @property
    def text(self) -> str:
        return "".join(self._text)

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._consume_line(line.strip())

    def _consume_line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            event = json.loads(payload.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError):
            return
        if isinstance(event, dict):
            self._consume_event(event)

    def _consume_event(self, event: Dict[str, Any]) -> None:
        model = event.get("model")
        if isinstance(model, str) and model and not self.usage.model:
            self.usage.model = model

        if self.provider == "anthropic":
            # message_start carries input tokens; message_delta the running
            # output count. Both are dicts keyed "usage".
            message = event.get("message")
            if isinstance(message, dict):
                if not self.usage.model and isinstance(message.get("model"), str):
                    self.usage.model = message["model"]
                if isinstance(message.get("usage"), dict):
                    _fill_usage(self.usage, "anthropic", message["usage"])
            if isinstance(event.get("usage"), dict):
                _fill_usage(self.usage, "anthropic", event["usage"])
            delta = event.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                self._append(delta["text"])
            return

        if isinstance(event.get("usage"), dict):
            _fill_usage(self.usage, self.provider, event["usage"])
        for choice in event.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                self._append(delta["content"])

    def _append(self, text: str) -> None:
        if self._text_len >= self.cap:
            return
        room = self.cap - self._text_len
        piece = text[:room]
        self._text.append(piece)
        self._text_len += len(piece)


class UsageMeter:
    """Accumulate per-call usage and flush it as ``llm_usage`` telemetry.

    Mirrors ``enterprise/heartbeat.py``: aggregate in memory, flush on a
    debounce, and hand the records to the shared uploader so offline periods
    spool and replay like everything else. Never raises into the request path.
    """

    def __init__(self, flush_interval: float = 30.0,
                 pricing: Optional[Dict[str, Tuple[float, float]]] = None):
        self.flush_interval = flush_interval
        self.pricing = pricing
        self._lock = threading.Lock()
        self._pending: List[Dict[str, Any]] = []
        self._last_flush = time.time()
        self.totals = Usage()
        self.total_cost_usd = 0.0
        self.calls = 0

    def record(self, *, provider: str, usage: Usage, session_id: str,
               agent_name: str, subject: Optional[Dict[str, Any]] = None,
               latency_ms: Optional[int] = None,
               blocked: bool = False) -> Dict[str, Any]:
        cost = estimate_cost_usd(usage, self.pricing)
        record = {
            "schema": "prismor.telemetry.v1",
            "event_id": uuid.uuid4().hex,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "llm_usage",
            "verdict": "blocked" if blocked else "observed",
            "title": "Model call metered",
            "agent": GATEWAY_AGENT,
            "agent_name": agent_name or None,
            "session_id": session_id or None,
            "subject": subject or None,
            "provider": provider,
            "tool_name": f"llm__{provider}__{usage.model or 'unknown'}",
            "usage": usage.as_dict(),
            "cost_usd": cost,
            "latency_ms": latency_ms,
            "redacted": True,
        }
        with self._lock:
            self._pending.append(record)
            self.calls += 1
            self.totals.input_tokens += usage.input_tokens
            self.totals.output_tokens += usage.output_tokens
            self.totals.cache_read_tokens += usage.cache_read_tokens
            self.totals.cache_write_tokens += usage.cache_write_tokens
            self.total_cost_usd = round(self.total_cost_usd + cost, 6)
        return record

    def maybe_flush(self, force: bool = False) -> int:
        now = time.time()
        with self._lock:
            if not self._pending:
                return 0
            if not force and (now - self._last_flush) < self.flush_interval:
                return 0
            batch, self._pending = self._pending, []
            self._last_flush = now
        try:
            from prismor.runtime.sinks import upload_telemetry
            upload_telemetry(batch)
        except Exception:
            # upload_telemetry spools on failure; anything it re-raises is
            # logged-and-dropped here so metering can never break a call.
            pass
        return len(batch)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "calls": self.calls,
                "usage": self.totals.as_dict(),
                "cost_usd": self.total_cost_usd,
                "pending_records": len(self._pending),
            }


# ── the gateway ──────────────────────────────────────────────────────────────

@dataclass
class GatewayConfig:
    provider: Optional[str] = None      # pin one provider; else multiplex
    base_url_override: str = ""
    mode: str = "observe"
    workspace: Path = field(default_factory=Path.cwd)
    session_id: str = ""
    agent_name: str = "llm-gateway"
    pricing: Optional[Dict[str, Tuple[float, float]]] = None
    flush_interval: float = 30.0


class LlmGateway:
    """Policy + metering around one model call. Transport-agnostic core.

    Kept free of ``http.server`` types so the whole request lifecycle is
    unit-testable without binding a socket.
    """

    def __init__(self, config: GatewayConfig):
        self.config = config
        self.session_id = config.session_id or ("llm-" + uuid.uuid4().hex[:12])
        self.meter = UsageMeter(flush_interval=config.flush_interval,
                                pricing=config.pricing)
        self._eval_lock = threading.Lock()

    # ── policy ───────────────────────────────────────────────────────────

    def _evaluate(self, event: Dict[str, Any]):
        """One event through the shared engine — the same call the hooks make.

        Serialized for the same reason the MCP gateway serializes: the tag
        ledger is session-ordered, and interleaved evaluation could let the
        completing call of a forbidden pair slip past.
        """
        try:
            from prismor.runtime.runtime import evaluate_tool_call
            with self._eval_lock:
                return evaluate_tool_call(
                    event=event,
                    workspace=self.config.workspace,
                    agent=GATEWAY_AGENT,
                    mode=self.config.mode,
                    session_id=self.session_id,
                    agent_name=self.config.agent_name,
                )
        except Exception as exc:
            # Fail open on engine errors only in observe mode; in enforce a
            # broken engine must not wave model traffic through.
            if self.config.mode == "enforce":
                raise LlmGatewayError(
                    f"policy evaluation failed ({exc}); call denied (fail-closed)")
            return None

    def _event_base(self, agent_event: str, model: str,
                    provider: str) -> Dict[str, Any]:
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "agent": GATEWAY_AGENT,
            "agent_event": agent_event,
            "metadata": {
                "cwd": str(self.config.workspace),
                "tool_name": f"llm__{provider}__{model or 'unknown'}",
            },
        }

    def build_request_event(self, spec: ProviderSpec, url: str,
                            body: bytes, model: str) -> Dict[str, Any]:
        """Outbound model call as a ``network`` event.

        Reusing the network type is the whole trick: the egress allowlist,
        secret-in-payload detection, and taint escalation already understand
        this shape, so the model lane inherits them without one new rule.
        """
        base = self._event_base("PreToolUse", model, spec.name)
        return {**base, "type": "network", "url": url,
                "outbound_payload": body[:SCAN_CAP].decode("utf-8", "replace")}

    def build_response_event(self, spec: ProviderSpec, text: str,
                             model: str) -> Dict[str, Any]:
        """Completion as a ``tool_result`` — untrusted content, scanned before
        it reaches the caller's context."""
        base = self._event_base("PostToolUse", model, spec.name)
        return {**base, "type": "tool_result", "response": text[:SCAN_CAP]}

    @staticmethod
    def model_of(body: bytes) -> str:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return ""
        return str(data.get("model") or "") if isinstance(data, dict) else ""

    @staticmethod
    def wants_stream(body: bytes) -> bool:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return False
        return bool(isinstance(data, dict) and data.get("stream"))


def blocked_payload(provider: str, blocking: Dict[str, Any]) -> Dict[str, Any]:
    """Render a denial in the provider's own error shape.

    A governed call that fails must look like an ordinary API error to the
    SDK on the other side — anything else surfaces as a client crash instead
    of a readable refusal the agent can adapt to.
    """
    parts = [f"Blocked by Prismor: [{blocking.get('severity', 'high')}] "
             f"{blocking.get('title', 'policy violation')}"]
    if blocking.get("ruleId"):
        parts[0] += f" (rule: {blocking['ruleId']})"
    if blocking.get("evidence"):
        parts.append(str(blocking["evidence"]))
    if blocking.get("remediation"):
        parts.append(f"Recommended fix: {blocking['remediation']}")
    message = "\n".join(parts)
    if provider == "anthropic":
        return {"type": "error",
                "error": {"type": "permission_error", "message": message}}
    return {"error": {"message": message, "type": "permission_error",
                      "code": "prismor_policy_block"}}


# ── HTTP surface ─────────────────────────────────────────────────────────────

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding",  # we relay bytes verbatim; no transparent decompression
}


def _make_handler(gateway: LlmGateway) -> type:
    import urllib.error
    import urllib.request

    class Handler(BaseHTTPRequestHandler):
        server_version = "prismor-llm-gateway"
        protocol_version = "HTTP/1.1"

        # Access logging goes through the runtime's own telemetry, not stderr
        # noise on every request.
        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            pass

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/healthz", "/health"):
                self._json(200, {"status": "ok",
                                 "session_id": gateway.session_id,
                                 "mode": gateway.config.mode})
                return
            if path in ("/metrics", "/usage"):
                self._json(200, gateway.meter.snapshot())
                return
            self._json(404, {"error": {"message": f"no route for {path}"}})

        def do_POST(self) -> None:  # noqa: N802
            try:
                self._proxy()
            except LlmGatewayError as exc:
                self._json(502, {"error": {"message": str(exc),
                                           "type": "prismor_gateway_error"}})
            except Exception as exc:  # never take the server down
                self._json(500, {"error": {"message": f"prismor-gateway: {exc}",
                                           "type": "prismor_gateway_error"}})

        # ── core proxy ───────────────────────────────────────────────

        def _proxy(self) -> None:
            cfg = gateway.config
            spec = (resolve_provider(cfg.provider) if cfg.provider
                    else provider_for_path(self.path))
            if spec is None:
                self._json(404, {"error": {
                    "message": f"no provider matches path {self.path!r}; "
                               "prefix it with /anthropic or /openai, or pin "
                               "one with --provider"}})
                return

            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            upstream_path = strip_provider_prefix(self.path, spec)
            base = (cfg.base_url_override or spec.base_url).rstrip("/")
            url = base + upstream_path
            model = gateway.model_of(body)

            # 1. Pre-call policy on the outbound payload.
            decision = gateway._evaluate(
                gateway.build_request_event(spec, url, body, model))
            self._log_observe(decision, model, spec)
            if decision is not None and decision.blocking is not None:
                gateway.meter.record(
                    provider=spec.name, usage=Usage(model=model),
                    session_id=gateway.session_id,
                    agent_name=cfg.agent_name, blocked=True)
                gateway.meter.maybe_flush()
                self._json(403, blocked_payload(spec.name, decision.blocking))
                return

            # 2. Broker the credential — the client never needs the real key.
            headers = self._upstream_headers(spec)

            started = time.time()
            request = urllib.request.Request(url, data=body, method="POST",
                                             headers=headers)
            try:
                response = urllib.request.urlopen(request,
                                                  timeout=UPSTREAM_TIMEOUT)
            except urllib.error.HTTPError as exc:
                # Relay provider errors verbatim: the SDK on the other side
                # knows how to read them, and masking them would make the
                # gateway look like the fault.
                payload = exc.read()
                self._relay_head(exc.code, dict(exc.headers or {}),
                                 len(payload))
                self.wfile.write(payload)
                return
            except urllib.error.URLError as exc:
                raise LlmGatewayError(f"upstream unreachable: {exc.reason}")

            streaming = ("text/event-stream"
                         in (response.headers.get("Content-Type") or "").lower())
            if streaming:
                self._relay_stream(spec, response, model, started)
            else:
                self._relay_buffered(spec, response, model, started)

        def _upstream_headers(self, spec: ProviderSpec) -> Dict[str, str]:
            headers: Dict[str, str] = {}
            for key, value in self.headers.items():
                if key.lower() in _HOP_BY_HOP:
                    continue
                if key.lower() == spec.auth_header.lower():
                    continue
                headers[key] = value
            client_key = self.headers.get(spec.auth_header)
            resolved = resolve_upstream_auth(spec, client_key)
            if resolved:
                headers[spec.auth_header] = spec.auth_format.format(key=resolved)
            headers.setdefault("Content-Type", "application/json")
            return headers

        def _relay_buffered(self, spec: ProviderSpec, response: Any,
                            model: str, started: float) -> None:
            payload = response.read()
            usage = extract_usage(spec.name, payload)
            if not usage.model:
                usage.model = model
            latency_ms = int((time.time() - started) * 1000)

            text = _assistant_text(spec.name, payload)
            decision = gateway._evaluate(
                gateway.build_response_event(spec, text, usage.model))
            self._log_observe(decision, usage.model, spec)
            gateway.meter.record(
                provider=spec.name, usage=usage,
                session_id=gateway.session_id,
                agent_name=gateway.config.agent_name, latency_ms=latency_ms,
                blocked=bool(decision is not None and decision.blocking))
            gateway.meter.maybe_flush()

            if decision is not None and decision.blocking is not None:
                self._json(403, blocked_payload(spec.name, decision.blocking))
                return
            self._relay_head(response.status, dict(response.headers or {}),
                             len(payload))
            self.wfile.write(payload)

        def _relay_stream(self, spec: ProviderSpec, response: Any,
                          model: str, started: float) -> None:
            # Chunked relay: the client sees tokens at upstream speed. Usage
            # is only knowable at the end of the stream, so scanning the
            # completion is necessarily post-hoc here — the pre-call check
            # already ran, and the response scan still lands in telemetry.
            tap = StreamTap(spec.name)
            self.send_response(response.status)
            for key, value in (response.headers or {}).items():
                if key.lower() in _HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    tap.feed(chunk)
                    self.wfile.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return  # client hung up mid-stream; still meter what we saw
            finally:
                usage = tap.usage
                if not usage.model:
                    usage.model = model
                latency_ms = int((time.time() - started) * 1000)
                decision = gateway._evaluate(
                    gateway.build_response_event(spec, tap.text, usage.model))
                self._log_observe(decision, usage.model, spec)
                gateway.meter.record(
                    provider=spec.name, usage=usage,
                    session_id=gateway.session_id,
                    agent_name=gateway.config.agent_name,
                    latency_ms=latency_ms,
                    blocked=bool(decision is not None and decision.blocking))
                gateway.meter.maybe_flush()

        # ── helpers ──────────────────────────────────────────────────

        def _log_observe(self, decision: Any, model: str,
                         spec: ProviderSpec) -> None:
            if decision is None:
                return
            try:
                from prismor.runtime.runtime import log_observe_findings
                log_observe_findings(decision, mode=gateway.config.mode,
                                     tool_name=f"llm__{spec.name}__{model}")
            except Exception:
                pass

        def _relay_head(self, status: int, headers: Dict[str, str],
                        length: int) -> None:
            self.send_response(status)
            for key, value in headers.items():
                if key.lower() in _HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(length))
            self.end_headers()

        def _json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _assistant_text(provider: str, payload: bytes) -> str:
    """Pull the assistant's own words out of a buffered completion."""
    try:
        data = json.loads(payload.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    parts: List[str] = []
    if provider == "anthropic":
        for block in data.get("content") or []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    else:
        for choice in data.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                parts.append(message["content"])
    return "\n".join(parts)[:SCAN_CAP]


def serve(config: GatewayConfig, host: str = "127.0.0.1",
          port: int = DEFAULT_PORT) -> int:
    gateway = LlmGateway(config)
    httpd = ThreadingHTTPServer((host, port), _make_handler(gateway))
    httpd.daemon_threads = True
    import sys
    target = config.provider or "auto-detect per request"
    sys.stderr.write(
        f"[prismor-gateway:llm] listening on http://{host}:{port} "
        f"provider={target} session={gateway.session_id} "
        f"mode={config.mode}\n")
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        gateway.meter.maybe_flush(force=True)
        httpd.server_close()
    return 0


def load_pricing(path: Optional[Path]) -> Optional[Dict[str, Tuple[float, float]]]:
    """Load a ``{"model-prefix": [in_per_mtok, out_per_mtok]}`` override."""
    if not path:
        return None
    try:
        raw = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise LlmGatewayError(f"invalid pricing file {path}: {exc}")
    table: Dict[str, Tuple[float, float]] = {}
    for key, value in (raw.get("pricing") or raw).items():
        if isinstance(value, (list, tuple)) and len(value) == 2:
            table[str(key)] = (float(value[0]), float(value[1]))
    return table or None


def run_llm_gateway(args, workspace: Path) -> int:
    """Entry point for ``prismor gateway llm`` (called from cli.main)."""
    config = GatewayConfig(
        provider=getattr(args, "provider", None) or None,
        base_url_override=getattr(args, "base_url", "") or "",
        mode=getattr(args, "mode", "observe") or "observe",
        workspace=workspace,
        session_id=(getattr(args, "session_id", "") or
                    os.environ.get("PRISMOR_SESSION_ID", "")),
        agent_name=getattr(args, "agent_name", "") or "llm-gateway",
        pricing=load_pricing(getattr(args, "pricing", None)),
        flush_interval=float(getattr(args, "flush_interval", 30.0) or 30.0),
    )
    return serve(config,
                 host=getattr(args, "host", "127.0.0.1") or "127.0.0.1",
                 port=int(getattr(args, "port", DEFAULT_PORT) or DEFAULT_PORT))
