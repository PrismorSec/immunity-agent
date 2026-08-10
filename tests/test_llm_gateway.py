"""LLM gateway — routing, brokering, metering, policy, and transport tests.

The model lane proxies provider API traffic through the same policy engine the
hooks run. Unit tests drive the pieces in-process; transport tests run the real
handler against a fake upstream bound on loopback, so the streaming relay and
header rewriting are exercised end to end rather than mocked away.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import llm_gateway as llm  # noqa: E402
from prismor.runtime.llm_gateway import (  # noqa: E402
    GatewayConfig,
    LlmGateway,
    LlmGatewayError,
    StreamTap,
    Usage,
    UsageMeter,
    blocked_payload,
    estimate_cost_usd,
    extract_usage,
    provider_for_path,
    resolve_provider,
    resolve_upstream_auth,
    strip_provider_prefix,
)


class _Decision:
    """Stand-in for the engine's decision object (only .blocking is read)."""

    def __init__(self, blocking=None):
        self.blocking = blocking
        self.findings = []


def _cfg(**kw) -> GatewayConfig:
    kw.setdefault("workspace", Path("/tmp"))
    kw.setdefault("session_id", "sess-test")
    return GatewayConfig(**kw)


# ── [A] provider resolution ──────────────────────────────────────────────────

class TestProviderResolution:
    def test_native_paths_map_to_their_provider(self):
        assert provider_for_path("/v1/messages").name == "anthropic"
        assert provider_for_path("/v1/chat/completions").name == "openai"
        assert provider_for_path("/v1/embeddings").name == "openai"

    def test_explicit_prefix_wins_over_native_path(self):
        # /openai/v1/messages is an OpenAI-fronted call even though the tail
        # looks Anthropic-shaped; the explicit prefix is authoritative.
        assert provider_for_path("/openai/v1/messages").name == "openai"
        assert provider_for_path("/anthropic/v1/messages").name == "anthropic"

    def test_query_string_is_ignored(self):
        assert provider_for_path("/v1/messages?beta=true").name == "anthropic"

    def test_unknown_path_is_none(self):
        assert provider_for_path("/nope") is None

    def test_strip_prefix_restores_upstream_path(self):
        spec = resolve_provider("anthropic")
        assert strip_provider_prefix("/anthropic/v1/messages", spec) == "/v1/messages"
        assert strip_provider_prefix("/v1/messages", spec) == "/v1/messages"
        assert strip_provider_prefix("/anthropic", spec) == "/"

    def test_unknown_provider_raises(self):
        with pytest.raises(LlmGatewayError):
            resolve_provider("bedrock-but-not-yet")


# ── [B] credential brokering ─────────────────────────────────────────────────

class TestCredentialBrokering:
    def test_env_key_used_when_client_sends_nothing(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
        spec = resolve_provider("anthropic")
        assert resolve_upstream_auth(spec, None) == "sk-from-env"

    def test_env_key_wins_over_client_supplied_key(self, monkeypatch):
        # The point of brokering: the gateway's own credential is authoritative,
        # so a client can hold a dummy value (or none) and still reach upstream.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-real")
        spec = resolve_provider("openai")
        assert resolve_upstream_auth(spec, "sk-client-placeholder") == "sk-real"

    def test_client_key_honoured_when_gateway_has_none(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        spec = resolve_provider("openai")
        assert resolve_upstream_auth(spec, "sk-byo") == "sk-byo"

    def test_cloak_placeholder_resolves_through_the_store(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setattr(llm, "_lookup_cloak_secret",
                            lambda name: "sk-unwrapped" if name == "anthropic_key" else None)
        spec = resolve_provider("anthropic")
        assert resolve_upstream_auth(spec, "@@SECRET:anthropic_key@@") == "sk-unwrapped"

    def test_unresolvable_placeholder_fails_loudly(self, monkeypatch):
        monkeypatch.setattr(llm, "_lookup_cloak_secret", lambda name: None)
        spec = resolve_provider("anthropic")
        with pytest.raises(LlmGatewayError):
            resolve_upstream_auth(spec, "@@SECRET:missing@@")

    def test_no_credential_anywhere_returns_none(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        spec = resolve_provider("anthropic")
        assert resolve_upstream_auth(spec, None) is None


# ── [C] usage extraction ─────────────────────────────────────────────────────

class TestUsageExtraction:
    def test_anthropic_buffered_usage(self):
        body = json.dumps({
            "model": "claude-sonnet-5",
            "usage": {"input_tokens": 120, "output_tokens": 42,
                      "cache_read_input_tokens": 900,
                      "cache_creation_input_tokens": 30},
        }).encode()
        usage = extract_usage("anthropic", body)
        assert usage.model == "claude-sonnet-5"
        assert usage.input_tokens == 120
        assert usage.output_tokens == 42
        assert usage.cache_read_tokens == 900
        assert usage.cache_write_tokens == 30
        assert usage.total_tokens == 1092

    def test_openai_buffered_usage(self):
        body = json.dumps({
            "model": "gpt-5",
            "usage": {"prompt_tokens": 200, "completion_tokens": 55,
                      "prompt_tokens_details": {"cached_tokens": 64}},
        }).encode()
        usage = extract_usage("openai", body)
        assert (usage.input_tokens, usage.output_tokens) == (200, 55)
        assert usage.cache_read_tokens == 64

    def test_malformed_body_yields_empty_usage_not_an_error(self):
        # A provider that returns HTML on an outage must not take the proxy down.
        assert extract_usage("openai", b"<html>502</html>").total_tokens == 0
        assert extract_usage("anthropic", b"").total_tokens == 0


class TestStreamTap:
    def test_anthropic_stream_recovers_usage_and_text(self):
        tap = StreamTap("anthropic")
        events = [
            {"type": "message_start",
             "message": {"model": "claude-sonnet-5", "usage": {"input_tokens": 77}}},
            {"type": "content_block_delta", "delta": {"text": "Hello "}},
            {"type": "content_block_delta", "delta": {"text": "world"}},
            {"type": "message_delta", "usage": {"output_tokens": 12}},
        ]
        for event in events:
            tap.feed(b"data: " + json.dumps(event).encode() + b"\n\n")
        assert tap.usage.model == "claude-sonnet-5"
        assert tap.usage.input_tokens == 77
        assert tap.usage.output_tokens == 12
        assert tap.text == "Hello world"

    def test_openai_stream_recovers_usage_and_text(self):
        tap = StreamTap("openai")
        chunks = [
            {"model": "gpt-5", "choices": [{"delta": {"content": "abc"}}]},
            {"model": "gpt-5", "choices": [{"delta": {"content": "def"}}]},
            {"model": "gpt-5", "choices": [],
             "usage": {"prompt_tokens": 9, "completion_tokens": 3}},
        ]
        for chunk in chunks:
            tap.feed(b"data: " + json.dumps(chunk).encode() + b"\n\n")
        tap.feed(b"data: [DONE]\n\n")
        assert tap.text == "abcdef"
        assert (tap.usage.input_tokens, tap.usage.output_tokens) == (9, 3)

    def test_split_across_chunk_boundaries(self):
        # Real SSE arrives in arbitrary TCP-sized pieces, not whole lines.
        tap = StreamTap("anthropic")
        payload = (b'data: {"type":"message_delta","usage":{"output_tokens":5}}\n\n')
        for i in range(0, len(payload), 7):
            tap.feed(payload[i:i + 7])
        assert tap.usage.output_tokens == 5

    def test_text_capture_is_capped(self):
        tap = StreamTap("anthropic", cap=10)
        for _ in range(5):
            tap.feed(b'data: {"delta":{"text":"aaaaa"}}\n\n')
        assert len(tap.text) == 10

    def test_garbage_lines_are_skipped(self):
        tap = StreamTap("openai")
        tap.feed(b": ping\ndata: not-json\ndata: {\"usage\":{\"prompt_tokens\":4}}\n\n")
        assert tap.usage.input_tokens == 4


# ── [D] cost ─────────────────────────────────────────────────────────────────

class TestCost:
    def test_longest_matching_prefix_wins(self):
        # "gpt-4o-mini" must not be priced as "gpt-4o".
        mini = estimate_cost_usd(Usage(model="gpt-4o-mini", input_tokens=1_000_000))
        full = estimate_cost_usd(Usage(model="gpt-4o", input_tokens=1_000_000))
        assert mini == pytest.approx(0.15)
        assert full == pytest.approx(2.50)

    def test_output_priced_separately(self):
        cost = estimate_cost_usd(Usage(model="claude-sonnet-5",
                                       input_tokens=1_000_000,
                                       output_tokens=1_000_000))
        assert cost == pytest.approx(3.0 + 15.0)

    def test_cache_reads_are_discounted(self):
        cached = estimate_cost_usd(Usage(model="claude-sonnet-5",
                                         cache_read_tokens=1_000_000))
        fresh = estimate_cost_usd(Usage(model="claude-sonnet-5",
                                        input_tokens=1_000_000))
        assert cached < fresh

    def test_unknown_model_uses_fallback_not_zero(self):
        # A cost signal that silently reports $0 for new models is worse than
        # a conservative estimate — it reads as "this model is free".
        assert estimate_cost_usd(Usage(model="some-new-model",
                                       input_tokens=1_000_000)) > 0

    def test_pricing_override(self):
        cost = estimate_cost_usd(Usage(model="house-model", input_tokens=1_000_000),
                                 pricing={"house": (10.0, 20.0)})
        assert cost == pytest.approx(10.0)


# ── [E] policy events ────────────────────────────────────────────────────────

class TestPolicyEvents:
    def test_request_is_a_network_event_carrying_the_payload(self):
        gateway = LlmGateway(_cfg())
        spec = resolve_provider("anthropic")
        event = gateway.build_request_event(
            spec, "https://api.anthropic.com/v1/messages",
            b'{"model":"claude-sonnet-5"}', "claude-sonnet-5")
        # Reusing "network" is what inherits the egress allowlist and the
        # secret-in-payload rules without any new policy surface.
        assert event["type"] == "network"
        assert event["url"] == "https://api.anthropic.com/v1/messages"
        assert "claude-sonnet-5" in event["outbound_payload"]
        assert event["agent_event"] == "PreToolUse"
        assert event["metadata"]["tool_name"] == "llm__anthropic__claude-sonnet-5"
        assert event["session_id"] == "sess-test"

    def test_response_is_a_tool_result_event(self):
        gateway = LlmGateway(_cfg())
        spec = resolve_provider("openai")
        event = gateway.build_response_event(spec, "the completion", "gpt-5")
        assert event["type"] == "tool_result"
        assert event["response"] == "the completion"
        assert event["agent_event"] == "PostToolUse"

    def test_scan_payload_is_capped(self):
        gateway = LlmGateway(_cfg())
        spec = resolve_provider("anthropic")
        event = gateway.build_request_event(spec, "https://x", b"x" * (llm.SCAN_CAP * 2), "m")
        assert len(event["outbound_payload"]) <= llm.SCAN_CAP

    def test_model_and_stream_detection(self):
        assert LlmGateway.model_of(b'{"model":"gpt-5"}') == "gpt-5"
        assert LlmGateway.model_of(b"not json") == ""
        assert LlmGateway.wants_stream(b'{"stream":true}') is True
        assert LlmGateway.wants_stream(b'{"stream":false}') is False

    def test_enforce_mode_fails_closed_on_engine_error(self, monkeypatch):
        gateway = LlmGateway(_cfg(mode="enforce"))
        monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                            lambda **kw: (_ for _ in ()).throw(RuntimeError("engine down")))
        with pytest.raises(LlmGatewayError):
            gateway._evaluate({"type": "network"})

    def test_observe_mode_fails_open_on_engine_error(self, monkeypatch):
        gateway = LlmGateway(_cfg(mode="observe"))
        monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                            lambda **kw: (_ for _ in ()).throw(RuntimeError("engine down")))
        assert gateway._evaluate({"type": "network"}) is None


class TestBlockedPayload:
    def test_anthropic_error_shape(self):
        payload = blocked_payload("anthropic", {"title": "secret exfil",
                                                "severity": "critical",
                                                "ruleId": "secret-exfiltration"})
        assert payload["type"] == "error"
        assert payload["error"]["type"] == "permission_error"
        assert "secret exfil" in payload["error"]["message"]
        assert "secret-exfiltration" in payload["error"]["message"]

    def test_openai_error_shape(self):
        payload = blocked_payload("openai", {"title": "blocked"})
        assert payload["error"]["code"] == "prismor_policy_block"
        assert "blocked" in payload["error"]["message"]


# ── [F] metering ─────────────────────────────────────────────────────────────

class TestUsageMeter:
    def test_record_accumulates_totals_and_cost(self):
        meter = UsageMeter(flush_interval=9999)
        meter.record(provider="anthropic",
                     usage=Usage(model="claude-sonnet-5", input_tokens=1000,
                                 output_tokens=500),
                     session_id="s1", agent_name="a")
        meter.record(provider="anthropic",
                     usage=Usage(model="claude-sonnet-5", input_tokens=2000,
                                 output_tokens=100),
                     session_id="s1", agent_name="a")
        snap = meter.snapshot()
        assert snap["calls"] == 2
        assert snap["usage"]["input_tokens"] == 3000
        assert snap["usage"]["output_tokens"] == 600
        assert snap["cost_usd"] > 0
        assert snap["pending_records"] == 2

    def test_record_shape_matches_the_telemetry_wire_contract(self):
        meter = UsageMeter(flush_interval=9999)
        record = meter.record(provider="openai",
                              usage=Usage(model="gpt-5", input_tokens=10,
                                          output_tokens=2),
                              session_id="s9", agent_name="svc",
                              latency_ms=123)
        assert record["type"] == "llm_usage"
        assert record["verdict"] == "observed"
        assert record["session_id"] == "s9"
        assert record["provider"] == "openai"
        assert record["tool_name"] == "llm__openai__gpt-5"
        assert record["usage"]["total_tokens"] == 12
        assert record["latency_ms"] == 123
        assert record["redacted"] is True
        # Every record must be independently addressable for at-least-once
        # upload dedupe, exactly like finding records.
        assert record["event_id"]

    def test_blocked_calls_are_still_metered(self):
        meter = UsageMeter(flush_interval=9999)
        record = meter.record(provider="anthropic", usage=Usage(model="m"),
                              session_id="s", agent_name="a", blocked=True)
        assert record["verdict"] == "blocked"

    def test_flush_is_debounced_then_forced(self, monkeypatch):
        sent = []
        monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry",
                            lambda batch, *a, **k: sent.append(list(batch)))
        meter = UsageMeter(flush_interval=9999)
        meter.record(provider="openai", usage=Usage(model="gpt-5"),
                     session_id="s", agent_name="a")
        assert meter.maybe_flush() == 0        # debounced
        assert meter.maybe_flush(force=True) == 1
        assert len(sent) == 1 and len(sent[0]) == 1
        assert meter.snapshot()["pending_records"] == 0

    def test_upload_failure_never_propagates(self, monkeypatch):
        def _boom(batch, *a, **k):
            raise RuntimeError("control plane down")
        monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", _boom)
        meter = UsageMeter(flush_interval=0)
        meter.record(provider="openai", usage=Usage(model="gpt-5"),
                     session_id="s", agent_name="a")
        assert meter.maybe_flush(force=True) == 1  # swallowed, not raised


# ── [G] transport (real sockets, fake upstream) ──────────────────────────────

class _FakeUpstream:
    """A minimal stand-in provider: echoes auth headers, streams on demand."""

    def __init__(self):
        self.seen_headers = {}
        self.seen_body = b""
        handler = self._make_handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                outer.seen_body = self.rfile.read(length) if length else b""
                outer.seen_headers = {k.lower(): v for k, v in self.headers.items()}
                if self.path.endswith("/stream"):
                    return self._stream()
                if self.path.endswith("/boom"):
                    body = json.dumps({"error": {"message": "upstream sad"}}).encode()
                    self.send_response(429)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = json.dumps({
                    "model": "claude-sonnet-5",
                    "content": [{"type": "text", "text": "hi there"}],
                    "usage": {"input_tokens": 11, "output_tokens": 7},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _stream(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                events = [
                    {"type": "message_start",
                     "message": {"model": "claude-sonnet-5",
                                 "usage": {"input_tokens": 21}}},
                    {"type": "content_block_delta", "delta": {"text": "streamed"}},
                    {"type": "message_delta", "usage": {"output_tokens": 4}},
                ]
                for event in events:
                    chunk = b"data: " + json.dumps(event).encode() + b"\n\n"
                    self.wfile.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        return Handler


class _GatewayHarness:
    def __init__(self, gateway: LlmGateway):
        self.gateway = gateway
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), llm._make_handler(gateway))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def upstream():
    server = _FakeUpstream()
    yield server
    server.stop()


@pytest.fixture
def allow_all(monkeypatch):
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **kw: None)
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry",
                        lambda batch, *a, **k: None)


def _post(url: str, body: dict, headers: dict = None):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    return urllib.request.urlopen(request, timeout=10)


def _wait_for(predicate, timeout: float = 5.0):
    """Await a server-side effect that lands after the client sees EOF.

    On a streamed call the terminating chunk reaches the client before the
    handler's post-stream metering runs — that ordering is deliberate (bytes
    are never held back for accounting), so the test waits rather than
    assuming the two finish together.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class TestTransport:
    def test_buffered_call_is_relayed_and_metered(self, upstream, allow_all,
                                                  monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-broker")
        gateway = LlmGateway(_cfg(provider="anthropic",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            response = _post(f"{harness.url}/v1/messages",
                             {"model": "claude-sonnet-5"})
            payload = json.loads(response.read())
            assert payload["content"][0]["text"] == "hi there"
            # The broker swapped in the gateway's own key.
            assert upstream.seen_headers.get("x-api-key") == "sk-broker"
            snap = gateway.meter.snapshot()
            assert snap["calls"] == 1
            assert snap["usage"]["input_tokens"] == 11
            assert snap["usage"]["output_tokens"] == 7
            assert snap["cost_usd"] > 0
        finally:
            harness.stop()

    def test_client_never_needs_a_real_key(self, upstream, allow_all, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-broker")
        monkeypatch.setattr(llm, "_lookup_cloak_secret", lambda n: None)
        gateway = LlmGateway(_cfg(provider="anthropic",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            _post(f"{harness.url}/v1/messages", {"model": "claude-sonnet-5"},
                  headers={"x-api-key": "not-a-real-key"})
            assert upstream.seen_headers.get("x-api-key") == "sk-broker"
        finally:
            harness.stop()

    def test_streaming_relays_and_meters(self, upstream, allow_all, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-broker")
        gateway = LlmGateway(_cfg(provider="anthropic",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            response = _post(f"{harness.url}/stream", {"model": "claude-sonnet-5",
                                                       "stream": True})
            body = response.read().decode()
            assert "streamed" in body
            assert _wait_for(lambda: gateway.meter.snapshot()["calls"] == 1), \
                "streamed call was never metered"
            snap = gateway.meter.snapshot()
            assert snap["usage"]["input_tokens"] == 21
            assert snap["usage"]["output_tokens"] == 4
        finally:
            harness.stop()

    def test_policy_block_returns_provider_shaped_error(self, upstream,
                                                        monkeypatch):
        monkeypatch.setattr(
            "prismor.runtime.runtime.evaluate_tool_call",
            lambda **kw: _Decision({"title": "secret in payload",
                                    "severity": "critical",
                                    "ruleId": "secret-exfiltration"}))
        monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry",
                            lambda batch, *a, **k: None)
        gateway = LlmGateway(_cfg(provider="anthropic", mode="enforce",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                _post(f"{harness.url}/v1/messages", {"model": "claude-sonnet-5"})
            assert excinfo.value.code == 403
            payload = json.loads(excinfo.value.read())
            assert payload["error"]["type"] == "permission_error"
            assert "secret in payload" in payload["error"]["message"]
            # Blocked before egress: upstream never saw the body.
            assert upstream.seen_body == b""
            # ...and the attempt is still metered, so blocked calls appear in
            # the spend view rather than vanishing.
            assert gateway.meter.snapshot()["calls"] == 1
        finally:
            harness.stop()

    def test_upstream_error_is_relayed_verbatim(self, upstream, allow_all,
                                                monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-broker")
        gateway = LlmGateway(_cfg(provider="anthropic",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                _post(f"{harness.url}/boom", {"model": "claude-sonnet-5"})
            assert excinfo.value.code == 429
            assert "upstream sad" in excinfo.value.read().decode()
        finally:
            harness.stop()

    def test_health_and_metrics_endpoints(self, upstream, allow_all):
        gateway = LlmGateway(_cfg(provider="anthropic",
                                  base_url_override=upstream.base_url))
        harness = _GatewayHarness(gateway)
        try:
            health = json.loads(urllib.request.urlopen(
                f"{harness.url}/healthz", timeout=5).read())
            assert health["status"] == "ok"
            assert health["session_id"] == gateway.session_id
            metrics = json.loads(urllib.request.urlopen(
                f"{harness.url}/metrics", timeout=5).read())
            assert metrics["calls"] == 0
        finally:
            harness.stop()

    def test_unroutable_path_is_a_clear_404(self, allow_all):
        gateway = LlmGateway(_cfg())  # no pinned provider
        harness = _GatewayHarness(gateway)
        try:
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                _post(f"{harness.url}/nonsense", {})
            assert excinfo.value.code == 404
            assert "no provider matches" in excinfo.value.read().decode()
        finally:
            harness.stop()



# ── [H] shared secret-exfil rule names the right surface ─────────────────────

class TestSecretExfilSurfaceNaming:
    """The outbound-payload rule now serves two lanes. It must say which one it
    saw, without changing the ruleId the enforcement floor keys on."""

    SECRET = "sk-surface-test-" + "a1b2c3d4" * 3

    def _findings(self, tmp_path, tool_name: str):
        import prismor.runtime.policy_engine as pe
        original = pe._check_cloaked_secrets_in_text
        pe._check_cloaked_secrets_in_text = lambda text: (
            "MY_TOKEN" if self.SECRET in text else None)
        try:
            engine = pe.PolicyEngine(workspace=tmp_path)
            found = engine.evaluate({
                "type": "network",
                "url": "https://api.anthropic.com/v1/messages",
                "outbound_payload": '{"prompt":"' + self.SECRET + '"}',
                "metadata": {"tool_name": tool_name},
            }, 0, session_id="s-surface")
        finally:
            pe._check_cloaked_secrets_in_text = original
        return [f for f in found
                if f.get("ruleId") == "cloaked-secret-in-mcp-args"]

    def test_model_lane_says_model_prompt(self, tmp_path):
        hits = self._findings(tmp_path, "llm__anthropic__claude-sonnet-5")
        assert hits, "expected the enrolled-secret rule to fire"
        assert "model prompt" in hits[0]["title"]
        # The floor and existing exemptions key on this id — it must not drift.
        assert hits[0]["ruleId"] == "cloaked-secret-in-mcp-args"
        assert hits[0]["category"] == "secret_exfiltration"

    def test_tool_lane_still_says_mcp_arguments(self, tmp_path):
        hits = self._findings(tmp_path, "mcp__github__create_issue")
        assert hits
        assert "MCP tool arguments" in hits[0]["title"]

    def test_title_names_the_secret_never_its_value(self, tmp_path):
        for tool in ("llm__anthropic__x", "mcp__gh__y"):
            for hit in self._findings(tmp_path, tool):
                assert self.SECRET not in hit["title"]
                assert "MY_TOKEN" in hit["title"]
                assert self.SECRET not in str(hit.get("evidence", ""))
