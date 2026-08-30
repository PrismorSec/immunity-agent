"""Tests for the OTLP/HTTP logs sink."""
import json

from prismor.runtime import sinks


def _event():
    finding = {
        "severity": "CRITICAL",
        "category": "secret_exfiltration",
        "ruleId": "secret-exfiltration",
        "action": "block",
        "title": "Secret file piped to network",
        "evidence": ".env | curl webhook.site",
        "id": "sess_4f2a:finding-1",
    }
    return sinks._build_event(
        finding, extra={"agent": "claude", "mode": "enforce", "subject": {"user_id": "alice"}}
    )


def _record(payload):
    return payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]


def _attrs(payload):
    return {a["key"]: a["value"]["stringValue"] for a in _record(payload)["attributes"]}


def test_otlp_shape():
    payload = sinks._format_otlp_logs(_event())
    resource = {
        a["key"]: a["value"]["stringValue"]
        for a in payload["resourceLogs"][0]["resource"]["attributes"]
    }
    assert resource["service.name"] == "prismor"
    assert resource["host.name"]

    rec = _record(payload)
    assert rec["severityNumber"] == 21  # CRITICAL -> FATAL
    assert rec["severityText"] == "CRITICAL"
    assert rec["body"]["stringValue"] == "Secret file piped to network"
    assert int(rec["timeUnixNano"]) > 0

    attrs = _attrs(payload)
    assert attrs["prismor.rule_id"] == "secret-exfiltration"
    assert attrs["prismor.action"] == "block"
    assert attrs["prismor.session_id"] == "sess_4f2a"
    # Runtime extras ride along without the formatter knowing about them.
    assert attrs["prismor.agent"] == "claude"
    assert attrs["prismor.mode"] == "enforce"
    # Nested values are JSON-encoded, never dropped.
    assert json.loads(attrs["prismor.subject"])["user_id"] == "alice"

    json.dumps(payload)  # collectors ingest JSON


def test_severity_mapping():
    for name, num in (("LOW", 9), ("MEDIUM", 13), ("HIGH", 17), ("CRITICAL", 21)):
        ev = sinks._build_event({"severity": name, "title": "t"})
        assert _record(sinks._format_otlp_logs(ev))["severityNumber"] == num


def test_bad_timestamp_does_not_raise():
    ev = sinks._build_event({"severity": "LOW", "title": "t"})
    ev["@timestamp"] = "not-a-timestamp"
    assert int(_record(sinks._format_otlp_logs(ev))["timeUnixNano"]) > 0


def test_dispatcher_registered():
    assert "otel" in sinks._DISPATCHERS


def test_otel_post(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *_):
            return b""

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode())
        return _Resp()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    sinks._dispatch_otel(
        {"endpoint": "http://localhost:4318", "headers": {"Authorization": "Bearer tok"}},
        _event(),
    )
    assert captured["url"] == "http://localhost:4318/v1/logs"
    assert captured["headers"]["authorization"] == "Bearer tok"
    assert _attrs(captured["body"])["prismor.rule_id"] == "secret-exfiltration"

    # An endpoint that already names the signal path is not double-suffixed.
    sinks._dispatch_otel({"endpoint": "https://otel.example/v1/logs"}, _event())
    assert captured["url"] == "https://otel.example/v1/logs"


def test_missing_endpoint_is_a_noop():
    sinks._dispatch_otel({}, _event())  # must not raise
