"""Telemetry sinks — forward Warden findings to external systems.

Supported sink types (configured under ``settings.outputs`` in policy.yaml):

  outputs:
    - type: webhook
      url: https://siem.example.com/ingest
      headers: { "X-API-Key": "${SIEM_TOKEN}" }
    - type: syslog
      host: siem.example.com
      port: 514
      facility: local7
    - type: file
      path: ~/.prismor/audit.log
      format: json     # or: cef

Each sink receives one JSON event per finding. Dispatch is best-effort
and non-blocking — a sink failure logs a warning but never blocks the
user's tool call.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
_SEVERITY_TO_SYSLOG = {
    "CRITICAL": 2,  # critical
    "HIGH": 3,      # error
    "MEDIUM": 4,    # warning
    "LOW": 6,       # info
}


def _expand_env(value: Any) -> Any:
    """Substitute ${VAR} references in string values with os.environ."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _build_event(finding: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "prismor-warden",
        "hostname": _hostname(),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "rule_id": finding.get("ruleId"),
        "action": finding.get("action"),
        "title": finding.get("title"),
        "evidence": finding.get("evidence"),
        "session_id": (finding.get("id") or "").split(":", 1)[0] if ":" in (finding.get("id") or "") else None,
        "finding_id": finding.get("id"),
    }
    if extra:
        event.update(extra)
    return event


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _dispatch_webhook(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    import urllib.request
    import urllib.error

    url = cfg.get("url")
    if not url:
        return
    headers = {"Content-Type": "application/json"}
    extra_headers = cfg.get("headers") or {}
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)
    timeout = float(cfg.get("timeout_seconds", 3))
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read(16)  # drain


def _dispatch_syslog(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 514))
    facility = _FACILITIES.get(str(cfg.get("facility", "local7")).lower(), 23)
    severity_name = str(event.get("severity", "LOW")).upper()
    severity = _SEVERITY_TO_SYSLOG.get(severity_name, 6)
    priority = (facility * 8) + severity
    tag = cfg.get("tag", "prismor-warden")
    msg = json.dumps(event)
    payload = f"<{priority}>{datetime.now().strftime('%b %d %H:%M:%S')} {_hostname()} {tag}: {msg}"

    transport = str(cfg.get("transport", "udp")).lower()
    if transport == "tcp":
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(payload.encode("utf-8") + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(payload.encode("utf-8"), (host, port))


def _dispatch_file(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    raw_path = cfg.get("path")
    if not raw_path:
        return
    path = Path(os.path.expanduser(str(raw_path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = str(cfg.get("format", "json")).lower()
    if fmt == "cef":
        line = _format_cef(event)
    else:
        line = json.dumps(event)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _format_cef(event: Dict[str, Any]) -> str:
    """Minimal ArcSight CEF formatter — enough for Splunk/QRadar ingest."""
    sev_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}
    severity = sev_map.get(str(event.get("severity", "")).upper(), 3)
    header = (
        "CEF:0|Prismor|Warden|1.1.0|"
        f"{event.get('rule_id','unknown')}|"
        f"{event.get('title','finding')}|"
        f"{severity}"
    )
    extensions = {
        "act": event.get("action", ""),
        "cat": event.get("category", ""),
        "msg": event.get("evidence", ""),
        "dhost": event.get("hostname", ""),
        "rt": event.get("@timestamp", ""),
    }
    ext_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)
    return f"{header}|{ext_str}"


_DISPATCHERS = {
    "webhook": _dispatch_webhook,
    "syslog": _dispatch_syslog,
    "file": _dispatch_file,
}


def dispatch(findings: List[Dict[str, Any]], sinks: List[Dict[str, Any]], extra: Optional[Dict[str, Any]] = None) -> None:
    """Send each finding to each configured sink. Errors are swallowed with
    a warning on stderr so telemetry never blocks the user."""
    if not findings or not sinks:
        return
    for finding in findings:
        event = _build_event(finding, extra=extra)
        for sink_cfg in sinks:
            sink = _expand_env(sink_cfg)
            kind = str(sink.get("type", "")).lower()
            disp = _DISPATCHERS.get(kind)
            if not disp:
                continue
            try:
                disp(sink, event)
            except Exception as exc:
                sys.stderr.write(f"[warden] sink {kind!r} failed: {exc}\n")
