"""warden/server.py — local HTTP API server for the Prismor Warden dashboard.

Serves a self-contained web dashboard and session/findings data from all
registered workspace DBs.  No external dependencies beyond the stdlib and
a single CDN link (Chart.js) loaded by the browser.

Usage (via CLI):
    python3 warden/cli.py serve [--port 7070] [--host 127.0.0.1]

Endpoints:
    GET /                  → self-hosted HTML dashboard
    GET /health            → {"status": "ok", "ts": "<iso>"}
    GET /api/stats         → aggregate stats for charts/KPIs
    GET /api/sessions      → paginated sessions  (?page&limit&sort&dir)
    GET /api/findings      → paginated findings  (?page&limit&agent&severity&category&q)
    GET /api/events        → paginated events    (?page&limit&verdict&agent)
    OPTIONS *              → 204 CORS preflight
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse, parse_qs

from warden.store import (
    get_aggregate_stats,
    get_sessions_page,
    get_findings_page,
    get_events_page,
)

_DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class WardenRequestHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the warden dashboard API."""

    # Silence the default per-request access log
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _send_cors(self) -> None:
        for key, value in _CORS_HEADERS.items():
            self.send_header(key, value)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_path: Path) -> None:
        try:
            body = html_path.read_bytes()
        except FileNotFoundError:
            self._send_json({"error": "dashboard.html not found"}, status=500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query, keep_blank_values=False)

        def qstr(key: str, default: str = "") -> str:
            return qs.get(key, [default])[0]

        def qint(key: str, default: int = 1) -> int:
            try:
                return int(qs.get(key, [default])[0])
            except (ValueError, TypeError):
                return default

        if path in ("", "/dashboard"):
            self._send_html(_DASHBOARD_HTML)
            return

        if path == "/health":
            self._send_json({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
            return

        if path == "/api/stats":
            try:
                stats = get_aggregate_stats()
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(stats)
            return

        if path == "/api/sessions":
            try:
                data = get_sessions_page(
                    page=qint("page", 1),
                    limit=qint("limit", 20),
                    sort=qstr("sort", "updatedAt"),
                    direction=qstr("dir", "desc"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/findings":
            try:
                data = get_findings_page(
                    page=qint("page", 1),
                    limit=qint("limit", 25),
                    agent=qstr("agent"),
                    severity=qstr("severity"),
                    category=qstr("category"),
                    search=qstr("q"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/events":
            try:
                data = get_events_page(
                    page=qint("page", 1),
                    limit=qint("limit", 30),
                    verdict=qstr("verdict"),
                    agent=qstr("agent"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        self._send_json({"error": "not found"}, status=404)

    # Suppress BrokenPipeError tracebacks when clients disconnect early
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def run_server(host: str = "127.0.0.1", port: int = 7070) -> None:
    """Start the warden HTTP API server (blocks until Ctrl-C)."""
    server = HTTPServer((host, port), WardenRequestHandler)
    print(f"[warden] dashboard → http://{host}:{port}  (Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[warden] server stopped", flush=True)
    finally:
        server.server_close()
