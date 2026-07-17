"""prismor/runtime/server.py — local HTTP API server for the Prismor dashboard.

Serves a self-contained web dashboard and session/findings data from all
registered workspace DBs.  No external dependencies beyond the stdlib and
a single CDN link (Chart.js) loaded by the browser.

Usage (via CLI):
    python3 prismor/runtime/cli.py serve [--port 7070] [--host 127.0.0.1]

Read endpoints:
    GET /                  → self-hosted HTML dashboard
    GET /health            → {"status": "ok", "ts": "<iso>"}
    GET /api/stats         → aggregate stats for charts/KPIs
    GET /api/sessions      → paginated sessions  (?page&limit&sort&dir)
    GET /api/findings      → paginated findings  (?page&limit&agent&severity&category&q)
    GET /api/events        → paginated events    (?page&limit&verdict&agent)
    GET /api/supply-chain  → supply chain enforcement stats
    GET /api/workspaces    → registered workspaces + enrollment status
    GET /api/policy        → all policy layers for a workspace (?workspace=…)
    GET /api/agents        → agent registry merged with per-agent call stats
    GET /api/sessions/:id/control → scoped rules + recent blocks for a session

Write endpoints (human-only — localhost):
    PUT /api/policy/global         → body: {yaml} — write ~/.prismor/policy.yaml
    PUT /api/policy/project        → body: {yaml, workspace} — write project policy
    POST /api/agents/:name         → body: {enabled?, mode?, iam_profile?}
    PATCH /api/sessions/:id/control → body: {action, workspace, …data}
    OPTIONS *              → 204 CORS preflight
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

from prismor.runtime.store import (
    get_aggregate_stats,
    get_sessions_page,
    get_findings_page,
    get_events_page,
    get_supply_chain_stats,
    get_token_stats,
    get_agents_overview,
    list_registered_workspaces,
    get_enrollment,
    read_policy_layer,
    get_policy_precedence,
    write_policy_layer,
    get_policy_rule_catalog,
    set_project_rule_states,
    get_session_scoped_detail,
    update_session_control,
    initialize_database,
    _migrate_workspace_runtime_state,
    prismor_home,
)

_DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

# The workspace where the server was launched (set by run_server).
_SERVER_WORKSPACE: Optional[Path] = None


class PrismorRequestHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the prismor dashboard API."""

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

    def _read_json_body(self) -> Any:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _resolve_workspace(self, qs: Dict[str, list]) -> Optional[Path]:
        """Resolve workspace from query param or fall back to server default."""
        ws_param = qs.get("workspace", [None])[0]
        if ws_param:
            p = Path(ws_param)
            return p if p.exists() else None
        return _SERVER_WORKSPACE

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

        if path == "/api/workspaces":
            workspaces = list_registered_workspaces()
            enrollment = get_enrollment()
            primary = str(_SERVER_WORKSPACE) if _SERVER_WORKSPACE else None
            self._send_json({
                "workspaces": [str(w) for w in workspaces],
                "primary": primary,
                "home": str(prismor_home()),
                "enrollment": enrollment,
            })
            return

        if path == "/api/policy":
            workspace = self._resolve_workspace(qs)
            enrollment = get_enrollment()
            result = {
                "global": read_policy_layer("global"),
                "project": read_policy_layer("project", workspace),
                "enterprise": read_policy_layer("enterprise"),
                "precedence": get_policy_precedence(workspace),
                "enrollment": enrollment,
                "workspace": str(workspace) if workspace else None,
                "enterprise_enrolled": enrollment is not None,
            }
            self._send_json(result)
            return

        if path == "/api/policy/rules":
            workspace = self._resolve_workspace(qs)
            try:
                rules = get_policy_rule_catalog(workspace)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json({
                "rules": rules,
                "workspace": str(workspace) if workspace else None,
            })
            return

        if path == "/api/stats":
            try:
                days = max(1, qint("days", 7))
                stats = get_aggregate_stats(hours=days * 24)
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

        if path == "/api/supply-chain":
            try:
                days = max(1, qint("days", 7))
                data = get_supply_chain_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/tokens":
            try:
                days = max(1, qint("days", 1))
                data = get_token_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/agents":
            try:
                from prismor.runtime.agents import list_agents, load_agents_config
                from prismor.runtime.iam import list_agent_ids, load_iam_config
                workspace = _SERVER_WORKSPACE or Path.cwd()

                # Merge store stats with registry config
                store_stats = {a["name"]: a for a in get_agents_overview()}
                registry = {a.name: a for a in list_agents(workspace)}

                # Union of both — include agents seen in store but not configured yet
                all_names = sorted(set(store_stats) | set(registry))
                items = []
                for name in all_names:
                    stats = store_stats.get(name, {})
                    ctrl = registry.get(name)
                    items.append({
                        "name": name,
                        "framework": (ctrl.framework if ctrl else "") or stats.get("framework", ""),
                        "enabled": ctrl.enabled if ctrl else True,
                        "mode": ctrl.mode if ctrl else None,
                        "iam_profile": ctrl.iam_profile if ctrl else None,
                        "deny_tools": list(ctrl.deny_tools) if ctrl else [],
                        "last_seen": stats.get("last_seen") or (ctrl.last_seen if ctrl else None),
                        "total_calls": stats.get("total_calls", 0),
                        "blocked_calls": stats.get("blocked_calls", 0),
                    })

                iam_profiles = list_agent_ids(load_iam_config(workspace))
                self._send_json({"agents": items, "iam_profiles": iam_profiles})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        # /api/sessions/<id>/control
        parts = path.split("/")
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "control":
            session_id = parts[3]
            workspace = self._resolve_workspace(qs)
            if not workspace:
                self._send_json({"error": "workspace not found"}, status=404)
                return
            try:
                detail = get_session_scoped_detail(workspace, session_id)
                self._send_json(detail)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/refresh":
            try:
                workspace = _SERVER_WORKSPACE or Path.cwd()
                _migrate_workspace_runtime_state(workspace, prismor_home())
                initialize_database(workspace)
                sessions = get_sessions_page(page=1, limit=1, sort="updatedAt", direction="desc")
                events = get_events_page(page=1, limit=1)
                self._send_json({
                    "ok": True,
                    "workspace": str(workspace),
                    "home": str(prismor_home()),
                    "latest_session": (sessions.get("items") or [{}])[0].get("sessionId"),
                    "sessions": sessions.get("total", 0),
                    "events": events.get("total", 0),
                })
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        # POST /api/tool-policy — deny/allow a tool tag at agent or global scope
        if path == "/api/tool-policy":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from prismor.runtime.agents import set_tool_policy
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else (_SERVER_WORKSPACE or Path.cwd())
                scope = body.get("scope") or "agent"
                action = body.get("action") or "deny"
                tool = body.get("tool") or ""
                agent = body.get("agent") or None
                deny = set_tool_policy(workspace, scope, tool, action, agent=agent)
                self._send_json({"ok": True, "scope": scope, "action": action,
                                 "tool": tool, "agent": agent, "deny_tools": deny})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        # POST /api/agents/<name> — update per-agent control settings
        if path.startswith("/api/agents/"):
            agent_name = path[len("/api/agents/"):]
            if not agent_name:
                self._send_json({"error": "agent name required"}, status=400)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from prismor.runtime.agents import upsert_agent
                # Resolve the workspace from the server's perspective
                workspace = _SERVER_WORKSPACE or Path.cwd()
                # Map camelCase keys the UI sends to snake_case
                fields = {}
                if "enabled" in body:
                    fields["enabled"] = bool(body["enabled"])
                if "mode" in body:
                    fields["mode"] = body["mode"] or None
                if "iam_profile" in body or "iamProfile" in body:
                    fields["iam_profile"] = body.get("iamProfile") or body.get("iam_profile") or None
                control = upsert_agent(agent_name, workspace, **fields)
                self._send_json({
                    "name": control.name,
                    "framework": control.framework,
                    "enabled": control.enabled,
                    "mode": control.mode,
                    "iam_profile": control.iam_profile,
                    "last_seen": control.last_seen,
                })
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/policy/global":
            try:
                body = self._read_json_body()
                content = body.get("yaml", "")
                result = write_policy_layer("global", content)
                self._send_json(result, status=200 if result["ok"] else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/policy/project":
            try:
                body = self._read_json_body()
                content = body.get("yaml", "")
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                result = write_policy_layer("project", content, workspace)
                self._send_json(result, status=200 if result["ok"] else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/policy/rules":
            try:
                body = self._read_json_body()
                disabled = body.get("disabled", [])
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                if not isinstance(disabled, list):
                    self._send_json({"ok": False, "error": "disabled must be a list"}, status=400)
                    return
                result = set_project_rule_states(workspace, [str(x) for x in disabled])
                self._send_json(result, status=200 if result.get("ok") else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_PATCH(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # /api/sessions/<id>/control
        parts = path.split("/")
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "control":
            session_id = parts[3]
            try:
                body = self._read_json_body()
                action = body.get("action", "")
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                result = update_session_control(workspace, session_id, action, body)
                self._send_json(result, status=200 if result.get("ok") else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def run_server(
    host: str = "127.0.0.1",
    port: int = 7070,
    open_browser: bool = False,
    workspace: Optional[Path] = None,
) -> None:
    """Start the prismor HTTP API server (blocks until Ctrl-C).

    ``workspace`` is optional. Runtime reads always use the single global
    Prismor home DB; when a launch workspace is available, older local state is
    imported once before serving requests.
    """
    global _SERVER_WORKSPACE
    _SERVER_WORKSPACE = workspace
    if workspace:
        _migrate_workspace_runtime_state(workspace, prismor_home())
        initialize_database(workspace)

    import errno as _errno
    while True:
        try:
            server = ThreadingHTTPServer((host, port), PrismorRequestHandler)
            break
        except OSError as exc:
            if exc.errno == _errno.EADDRINUSE:
                print(f"[prismor] port {port} in use, trying {port + 1}…", flush=True)
                port += 1
            else:
                raise

    url = f"http://{host}:{port}"
    print(f"[prismor] dashboard → {url}  (Ctrl-C to stop)  state → {prismor_home()}", flush=True)
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] server stopped", flush=True)
    finally:
        server.server_close()
