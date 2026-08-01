"""prismor term — full-screen terminal console for agents, sessions and events.

The web dashboard (`prismor dashboard`) and this share one data layer: every
number on screen comes from :mod:`prismor.runtime.store`, which already fans
out across every registered workspace DB and re-cloaks secrets on read. This
module is purely a renderer — it never queries SQLite itself.

Layout::

    ┌ header: enrollment · winning policy layer · agent count ──────────────┐
    │ Agents ▸ sessions │ selected node detail                              │
    │ (tree, j/k)       ├───────────────────────────────────────────────────┤
    │                   │ Events (live tail, scoped to the selection)       │
    └ footer: keybinds ─────────────────────────────────────────────────────┘

The left pane is a two-level tree: agents expand into their sessions. What the
event tail shows follows the selected node — all agents, one agent, or one
session.

Degrades to a plain text dump when curses is unusable (no tty, no
windows-curses, terminal too small) so it stays scriptable.
"""

from __future__ import annotations

import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# How stale an agent's last_seen can be before it stops counting as live.
_LIVE_WINDOW_SECONDS = 300
_IDLE_WINDOW_SECONDS = 86400

# Seconds between automatic refetches while follow mode is on.
_FOLLOW_INTERVAL = 2.0
# Poll granularity for getch(). Short so idle-debounced work fires promptly;
# a wakeup that finds no key and nothing dirty costs nothing.
_TICK_MS = 60
# Navigation redraws immediately from cached rows and only re-queries once the
# selection has been still this long — so holding j/k never queues store calls.
_SETTLE_SECONDS = 0.12

# The 24h aggregate is expensive (~900ms); reuse it this long before refetching.
_STATS_TTL_SECONDS = 30.0

# Sessions priced per idle tick, so pricing a wide tree never blocks a keypress.
_COST_BATCH = 6

# Session paging. ``get_sessions_page`` has no agent filter, so an agent's
# sessions are found by walking pages and filtering client-side. Both caps are
# surfaced in the UI rather than silently truncating.
_SESSION_PAGE_SIZE = 200
_SESSION_MAX_PAGES = 5
_SESSION_MAX_PER_AGENT = 50

# ``get_session_scoped_detail`` returns at most this many events (store-side).
_SESSION_EVENT_CAP = 60

# Agent frameworks whose session ids are resumable Claude Code conversations.
_CLAUDE_FRAMEWORKS = {"claude", "claude-code"}

# Session sort orders. Sessions are always *fetched* newest-first (so a
# truncated load holds the most recent ones); these re-order what was loaded.
_SORTS = ("recent", "risk", "findings", "cost")
_SORT_LABELS = {"recent": "last run", "risk": "risk",
                "findings": "findings", "cost": "cost"}


# ── Data ──────────────────────────────────────────────────────────────────────

def _age_seconds(ts: str) -> Optional[int]:
    """Seconds since an ISO timestamp, or None if it can't be parsed."""
    if not ts:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - dt).total_seconds())
    except Exception:
        return None


def _agent_status(agent: Dict[str, Any]) -> Tuple[str, str]:
    """Map last_seen → (label, color key).

    There is no liveness signal in the store — sessions record timestamps, not
    a heartbeat — so "Active" here means *recently seen*, not *running now*.
    """
    age = _age_seconds(agent.get("last_seen", ""))
    if age is None:
        return "Unknown", "dim"
    if age <= _LIVE_WINDOW_SECONDS:
        return "Active", "green"
    if age <= _IDLE_WINDOW_SECONDS:
        return "Idle", "yellow"
    return "Dormant", "dim"


def _relative(ts: str) -> str:
    from prismor.runtime.store import _relative_time_store
    return _relative_time_store(ts) if ts else "never"


def fmt_usd(amount: float, compact: bool = False) -> str:
    from prismor.runtime.cost import fmt_usd as _fmt
    return _fmt(amount, compact)


def _risk_color(score: int) -> str:
    if score >= 70:
        return "red"
    if score >= 40:
        return "yellow"
    if score > 0:
        return "white"
    return "dim"


def _compact_age(relative: str) -> str:
    """'2 days ago' / '1d ago' → '1d'. Keeps the session row narrow."""
    return str(relative or "").replace(" ago", "").replace(" ", "")[:4] or "—"


def _sort_sessions(
    items: List[Dict[str, Any]], order: str, costs: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Re-order loaded sessions. ``updatedAtAbs`` is lexicographically sortable."""
    costs = costs or {}
    if order == "risk":
        key = lambda s: (-(s.get("riskScore") or 0), s.get("updatedAtAbs") or "")  # noqa: E731
    elif order == "findings":
        key = lambda s: (-(s.get("findingsCount") or 0), s.get("updatedAtAbs") or "")  # noqa: E731
    elif order == "cost":
        # Sessions with no transcript have unknown cost, not zero — sort them
        # last rather than letting them rank as "cheapest".
        key = lambda s: (  # noqa: E731
            -((costs.get(s.get("sessionId")) or {}).get("usd") or 0.0),
            s.get("updatedAtAbs") or "",
        )
    else:
        return sorted(items, key=lambda s: s.get("updatedAtAbs") or "", reverse=True)
    return sorted(items, key=key)


def _resume_blocker(session: Dict[str, Any], agent: Dict[str, Any]) -> Optional[str]:
    """Why this session can't be resumed in Claude Code, or None if it can."""
    import shutil

    framework = str(agent.get("framework") or "").lower()
    if framework not in _CLAUDE_FRAMEWORKS:
        return f"resume is Claude Code only — this session ran under '{framework or 'unknown'}'"
    if not shutil.which("claude"):
        return "the `claude` CLI is not on PATH"
    workspace = str(session.get("workspace") or "")
    if not workspace or not Path(workspace).is_dir():
        return f"workspace no longer exists: {workspace or '(unknown)'}"
    return None


def _agent_event_key(agent: Optional[Dict[str, Any]]) -> str:
    """Which value to pass to ``get_events_page(agent=...)``.

    Events carry ``sessions.agent`` (the framework id), while the agents
    overview keys on ``agent_name`` and only falls back to ``agent``. Filter on
    the framework so labelled agent instances still match their own events.
    """
    if not agent:
        return ""
    return str(agent.get("framework") or agent.get("name") or "")


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def _fetch_base() -> Dict[str, Any]:
    """Agents, policy chain and enrollment — all sub-5ms queries.

    Deliberately excludes ``get_aggregate_stats``, which costs ~900ms (it scans
    every session and event in the window) and feeds only the four KPI numbers
    on the "All agents" panel. That is fetched on demand by :func:`_fetch_stats`
    so startup and refresh stay instant.
    """
    from prismor.runtime import store
    return {
        "agents": _safe(store.get_agents_overview, []),
        "policy": _safe(store.get_policy_precedence, {"winner": "default", "chain": []}),
        "enrollment": _safe(store.get_enrollment, None),
    }


def _fetch_stats() -> Dict[str, Any]:
    """The expensive 24h aggregate. Only called when its panel is on screen."""
    from prismor.runtime import store
    return _safe(lambda: store.get_aggregate_stats(24), {})


def _fetch_sessions_for_agent(agent: Dict[str, Any]) -> Dict[str, Any]:
    """Sessions belonging to one agent.

    ``get_sessions_page`` can't filter by agent, so walk pages (newest first)
    and match client-side on the agent label, falling back to the framework id
    for unlabelled sessions. Bounded by ``_SESSION_MAX_PAGES`` — the returned
    ``truncated`` flag tells the UI to say so rather than imply completeness.
    """
    from prismor.runtime import store

    name = str(agent.get("name", ""))
    framework = str(agent.get("framework", ""))
    found: List[Dict[str, Any]] = []
    scanned = 0
    total = 0
    truncated = False

    for page in range(1, _SESSION_MAX_PAGES + 1):
        result = _safe(
            lambda: store.get_sessions_page(
                page=page, limit=_SESSION_PAGE_SIZE, sort="updatedAt", direction="desc"
            ),
            {"items": [], "total": 0, "pages": 1},
        )
        items = result.get("items", [])
        total = result.get("total", 0)
        scanned += len(items)
        for s in items:
            label = s.get("agentName") or s.get("agent") or ""
            if label == name or (not s.get("agentName") and s.get("agent") == framework):
                found.append(s)
                if len(found) >= _SESSION_MAX_PER_AGENT:
                    truncated = True
                    break
        if truncated or page >= result.get("pages", 1):
            break
    else:
        truncated = True

    if scanned < total and len(found) < _SESSION_MAX_PER_AGENT:
        truncated = True

    return {"items": found, "truncated": truncated, "scanned": scanned, "total": total}


def _normalize_session_event(ev: Dict[str, Any], session: Dict[str, Any]) -> Dict[str, Any]:
    """Give a scoped-detail event the same shape as a ``get_events_page`` item.

    The two store calls return overlapping but not identical dicts — scoped
    detail omits agent/session/workspace since they're implied by the query.
    """
    out = dict(ev)
    out.setdefault("agent", session.get("agent", ""))
    out.setdefault("actionType", ev.get("type", ""))
    out.setdefault("sessionId", session.get("sessionId", ""))
    out.setdefault("workspace", session.get("workspace", ""))
    return out


def _fetch_events(
    node: Dict[str, Any], verdict: str, page: int = 1, limit: int = 20
) -> Dict[str, Any]:
    """One screenful of events for the selected tree node.

    ``limit`` is the number of rows actually visible, not a fixed 200. That
    matters: ``get_events_page`` scales its internal scan with ``page * limit``,
    so asking for a screenful costs ~8ms where asking for 200 rows costs
    35-70ms — and this runs on every navigation keypress.

    A session's events come from ``get_session_scoped_detail`` (the only
    session-scoped read the store offers). It returns at most 60 and does its
    own verdict-free query, so filtering and paging happen here.
    """
    from prismor.runtime import store

    kind = node.get("kind")
    limit = max(1, limit)
    page = max(1, page)

    if kind == "session":
        session = node["session"]
        detail = _safe(
            lambda: store.get_session_scoped_detail(
                Path(session.get("workspace") or "."), session.get("sessionId", "")
            ),
            {"recent_events": [], "paused": False, "scoped": {}},
        )
        raw = detail.get("recent_events", [])
        items = [_normalize_session_event(e, session) for e in raw]
        if verdict == "blocked":
            items = [e for e in items if e.get("verdict") == "blocked"]
        elif verdict == "allowed":
            items = [e for e in items if e.get("verdict") != "blocked"]
        total = len(items)
        pages = max(1, (total + limit - 1) // limit)
        page = min(page, pages)
        return {
            "items": items[(page - 1) * limit: page * limit],
            "total": total,
            "page": page,
            "pages": pages,
            "exact": True,          # sliced locally from a complete list
            "has_next": page < pages,
            "capped": len(raw) >= _SESSION_EVENT_CAP,
            "session_detail": detail,
        }

    agent_key = _agent_event_key(node.get("agent")) if kind == "agent" else ""
    result = _safe(
        lambda: store.get_events_page(
            page=page, limit=limit, verdict=verdict, agent=agent_key
        ),
        {"items": [], "total": 0, "page": 1, "pages": 1},
    )
    # ``get_events_page`` derives total/pages from an internal window that grows
    # with page depth, so both climb as you page deeper (200 → 276 → 621...).
    # They are a floor on what exists, never a true count — reported as "N+"
    # rather than dressed up as a fixed page count.
    items = result.get("items", [])
    return {
        "items": items,
        "total": result.get("total", 0),
        "page": result.get("page", 1),
        "pages": result.get("pages", 1),
        "exact": False,
        "has_next": len(items) >= limit,
        "capped": False,
        "session_detail": None,
    }


# ── Plain-text fallback ───────────────────────────────────────────────────────

def _render_plain() -> None:
    """Non-interactive dump — used when curses can't run (pipes, CI, no tty)."""
    from prismor.runtime import store

    base = _fetch_base()
    enrollment = base["enrollment"]
    org = enrollment.get("org_id") if enrollment else None
    print(f"prismor term — {org or 'local (not enrolled)'}")
    print(f"policy: {base['policy'].get('winner', 'default')}")
    print()
    agents = base["agents"]
    if not agents:
        print("No agents recorded yet. Run `prismor install-hooks` in a project first.")
        return
    print("AGENT                FRAMEWORK      STATUS    CALLS  FLAGGED  LAST SEEN")
    for a in agents:
        label, _ = _agent_status(a)
        print(
            f"{str(a.get('name', ''))[:20]:<20} {str(a.get('framework', ''))[:14]:<14} "
            f"{label:<9} {a.get('total_calls', 0):>5}  {a.get('blocked_calls', 0):>7}  "
            f"{_relative(a.get('last_seen', ''))}"
        )
    print()
    sessions = _safe(lambda: store.get_sessions_page(page=1, limit=10), {"items": [], "total": 0})
    print(f"{sessions.get('total', 0)} sessions — 10 most recent:")
    for s in sessions.get("items", []):
        print(
            f"  {str(s.get('sessionId', ''))[:16]:<16} {str(s.get('agentName', ''))[:16]:<16} "
            f"risk {s.get('riskScore', 0):>3}  {s.get('findingsCount', 0):>2} findings  "
            f"{s.get('updatedAt', '')}"
        )
    print()
    print("Run `prismor term` in a tty for the live tree view.")


# ── Curses app ────────────────────────────────────────────────────────────────

def _run_curses() -> bool:
    try:
        import curses
    except ImportError:
        return False  # stock Windows Python without windows-curses

    state: Dict[str, Any] = {
        "sel": 0,             # index into the flattened tree
        "top": 0,             # tree scroll offset
        "expanded": set(),    # agent names currently expanded
        "sessions": {},       # agent name → _fetch_sessions_for_agent() result
        "ev_sel": 0,
        "ev_page": 1,
        "ev_rows": 20,        # visible event rows — becomes the fetch limit
        "dirty": False,       # selection changed; re-query once it settles
        "redraw": True,       # screen is stale; repaint on the next loop pass
        "last_input_at": 0.0,
        "stats": None,        # lazily fetched 24h aggregate
        "stats_at": 0.0,
        "want_stats": False,  # request pending; the idle tick does the work
        "focus": "tree",      # tree | events
        "follow": True,
        "verdict": "",        # "" | blocked | allowed
        "sort": "recent",     # session order: recent | risk | findings | cost
        "pricing": None,      # live token prices (see prismor.runtime.cost)
        "costs": {},          # session id → session_cost() result
        "mode": "main",       # main | detail | policy | confirm
        "confirm": None,      # pending {"prompt", "apply"}
        "flash": "",          # transient status message
        "base": None,
        "events": None,
    }

    def draw(stdscr) -> None:
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        stdscr.keypad(True)
        stdscr.timeout(_TICK_MS)

        colors = {
            "red": curses.color_pair(1),
            "yellow": curses.color_pair(2),
            "white": curses.color_pair(3),
            "cyan": curses.color_pair(4),
            "green": curses.color_pair(5),
            "magenta": curses.color_pair(6),
            "dim": curses.A_DIM,
        }

        def put(y: int, x: int, text: str, attr: int = 0) -> None:
            """addstr that never raises at the screen edge."""
            h, w = stdscr.getmaxyx()
            if y < 0 or y >= h or x < 0 or x >= w:
                return
            try:
                stdscr.addstr(y, x, str(text)[: max(0, w - x - 1)], attr)
            except curses.error:
                pass

        # ── tree model ──

        def build_tree() -> List[Dict[str, Any]]:
            """Flatten agents (+ expanded sessions) into selectable rows."""
            rows: List[Dict[str, Any]] = [{"kind": "all", "depth": 0}]
            for agent in state["base"]["agents"]:
                name = str(agent.get("name", ""))
                rows.append({"kind": "agent", "agent": agent, "name": name, "depth": 0})
                if name not in state["expanded"]:
                    continue
                bundle = state["sessions"].get(name)
                if bundle is None:
                    rows.append({"kind": "loading", "depth": 1})
                    continue
                for session in _sort_sessions(bundle["items"], state["sort"], state["costs"]):
                    rows.append({
                        "kind": "session", "session": session,
                        "agent": agent, "depth": 1,
                    })
                if not bundle["items"]:
                    rows.append({"kind": "empty", "depth": 1})
                elif bundle["truncated"]:
                    rows.append({"kind": "note", "depth": 1,
                                 "text": f"… showing first {len(bundle['items'])}"})
            return rows

        def current_node() -> Dict[str, Any]:
            rows = build_tree()
            if not rows:
                return {"kind": "all"}
            return rows[min(state["sel"], len(rows) - 1)]

        def refetch_events() -> None:
            state["events"] = _fetch_events(
                current_node(), state["verdict"], state["ev_page"], state["ev_rows"]
            )
            state["events"]["fetched_at"] = time.monotonic()
            state["ev_page"] = state["events"].get("page", 1)
            state["ev_sel"] = min(state["ev_sel"], max(0, len(state["events"]["items"]) - 1))
            state["dirty"] = False

        def mark_dirty() -> None:
            """Selection changed: redraw now, re-query once the user settles."""
            state["dirty"] = True
            state["redraw"] = True
            state["last_input_at"] = time.monotonic()

        def settled() -> bool:
            return time.monotonic() - state["last_input_at"] >= _SETTLE_SECONDS

        def price_some(sessions: List[Dict[str, Any]], budget: int = _COST_BATCH) -> bool:
            """Price up to ``budget`` unpriced sessions. True if any work was done.

            Each transcript is ~5ms, so a small batch per idle tick keeps the UI
            responsive even when an agent has 50 sessions to price.
            """
            from prismor.runtime import cost as cost_mod
            pricing = state["pricing"] or {"models": {}}
            done = 0
            for session in sessions:
                if done >= budget:
                    break
                sid = session.get("sessionId") or ""
                if not sid or sid in state["costs"]:
                    continue
                state["costs"][sid] = _safe(
                    lambda: cost_mod.session_cost(sid, pricing),
                    {"known": False, "priced": False, "usd": 0.0},
                )
                done += 1
            return done > 0

        def pending_cost_sessions() -> List[Dict[str, Any]]:
            """Sessions on screen that still need pricing (visible rows first)."""
            pending = []
            for row in build_tree():
                if row["kind"] != "session":
                    continue
                sid = row["session"].get("sessionId")
                if sid and sid not in state["costs"]:
                    pending.append(row["session"])
            return pending

        def get_stats() -> Optional[Dict[str, Any]]:
            """The 24h aggregate — never computed on the draw path.

            This is the one ~900ms query in the app. Requesting it here only
            sets a flag; the idle tick does the work, so selecting "All agents"
            paints instantly and fills in a moment later.
            """
            now = time.monotonic()
            if state["stats"] is None or now - state["stats_at"] >= _STATS_TTL_SECONDS:
                state["want_stats"] = True
            return state["stats"]

        def load_sessions(agent: Dict[str, Any]) -> None:
            name = str(agent.get("name", ""))
            if name in state["sessions"]:
                return
            state["flash"] = f"loading sessions for {name}…"
            draw_main()
            state["sessions"][name] = _fetch_sessions_for_agent(agent)
            # Price only the first screenful now; the rest fills in on idle.
            price_some(state["sessions"][name]["items"])
            state["flash"] = ""

        from prismor.runtime import cost as cost_mod
        state["pricing"] = _safe(cost_mod.load_pricing,
                                 {"models": {}, "source": "unavailable"})
        state["base"] = _fetch_base()
        state["events"] = _fetch_events({"kind": "all"}, "", 1, state["ev_rows"])
        state["events"]["fetched_at"] = time.monotonic()

        # ── panes ──

        def draw_header() -> None:
            h, w = stdscr.getmaxyx()
            base = state["base"]
            org = (base["enrollment"] or {}).get("org_id") or "local"
            policy = base["policy"].get("winner", "default")
            follow = "FOLLOW" if state["follow"] else "PAUSED"
            prices = {"live": "prices live", "cache": "prices cached",
                      "stale": "prices STALE", "unavailable": "prices n/a"}.get(
                          (state["pricing"] or {}).get("source", ""), "prices n/a")
            bar = (
                f" >_ PRISMOR  TERM  │ Org: {org}  │ Policy: {policy}  "
                f"│ Agents: {len(base['agents'])}  │ {prices}  │ {follow} "
            )
            put(0, 0, bar.ljust(w - 1), curses.A_REVERSE | curses.A_BOLD)

        def draw_footer(hint: str) -> None:
            h, w = stdscr.getmaxyx()
            if state["flash"]:
                put(h - 1, 0, f" {state['flash']} ".ljust(w - 1)[: w - 1],
                    colors["yellow"] | curses.A_BOLD)
                return
            put(h - 1, 0, hint.ljust(w - 1)[: w - 1], colors["cyan"])

        def draw_tree(lw: int, top_y: int, bot_y: int) -> None:
            rows = build_tree()
            active = state["focus"] == "tree"
            put(top_y, 0,
                f" Agents ▸ sessions  ↓{_SORT_LABELS[state['sort']]}" + (" ◂" if active else ""),
                curses.A_BOLD | (colors["cyan"] if active else 0))
            put(top_y + 1, 0, "─" * (lw - 1), colors["dim"])

            visible = max(1, bot_y - (top_y + 2))
            state["sel"] = max(0, min(state["sel"], len(rows) - 1))
            if state["sel"] < state["top"]:
                state["top"] = state["sel"]
            if state["sel"] >= state["top"] + visible:
                state["top"] = state["sel"] - visible + 1

            for i, row in enumerate(rows[state["top"]: state["top"] + visible]):
                idx = state["top"] + i
                kind = row["kind"]
                color = colors["white"]
                if kind == "all":
                    line = "   All agents"
                elif kind == "agent":
                    agent = row["agent"]
                    _, ckey = _agent_status(agent)
                    color = colors[ckey]
                    caret = "▾" if row["name"] in state["expanded"] else "▸"
                    dot = {"Active": "●", "Idle": "◐"}.get(_agent_status(agent)[0], "○")
                    counts = f"{agent.get('total_calls', 0)}/{agent.get('blocked_calls', 0)}"
                    head = f" {caret} {dot} {row['name'][: max(4, lw - 16)]}"
                    line = head + " " * max(1, lw - 2 - len(head) - len(counts)) + counts
                elif kind == "session":
                    session = row["session"]
                    risk = session.get("riskScore", 0) or 0
                    color = colors[_risk_color(risk)]
                    sid = str(session.get("sessionId", ""))[:10]
                    sid_full = session.get("sessionId")
                    if sid_full not in state["costs"]:
                        spend = "  ·"          # not priced yet (fills in on idle)
                    else:
                        money = state["costs"][sid_full] or {}
                        spend = (fmt_usd(money["usd"], compact=True)
                                 if money.get("priced") else "  —")
                    tail = (f"r{risk} {session.get('findingsCount', 0)}f "
                            f"{spend} {_compact_age(session.get('updatedAt', ''))}")
                    head = f"     {sid}"
                    line = head + " " * max(1, lw - 2 - len(head) - len(tail)) + tail
                elif kind == "loading":
                    line, color = "     loading…", colors["dim"]
                elif kind == "empty":
                    line, color = "     no sessions", colors["dim"]
                else:
                    line, color = f"     {row.get('text', '')}", colors["dim"]

                attr = color | (curses.A_REVERSE if active and idx == state["sel"] else 0)
                put(top_y + 2 + i, 0, line.ljust(lw - 1)[: lw - 1], attr)

        def draw_detail(x0: int, y0: int, width: int) -> int:
            node = current_node()
            base = state["base"]
            put(y0, x0, " Detail", curses.A_BOLD)
            put(y0 + 1, x0, "─" * (width - 1), colors["dim"])
            y = y0 + 2

            if node["kind"] == "session":
                session = node["session"]
                detail = (state["events"] or {}).get("session_detail") or {}
                scoped = detail.get("scoped") or {}
                paused = bool(detail.get("paused"))
                risk = session.get("riskScore", 0) or 0
                scope_bits = []
                for field, label in (
                    ("allowed_tools", "tools"), ("deny_tools", "deny-tools"),
                    ("allowed_paths", "paths"), ("deny_network", "no-net"),
                ):
                    if scoped.get(field):
                        scope_bits.append(label)
                fields = [
                    ("Session", str(session.get("sessionId", ""))),
                    ("Agent", f"{session.get('agentName', '')}  ({session.get('agent', '')})"),
                    ("Risk", f"{risk}/100 · {session.get('findingsCount', 0)} findings"),
                    ("Workspace", str(session.get("workspaceName") or session.get("workspace", ""))),
                    ("Started", f"{session.get('startedAt', '')} · updated {session.get('updatedAt', '')}"),
                    ("Immunity", "PAUSED" if paused else "active"),
                ]
                if scope_bits:
                    fields.append(("Scope", ", ".join(scope_bits)))

                from prismor.runtime.cost import fmt_tokens
                money = state["costs"].get(session.get("sessionId")) or {}
                if money.get("priced"):
                    totals = money.get("totals", {})
                    fields.append((
                        "Cost",
                        f"{fmt_usd(money['usd'])} est · {money.get('turns', 0)} turns "
                        f"· {', '.join(money.get('models', []))}",
                    ))
                    fields.append((
                        "Tokens",
                        f"in {fmt_tokens(totals.get('input', 0))} · "
                        f"out {fmt_tokens(totals.get('output', 0))} · "
                        f"cache r{fmt_tokens(totals.get('cache_read', 0))}"
                        f"/w{fmt_tokens(totals.get('cache_write', 0))}",
                    ))
                elif money.get("known"):
                    fields.append(("Cost", "usage found, but no live price for its model"))
                else:
                    fields.append(("Cost", "unknown — no Claude Code transcript"))
            elif node["kind"] == "agent":
                agent = node["agent"]
                label, _ = _agent_status(agent)
                total = agent.get("total_calls", 0) or 0
                blocked = agent.get("blocked_calls", 0) or 0
                rate = f"{(blocked / total * 100):.0f}%" if total else "—"
                fields = [
                    ("Name", str(agent.get("name", "unknown"))),
                    ("Framework", str(agent.get("framework") or "—")),
                    ("Status", f"{label}  (last seen {_relative(agent.get('last_seen', ''))})"),
                    ("Sessions", f"{total} total · {blocked} flagged · {rate} flag rate"),
                ]
                bundle = state["sessions"].get(str(agent.get("name", "")))
                if bundle:
                    priced = [
                        state["costs"].get(s.get("sessionId")) or {}
                        for s in bundle["items"]
                    ]
                    known = [c for c in priced if c.get("priced")]
                    if known:
                        spend = sum(c["usd"] for c in known)
                        fields.append((
                            "Cost",
                            f"{fmt_usd(spend)} est across {len(known)} of "
                            f"{len(bundle['items'])} loaded sessions",
                        ))
            else:
                # Fetched lazily — this is the only ~900ms query in the app, so
                # it runs when its panel is first shown, not at startup.
                stats = get_stats()
                if stats is None:
                    fields = [
                        ("Scope", "All agents (no filter)"),
                        ("Sessions", "computing 24h totals…"),
                        ("Tool calls", "…"),
                        ("Prevented", "…"),
                    ]
                else:
                    kpis = stats.get("kpis", {})
                    fields = [
                        ("Scope", "All agents (no filter)"),
                        ("Sessions", f"{kpis.get('activeSessions', 0)} active in 24h"),
                        ("Tool calls", f"{kpis.get('toolCallsInspected24h', 0)} inspected in 24h"),
                        ("Prevented",
                         f"{kpis.get('dangerousCommandsPrevented24h', 0)} dangerous in 24h"),
                    ]

            for name, value in fields:
                put(y, x0 + 1, f"{name:<11}", colors["dim"])
                attr = 0
                if name == "Status" and "Active" in str(value):
                    attr = colors["green"]
                elif name == "Immunity":
                    attr = colors["yellow"] | curses.A_BOLD if value == "PAUSED" else colors["green"]
                elif name == "Risk":
                    attr = colors[_risk_color(int(str(value).split("/")[0] or 0))]
                put(y, x0 + 13, str(value), attr)
                y += 1
            return y + 1

        def draw_events(x0: int, y0: int, bot_y: int, width: int) -> None:
            bundle = state["events"] or {"items": [], "capped": False}
            events = bundle["items"]
            node = current_node()
            active = state["focus"] == "events"
            scope = {"session": "session", "agent": "agent"}.get(node["kind"], "all agents")
            cap = " · store caps at 60" if bundle.get("capped") else ""
            total = bundle.get("total", len(events))
            if bundle.get("exact"):
                where = f"page {bundle.get('page', 1)}/{bundle.get('pages', 1)} of {total}"
            else:
                # total is a growing floor, not a count — say so with "+".
                where = f"page {bundle.get('page', 1)} · {len(events)} of {total}+"
            head = (f" Events  [{where} · {scope} · "
                    f"filter: {state['verdict'] or 'all'}{cap}]" + (" ◂" if active else ""))
            put(y0, x0, head, curses.A_BOLD | (colors["cyan"] if active else 0))
            put(y0 + 1, x0, "─" * (width - 1), colors["dim"])

            # The visible row count *is* the page size — recorded here so the
            # next fetch asks for exactly one screenful.
            visible = max(1, bot_y - (y0 + 2))
            if visible != state["ev_rows"]:
                state["ev_rows"] = visible
                mark_dirty()

            if not events:
                put(y0 + 2, x0 + 1, "No events for this selection.", colors["dim"])
                return

            for i, ev in enumerate(events[:visible]):
                idx = i
                blocked = ev.get("verdict") == "blocked"
                sev = str(ev.get("severity", "low")).lower()
                if blocked:
                    color = colors["red"] if sev in ("critical", "high") else colors["yellow"]
                else:
                    color = colors["dim"]
                ts = str(ev.get("tsAbs", ""))[11:19] or str(ev.get("ts", ""))[:8]
                agent = str(ev.get("agent", ""))[:10]
                verdict = "BLOCK" if blocked else "allow"
                line = f" {ts:<8} {agent:<10} {verdict:<5} {ev.get('action', '')}"
                attr = color | (curses.A_REVERSE if active and idx == state["ev_sel"] else 0)
                put(y0 + 2 + i, x0, line.ljust(width - 1)[: width - 1], attr)

        def draw_main() -> None:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            lw = max(26, min(36, w // 3))
            draw_header()
            draw_tree(lw, 1, h - 1)
            for y in range(1, h - 1):
                put(y, lw - 1, "│", colors["dim"])
            x0 = lw + 1
            width = w - x0
            ev_y = draw_detail(x0, 1, width)
            draw_events(x0, ev_y, h - 1, width)
            node = current_node()
            session_hint = "  [P] Pause  [R] Resume in claude" if node["kind"] == "session" else ""
            draw_footer(
                " [j/k] Move  [→/←] Expand  [Tab] Pane  [[/]] Page  [Enter] Detail  "
                f"[s] Sort  [f] Follow  [v] Verdict  [p] Policy{session_hint}  [q] Quit "
            )
            stdscr.refresh()

        def draw_event_detail() -> None:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            events = (state["events"] or {}).get("items", [])
            if not events:
                state["mode"] = "main"
                return
            ev = events[min(state["ev_sel"], len(events) - 1)]
            policy = ev.get("policy", {}) or {}
            blocked = ev.get("verdict") == "blocked"
            put(0, 0, f" Event {state['ev_sel'] + 1}/{len(events)} ".ljust(w - 1),
                curses.A_REVERSE | curses.A_BOLD)
            y = 2
            fields = [
                ("verdict", "BLOCKED" if blocked else "allowed"),
                ("time", ev.get("tsAbs", "")),
                ("agent", ev.get("agent", "")),
                ("type", ev.get("actionType", "")),
                ("tool", ev.get("toolTag", "") or "—"),
                ("session", ev.get("sessionId", "")),
                ("workspace", ev.get("workspace", "")),
            ]
            if blocked or policy.get("ruleId"):
                fields += [
                    ("rule", policy.get("ruleId", "") or "—"),
                    ("category", policy.get("category", "") or "—"),
                    ("action", policy.get("action", "") or "—"),
                    ("source", policy.get("source", "") or "—"),
                ]
            for label, value in fields:
                if y >= h - 2:
                    break
                put(y, 1, f"{label}:", colors["cyan"])
                attr = colors["red"] if label == "verdict" and blocked else 0
                put(y, 13, str(value), attr)
                y += 1
            y += 1
            if policy.get("title") and y < h - 2:
                for line in textwrap.wrap(str(policy["title"]), max(w - 3, 10)):
                    if y >= h - 2:
                        break
                    put(y, 1, line, curses.A_BOLD)
                    y += 1
                y += 1
            put(y, 1, "command / detail:", colors["cyan"])
            y += 1
            for line in textwrap.wrap(str(ev.get("action", "")), max(w - 5, 10)):
                if y >= h - 2:
                    break
                put(y, 3, line)
                y += 1
            evidence = policy.get("evidence")
            if evidence and y < h - 3:
                y += 1
                put(y, 1, "evidence:", colors["cyan"])
                y += 1
                for line in textwrap.wrap(str(evidence), max(w - 5, 10)):
                    if y >= h - 2:
                        break
                    put(y, 3, line, colors["dim"])
                    y += 1
            draw_footer(" [j/k] Prev/Next event  ·  [Esc/b] Back  ·  [q] Quit ")
            stdscr.refresh()

        def draw_policy() -> None:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            chain = state["base"]["policy"].get("chain", [])
            winner = state["base"]["policy"].get("winner", "default")
            put(0, 0, f" Policy precedence — winner: {winner} ".ljust(w - 1),
                curses.A_REVERSE | curses.A_BOLD)
            y = 2
            for layer in chain:
                if y >= h - 2:
                    break
                mark = "▶" if layer.get("winning") else " "
                exists = "active" if layer.get("exists") else "not set"
                attr = curses.A_BOLD | colors["green"] if layer.get("winning") else colors["dim"]
                put(y, 1, f"{mark} {str(layer.get('label', '')):<20} {exists:<9} "
                          f"mode={layer.get('mode', '')}", attr)
                y += 1
                for line in textwrap.wrap(str(layer.get("summary") or ""), max(w - 8, 10))[:2]:
                    if y >= h - 2:
                        break
                    put(y, 5, line, colors["dim"])
                    y += 1
                if layer.get("path") and y < h - 2:
                    put(y, 5, str(layer["path"]), colors["dim"])
                    y += 1
                y += 1
            draw_footer(" [Esc/p] Back  ·  [q] Quit ")
            stdscr.refresh()

        def draw_confirm() -> None:
            h, w = stdscr.getmaxyx()
            pending = state["confirm"] or {}
            lines = pending.get("prompt", [])
            box_w = min(w - 6, max(40, max((len(l) for l in lines), default=40) + 6))
            box_h = len(lines) + 4
            y0 = max(1, (h - box_h) // 2)
            x0 = max(1, (w - box_w) // 2)
            # Blank the interior first — this draws over the live main view,
            # and without it the event tail bleeds through the box.
            for i in range(1, box_h - 1):
                put(y0 + i, x0, " " * box_w)

            def edges(row: int) -> None:
                put(row, x0, "│", colors["yellow"])
                put(row, x0 + box_w - 1, "│", colors["yellow"])

            put(y0, x0, "╭" + "─" * (box_w - 2) + "╮", colors["yellow"])
            for i, line in enumerate(lines):
                edges(y0 + 1 + i)
                put(y0 + 1 + i, x0 + 2, line, curses.A_BOLD if i == 0 else 0)
            edges(y0 + box_h - 3)
            edges(y0 + box_h - 2)
            put(y0 + box_h - 2, x0 + 2, "[y] confirm     [n] cancel", colors["cyan"])
            put(y0 + box_h - 1, x0, "╰" + "─" * (box_w - 2) + "╯", colors["yellow"])
            stdscr.refresh()

        def ask_pause_toggle() -> None:
            """Queue a pause/resume confirm for the selected session."""
            node = current_node()
            if node["kind"] != "session":
                return
            session = node["session"]
            detail = (state["events"] or {}).get("session_detail") or {}
            paused = bool(detail.get("paused"))
            action = "resume" if paused else "pause"
            sid = str(session.get("sessionId", ""))

            def apply() -> str:
                from prismor.runtime import store
                result = store.update_session_control(
                    Path(session.get("workspace") or "."), sid, action
                )
                if not result.get("ok"):
                    return f"failed: {result.get('error', 'unknown error')}"
                refetch_events()
                return f"session {sid[:12]} — immunity {action}d"

            state["confirm"] = {
                "prompt": [
                    f"{action.capitalize()} immunity for session {sid[:12]}…?",
                    "",
                    ("This stops screening for that session only."
                     if action == "pause" else
                     "This re-enables screening for that session."),
                ],
                "apply": apply,
            }
            state["mode"] = "confirm"

        def launch_claude(session: Dict[str, Any]) -> str:
            """Hand the terminal to `claude --resume <id>`, then take it back.

            curses owns the tty, so the child would render into a broken
            terminal without ``endwin()`` first — and the tree would come back
            as garbage without ``reset_prog_mode()`` after. Session ids from
            the Claude Code hooks *are* Claude Code conversation ids, and
            --resume is project-scoped, so it runs in the session's workspace.
            """
            import subprocess

            sid = str(session.get("sessionId", ""))
            workspace = str(session.get("workspace") or "")

            curses.def_prog_mode()
            curses.endwin()
            try:
                result = subprocess.call(["claude", "--resume", sid], cwd=workspace)
            except Exception as exc:
                result = -1
                error = str(exc)
            else:
                error = ""
            finally:
                curses.reset_prog_mode()
                stdscr.clear()
                stdscr.refresh()

            if error:
                return f"could not launch claude: {error}"
            if result != 0:
                return f"claude exited with status {result}"
            # The conversation may have added events while we were away.
            state["base"] = _fetch_base()
            refetch_events()
            return f"returned from claude session {sid[:12]}"

        def ask_resume() -> None:
            """Queue a confirm for resuming the selected session in Claude Code."""
            node = current_node()
            if node["kind"] != "session":
                state["flash"] = "select a session first"
                return
            session, agent = node["session"], node["agent"]
            blocker = _resume_blocker(session, agent)
            if blocker:
                state["flash"] = blocker
                return
            sid = str(session.get("sessionId", ""))
            workspace = str(session.get("workspace") or "")
            home = str(Path.home())
            state["confirm"] = {
                "prompt": [
                    f"Resume session {sid[:12]}… in Claude Code?",
                    "",
                    f"cwd: {workspace.replace(home, '~')}",
                    "prismor term returns when you exit claude.",
                ],
                "apply": lambda: launch_claude(session),
            }
            state["mode"] = "confirm"

        # ── event loop ──

        while True:
            h, w = stdscr.getmaxyx()
            if h < 10 or w < 50:
                stdscr.erase()
                put(0, 0, "Terminal too small — need at least 50x10.")
                stdscr.refresh()
                if stdscr.getch() in (ord("q"), 27):
                    return
                continue

            # Only repaint when something actually changed. Without this the
            # whole screen redraws every tick (~16x/sec) while idle, which
            # burns CPU and makes modals flicker as they are erased and
            # re-stacked on top of the main view each frame.
            if state["redraw"]:
                if state["mode"] == "detail":
                    draw_event_detail()
                elif state["mode"] == "policy":
                    draw_policy()
                elif state["mode"] == "confirm":
                    draw_main()
                    draw_confirm()
                else:
                    draw_main()
                state["redraw"] = False

            key = stdscr.getch()

            if key == -1:  # idle tick — do deferred work only when input settled
                if state["mode"] != "main" or not settled():
                    continue
                if state["dirty"]:
                    refetch_events()
                    state["redraw"] = True
                    continue
                if state["follow"]:
                    if time.monotonic() - state["events"]["fetched_at"] >= _FOLLOW_INTERVAL:
                        refetch_events()
                        state["redraw"] = True
                        continue
                if state["want_stats"]:
                    state["want_stats"] = False
                    state["stats"] = _fetch_stats()
                    state["stats_at"] = time.monotonic()
                    state["redraw"] = True
                    continue
                # Nothing urgent: spend the idle slice pricing sessions.
                pending = pending_cost_sessions()
                if pending and price_some(pending):
                    state["redraw"] = True
                continue

            state["last_input_at"] = time.monotonic()
            state["redraw"] = True   # any keypress repaints

            if state["mode"] == "confirm":
                if key in (ord("y"), ord("Y")):
                    pending = state["confirm"]
                    state["confirm"] = None
                    state["mode"] = "main"
                    if pending:
                        state["flash"] = pending["apply"]()
                elif key in (ord("n"), ord("N"), 27, ord("q")):
                    state["confirm"] = None
                    state["mode"] = "main"
                continue

            if state["flash"]:
                state["flash"] = ""

            if key == ord("q"):
                return

            if state["mode"] == "policy":
                if key in (27, ord("p"), ord("b")):
                    state["mode"] = "main"
                continue

            if state["mode"] == "detail":
                events = (state["events"] or {}).get("items", [])
                if key in (27, ord("b"), curses.KEY_BACKSPACE, 127):
                    state["mode"] = "main"
                elif key in (curses.KEY_DOWN, ord("j")):
                    state["ev_sel"] = min(len(events) - 1, state["ev_sel"] + 1)
                elif key in (curses.KEY_UP, ord("k")):
                    state["ev_sel"] = max(0, state["ev_sel"] - 1)
                continue

            # main view
            rows = build_tree()
            node = rows[min(state["sel"], len(rows) - 1)] if rows else {"kind": "all"}

            def move_tree(delta: int) -> None:
                """Move the cursor and redraw now; the query happens on settle."""
                state["sel"] = max(0, min(len(rows) - 1, state["sel"] + delta))
                state["ev_sel"] = 0
                state["ev_page"] = 1
                mark_dirty()

            def turn_page(delta: int) -> None:
                bundle = state["events"] or {}
                if delta > 0 and not bundle.get("has_next"):
                    return                      # short page = genuine end
                nxt = max(1, state["ev_page"] + delta)
                if bundle.get("exact"):
                    nxt = min(nxt, bundle.get("pages", 1))
                if nxt != state["ev_page"]:
                    state["ev_page"] = nxt
                    state["ev_sel"] = 0
                    mark_dirty()

            if key == ord("\t"):
                state["focus"] = "events" if state["focus"] == "tree" else "tree"
            elif key == ord("f"):
                state["follow"] = not state["follow"]
            elif key == ord("p"):
                state["mode"] = "policy"
            elif key == ord("P"):
                ask_pause_toggle()
            elif key == ord("R"):
                ask_resume()
            elif key == ord("s"):
                state["sort"] = _SORTS[(_SORTS.index(state["sort"]) + 1) % len(_SORTS)]
                state["ev_sel"] = 0
                state["ev_page"] = 1
                mark_dirty()
            elif key == ord("r"):
                from prismor.runtime import cost as cost_mod
                state["pricing"] = _safe(lambda: cost_mod.load_pricing(force=True),
                                         state["pricing"])
                state["base"] = _fetch_base()
                state["sessions"].clear()
                state["costs"].clear()
                state["stats"] = None; state["want_stats"] = True
                refetch_events()
            elif key == ord("v"):
                state["verdict"] = {"": "blocked", "blocked": "allowed", "allowed": ""}[state["verdict"]]
                state["ev_sel"] = 0
                state["ev_page"] = 1
                mark_dirty()
            elif key in (ord("]"), curses.KEY_NPAGE):
                turn_page(1)
            elif key in (ord("["), curses.KEY_PPAGE):
                turn_page(-1)
            elif key in (curses.KEY_RIGHT, ord("l")):
                if node["kind"] == "agent":
                    name = node["name"]
                    if name not in state["expanded"]:
                        state["expanded"].add(name)
                        load_sessions(node["agent"])
            elif key in (curses.KEY_LEFT, ord("h")):
                if node["kind"] == "agent":
                    state["expanded"].discard(node["name"])
                elif node["kind"] in ("session", "loading", "empty", "note"):
                    # jump back up to the owning agent row and collapse it
                    for i in range(state["sel"], -1, -1):
                        if rows[i]["kind"] == "agent":
                            state["expanded"].discard(rows[i]["name"])
                            state["sel"] = i
                            mark_dirty()
                            break
            elif key in (curses.KEY_ENTER, 10, 13):
                if state["focus"] == "events" and (state["events"] or {}).get("items"):
                    state["mode"] = "detail"
                elif node["kind"] == "agent":
                    name = node["name"]
                    if name in state["expanded"]:
                        state["expanded"].discard(name)
                    else:
                        state["expanded"].add(name)
                        load_sessions(node["agent"])
                else:
                    state["focus"] = "events"
            elif key in (curses.KEY_DOWN, ord("j")):
                if state["focus"] == "tree":
                    move_tree(1)
                else:
                    items = (state["events"] or {}).get("items", [])
                    if state["ev_sel"] + 1 >= len(items):
                        turn_page(1)          # roll onto the next page
                    else:
                        state["ev_sel"] += 1
            elif key in (curses.KEY_UP, ord("k")):
                if state["focus"] == "tree":
                    move_tree(-1)
                elif state["ev_sel"] == 0:
                    turn_page(-1)
                else:
                    state["ev_sel"] -= 1
            elif key == ord("g"):
                if state["focus"] == "events":
                    state["ev_sel"] = 0
                    state["ev_page"] = 1
                    mark_dirty()
                else:
                    state["sel"] = 0
                    mark_dirty()
            elif key == ord("G"):
                if state["focus"] == "events":
                    bundle = state["events"] or {}
                    if bundle.get("exact"):
                        state["ev_page"] = bundle.get("pages", 1)
                        state["ev_sel"] = 0
                        mark_dirty()
                    else:
                        # Last page is unknowable for store-backed paging;
                        # jump to the end of what's loaded instead.
                        state["ev_sel"] = max(0, len(bundle.get("items", [])) - 1)
                else:
                    state["sel"] = len(rows) - 1
                    mark_dirty()

    try:
        curses.wrapper(draw)
    except curses.error:
        return False
    except KeyboardInterrupt:
        pass
    return True


def run_term() -> None:
    """Entry point for ``prismor term``."""
    import sys

    if not sys.stdout.isatty() or not sys.stdin.isatty():
        _render_plain()
        return
    if not _run_curses():
        _render_plain()
