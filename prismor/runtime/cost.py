"""Token cost for agent sessions — live prices × real usage.

Prismor's own event store records *what* an agent did, never how many tokens
it took: there is no usage column and no usage payload anywhere in the events
table. So cost is joined from two outside sources:

  prices  aipricing.guru's published feed (``/api/pricing.json``), cached on
          disk so the TUI still renders offline.
  usage   the agent's own transcript. Claude Code writes one JSONL per session
          under ``~/.claude/projects/<slug>/<session-id>.jsonl`` with a
          ``message.usage`` block per assistant turn — and the session ids
          there are the same ids Prismor records, so they join directly.

Only Claude Code keeps transcripts in a known location, so cost is reported
for Claude Code sessions and left unknown (not zero) for every other
framework. See :func:`session_cost`.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PRICING_URL = "https://www.aipricing.guru/api/pricing.json"

# Refetch prices at most this often; the feed updates on publish, not per-minute.
PRICING_TTL_SECONDS = 12 * 3600
PRICING_TIMEOUT_SECONDS = 6

# The feed publishes inputPerM / cachedInputPerM / outputPerM but no cache
# *write* rate, which Anthropic bills above base input. 1.25x is the standard
# 5-minute-TTL multiplier; 1-hour-TTL caching costs 2x, so totals for
# long-lived caches are an underestimate. Surfaced as an estimate in the UI.
CACHE_WRITE_MULTIPLIER = 1.25

_CLAUDE_PROJECTS = Path.home() / ".claude" / "projects"


# ── Prices ────────────────────────────────────────────────────────────────────

def _cache_path() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "pricing-cache.json"


def _read_cache() -> Optional[Dict[str, Any]]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _fetch_pricing() -> Dict[str, Any]:
    import urllib.request

    request = urllib.request.Request(
        PRICING_URL,
        headers={"Accept": "application/json", "User-Agent": "prismor-term"},
    )
    with urllib.request.urlopen(request, timeout=PRICING_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def load_pricing(force: bool = False) -> Dict[str, Any]:
    """Return ``{models: {id: pricing}, fetched_at, source, error}``.

    Never raises and never blocks the UI for longer than the HTTP timeout: on
    any network failure it falls back to the on-disk cache, and only reports
    ``source="unavailable"`` when there is no cache either.
    """
    cached = _read_cache()
    fresh_enough = (
        cached
        and not force
        and (time.time() - float(cached.get("fetched_at", 0))) < PRICING_TTL_SECONDS
    )
    if fresh_enough:
        return {**cached, "source": "cache"}

    try:
        payload = _fetch_pricing()
    except Exception as exc:
        if cached:
            return {**cached, "source": "stale", "error": str(exc)}
        return {"models": {}, "fetched_at": 0, "source": "unavailable", "error": str(exc)}

    models: Dict[str, Dict[str, float]] = {}
    for entry in payload.get("models", []):
        model_id = str(entry.get("id", "")).lower()
        pricing = entry.get("pricing") or {}
        if not model_id or not pricing:
            continue
        models[model_id] = {
            "input": float(pricing.get("inputPerM") or 0.0),
            "cached": float(pricing.get("cachedInputPerM") or 0.0),
            "output": float(pricing.get("outputPerM") or 0.0),
        }

    result = {
        "models": models,
        "fetched_at": time.time(),
        "upstream_updated": payload.get("lastUpdated") or payload.get("updated") or "",
        "source": "live",
    }
    try:
        _cache_path().write_text(json.dumps(result), encoding="utf-8")
    except Exception:
        pass
    return result


def _model_candidates(model: str) -> List[str]:
    """Transcript model ids → feed ids.

    Handles the shapes Claude Code actually writes: ``claude-opus-5``,
    ``claude-opus-5[1m]`` (context-window suffix), ``claude-opus-4-8``
    (dashed minor) and ``claude-opus-4-20250514`` (dated release).
    """
    base = str(model or "").strip().lower()
    if not base:
        return []
    base = re.sub(r"\[.*?\]$", "", base)
    candidates = [base]
    undated = re.sub(r"-\d{8}$", "", base)
    if undated != base:
        candidates.append(undated)
    for candidate in list(candidates):
        dotted = re.sub(r"(\d)-(\d)$", r"\1.\2", candidate)
        if dotted != candidate:
            candidates.append(dotted)
    return candidates


def price_for(model: str, pricing: Dict[str, Any]) -> Optional[Dict[str, float]]:
    models = pricing.get("models") or {}
    for candidate in _model_candidates(model):
        if candidate in models:
            return models[candidate]
    return None


# ── Usage ─────────────────────────────────────────────────────────────────────

_transcript_index: Dict[str, Path] = {}
_index_built_at: float = 0.0


def find_transcript(session_id: str) -> Optional[Path]:
    """Locate a Claude Code transcript by session id.

    Indexes ``~/.claude/projects`` once and rebuilds only when a lookup misses,
    so a live session that started after the index was built is still found.
    """
    global _transcript_index, _index_built_at

    if not session_id:
        return None
    hit = _transcript_index.get(session_id)
    if hit is not None and hit.exists():
        return hit

    if not _CLAUDE_PROJECTS.is_dir():
        return None
    # Rebuild at most once every few seconds — a miss is usually a genuine
    # non-Claude-Code session, and rescanning per row would be wasteful.
    if time.time() - _index_built_at < 5.0 and hit is None and _transcript_index:
        return None
    index: Dict[str, Path] = {}
    try:
        for path in _CLAUDE_PROJECTS.glob("*/*.jsonl"):
            index[path.stem] = path
    except Exception:
        return None
    _transcript_index = index
    _index_built_at = time.time()
    return index.get(session_id)


def session_usage(session_id: str) -> Optional[Dict[str, Any]]:
    """Sum token usage for one session, or None when there's no transcript."""
    path = find_transcript(session_id)
    if path is None:
        return None

    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    by_model: Dict[str, Dict[str, int]] = {}
    turns = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except Exception:
                    continue
                message = record.get("message")
                if not isinstance(message, dict):
                    continue
                usage = message.get("usage")
                if not isinstance(usage, dict):
                    continue
                model = str(message.get("model") or "unknown")
                bucket = by_model.setdefault(
                    model, {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
                )
                pairs = (
                    ("input", "input_tokens"),
                    ("output", "output_tokens"),
                    ("cache_read", "cache_read_input_tokens"),
                    ("cache_write", "cache_creation_input_tokens"),
                )
                for key, field in pairs:
                    value = int(usage.get(field) or 0)
                    bucket[key] += value
                    totals[key] += value
                turns += 1
    except Exception:
        return None

    if not turns:
        return None
    return {"totals": totals, "by_model": by_model, "turns": turns, "path": str(path)}


def session_cost(session_id: str, pricing: Dict[str, Any]) -> Dict[str, Any]:
    """Cost for one session.

    ``known`` is False when there's no transcript (non-Claude-Code agent, or a
    deleted one) — the caller must render that as unknown, never as $0.00.
    ``priced`` is False when usage exists but no model in it matched the feed.
    """
    usage = session_usage(session_id)
    if usage is None:
        return {"known": False, "priced": False, "usd": 0.0}

    total = 0.0
    priced_any = False
    unpriced: List[str] = []

    for model, tokens in usage["by_model"].items():
        rate = price_for(model, pricing)
        if rate is None:
            unpriced.append(model)
            continue
        priced_any = True
        total += (
            tokens["input"] * rate["input"]
            + tokens["output"] * rate["output"]
            + tokens["cache_read"] * rate["cached"]
            + tokens["cache_write"] * rate["input"] * CACHE_WRITE_MULTIPLIER
        ) / 1_000_000

    return {
        "known": True,
        "priced": priced_any,
        "usd": total,
        "totals": usage["totals"],
        "models": sorted(usage["by_model"].keys()),
        "unpriced": unpriced,
        "turns": usage["turns"],
    }


# ── Formatting ────────────────────────────────────────────────────────────────

def fmt_usd(amount: float, compact: bool = False) -> str:
    if not compact:
        return f"${amount:,.2f}"
    if amount >= 1000:
        return f"${amount / 1000:.1f}k"
    if amount >= 10:
        return f"${amount:.0f}"
    if amount >= 0.01:
        return f"${amount:.2f}"
    return "$0"


def fmt_tokens(count: int) -> str:
    if count >= 1_000_000_000:
        return f"{count / 1e9:.1f}B"
    if count >= 1_000_000:
        return f"{count / 1e6:.1f}M"
    if count >= 1_000:
        return f"{count / 1e3:.1f}k"
    return str(count)
