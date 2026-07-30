"""Loader for the Prismor integration registry (``registry.yaml``).

The registry is the single source of truth for which agents and frameworks
Prismor can intercept, the surface each exposes, and how blocking works there.
Both the docs matrix generator (``scripts/gen_integration_matrix.py``) and any
runtime adapter wiring read it through this module so there is exactly one
parser and one shape.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - mirrors policy_engine's hard requirement
    sys.stderr.write("FATAL: PyYAML is required to load the integration registry.\n")
    raise SystemExit(1)

_REGISTRY_PATH = Path(__file__).resolve().parent / "registry.yaml"

# Allowed enum values — kept in sync with registry.schema.json.
# multiplexer = terminal session manager that spawns other agents (e.g. Herdr) —
# not itself a coding agent or a framework, and never intercepted directly.
KINDS = frozenset({"coding-agent", "framework", "multiplexer"})
# http = language-agnostic eval-server / Vercel AI sidecar (POST /v1/evaluate)
# pass-through = no interception surface at all; wrapped agents' own hooks fire unchanged
SURFACES = frozenset({"hook-config", "sdk", "mcp", "rules-only", "http", "pass-through"})
STATUSES = frozenset({"shipped", "roadmap", "sweep-only"})
# client-side = HTTP eval-server adapters that enforce in the caller (Node/Ruby/Java/Rust)
BLOCKING = frozenset({"exit-2", "json-permission", "throw", "proxy-deny", "none", "client-side"})


@dataclass(frozen=True)
class Integration:
    """One agent/framework entry from the registry."""

    id: str
    name: str
    kind: str
    surface: str
    status: str
    blocking: str
    events: List[str] = field(default_factory=list)
    config_paths: Dict[str, str] = field(default_factory=dict)
    normalizer: Optional[str] = None
    sweep_dir: Optional[str] = None
    notes: Optional[str] = None
    sources: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Integration":
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name", raw["id"])),
            kind=str(raw.get("kind", "")),
            surface=str(raw.get("surface", "")),
            status=str(raw.get("status", "")),
            blocking=str(raw.get("blocking", "none")),
            events=list(raw.get("events") or []),
            config_paths=dict(raw.get("config_paths") or {}),
            normalizer=raw.get("normalizer"),
            sweep_dir=raw.get("sweep_dir"),
            notes=raw.get("notes"),
            sources=list(raw.get("sources") or []),
        )


def registry_path() -> Path:
    """Absolute path to the bundled ``registry.yaml``."""
    return _REGISTRY_PATH


def load_registry(path: Optional[Path] = None) -> List[Integration]:
    """Parse the registry into ``Integration`` objects (declaration order)."""
    src = path or _REGISTRY_PATH
    raw = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    entries = raw.get("agents") or []
    return [Integration.from_dict(e) for e in entries]


def get(agent_id: str, path: Optional[Path] = None) -> Optional[Integration]:
    """Return the integration with ``agent_id`` or ``None``."""
    for item in load_registry(path):
        if item.id == agent_id:
            return item
    return None


def by_surface(surface: str, path: Optional[Path] = None) -> List[Integration]:
    """All integrations exposing ``surface`` (hook-config|sdk|mcp|rules-only|http)."""
    return [i for i in load_registry(path) if i.surface == surface]


def by_status(status: str, path: Optional[Path] = None) -> List[Integration]:
    """All integrations with the given ``status`` (shipped|roadmap|sweep-only)."""
    return [i for i in load_registry(path) if i.status == status]
