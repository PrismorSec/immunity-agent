"""Shared User-Agent for every control-plane / sink HTTP request.

urllib's default ``Python-urllib/x.y`` UA is rejected outright by common
CDN/WAF fronts (Cloudflare's browser integrity check returns 403 error 1010
before the request reaches the app). A 403 on the policy endpoints is
interpreted as key revocation, silently killing telemetry and policy sync —
so every outbound request must identify itself honestly. Found live when
prismor.dev moved behind a proxying CDN.
"""
from __future__ import annotations


def user_agent() -> str:
    try:
        from importlib.metadata import version
        return f"prismor-runtime/{version('prismor')}"
    except Exception:
        return "prismor-runtime/0"
