"""Signed attestation bundle — a portable evidence package for auditors.

A bundle is a single JSON file that snapshots this machine's governance
posture at a point in time and signs it, so an auditor can re-verify it later
with one command and no access to the machine:

    {
      "schema": "prismor.attestation.v1",
      "generated_at", "device_id", "prismor_version",
      "agents":         [ {name, framework, enabled, mode, last_seen} ],   # what runs here
      "audit_findings": [ {severity, category, message} ],                 # posture (run_audit)
      "trail_checkpoint": { seq, hash, ... },                             # signed audit-trail anchor
      "content_hash":   sha256 over the JCS-canonical bundle body,
      "signature", "signing_alg", "signing_pubkey", "signing_key_id"       # Ed25519 (receipt_signing)
    }

Everything here is assembled from parts that already exist: ``run_audit`` for
posture, ``list_agents`` for the inventory, ``audit_trail.checkpoint`` for the
tamper-evident anchor, and ``receipt_signing`` for the key. The one addition is
RFC 8785 (JCS) canonicalization for the signed body, so a verifier in any
language can reproduce the exact bytes we signed — the internal audit trail
keeps its own canonical form.

Signing needs the optional ``cryptography`` extra; without it the bundle is
still assembled (with its content hash) but unsigned.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.enterprise import receipt_signing as _signing

SCHEMA = "prismor.attestation.v1"

# Fields that are the signature envelope, never part of the signed body.
_ENVELOPE = frozenset(
    {"content_hash", "signature", "signing_alg", "signing_pubkey", "signing_key_id"}
)


def _jcs(value: Any) -> str:
    """RFC 8785 (JSON Canonical Serialization), for the subset of JSON we emit.

    Object keys sorted by UTF-16 code unit, minimal separators, no insignificant
    whitespace. Integers stay bare; we never emit floats in a bundle, so the
    full ECMAScript number grammar isn't needed."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _content_hash(body: Dict[str, Any]) -> str:
    return hashlib.sha256(_jcs(body).encode("utf-8")).hexdigest()


def _prismor_version() -> Optional[str]:
    try:
        from prismor.runtime import __version__
        return __version__
    except Exception:
        return None


def _device_id() -> Optional[str]:
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        return ident.get("device_id") if ident else None
    except Exception:
        return None


def build_bundle(workspace: Path, repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """Assemble and sign an attestation bundle for ``workspace``.

    Best-effort per section: a subsystem that errors contributes an empty list
    rather than failing the whole bundle. The signature covers the JCS-canonical
    body (everything except the envelope fields)."""
    agents: List[Dict[str, Any]] = []
    try:
        from prismor.runtime.agents import list_agents
        for a in list_agents(workspace):
            agents.append({
                "name": a.name,
                "framework": a.framework,
                "enabled": a.enabled,
                "mode": a.mode,
                "last_seen": a.last_seen,
            })
    except Exception:
        pass

    findings: List[Dict[str, Any]] = []
    try:
        from prismor.runtime.audit import run_audit
        findings = [f.to_dict() for f in run_audit(workspace=workspace, repo_root=repo_root)]
    except Exception:
        pass

    checkpoint: Optional[Dict[str, Any]] = None
    try:
        from prismor.runtime.enterprise import audit_trail as _trail
        checkpoint = _trail.checkpoint()
    except Exception:
        pass

    bundle: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_id": _device_id(),
        "prismor_version": _prismor_version(),
        "agents": agents,
        "audit_findings": findings,
        "trail_checkpoint": checkpoint,
    }
    bundle["content_hash"] = _content_hash(
        {k: v for k, v in bundle.items() if k not in _ENVELOPE}
    )
    # Bind the Ed25519 signature to content_hash by placing it on `hash`, the
    # field receipt_signing.sign_record signs over. No-op without `cryptography`.
    signable = {**bundle, "hash": bundle["content_hash"]}
    _signing.sign_record(signable)
    for k in ("signature", "signing_alg", "signing_pubkey", "signing_key_id"):
        if k in signable:
            bundle[k] = signable[k]
    return bundle


def verify_bundle(
    bundle: Dict[str, Any],
    pubkey_b64: Optional[str] = None,
) -> Dict[str, Any]:
    """Re-verify a bundle: recompute the content hash and check the Ed25519
    signature. Returns a report; ``ok`` is True only when both pass.

    ``pubkey_b64`` pins verification to an out-of-band copy of the signer's key
    (what an auditor uses); otherwise the bundle's inline pubkey is trusted."""
    report: Dict[str, Any] = {
        "schema": bundle.get("schema"),
        "generated_at": bundle.get("generated_at"),
        "signing_key_id": bundle.get("signing_key_id"),
        "content_hash_ok": False,
        "signature_ok": False,
        "errors": [],
    }

    body = {k: v for k, v in bundle.items() if k not in _ENVELOPE}
    recomputed = _content_hash(body)
    if recomputed == bundle.get("content_hash"):
        report["content_hash_ok"] = True
    else:
        report["errors"].append("content_hash mismatch — the bundle body was altered")

    if not bundle.get("signature"):
        report["errors"].append("bundle is unsigned")
    else:
        key_id = bundle.get("signing_key_id")
        pinned_id = _signing.key_id(pubkey_b64) if pubkey_b64 else None
        if pubkey_b64 and key_id != pinned_id:
            report["errors"].append(
                f"signed by key {key_id}, not the pinned key {pinned_id}"
            )
        else:
            signable = {**body, "hash": bundle.get("content_hash"),
                        "signature": bundle.get("signature"),
                        "signing_pubkey": bundle.get("signing_pubkey")}
            if _signing.verify_record(signable, pubkey_b64):
                report["signature_ok"] = True
            else:
                report["errors"].append("Ed25519 signature does not verify")

    report["ok"] = report["content_hash_ok"] and report["signature_ok"]
    return report
