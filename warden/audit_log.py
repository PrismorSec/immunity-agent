"""Tamper-evident, replayable audit log for Warden decisions.

One record per decision (allow / observe / block) is written to a per-session
NDJSON file. Each record is hash-chained to its predecessor — modifying any
prior record breaks the chain. Records are optionally Ed25519-signed when a
signing key is configured.

Layout under the workspace:

    .prismor-warden/audit/
        <session_id>.ndjson          # chained records (one JSON per line)
        <session_id>.seal            # final manifest (head hash + sig) on close
        policies/<policy_hash>/      # pinned policy snapshot (for replay)
        feed/<feed_hash>.json        # pinned advisory feed snapshot (for replay)
        pubkeys/<key_id>.pub         # registered verifier public keys

Public API used by the hook dispatcher:

    write_record(workspace, session_id, agent, mode, event, decision,
                 findings, repo_root) -> Dict
    verify_chain(path) -> VerifyResult
    read_records(path) -> Iterator[Dict]

Default behavior:
  - Always: SHA-256 hash chain (zero setup).
  - Signing: enabled when ``~/.prismor/keys/audit-signer.key`` exists OR
    the env var ``WARDEN_AUDIT_SIGNING_KEY`` points to a private key file.
  - Raw evidence (commands/paths/etc.) is hashed-only by default. Set
    ``audit.include_raw: true`` in policy.yaml settings to retain plaintext.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from warden.signing import (
    SigningUnavailable,
    b64decode,
    b64encode,
    key_id as _key_id,
    sign as _sign,
    verify as _verify,
)

RECORD_VERSION = 1
HASH_ALGO = "sha256"

_SENSITIVE_FIELDS = ("command", "path", "url", "content", "prompt", "response")


# ── Paths ───────────────────────────────────────────────────────────────────

def audit_dir(workspace: Path) -> Path:
    return Path(workspace) / ".prismor-warden" / "audit"


def session_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    return audit_dir(workspace) / f"{safe}.ndjson"


def seal_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    return audit_dir(workspace) / f"{safe}.seal"


def policies_dir(workspace: Path) -> Path:
    return audit_dir(workspace) / "policies"


def feed_dir(workspace: Path) -> Path:
    return audit_dir(workspace) / "feed"


def pubkeys_dir(workspace: Path) -> Path:
    return audit_dir(workspace) / "pubkeys"


def default_signing_key_path() -> Path:
    return Path.home() / ".prismor" / "keys" / "audit-signer.key"


def default_signing_pubkey_path() -> Path:
    return Path.home() / ".prismor" / "keys" / "audit-signer.pub"


# ── Canonicalization & hashing ──────────────────────────────────────────────

def canonical_bytes(record: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used for hashing and signing.

    Sorted keys, no whitespace, UTF-8, ensure_ascii=False so unicode is
    represented byte-for-byte the same regardless of platform. Excludes the
    fields that depend on the hash itself (``record_hash`` and ``sig``).
    """
    cleaned = {k: v for k, v in record.items() if k not in ("record_hash", "sig")}
    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Pinning policy & feed ───────────────────────────────────────────────────

def _pin_policy(workspace: Path, repo_root: Path) -> str:
    """Compute a stable hash of the effective policy and snapshot the source
    files into ``audit/policies/<hash>/`` the first time we see this hash.

    The hash is over (default_policy_bytes || b'\\x00' || override_bytes).
    """
    default_path = repo_root / "warden" / "default_policy.yaml"
    if not default_path.exists():
        # Some installs ship default_policy.yaml inside the warden package.
        alt = Path(__file__).parent / "default_policy.yaml"
        if alt.exists():
            default_path = alt

    override_path = workspace / ".prismor-warden" / "policy.yaml"

    h = hashlib.sha256()
    default_bytes = default_path.read_bytes() if default_path.exists() else b""
    override_bytes = override_path.read_bytes() if override_path.exists() else b""
    h.update(default_bytes)
    h.update(b"\x00")
    h.update(override_bytes)
    digest = h.hexdigest()

    snap_dir = policies_dir(workspace) / digest
    if not snap_dir.exists():
        snap_dir.mkdir(parents=True, exist_ok=True)
        if default_bytes:
            (snap_dir / "default_policy.yaml").write_bytes(default_bytes)
        if override_bytes:
            (snap_dir / "policy.yaml").write_bytes(override_bytes)

    return digest


def _pin_feed(workspace: Path, repo_root: Path) -> Optional[str]:
    feed_path = repo_root / "advisories" / "immunity-feed.json"
    if not feed_path.exists():
        return None
    digest = sha256_file(feed_path)
    if digest is None:
        return None
    snap = feed_dir(workspace) / f"{digest}.json"
    if not snap.exists():
        snap.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(feed_path, snap)
    return digest


# ── Event redaction ─────────────────────────────────────────────────────────

def _redact_event(event: Dict[str, Any], include_raw: bool) -> Dict[str, Any]:
    """Build the ``event`` block for an audit record.

    Always includes ``type``, ``ts``, ``agent_event``, ``tool``. Sensitive
    string fields are hashed; raw values are only attached when
    ``include_raw=True``.
    """
    out: Dict[str, Any] = {
        "type": event.get("type"),
        "ts": event.get("ts"),
        "agent_event": event.get("agent_event"),
        "tool": event.get("tool"),
    }
    for fname in _SENSITIVE_FIELDS:
        val = event.get(fname)
        if val is None or val == "":
            continue
        if not isinstance(val, str):
            val = str(val)
        out[f"{fname}_hash"] = sha256_hex(val.encode("utf-8"))
        out[f"{fname}_len"] = len(val)
        if include_raw:
            out[fname] = val
    return {k: v for k, v in out.items() if v is not None}


def _redact_finding(finding: Dict[str, Any], include_raw: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": finding.get("id"),
        "rule_id": finding.get("ruleId"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "title": finding.get("title"),
        "action": finding.get("action"),
    }
    evidence = finding.get("evidence")
    if evidence:
        if not isinstance(evidence, str):
            evidence = str(evidence)
        out["evidence_hash"] = sha256_hex(evidence.encode("utf-8"))
        out["evidence_len"] = len(evidence)
        if include_raw:
            out["evidence"] = evidence
    return {k: v for k, v in out.items() if v is not None}


# ── Workspace ID ────────────────────────────────────────────────────────────

def _workspace_id(workspace: Path) -> str:
    return sha256_hex(str(Path(workspace).resolve()).encode("utf-8"))[:16]


# ── Read chain head ─────────────────────────────────────────────────────────

def _last_record(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    last_line = ""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if not last_line:
        return None
    try:
        return json.loads(last_line)
    except json.JSONDecodeError:
        return None


# ── Signing config ──────────────────────────────────────────────────────────

@dataclass
class SigningConfig:
    private_key: Optional[Path] = None
    public_key: Optional[Path] = None
    key_id: Optional[str] = None
    enabled: bool = False


def detect_signing() -> SigningConfig:
    """Determine whether signing is enabled, based on env + default key path."""
    env_key = os.environ.get("WARDEN_AUDIT_SIGNING_KEY")
    if env_key:
        priv = Path(env_key).expanduser()
        if priv.exists():
            pub = Path(os.environ.get("WARDEN_AUDIT_SIGNING_PUBKEY",
                                      str(priv) + ".pub")).expanduser()
            if pub.exists():
                try:
                    return SigningConfig(
                        private_key=priv, public_key=pub,
                        key_id=_key_id(pub), enabled=True,
                    )
                except Exception:
                    pass

    priv = default_signing_key_path()
    pub = default_signing_pubkey_path()
    if priv.exists() and pub.exists():
        try:
            return SigningConfig(
                private_key=priv, public_key=pub,
                key_id=_key_id(pub), enabled=True,
            )
        except Exception:
            pass
    return SigningConfig(enabled=False)


def register_pubkey(workspace: Path, pubkey_src: Path) -> str:
    """Copy a public key into the workspace pubkey registry.
    Returns its key_id. Verifiers walk this dir on `audit verify`."""
    pubkey_src = Path(pubkey_src).expanduser()
    kid = _key_id(pubkey_src)
    dst_dir = pubkeys_dir(workspace)
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / f"{kid}.pub"
    if not dst.exists():
        shutil.copy2(pubkey_src, dst)
    return kid


# ── Write a record ──────────────────────────────────────────────────────────

def write_record(
    *,
    workspace: Path,
    session_id: str,
    agent: str,
    mode: str,
    event: Dict[str, Any],
    decision: str,
    findings: List[Dict[str, Any]],
    repo_root: Path,
    agent_version: str = "warden",
    include_raw: bool = False,
    signing: Optional[SigningConfig] = None,
) -> Dict[str, Any]:
    """Append a chained, optionally-signed audit record. Returns the record."""
    audit_dir(workspace).mkdir(parents=True, exist_ok=True)
    chain_path = session_path(workspace, session_id)

    # Self-register the public key in this workspace so a remote verifier
    # cloning just the audit dir can validate signatures.
    if signing and signing.enabled and signing.public_key:
        try:
            register_pubkey(workspace, signing.public_key)
        except Exception:
            pass

    prev = _last_record(chain_path)
    seq = (prev.get("seq") + 1) if prev and isinstance(prev.get("seq"), int) else 0
    prev_hash = prev.get("record_hash") if prev else "GENESIS"

    policy_hash = _pin_policy(workspace, repo_root)
    feed_hash = _pin_feed(workspace, repo_root)

    record: Dict[str, Any] = {
        "v": RECORD_VERSION,
        "alg": HASH_ALGO,
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "session_id": session_id,
        "agent": agent,
        "mode": mode,
        "workspace_id": _workspace_id(workspace),
        "event": _redact_event(event, include_raw),
        "decision": decision,
        "findings": [_redact_finding(f, include_raw) for f in (findings or [])],
        "policy_hash": policy_hash,
        "feed_hash": feed_hash,
        "agent_version": agent_version,
        "prev_hash": prev_hash,
    }

    record_hash = sha256_hex(canonical_bytes(record))
    record["record_hash"] = record_hash

    if signing and signing.enabled and signing.private_key:
        try:
            sig = _sign(canonical_bytes(record), signing.private_key)
            record["sig"] = {
                "alg": "ed25519",
                "key_id": signing.key_id,
                "value": b64encode(sig),
            }
        except SigningUnavailable:
            pass
        except Exception:
            pass

    line = json.dumps(record, ensure_ascii=False) + "\n"
    with chain_path.open("a", encoding="utf-8") as f:
        f.write(line)

    return record


# ── Read & verify ───────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    ok: bool = True
    records: int = 0
    chain_breaks: List[Tuple[int, str]] = field(default_factory=list)  # (seq, reason)
    bad_signatures: List[Tuple[int, str]] = field(default_factory=list)
    missing_pubkeys: List[str] = field(default_factory=list)
    unsigned: int = 0
    signed: int = 0

    def summary(self) -> str:
        parts = [f"{self.records} record(s)"]
        if self.signed:
            parts.append(f"{self.signed} signed")
        if self.unsigned:
            parts.append(f"{self.unsigned} unsigned")
        if self.chain_breaks:
            parts.append(f"{len(self.chain_breaks)} chain break(s)")
        if self.bad_signatures:
            parts.append(f"{len(self.bad_signatures)} bad signature(s)")
        if self.missing_pubkeys:
            parts.append(f"{len(self.missing_pubkeys)} missing pubkey(s)")
        return ", ".join(parts)


def read_records(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _resolve_pubkey(workspace: Path, key_id_value: str) -> Optional[Path]:
    """Look up a pubkey by key_id in the workspace registry, then fall back to
    the default user-level signing pubkey."""
    candidate = pubkeys_dir(workspace) / f"{key_id_value}.pub"
    if candidate.exists():
        return candidate
    default_pub = default_signing_pubkey_path()
    if default_pub.exists():
        try:
            if _key_id(default_pub) == key_id_value:
                return default_pub
        except Exception:
            pass
    return None


def verify_chain(path: Path, workspace: Optional[Path] = None) -> VerifyResult:
    """Walk the chain file, recompute hashes, validate ``prev_hash`` links,
    and verify any present signatures. Returns a structured result."""
    result = VerifyResult()
    workspace = workspace or path.parent.parent.parent  # .../audit/<file> -> ws
    expected_prev = "GENESIS"
    expected_seq = 0
    pubkey_cache: Dict[str, Optional[Path]] = {}

    for record in read_records(path):
        result.records += 1
        seq = record.get("seq")
        prev_hash = record.get("prev_hash")
        record_hash = record.get("record_hash")

        if seq != expected_seq:
            result.ok = False
            result.chain_breaks.append((expected_seq, f"seq mismatch: got {seq}"))
        if prev_hash != expected_prev:
            result.ok = False
            result.chain_breaks.append((expected_seq, f"prev_hash mismatch (expected {expected_prev[:12]}…)"))

        # Recompute record_hash
        recomputed = sha256_hex(canonical_bytes(record))
        if recomputed != record_hash:
            result.ok = False
            result.chain_breaks.append((expected_seq, "record_hash does not match canonical bytes"))

        # Verify signature if present
        sig = record.get("sig")
        if sig:
            kid = sig.get("key_id", "")
            if kid not in pubkey_cache:
                pubkey_cache[kid] = _resolve_pubkey(workspace, kid)
            pub = pubkey_cache[kid]
            if pub is None:
                if kid not in result.missing_pubkeys:
                    result.missing_pubkeys.append(kid)
                result.bad_signatures.append((seq or expected_seq, f"no pubkey for key_id={kid}"))
                result.ok = False
            else:
                try:
                    raw_sig = b64decode(sig.get("value", ""))
                    if not _verify(canonical_bytes(record), raw_sig, pub):
                        result.bad_signatures.append((seq or expected_seq, "bad signature"))
                        result.ok = False
                    else:
                        result.signed += 1
                except Exception as e:
                    result.bad_signatures.append((seq or expected_seq, f"verify error: {e}"))
                    result.ok = False
        else:
            result.unsigned += 1

        expected_prev = record_hash or expected_prev
        expected_seq += 1

    return result


# ── Seal a session ──────────────────────────────────────────────────────────

def seal_session(
    *,
    workspace: Path,
    session_id: str,
    signing: Optional[SigningConfig] = None,
) -> Optional[Dict[str, Any]]:
    """Write a final manifest with the head hash + record count.
    Optionally sign the manifest. Idempotent — repeated calls overwrite."""
    chain = session_path(workspace, session_id)
    if not chain.exists():
        return None

    head: Optional[Dict[str, Any]] = None
    n = 0
    for rec in read_records(chain):
        head = rec
        n += 1
    if head is None:
        return None

    manifest: Dict[str, Any] = {
        "v": RECORD_VERSION,
        "session_id": session_id,
        "workspace_id": _workspace_id(workspace),
        "records": n,
        "head_seq": head.get("seq"),
        "head_hash": head.get("record_hash"),
        "sealed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    if signing and signing.enabled and signing.private_key:
        try:
            sig = _sign(canonical_bytes(manifest), signing.private_key)
            manifest["sig"] = {
                "alg": "ed25519",
                "key_id": signing.key_id,
                "value": b64encode(sig),
            }
        except Exception:
            pass

    seal = seal_path(workspace, session_id)
    seal.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


# ── List sessions ───────────────────────────────────────────────────────────

def list_session_files(workspace: Path) -> List[Path]:
    d = audit_dir(workspace)
    if not d.exists():
        return []
    return sorted([p for p in d.iterdir() if p.suffix == ".ndjson"])
