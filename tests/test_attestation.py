"""Tests for the signed attestation bundle (enterprise/attestation.py).

A bundle snapshots governance posture (agent inventory + audit findings +
audit-trail anchor) and signs it so an auditor can re-verify offline.

Invariants:
  * A freshly built bundle verifies (hash + signature), and with the signer's
    pinned pubkey.
  * Any edit to the body breaks the content hash.
  * A bundle signed by a different key fails pinned verification.
  * Without `cryptography`, the bundle is assembled + hashed but unsigned, and
    verify reports it as unsigned (not verified).

Runs against an isolated $PRISMOR_HOME. Run: python3 -m pytest tests/test_attestation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

try:
    import cryptography  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


@pytest.fixture()
def attest(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    for mod in (
        "prismor.runtime.enterprise.attestation",
        "prismor.runtime.enterprise.receipt_signing",
        "prismor.runtime.enterprise.identity",
    ):
        sys.modules.pop(mod, None)
    from prismor.runtime.enterprise import attestation
    return attestation


@pytest.fixture()
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def test_bundle_shape(attest, workspace):
    b = attest.build_bundle(workspace)
    assert b["schema"] == attest.SCHEMA
    assert b["generated_at"] and "content_hash" in b
    for key in ("agents", "audit_findings", "trail_checkpoint", "prismor_version"):
        assert key in b
    assert isinstance(b["agents"], list) and isinstance(b["audit_findings"], list)


def test_clean_bundle_verifies(attest, workspace):
    b = attest.build_bundle(workspace)
    report = attest.verify_bundle(b)
    assert report["content_hash_ok"]
    if _HAVE_CRYPTO:
        assert report["ok"] and report["signature_ok"] and not report["errors"]
    else:
        assert not report["ok"]
        assert "bundle is unsigned" in report["errors"]


def test_body_edit_breaks_content_hash(attest, workspace):
    b = attest.build_bundle(workspace)
    b["audit_findings"].append({"severity": "PASS", "category": "x", "message": "injected"})
    report = attest.verify_bundle(b)
    assert not report["content_hash_ok"]
    assert any("content_hash mismatch" in e for e in report["errors"])


def test_field_swap_breaks_content_hash(attest, workspace):
    b = attest.build_bundle(workspace)
    b["device_id"] = "someone-elses-device"
    assert not attest.verify_bundle(b)["content_hash_ok"]


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_pinned_pubkey_accepts_signer(attest, workspace):
    from prismor.runtime.enterprise import receipt_signing as signing
    b = attest.build_bundle(workspace)
    report = attest.verify_bundle(b, pubkey_b64=signing.public_key_b64())
    assert report["ok"]


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_pinned_wrong_key_rejected(attest, workspace):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    b = attest.build_bundle(workspace)
    other = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode("ascii")
    report = attest.verify_bundle(b, pubkey_b64=other)
    assert not report["ok"]
    assert any("not the pinned key" in e for e in report["errors"])


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_foreign_signature_rejected(attest, workspace):
    """A bundle re-signed by another key (its inline pubkey swapped) fails when
    the auditor pins the real signer's key."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from prismor.runtime.enterprise import receipt_signing as signing

    real_pub = signing.public_key_b64()
    b = attest.build_bundle(workspace)

    attacker = Ed25519PrivateKey.generate()
    payload = signing.canonical(signing.signing_payload({**b, "hash": b["content_hash"]}))
    b["signature"] = base64.b64encode(attacker.sign(payload)).decode("ascii")
    b["signing_pubkey"] = base64.b64encode(attacker.public_key().public_bytes_raw()).decode("ascii")
    b["signing_key_id"] = signing.key_id(b["signing_pubkey"])

    # Inline (trust-on-first-use) verify passes — that's why auditors pin.
    assert attest.verify_bundle(b)["signature_ok"]
    # Pinned to the real signer, the foreign key is rejected.
    assert not attest.verify_bundle(b, pubkey_b64=real_pub)["ok"]


def test_unsigned_without_crypto(attest, workspace, monkeypatch):
    from prismor.runtime.enterprise import receipt_signing as signing
    monkeypatch.setattr(signing, "_HAVE_CRYPTO", False)
    b = attest.build_bundle(workspace)
    assert "signature" not in b
    report = attest.verify_bundle(b)
    assert report["content_hash_ok"] and not report["ok"]


def test_jcs_is_deterministic(attest):
    a = attest._jcs({"b": 1, "a": [3, {"z": 1, "y": 2}]})
    b = attest._jcs({"a": [3, {"y": 2, "z": 1}], "b": 1})
    assert a == b == '{"a":[3,{"y":2,"z":1}],"b":1}'
