"""Ed25519 signing utilities for Warden audit records.

Two backends are supported:

  1. ``cryptography`` library (preferred — pure-python, deterministic, no shellout).
  2. ``openssl pkeyutl`` (fallback — same approach as ``pipeline/sign_feed.sh``).

Public API:

    keygen(private_path, public_path) -> None
    sign(message: bytes, private_key_path: Path) -> bytes      # raw signature
    verify(message: bytes, signature: bytes, public_key_path: Path) -> bool
    key_id(public_key_path: Path) -> str                       # short fingerprint

All functions are best-effort: if neither backend is available, ``sign`` raises
``SigningUnavailable`` and the caller falls back to chain-only audit records.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


class SigningUnavailable(RuntimeError):
    """Raised when no signing backend is available."""


# ── Backend selection ───────────────────────────────────────────────────────

def _have_cryptography() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
        return True
    except ImportError:
        return False


def _have_openssl() -> bool:
    return shutil.which("openssl") is not None


# ── Key generation ──────────────────────────────────────────────────────────

def keygen(private_path: Path, public_path: Path) -> None:
    """Generate a new Ed25519 keypair, writing PEM files to the given paths.

    Private key file is created with mode 0600, parent dir 0700.
    """
    private_path = Path(private_path).expanduser()
    public_path = Path(public_path).expanduser()
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(private_path.parent, 0o700)
    except OSError:
        pass

    if _have_cryptography():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        key = Ed25519PrivateKey.generate()
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.write_bytes(priv_pem)
        public_path.write_bytes(pub_pem)
    elif _have_openssl():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_path)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
            check=True,
            capture_output=True,
        )
    else:
        raise SigningUnavailable("no Ed25519 backend (install 'cryptography' or 'openssl')")

    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)


# ── Sign ────────────────────────────────────────────────────────────────────

def sign(message: bytes, private_key_path: Path) -> bytes:
    """Return a raw Ed25519 signature over ``message``."""
    private_key_path = Path(private_key_path).expanduser()
    if not private_key_path.exists():
        raise SigningUnavailable(f"private key not found: {private_key_path}")

    if _have_cryptography():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv_pem = private_key_path.read_bytes()
        key = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningUnavailable("private key is not Ed25519")
        return key.sign(message)

    if _have_openssl():
        with tempfile.NamedTemporaryFile(delete=False) as msg_f:
            msg_f.write(message)
            msg_path = msg_f.name
        sig_path = msg_path + ".sig"
        try:
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign",
                    "-inkey", str(private_key_path),
                    "-rawin", "-in", msg_path,
                    "-out", sig_path,
                ],
                check=True, capture_output=True,
            )
            return Path(sig_path).read_bytes()
        finally:
            for p in (msg_path, sig_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    raise SigningUnavailable("no Ed25519 backend available")


# ── Verify ──────────────────────────────────────────────────────────────────

def verify(message: bytes, signature: bytes, public_key_path: Path) -> bool:
    """Verify an Ed25519 signature; return True iff valid."""
    public_key_path = Path(public_key_path).expanduser()
    if not public_key_path.exists():
        return False

    if _have_cryptography():
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_pem = public_key_path.read_bytes()
        try:
            key = serialization.load_pem_public_key(pub_pem)
            if not isinstance(key, Ed25519PublicKey):
                return False
            key.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    if _have_openssl():
        with tempfile.NamedTemporaryFile(delete=False) as msg_f:
            msg_f.write(message)
            msg_path = msg_f.name
        with tempfile.NamedTemporaryFile(delete=False) as sig_f:
            sig_f.write(signature)
            sig_path = sig_f.name
        try:
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify",
                    "-pubin", "-inkey", str(public_key_path),
                    "-rawin", "-in", msg_path,
                    "-sigfile", sig_path,
                ],
                capture_output=True,
            )
            return result.returncode == 0
        finally:
            for p in (msg_path, sig_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    return False


# ── Key ID ──────────────────────────────────────────────────────────────────

def key_id(public_key_path: Path) -> str:
    """Return a short stable fingerprint (first 16 hex chars of SHA-256 of the
    raw public key bytes). Used as ``key_id`` field on records so verifiers
    know which pubkey to use when multiple are in play."""
    public_key_path = Path(public_key_path).expanduser()
    pub_pem = public_key_path.read_bytes()

    raw_bytes: Optional[bytes] = None
    if _have_cryptography():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            key = serialization.load_pem_public_key(pub_pem)
            if isinstance(key, Ed25519PublicKey):
                raw_bytes = key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
        except ValueError:
            raw_bytes = None

    if raw_bytes is None:
        # Fallback: hash the PEM. Less canonical but still stable per file.
        raw_bytes = pub_pem

    return hashlib.sha256(raw_bytes).hexdigest()[:16]


# ── Helpers for callers ─────────────────────────────────────────────────────

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
