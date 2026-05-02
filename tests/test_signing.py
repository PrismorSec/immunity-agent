"""Tests for warden.signing — Ed25519 keygen, sign, verify."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.signing import (
    SigningUnavailable,
    b64decode,
    b64encode,
    key_id,
    keygen,
    sign,
    verify,
)


class TestKeygen(unittest.TestCase):
    def test_keygen_writes_files_with_correct_modes(self):
        with tempfile.TemporaryDirectory() as td:
            priv = Path(td) / "k.key"
            pub = Path(td) / "k.pub"
            keygen(priv, pub)
            self.assertTrue(priv.exists())
            self.assertTrue(pub.exists())
            self.assertEqual(priv.stat().st_mode & 0o777, 0o600)
            # public key bytes should be a valid PEM
            self.assertIn(b"BEGIN PUBLIC KEY", pub.read_bytes())

    def test_keygen_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as td:
            nested = Path(td) / "deep" / "nested"
            priv = nested / "k.key"
            pub = nested / "k.pub"
            keygen(priv, pub)
            self.assertTrue(priv.exists())


class TestSignVerifyRoundtrip(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.priv = Path(self._td.name) / "k.key"
        self.pub = Path(self._td.name) / "k.pub"
        keygen(self.priv, self.pub)

    def tearDown(self):
        self._td.cleanup()

    def test_signature_roundtrip_succeeds(self):
        msg = b"audit record bytes"
        sig = sign(msg, self.priv)
        self.assertEqual(len(sig), 64)  # Ed25519 sigs are 64 bytes
        self.assertTrue(verify(msg, sig, self.pub))

    def test_verify_rejects_tampered_message(self):
        msg = b"original"
        sig = sign(msg, self.priv)
        self.assertFalse(verify(b"tampered", sig, self.pub))

    def test_verify_rejects_tampered_signature(self):
        msg = b"original"
        sig = bytearray(sign(msg, self.priv))
        sig[0] ^= 0xFF  # flip a byte
        self.assertFalse(verify(msg, bytes(sig), self.pub))

    def test_verify_rejects_wrong_pubkey(self):
        msg = b"original"
        sig = sign(msg, self.priv)
        with tempfile.TemporaryDirectory() as td:
            other_priv = Path(td) / "other.key"
            other_pub = Path(td) / "other.pub"
            keygen(other_priv, other_pub)
            self.assertFalse(verify(msg, sig, other_pub))

    def test_sign_missing_key_raises(self):
        with self.assertRaises(SigningUnavailable):
            sign(b"x", Path("/nonexistent/key.key"))

    def test_b64_roundtrip(self):
        data = b"\x00\x01\x02\xff binary"
        self.assertEqual(b64decode(b64encode(data)), data)


class TestKeyID(unittest.TestCase):
    def test_key_id_is_stable(self):
        with tempfile.TemporaryDirectory() as td:
            priv = Path(td) / "k.key"
            pub = Path(td) / "k.pub"
            keygen(priv, pub)
            kid1 = key_id(pub)
            kid2 = key_id(pub)
            self.assertEqual(kid1, kid2)
            self.assertEqual(len(kid1), 16)

    def test_key_id_differs_per_keypair(self):
        with tempfile.TemporaryDirectory() as td:
            p1, k1 = Path(td) / "a.key", Path(td) / "a.pub"
            p2, k2 = Path(td) / "b.key", Path(td) / "b.pub"
            keygen(p1, k1)
            keygen(p2, k2)
            self.assertNotEqual(key_id(k1), key_id(k2))


if __name__ == "__main__":
    unittest.main()
