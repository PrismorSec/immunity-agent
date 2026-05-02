"""Tests for warden.audit_log — chained, signed, replayable decision log."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden import audit_log as al
from warden.audit_log import (
    SigningConfig,
    canonical_bytes,
    read_records,
    seal_session,
    session_path,
    sha256_hex,
    verify_chain,
    write_record,
)
from warden.signing import key_id, keygen


def _fresh_repo(td: Path) -> Path:
    """Create a minimal repo skeleton with a default_policy.yaml under it."""
    repo = td / "repo"
    (repo / "warden").mkdir(parents=True)
    (repo / "warden" / "default_policy.yaml").write_text("rules: []\nsettings: {}\n")
    return repo


def _signing(td: Path) -> SigningConfig:
    keys = td / "keys"
    keys.mkdir()
    priv = keys / "a.key"
    pub = keys / "a.pub"
    keygen(priv, pub)
    return SigningConfig(
        private_key=priv,
        public_key=pub,
        key_id=key_id(pub),
        enabled=True,
    )


def _event(cmd: str = "ls -la") -> dict:
    return {
        "type": "shell",
        "agent_event": "PreToolUse",
        "command": cmd,
        "ts": "2026-05-03T00:00:00Z",
    }


def _finding(rule_id: str = "test-rule") -> dict:
    return {
        "id": f"sess:{rule_id}-0",
        "ruleId": rule_id,
        "severity": "HIGH",
        "category": "test",
        "title": "test title",
        "evidence": "matched-evidence",
        "action": "block",
    }


class TestCanonicalEncoding(unittest.TestCase):
    def test_canonical_bytes_excludes_record_hash_and_sig(self):
        rec = {"a": 1, "record_hash": "x", "sig": {"value": "y"}}
        out = canonical_bytes(rec)
        self.assertEqual(out, b'{"a":1}')

    def test_canonical_bytes_sorted_keys(self):
        rec = {"b": 2, "a": 1}
        self.assertEqual(canonical_bytes(rec), b'{"a":1,"b":2}')

    def test_canonical_bytes_no_whitespace(self):
        rec = {"a": [1, 2], "b": {"c": 3}}
        self.assertNotIn(b" ", canonical_bytes(rec))

    def test_sha256_hex_is_deterministic(self):
        self.assertEqual(sha256_hex(b"hello"), sha256_hex(b"hello"))
        self.assertNotEqual(sha256_hex(b"hello"), sha256_hex(b"world"))


class TestChain(unittest.TestCase):
    def test_first_record_uses_genesis_prev_hash(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"
            ws.mkdir()
            repo = _fresh_repo(td_path)
            rec = write_record(
                workspace=ws, session_id="s1", agent="claude", mode="enforce",
                event=_event(), decision="allow", findings=[], repo_root=repo,
            )
            self.assertEqual(rec["prev_hash"], "GENESIS")
            self.assertEqual(rec["seq"], 0)

    def test_subsequent_records_chain_to_predecessor(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            r0 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event("a"),
                              decision="allow", findings=[], repo_root=repo)
            r1 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event("b"),
                              decision="block", findings=[_finding()], repo_root=repo)
            self.assertEqual(r1["prev_hash"], r0["record_hash"])
            self.assertEqual(r1["seq"], 1)

    def test_record_hash_is_sha256_of_canonical_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            rec = write_record(workspace=ws, session_id="s", agent="claude",
                               mode="enforce", event=_event(),
                               decision="allow", findings=[], repo_root=repo)
            self.assertEqual(sha256_hex(canonical_bytes(rec)), rec["record_hash"])


class TestVerify(unittest.TestCase):
    def _build_session(self, td: Path, *, sign: bool = False, n: int = 3):
        ws = td / "ws"; ws.mkdir()
        repo = _fresh_repo(td)
        sig_cfg = _signing(td) if sign else None
        for i in range(n):
            decision = "allow" if i == 0 else "block"
            findings = [] if decision == "allow" else [_finding(f"r{i}")]
            write_record(
                workspace=ws, session_id="s", agent="claude", mode="enforce",
                event=_event(f"cmd{i}"), decision=decision, findings=findings,
                repo_root=repo, signing=sig_cfg,
            )
        return ws

    def test_verify_passes_clean_unsigned_chain(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=False)
            res = verify_chain(session_path(ws, "s"), workspace=ws)
            self.assertTrue(res.ok)
            self.assertEqual(res.records, 3)
            self.assertEqual(res.unsigned, 3)
            self.assertEqual(res.signed, 0)

    def test_verify_passes_clean_signed_chain(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=True)
            res = verify_chain(session_path(ws, "s"), workspace=ws)
            self.assertTrue(res.ok)
            self.assertEqual(res.signed, 3)

    def test_verify_detects_field_tamper_via_record_hash(self):
        """Modify a field but leave record_hash unchanged — must fail."""
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=False)
            path = session_path(ws, "s")
            lines = path.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["decision"] = "allow"  # was "block"
            lines[1] = json.dumps(rec)
            path.write_text("\n".join(lines) + "\n")
            res = verify_chain(path, workspace=ws)
            self.assertFalse(res.ok)
            self.assertTrue(any("record_hash" in reason for _, reason in res.chain_breaks))

    def test_verify_detects_signature_tamper(self):
        """Modify a field; sig over the new bytes won't validate."""
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=True)
            path = session_path(ws, "s")
            lines = path.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["decision"] = "allow"
            lines[1] = json.dumps(rec)
            path.write_text("\n".join(lines) + "\n")
            res = verify_chain(path, workspace=ws)
            self.assertFalse(res.ok)
            self.assertTrue(len(res.bad_signatures) >= 1)

    def test_verify_detects_dropped_record(self):
        """Removing a middle record breaks the chain via prev_hash mismatch."""
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=False)
            path = session_path(ws, "s")
            lines = path.read_text().splitlines()
            del lines[1]
            path.write_text("\n".join(lines) + "\n")
            res = verify_chain(path, workspace=ws)
            self.assertFalse(res.ok)
            self.assertTrue(any("prev_hash" in reason or "seq" in reason
                                for _, reason in res.chain_breaks))

    def test_verify_detects_full_recompute_attempt_without_key(self):
        """Even if attacker recomputes hashes for a tampered chain, missing
        signature (since they don't have the private key) is detected."""
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_session(Path(td), sign=True)
            path = session_path(ws, "s")
            lines = path.read_text().splitlines()
            # Attacker rewrites record 1: changes decision and recomputes record_hash
            rec = json.loads(lines[1])
            rec["decision"] = "allow"
            from warden.audit_log import canonical_bytes as _cb
            new_hash = sha256_hex(_cb(rec))
            rec["record_hash"] = new_hash
            # ...and updates seq=2's prev_hash to point at the new hash
            lines[1] = json.dumps(rec)
            rec2 = json.loads(lines[2])
            rec2["prev_hash"] = new_hash
            new_hash2 = sha256_hex(_cb(rec2))
            rec2["record_hash"] = new_hash2
            lines[2] = json.dumps(rec2)
            path.write_text("\n".join(lines) + "\n")
            res = verify_chain(path, workspace=ws)
            # Signatures invalidated even though chain looks well-formed
            self.assertFalse(res.ok)
            self.assertGreaterEqual(len(res.bad_signatures), 1)


class TestRedaction(unittest.TestCase):
    def test_default_redacts_command_to_hash(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            secret_cmd = "cat /etc/shadow"
            rec = write_record(
                workspace=ws, session_id="s", agent="claude", mode="enforce",
                event=_event(secret_cmd), decision="block",
                findings=[_finding()], repo_root=repo,
            )
            ev = rec["event"]
            self.assertNotIn("command", ev)
            self.assertEqual(ev["command_hash"], sha256_hex(secret_cmd.encode()))
            self.assertEqual(ev["command_len"], len(secret_cmd))

    def test_include_raw_keeps_command_text(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            secret_cmd = "echo hello"
            rec = write_record(
                workspace=ws, session_id="s", agent="claude", mode="enforce",
                event=_event(secret_cmd), decision="allow",
                findings=[], repo_root=repo, include_raw=True,
            )
            self.assertEqual(rec["event"]["command"], secret_cmd)
            self.assertEqual(rec["event"]["command_hash"], sha256_hex(secret_cmd.encode()))


class TestPolicyAndFeedPinning(unittest.TestCase):
    def test_policy_hash_is_stable_across_records(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            r0 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event("a"),
                              decision="allow", findings=[], repo_root=repo)
            r1 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event("b"),
                              decision="allow", findings=[], repo_root=repo)
            self.assertEqual(r0["policy_hash"], r1["policy_hash"])

    def test_policy_snapshot_is_pinned_on_disk(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            rec = write_record(workspace=ws, session_id="s", agent="claude",
                               mode="enforce", event=_event(),
                               decision="allow", findings=[], repo_root=repo)
            snap = al.policies_dir(ws) / rec["policy_hash"] / "default_policy.yaml"
            self.assertTrue(snap.exists())

    def test_policy_hash_changes_when_override_added(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            r0 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event(),
                              decision="allow", findings=[], repo_root=repo)
            override_dir = ws / ".prismor-warden"
            override_dir.mkdir(exist_ok=True)
            (override_dir / "policy.yaml").write_text("rules:\n  - id: extra\n")
            r1 = write_record(workspace=ws, session_id="s", agent="claude",
                              mode="enforce", event=_event(),
                              decision="allow", findings=[], repo_root=repo)
            self.assertNotEqual(r0["policy_hash"], r1["policy_hash"])


class TestSeal(unittest.TestCase):
    def test_seal_writes_manifest_with_head_hash(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            sig = _signing(td_path)
            for i in range(3):
                write_record(workspace=ws, session_id="s", agent="claude",
                             mode="enforce", event=_event(f"c{i}"),
                             decision="allow", findings=[],
                             repo_root=repo, signing=sig)
            manifest = seal_session(workspace=ws, session_id="s", signing=sig)
            self.assertIsNotNone(manifest)
            self.assertEqual(manifest["records"], 3)
            self.assertEqual(manifest["head_seq"], 2)
            self.assertIn("head_hash", manifest)
            self.assertIn("sig", manifest)

    def test_seal_returns_none_for_unknown_session(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"; ws.mkdir()
            self.assertIsNone(seal_session(workspace=ws, session_id="nope"))


class TestReadRecords(unittest.TestCase):
    def test_read_records_yields_in_order(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ws = td_path / "ws"; ws.mkdir()
            repo = _fresh_repo(td_path)
            for i in range(4):
                write_record(workspace=ws, session_id="s", agent="claude",
                             mode="enforce", event=_event(f"c{i}"),
                             decision="allow", findings=[], repo_root=repo)
            seqs = [r["seq"] for r in read_records(session_path(ws, "s"))]
            self.assertEqual(seqs, [0, 1, 2, 3])


if __name__ == "__main__":
    unittest.main()
