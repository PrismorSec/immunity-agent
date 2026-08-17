"""The documented receipt schema must match what the runtime actually emits.

docs/telemetry-receipts.md is a wire specification: people implement verifiers
against it in other languages and other stacks. A doc that has drifted from the
code is worse than no doc, because it produces verifiers that silently pass. So
the reference verifier printed in the page is *extracted from the page and
executed* here, against records this runtime just signed.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime.enterprise import chain  # noqa: E402
from prismor.runtime.enterprise import receipt_signing as rs  # noqa: E402

DOC = _ROOT / "docs" / "telemetry-receipts.md"

pytestmark = pytest.mark.skipif(not rs._HAVE_CRYPTO,
                                reason="signing needs the optional cryptography extra")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    rs._CACHED_KEY = None
    rs._CACHED_PUBKEY_B64 = None
    rs._LOAD_ATTEMPTED = False
    yield
    rs._CACHED_KEY = None
    rs._CACHED_PUBKEY_B64 = None
    rs._LOAD_ATTEMPTED = False


def _receipt(**overrides):
    record = {
        "event_id": "evt-9f2c", "verdict": "blocked", "severity": "high",
        "rule_id": "egress-deny", "tool_name": "Bash",
        "evidence_hash": "a3f1" + "0" * 60, "session_id": "sess-71b4",
        "ts": "2026-08-16T10:04:11.512834+00:00", "device_id": "dev-4a1e",
        "agent": "claude-code", "agent_name": "release-bot", "subagent_id": None,
        "subject": {"user_id": "u-77", "team_id": "t-3", "org_id": "o-1"},
    }
    record.update(overrides)
    seq, prev, digest = chain.next_link(record)
    record.update(seq=seq, prev_hash=prev, hash=digest)
    rs.sign_record(record)
    return record


@pytest.fixture(scope="module")
def documented():
    """The reference verifier, lifted out of the docs and compiled."""
    text = DOC.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
    impl = next((b for b in blocks if "def verify(" in b), None)
    assert impl, "docs/telemetry-receipts.md no longer publishes a verifier"
    namespace: dict = {}
    exec(compile(impl, str(DOC), "exec"), namespace)   # noqa: S102 - the point
    return namespace


# ── the published verifier works ─────────────────────────────────────────────

def test_documented_verifier_accepts_a_real_receipt(documented):
    intact, authentic = documented["verify"](_receipt())

    assert intact is True
    assert authentic is True


def test_documented_chain_hash_matches_the_runtime(documented):
    record = _receipt()

    assert documented["chain_hash"](record) == record["hash"]


def test_documented_canonical_bytes_match_the_runtime(documented):
    record = _receipt()

    assert documented["canonical"](documented["signing_payload"](record)) == \
        rs.canonical(rs.signing_payload(record))


# ── the two-layer claim in the docs is the real behaviour ────────────────────

@pytest.mark.parametrize("field,value", [
    ("verdict", "allowed"),
    ("rule_id", "something-else"),
    ("tool_name", "Read"),
    ("evidence_hash", "b" * 64),
    ("session_id", "sess-other"),
    ("event_id", "evt-other"),
    ("severity", "low"),
])
def test_event_fields_are_caught_by_the_chain_hash_only(documented, field, value):
    """Exactly the docs' first table row: chain ✅, signature ❌."""
    record = _receipt()
    record[field] = value
    intact, authentic = documented["verify"](record)

    assert intact is False, f"{field} tamper slipped past the chain hash"
    assert authentic is True, f"{field} unexpectedly covered by the signature"


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(device_id="dev-OTHER"),
    lambda r: r.update(agent="codex"),
    lambda r: r.update(agent_name="other-bot"),
    lambda r: r.update(subagent_id="sub-1"),
    lambda r: r["subject"].update(user_id="u-99"),
    lambda r: r["subject"].update(team_id="t-9"),
    lambda r: r["subject"].update(org_id="o-9"),
    lambda r: r.update(ts="2020-01-01T00:00:00+00:00"),
])
def test_identity_and_time_are_caught_by_the_signature_only(documented, mutate):
    """The docs' second and third rows: chain ❌, signature ✅."""
    record = _receipt()
    mutate(record)
    intact, authentic = documented["verify"](record)

    assert intact is True, "unexpectedly covered by the chain hash"
    assert authentic is False, "identity/timestamp tamper slipped past the signature"


def test_a_verifier_checking_only_one_layer_has_a_blind_spot(documented):
    """The reason the page insists on both, stated as a test."""
    flipped = _receipt()
    flipped["verdict"] = "allowed"
    reassigned = _receipt()
    reassigned["device_id"] = "dev-OTHER"

    assert documented["verify"](flipped)[1] is True       # signature alone: fooled
    assert documented["verify"](reassigned)[0] is True    # chain alone: fooled
    assert documented["verify"](flipped) != (True, True)
    assert documented["verify"](reassigned) != (True, True)


# ── pinning ──────────────────────────────────────────────────────────────────

def test_resigning_with_a_fresh_key_passes_inline_but_fails_pinned(documented):
    """Why the page says to pin: inline keys prove consistency, not identity."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    record = _receipt()
    pinned = record["signing_pubkey"]

    attacker = Ed25519PrivateKey.generate()
    record["verdict"] = "allowed"
    seq, prev, digest = record["seq"], record["prev_hash"], documented["chain_hash"](record)
    record["hash"] = digest
    payload = documented["canonical"](documented["signing_payload"](record))
    record["signature"] = base64.b64encode(attacker.sign(payload)).decode()
    record["signing_pubkey"] = base64.b64encode(
        attacker.public_key().public_bytes_raw()).decode()

    assert documented["verify"](record) == (True, True)          # inline: fooled
    assert documented["verify"](record, pinned)[1] is False      # pinned: caught


# ── the schema documented is the schema emitted ──────────────────────────────

def test_every_documented_field_is_present_on_a_real_receipt():
    record = _receipt()
    text = DOC.read_text(encoding="utf-8")
    documented_fields = set(re.findall(r"^\| `([a-z_]+)` \| ", text, re.MULTILINE))

    assert documented_fields, "field table not found"
    missing = documented_fields - set(record)
    assert not missing, f"documented but never emitted: {sorted(missing)}"


def test_worked_example_in_the_docs_is_internally_consistent(documented):
    """The sample receipt on the page must verify against the bytes shown."""
    text = DOC.read_text(encoding="utf-8")
    sample = json.loads(re.search(r"```json\n(\{.*?\})\n```", text, re.DOTALL).group(1))
    shown = re.search(r"^\{\"hash\":.*$", text, re.MULTILINE).group(0)

    assert documented["canonical"](documented["signing_payload"](sample)).decode() == shown
    assert documented["verify"](sample) == (True, True)


def test_key_id_derivation_matches_the_documented_formula():
    import hashlib

    record = _receipt()
    raw = base64.b64decode(record["signing_pubkey"])

    assert record["signing_key_id"] == hashlib.sha256(raw).hexdigest()[:16]
    assert len(record["signing_key_id"]) == 16
