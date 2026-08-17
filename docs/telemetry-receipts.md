# Signed Telemetry Receipts

**Schema version: `1`**

Every policy decision a device reports leaves a *receipt*: a small, signed
record of what an agent tried to do and what Prismor decided. Receipts are the
wire format between a device and whatever consumes its telemetry — the
organization console, a SIEM, an archive, an auditor's script.

This page is the format's specification. It exists so a receipt can be verified
by something that is not Prismor: the canonical bytes, the field set, and the
two integrity layers are all fixed and reproducible.

Related but distinct: [Signed Audit Trail](audit-trail.md) is the *local*,
full-fidelity log at `~/.prismor/audit/trail.jsonl`. It hashes every field of
every record, including the timestamp. Receipts are the narrower thing that
leaves the machine, and their integrity model is different in ways that matter
to a verifier — see [Two layers](#two-layers-and-why-you-need-both).

## A receipt

```json
{
  "event_id": "evt-9f2c",
  "verdict": "blocked",
  "severity": "high",
  "rule_id": "egress-deny",
  "tool_name": "Bash",
  "evidence_hash": "a3f1000000000000000000000000000000000000000000000000000000000000",
  "session_id": "sess-71b4",
  "ts": "2026-08-16T10:04:11.512834+00:00",
  "device_id": "dev-4a1e",
  "agent": "claude-code",
  "agent_name": "release-bot",
  "subagent_id": null,
  "subject": { "user_id": "u-77", "team_id": "t-3", "org_id": "o-1" },
  "seq": 0,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "b55d478cf0040f4247dd4845853e2356d7042e71142912221cbdcfbca8d631e5",
  "signature": "wXXt5bTpx0em1X7Sz836y4oePcq1OzwNajCoOokgtODJxqKug7r5iqSAOL/kE5ZkCZvzFdhoDa2KBavTr+ErAw==",
  "signing_alg": "ed25519",
  "signing_pubkey": "43SRf1/B5KQlZli62ixHBCvMvTPrFJtqSOyc0pQHbCE=",
  "signing_key_id": "7c342dfc18247604"
}
```

A receipt never carries the tool input itself. `evidence_hash` stands in for it,
so a receipt can prove *which* input was seen without transporting a command
line, a file path, or a secret.

### Fields

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string ≤60 | Identifier for this decision |
| `verdict` | enum | `blocked` \| `warned` \| `observed` \| `allowed` |
| `severity` | enum | `critical` \| `high` \| `medium` \| `low` |
| `rule_id` | string ≤80 | Rule that produced the verdict |
| `tool_name` | string ≤80 | Tool the agent invoked |
| `evidence_hash` | string ≤64 | Digest standing in for the tool input |
| `session_id` | string ≤80 | Agent session |
| `ts` | string | ISO-8601 UTC, microsecond precision |
| `device_id` | string | Enrolled device |
| `agent` | string | Framework (`claude-code`, `codex`, …) |
| `agent_name` | string | Agent instance |
| `subagent_id` | string \| null | Sub-agent, when one is in play |
| `subject` | object \| null | Human principal: `user_id`, `team_id`, `org_id` |
| `seq` | int | Monotonic per-device sequence, from 0 |
| `prev_hash` | hex(64) | Previous receipt's `hash`; genesis is 64 zeroes |
| `hash` | hex(64) | See [chain hash](#layer-1-the-chain-hash) |
| `signature` | base64 | Ed25519 over the [signing payload](#layer-2-the-signature) |
| `signing_alg` | string | `ed25519` |
| `signing_pubkey` | base64 | Raw 32-byte public key |
| `signing_key_id` | hex(16) | Key fingerprint: `sha256(raw_pubkey).hex()[:16]` |

## Two layers, and why you need both

Integrity comes from two independent mechanisms covering **different fields**.
A verifier that implements one and skips the other has a blind spot, so this is
the part to get right:

| Tampered field | Caught by chain hash | Caught by signature |
|---|---|---|
| `verdict`, `rule_id`, `tool_name`, `evidence_hash`, `session_id`, `event_id`, `severity` | ✅ | ❌ |
| `device_id`, `agent`, `agent_name`, `subagent_id`, `subject.*` | ❌ | ✅ |
| `ts` | ❌ | ✅ |

Flipping `verdict` from `blocked` to `allowed` leaves a *valid signature*,
because the signature binds the `hash`, not the verdict — only recomputing the
chain hash catches it. Re-pointing a receipt at another device leaves a *valid
chain hash* — only the signature catches that. **Check both.**

### Layer 1: the chain hash

Tamper-evidence and ordering. Keyless SHA-256 over seven normalized fields plus
the chain position:

```
hash = sha256(canonical_json({
    event_id, verdict, severity, rule_id, tool_name, evidence_hash, session_id,
    seq, prev_hash
}))
```

Normalization runs first, and mirrors exactly how a consumer is expected to
store the values, so the hash can be recomputed from stored columns rather than
from the original JSON:

- strings: non-empty only, truncated to the cap in the field table; anything
  else (including `""`) becomes `null`
- `verdict` / `severity`: lowercased, then dropped to `null` unless in the enum
- `seq` is an integer; `prev_hash` is the previous `hash`, or 64 zeroes at
  genesis

`ts` is deliberately **not** hashed. Clients emit microsecond precision while
stores commonly keep milliseconds, so no byte-stable round-trip exists. Ordering
integrity comes from `seq` + `prev_hash` instead, and the timestamp is covered by
the signature.

### Layer 2: the signature

Non-repudiation and identity binding. Ed25519 over a payload that ties the
immutable `hash` to the identity claims and the timestamp:

```json
{
  "hash": "<chain hash>",
  "ts": "<ISO timestamp>",
  "identity": {
    "device_id": "…", "agent": "…", "agent_name": "…", "subagent_id": null,
    "user_id": "…", "team_id": "…", "org_id": "…"
  }
}
```

Note the identity block is **flattened** — `subject.user_id` in the receipt is
`identity.user_id` in the payload. Absent values are present with value `null`;
the field set never varies.

### Canonical bytes

Both layers serialize identically. A verifier must byte-match this or every
check fails:

```
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

sorted keys, no whitespace, raw (non-escaped) Unicode, UTF-8. For the receipt
above the signed bytes are exactly:

```
{"hash":"b55d478cf0040f4247dd4845853e2356d7042e71142912221cbdcfbca8d631e5","identity":{"agent":"claude-code","agent_name":"release-bot","device_id":"dev-4a1e","org_id":"o-1","subagent_id":null,"team_id":"t-3","user_id":"u-77"},"ts":"2026-08-16T10:04:11.512834+00:00"}
```

## Verifying without Prismor

Standard library plus `cryptography`; no Prismor import:

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CAPS = {"event_id": 60, "rule_id": 80, "tool_name": 80,
        "evidence_hash": 64, "session_id": 80}
VERDICTS = {"blocked", "warned", "observed", "allowed"}
SEVERITIES = {"critical", "high", "medium", "low"}


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _str(value, cap):
    return value[:cap] if isinstance(value, str) and value else None


def _enum(value, allowed):
    v = _str(value, 16)
    return v.lower() if v and v.lower() in allowed else None


def chain_hash(r):
    payload = {k: _str(r.get(k), cap) for k, cap in CAPS.items()}
    payload["verdict"] = _enum(r.get("verdict"), VERDICTS)
    payload["severity"] = _enum(r.get("severity"), SEVERITIES)
    payload["seq"] = r["seq"]
    payload["prev_hash"] = r["prev_hash"]
    return hashlib.sha256(canonical(payload)).hexdigest()


def signing_payload(r):
    subject = r.get("subject") or {}
    return {
        "hash": r.get("hash"),
        "ts": r.get("ts"),
        "identity": {
            "device_id": r.get("device_id"), "agent": r.get("agent"),
            "agent_name": r.get("agent_name"), "subagent_id": r.get("subagent_id"),
            "user_id": subject.get("user_id"), "team_id": subject.get("team_id"),
            "org_id": subject.get("org_id"),
        },
    }


def verify(record, pinned_pubkey_b64=None):
    """(fields_intact, identity_authentic). Both must be True."""
    intact = chain_hash(record) == record.get("hash")
    key_b64 = pinned_pubkey_b64 or record.get("signing_pubkey")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64)).verify(
            base64.b64decode(record["signature"]), canonical(signing_payload(record)))
        authentic = True
    except Exception:
        authentic = False
    return intact, authentic
```

Verify a **stream** of receipts by additionally walking the chain: each
record's `prev_hash` must equal the previous record's `hash`, and `seq` must
increase by one. A gap is reported, not failed — a crashed process skips a
sequence number, whereas a deleted row breaks the linkage of its neighbours.
Distinguishing the two is the point of keeping both signals.

### Key pinning

Passing `pinned_pubkey_b64` is what gives the signature teeth. Verifying against
the receipt's own inline `signing_pubkey` proves internal consistency only — an
attacker who rewrites history can re-sign with a fresh key and every receipt
will still verify. Pin the device's public key out of band (it is registered at
enrollment) and compare `signing_key_id` to detect rotation.

## Failure posture

Signing requires the optional extra:

```bash
pip install "prismor[signing]"
```

Without it, receipts are hash-chained but carry no `signature`,
`signing_pubkey`, `signing_key_id`, or `signing_alg`. Signing never blocks or
breaks telemetry: on a missing dependency, an unreadable key, or any signing
error, the receipt is emitted unsigned rather than dropped. Consumers should
treat missing signature fields as "unsigned", which is a weaker claim than a
receipt makes — not as a verification failure.

The private key lives at `$PRISMOR_HOME/receipt_signing_key.pem`, mode `0600`,
and is generated on first use.

## Compatibility

Schema version `1`. Fields may be **added** in a minor revision; consumers must
ignore unknown fields. The canonical serialization, the seven hashed fields, and
the signing payload's shape are fixed for version `1` — changing any of them
would invalidate every previously issued receipt, so it would come with a new
version number.
