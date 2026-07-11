# Attestation Bundle

An attestation bundle is one signed JSON file that captures this machine's
governance posture at a moment in time. It bundles three things Prismor already
tracks:

- **Agent inventory**: every agent Prismor governs on this host (name,
  framework, enforce/observe mode, last seen)
- **Posture findings**: the full `prismor audit` sweep across hooks, policy,
  cloaking, permissions, feed signature, egress, network, and sandbox
- **Audit-trail anchor**: the signed head of the [signed audit
  trail](audit-trail.md), tying the bundle to the tamper-evident action log

The whole thing gets a SHA-256 content hash and an Ed25519 signature. Hand the
file to an auditor and they re-verify it with one command, on their own machine,
without touching yours.

Signing needs the optional `cryptography` extra:

```bash
pip install "prismor[signing]"
```

Without it the bundle is still assembled and hashed, just unsigned.

## What's in a bundle

| Field | Meaning |
|---|---|
| `schema` | `prismor.attestation.v1`, the version an auditor verifies against |
| `generated_at` | ISO-8601 UTC timestamp |
| `device_id`, `prismor_version` | which machine and which Prismor built it |
| `agents` | the governed-agent inventory |
| `audit_findings` | posture findings from `prismor audit` |
| `trail_checkpoint` | signed audit-trail head (`seq`, `hash`) |
| `content_hash` | SHA-256 over the JCS-canonical bundle body |
| `signature`, `signing_pubkey`, `signing_key_id` | the Ed25519 signature |

The body is canonicalized with [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
before signing. That matters for auditors: a verifier written in any language
can reproduce the exact bytes Prismor signed, so re-verification doesn't depend
on Python.

## Commands

```bash
prismor attest                        # print a fresh bundle to stdout
prismor attest --out evidence.json    # write it to a file
prismor attest verify evidence.json   # re-check hash + signature
prismor attest verify evidence.json --pubkey B64   # pin an out-of-band signer key
prismor attest verify evidence.json --json         # machine-readable report
```

Building a bundle is read-only. It runs the audit, reads the inventory, grabs
the current trail head, and signs the result. Nothing on disk changes except the
file you asked for with `--out`.

## Handing a bundle to an auditor

Say you're closing out a compliance review. You run:

```bash
prismor attest --out q3-evidence.json
```

and send `q3-evidence.json` to the auditor. On their machine, they run:

```bash
prismor attest verify q3-evidence.json
```

A clean bundle prints:

```
✓ attestation verified — schema prismor.attestation.v1, generated 2026-07-11T18:24:31
  signed by key id 18ea124a3b10e500
```

Edit a single field of the file and re-verify, and the content hash no longer
matches:

```
✗ attestation FAILED — schema prismor.attestation.v1, generated 2026-07-11T18:24:31
  ✗ content_hash mismatch — the bundle body was altered
```

Verify exits non-zero on any failure, so it drops straight into CI or a
compliance script.

### Pinning the signer

By default `verify` trusts the public key embedded in the bundle. That catches
tampering, but not a bundle forged wholesale by someone with a different key. An
auditor who has your device's public key out of band (from enrollment, or a
key you published) pins it:

```bash
prismor attest verify q3-evidence.json --pubkey <your-device-pubkey>
```

Now a bundle signed by any other key is rejected, even if its own hash and
signature are internally consistent.

## What this is not (yet)

The bundle proves *what Prismor was enforcing* and *which agents it saw*, signed
and re-verifiable. Mapping those controls onto named compliance frameworks
(NIST AI RMF, ISO/IEC 42001, EU AI Act, and the rest) is the next step, not
today's. That work is per-framework checklist packs plus a crosswalk from
Prismor rules to framework controls, rolled into this same bundle. For now,
read the bundle as signed evidence of runtime posture. It's not yet a
framework-by-framework compliance report.
