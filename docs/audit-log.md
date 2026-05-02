# Audit Log

Warden writes a tamper-evident, optionally signed record for every decision
(allow / observe / block) it makes. The log is what governance and audit
teams ask for when they want to know "what did the agent attempt, what was
blocked, and why — and can you prove it?"

## What gets recorded

One NDJSON record per decision, appended to
`.prismor-warden/audit/<session_id>.ndjson`:

```json
{
  "v": 1,
  "alg": "sha256",
  "seq": 0,
  "ts": "2026-05-03T19:03:24.139Z",
  "session_id": "...",
  "agent": "claude",
  "mode": "enforce",
  "workspace_id": "5a25e2b3711fcbf2",
  "event": {
    "type": "shell",
    "agent_event": "PreToolUse",
    "command_hash": "1de700c2...",
    "command_len": 6
  },
  "decision": "allow",
  "findings": [],
  "policy_hash": "a0066d3f...",
  "feed_hash":   "fb010dd8...",
  "agent_version": "warden 1.3.0",
  "prev_hash": "GENESIS",
  "record_hash": "9286523ecb239dc5...",
  "sig": {
    "alg": "ed25519",
    "key_id": "0d835451d9e089ff",
    "value": "<base64 signature>"
  }
}
```

- **`prev_hash` / `record_hash`** — every record links to its predecessor.
  Modifying any field changes `record_hash`; modifying `record_hash` breaks
  `prev_hash` on the next record. `warden audit-log verify` walks the chain
  and reports both kinds of break.
- **`policy_hash` / `feed_hash`** — fingerprint of the policy and threat feed
  that were in effect when the decision was made. The first time we see a
  hash, we copy the source files into `audit/policies/<hash>/` and
  `audit/feed/<hash>.json`, so replay has the exact rule set the decision was
  derived from.
- **`sig`** — present when an Ed25519 signing key is configured (see below).
  Signs the canonical bytes of the record (excluding `record_hash` and `sig`
  itself).

## Privacy: hashed evidence by default

Sensitive event fields — `command`, `path`, `url`, `prompt`, `content`,
`response`, and the `evidence` field of every finding — are stored as
SHA-256 digests plus length only. The raw text is **not** written to the
audit log. This makes the log safe to forward to a SIEM without leaking
secrets.

To retain raw text (for orgs that need full text in their audit trail), set
`audit.include_raw: true` under `settings` in `.prismor-warden/policy.yaml`:

```yaml
settings:
  audit:
    include_raw: true
```

## Enabling signatures

Hash chaining is on by default — no setup. To turn on Ed25519 signing:

```bash
warden audit-log keygen
```

This writes:

- `~/.prismor/keys/audit-signer.key` (mode 0600, parent dir 0700)
- `~/.prismor/keys/audit-signer.pub` (the public key to distribute)

From the next decision onward, every record carries a signature. The public
key fingerprint (`key_id`, first 16 hex chars of SHA-256 over the raw key
bytes) is written to each record so a verifier with multiple pubkeys can
pick the right one.

To use a centrally-managed key (for example a key issued from a KMS or
mounted from a secret manager in CI), set:

```bash
export WARDEN_AUDIT_SIGNING_KEY=/path/to/private.pem
export WARDEN_AUDIT_SIGNING_PUBKEY=/path/to/public.pem
```

If neither the env var nor the default path is set, records are still
hash-chained but unsigned.

## CLI

```bash
warden audit-log keygen [--out-dir DIR] [--force]
warden audit-log pubkey [--key PATH]                # print PEM + key_id
warden audit-log list                               # all sessions in workspace
warden audit-log show <session_id>                  # human-readable trace
warden audit-log verify [--session-id ID] [--json]  # exit 2 on tamper
warden audit-log seal <session_id>                  # write signed manifest
warden audit-log register-pubkey <pubkey.pem>       # add a verifier key
warden audit-log replay <session_id> [--json]       # check pinned policy presence
```

`verify` is the workhorse: for each record it recomputes the hash from
canonical bytes, checks `prev_hash` against the previous record, and (if
present) verifies the Ed25519 signature against the registered public key.
Any failure produces a structured report and a non-zero exit code.

## Verifying from outside the workspace

Any third party with the public key can verify the chain themselves:

```bash
# Copy the audit dir + the public key off the host
scp -r host:.prismor-warden/audit ./audit-dump/
scp host:~/.prismor/keys/audit-signer.pub ./

# Register the pubkey in the dump and verify
warden --workspace ./audit-dump audit-log register-pubkey ./audit-signer.pub
warden --workspace ./audit-dump audit-log verify
```

This is the answer to the question "are you generating a signed, replayable
log of what gets blocked and why?" — yes, and a verifier doesn't need to
trust the host to confirm it.

## Sealing on session close

`warden audit-log seal <session_id>` writes a manifest at
`.prismor-warden/audit/<session_id>.seal` containing the record count, the
head record hash, and (if signing is on) a signature over the manifest. The
seal is the single artifact a downstream system needs to keep — anyone
holding the seal and the audit file can later prove that no records were
appended, removed, or modified after the seal was written.
