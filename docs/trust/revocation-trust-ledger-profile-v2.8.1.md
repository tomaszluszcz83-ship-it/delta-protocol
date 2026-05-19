# DELTA Protocol — Revocation Trust Ledger Profile (v2.8.1)

Status: Design-only profile

## 1. Purpose

This profile describes how future DELTA revocation events should integrate with the Trust Ledger layer.

A Trust Ledger SHOULD be able to carry revocation and invalidation events without rewriting prior entries.

## 2. Proposed trust event categories

Future trust ledger entries SHOULD support:

```text
trust_delegation_created
trust_delegation_revoked
public_key_revoked
artifact_invalidated
artifact_superseded
bundle_signature_revoked
policy_changed
```

## 3. Hash-chain continuity

Revocation events SHOULD be appended to the ledger as new entries.

The ledger hash chain MUST remain append-only.

A revocation event MUST reference the revoked subject by hash, not by mutable name.

## 4. Trust interpretation

A verifier SHOULD consider:

- artifact cryptographic validity,
- ledger chain validity,
- issuer authority under policy,
- revocation event effective time,
- supersession relationships,
- local relying-party policy.

## 5. Example trust-ledger revocation entry

```json
{
  "entry_type": "trust_ledger_entry",
  "profile": "delta_trust_revocation_v2_8_1",
  "event_type": "public_key_revoked",
  "subject": {
    "subject_type": "public_key_hash",
    "hash": "sha256:..."
  },
  "issuer": {
    "public_key_hash": "sha256:..."
  },
  "effective_time": {
    "not_trusted_after": "2026-05-19T00:00:00Z"
  },
  "previous_entry_hash": "sha256:..."
}
```

## 6. Security boundary

A revocation ledger entry does not prove the real-world reason for revocation.

It proves that a revocation statement was added to a hash-linked trust ledger.
