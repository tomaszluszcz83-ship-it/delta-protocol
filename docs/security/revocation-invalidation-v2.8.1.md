# DELTA Protocol — Revocation and Invalidation Design (v2.8.1)

Status: Design-only / no new proof functionality  
Scope: key compromise, invalidation records, signed bundle revocation, trust-ledger integration

## 1. Purpose

v2.8.1 defines how DELTA should represent revocation and invalidation events before implementing them in code.

This is a design milestone. It does not change verifier behavior.

The goal is to answer:

- What happens when a signing key is compromised?
- How can a bundle signature be invalidated?
- How can a record, intent, audit package, publication proof, trust entry, or wallet proof be marked as superseded or invalid?
- How should auditors reason about revocation without rewriting history?

## 2. Design principles

DELTA MUST NOT delete or rewrite historical proof artifacts.

Revocation MUST be represented as a new signed event, not as mutation of the old record.

Invalidation MUST preserve evidence of what was invalidated, when, by whom, and why.

A verifier MUST distinguish:

- cryptographic validity,
- trust validity,
- revocation status,
- business/legal acceptance.

A cryptographic signature can remain mathematically valid even if the key is later revoked.

## 3. Core concepts

### 3.1 Revocation

Revocation applies to keys, signer identities, bundle signing authority, trust delegations, or proof profiles.

Example:

```text
Key K signed bundle B on date T1.
Key K was compromised on date T2.
A revocation event R says K must not be trusted after T2.
```

The old signature may still verify cryptographically, but trust policy may reject it.

### 3.2 Invalidation

Invalidation applies to a specific artifact or artifact hash.

Example:

```text
Bundle hash H is invalidated because it accidentally contained stale evidence.
Record hash R is superseded by corrected record hash R2.
Intent I is withdrawn by an authorized signer.
```

### 3.3 Supersession

Supersession does not necessarily mean fraud or compromise.

It means an artifact has been replaced by a later artifact.

## 4. Proposed event types

DELTA revocation/invalidation events SHOULD support the following `event_type` values:

| Event type | Meaning |
| --- | --- |
| `key_revoked` | A public key or public key hash must no longer be trusted under a policy. |
| `bundle_signature_revoked` | A signed bundle signature is explicitly revoked. |
| `artifact_invalidated` | A specific artifact hash is marked invalid. |
| `artifact_superseded` | A specific artifact hash is replaced by another artifact hash. |
| `trust_delegation_revoked` | A trust relationship is revoked. |
| `intent_withdrawn` | An intent attestation or intent signature is withdrawn. |
| `policy_changed` | A verifier policy changed and affects trust interpretation. |

## 5. Proposed revocation event shape

Draft object shape:

```json
{
  "type": "delta_revocation_event",
  "revocation_profile": "delta_revocation_v2_8_1",
  "event_id": "R-...",
  "event_type": "key_revoked",
  "created_at": "2026-05-19T00:00:00Z",
  "subject": {
    "subject_type": "public_key_hash",
    "hash_alg": "sha256",
    "hash": "sha256:..."
  },
  "reason": {
    "reason_code": "key_compromise",
    "description": "Operator reported private key compromise."
  },
  "effective_time": {
    "not_trusted_after": "2026-05-19T00:00:00Z",
    "interpretation": "policy_time_not_absolute_truth"
  },
  "issuer": {
    "issuer_label": "delta-security-admin",
    "issuer_public_key": "ed25519:...",
    "issuer_public_key_hash": "sha256:..."
  },
  "links": {
    "supersedes": [],
    "related_artifacts": [
      "sha256:..."
    ]
  },
  "security_boundary": {
    "does_not_delete_history": true,
    "does_not_prove_legal_authority": true,
    "does_not_prove_real_world_identity": true
  }
}
```

A later implementation SHOULD sign the canonical JSON of this body.

## 6. Verification model

A DELTA verifier SHOULD eventually return separate statuses:

```text
CRYPTO_SIGNATURE_VALID=True
ARTIFACT_HASH_VALID=True
REVOCATION_STATUS=not_revoked | revoked | superseded | unknown
TRUST_STATUS=trusted | not_trusted | unknown | policy_not_configured
ACCEPTANCE_STATUS=accepted | rejected | manual_review
```

Important: `CRYPTO_SIGNATURE_VALID=True` does not imply `TRUST_STATUS=trusted`.

## 7. Bundle signature revocation

For v2.8.0 signed bundles, a revocation event can target:

- signer public key hash,
- exact bundle hash,
- exact signature body hash,
- signature file hash,
- signed bundle profile.

Recommended subject examples:

```json
{
  "subject_type": "bundle_hash",
  "hash": "sha256:..."
}
```

or:

```json
{
  "subject_type": "public_key_hash",
  "hash": "sha256:..."
}
```

## 8. Incident-response relationship

Revocation design MUST connect to incident response:

1. Detect compromise or invalidity.
2. Freeze affected keys.
3. Publish revocation event.
4. Publish replacement key or artifact if needed.
5. Update trust registry or trust ledger.
6. Notify relying parties.
7. Keep old artifacts for audit history.
8. Verify that old artifacts now produce `REVOCATION_STATUS=revoked` under policy.

## 9. Security boundaries

Revocation does not prove:

- legal truth,
- real-world truth,
- real-world identity,
- signer legal authority,
- that the compromise truly occurred,
- that all relying parties saw the revocation,
- that old data should be deleted.

Revocation is a cryptographically linked trust/policy event, not an eraser.

## 10. Future implementation milestones

Possible future milestones:

- `tools/delta_revocation.py create`
- `tools/delta_revocation.py verify`
- revocation registry JSON schema
- trust-ledger revocation event integration
- signed bundle revocation checks
- key rotation helper
- public revocation publication proof
- conformance tests for revoked/superseded artifacts
