# DELTA v2.7.1 — Intent Create Helper

## Purpose

DELTA v2.7.1 adds an adoption and UX helper for Proof of Intent.

The goal is to stop users from writing intent JSON by hand. The helper creates a structured intent attestation draft bound to the full `delta-record.json` hash.

## Tool

```bash
python tools/delta_intent_create.py create \
  --record path/to/delta-record.json \
  --issue SEC-992 \
  --purpose "Approve replay verification for release candidate" \
  --out .delta/intent-tests/I-001/intent-attestation.json
```

The tool prints:

```text
DELTA_INTENT_CREATE_OK=True
DELTA_INTENT_RECORD_HASH=sha256:...
DELTA_INTENT_BODY_HASH=sha256:...
DELTA_INTENT_SIGNATURE_STATUS=unsigned_draft
```

## Verification

```bash
python tools/delta_intent_create.py verify \
  --attestation .delta/intent-tests/I-001/intent-attestation.json \
  --record path/to/delta-record.json
```

Expected result:

```text
DELTA_INTENT_VERIFY_OK=True
DELTA_INTENT_RECORD_BINDING_OK=True
```

## Security boundary

This release creates an unsigned intent attestation draft.

It does not replace the existing detached Proof of Intent signature and registry verification path.

DELTA v2.7.1 intent create:

- binds an intent attestation draft to a full `delta-record.json` hash;
- computes canonical JSON body hashes;
- adds self-check integrity fields;
- verifies draft integrity and optional record binding.

It does **not** prove:

- legal approval;
- real-world identity;
- signer authority;
- regulatory compliance;
- ticket truth;
- that an organization actually followed a governance process.

A production Proof of Intent still requires detached signing, public key registry verification, policy evaluation, and record binding verification.

## Why unsigned first?

The v2.7.1 goal is safe UX automation without touching private key handling.

Private keys must not be committed, pasted into chats, or included in generated artifacts.

Signing automation should be added only after key formats, registry behavior, and revocation/invalidation semantics are stable.

## Relationship to conformance levels

This helper supports adoption and operator workflow. It is not itself a conformance level.

A verifier MUST NOT accept an unsigned draft as a complete Proof of Intent.

A verifier MAY use this object as input to a later detached signature workflow.
