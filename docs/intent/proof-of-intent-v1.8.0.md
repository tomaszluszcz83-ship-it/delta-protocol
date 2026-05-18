# DELTA Protocol v1.8.0 — Proof of Intent MVP

## Purpose

Proof of Intent adds a detached, cryptographic approval layer to DELTA Proof of Change.

Main statement:

> DELTA can cryptographically bind a signed human/system intent attestation to a specific signed proof-of-change sensor record.

This is not a legal-consent system, ticket verifier, identity provider, SaaS approval workflow, token, cryptocurrency, or blockchain application. It is a protocol layer for binding a separately signed approval intent to a concrete DELTA sensor record by hash.

## Security boundary

Proof of Intent proves only that:

1. a specific intent attestation existed,
2. the attestation canonical hash matches the detached signature target,
3. the detached Ed25519 signature verifies under the published intent public key,
4. the attestation is bound to a specific DELTA sensor record through `target.record_hash`,
5. the signing public key is present and active in the intent key registry, when a registry is supplied.

Proof of Intent does not prove:

- legal consent,
- true real-world identity,
- ticket truth,
- MFA truth,
- that the approver read or understood the change,
- that a business process was actually followed,
- that the underlying sensor record itself is truthful beyond DELTA's existing sensor/replay evidence model.

## Key separation

DELTA separates signing responsibilities:

| Key | Purpose | Location |
| --- | --- | --- |
| Executor / Sensor Key | signs sensor observations and measurement results | CI/sensor environment |
| Intent Key | signs approval/intent attestation | local approver machine, HSM, YubiKey, future hardware wallet |
| Verifier Key | future independent verifier attestations | future verifier/auditor environment |

The intent private key must never be committed, uploaded to CI, pasted into chat, or included in generated artifacts.

Recommended local path for the MVP:

```text
C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_INTENT_PRIVATE_KEY.txt
```

## Files

For one intent test such as `I-001`, the MVP stores:

```text
.delta/intent-tests/I-001/delta-record.intent.json
.delta/intent-tests/I-001/delta-record.intent.sig.json
.delta/intent-public-key.json
.delta/intent_registry.json
```

Only public/signed intent artifacts may be committed. The private intent key must remain outside the repository.

## Attestation format

The intent attestation is detached from the sensor record:

```json
{
  "type": "delta_intent_attestation",
  "version": "1.0.0",
  "protocol": "DELTA-0",
  "target": {
    "record_hash": "sha256:...",
    "record_type": "delta_sensor_record",
    "sensor_method": "local-file-audit-v1",
    "commit_after": "..."
  },
  "approval": {
    "ticket_id": "DELTA-POI-001",
    "approver": "local-approver",
    "role": "tech_lead",
    "reason": "Approve Proof of Intent MVP test"
  },
  "policy": {
    "requires_mfa": true,
    "valid_from": null,
    "valid_until": null,
    "time_window": null
  },
  "created_at": "2026-05-18T12:00:00Z"
}
```

The canonical hash of this JSON is the signature target.

## Detached signature format

```json
{
  "type": "delta_intent_signature",
  "version": "1.0.0",
  "protocol": "DELTA-0",
  "alg": "Ed25519",
  "target_hash": "sha256:<hash-of-canonical-attestation>",
  "public_key": "ed25519:<base64-raw-public-key>",
  "public_key_hash": "sha256:<hash-of-raw-public-key>",
  "signature": "ed25519sig:<base64-raw-signature>",
  "key_hint": "...",
  "created_at": "2026-05-18T12:00:00Z"
}
```

## Record binding

The binding is one-way and detached:

1. Load the full `delta-record.json`.
2. Canonicalize the record as JSON with sorted keys and compact separators.
3. Compute `sha256(canonical_json(record))`.
4. Store that value as `attestation.target.record_hash`.
5. Sign the canonical intent attestation, not the sensor record directly.

This means the intent can be created after the sensor record exists, without modifying the sensor record.

## Forward-compatible sensor policy fields

Future sensor records may include:

```json
{
  "intent_required": true,
  "intent_deadline": "2026-05-19T00:00:00Z"
}
```

The v1.8.0 verifier is forward-compatible with these fields:

- if the fields are absent, detached MVP mode is accepted;
- if `intent_required` is present, it must be `true`;
- if `intent_deadline` is present, the intent `created_at` must not be after the deadline.

The MVP deliberately does not modify existing v1.4-v1.7 sensor records.

## Intent key registry

The public registry is a repository-safe JSON file:

```json
{
  "type": "delta_intent_key_registry",
  "version": "1.0.0",
  "protocol": "DELTA-0",
  "created_at": "2026-05-18T12:00:00Z",
  "updated_at": "2026-05-18T12:00:00Z",
  "keys": [
    {
      "id": "intent-key-local-v1",
      "public_key": "ed25519:...",
      "public_key_hash": "sha256:...",
      "owner": "local-approver",
      "role": "tech_lead",
      "active_from": "2026-05-18T12:00:00Z",
      "revoked_at": null
    }
  ]
}
```

Verification checks whether the signing public key is present and active at the intent `created_at` timestamp.

## Offline approval flow

1. CI/sensor generates a signed DELTA sensor record.
2. The approver obtains the record file outside CI.
3. The approver runs `delta_intent.py approve` locally using the intent private key.
4. The public intent attestation and signature are committed or stored in an audit package.
5. `delta_intent.py verify` checks signature, registry, time policy, and record binding.
6. Future `delta_replay.py` can call the same verification logic to produce `INTENT_VERIFIED`, `INTENT_MISSING`, or `INTENT_INVALID`.

## Future higher layers

The MVP intentionally leaves the following for later versions:

- Threshold Intent: k-of-n approval.
- Intent revocation: signed cancellation of a previous intent.
- Standing/recurring approvals: one intent covering a bounded set of records.
- Hardware-backed intent: YubiKey/HSM/Ledger/Trezor.
- DID/Verifiable Credentials identity binding.
- Zero-Knowledge Proof of Intent for private approval proofs.
- API-based approval service.
- Jira/GitHub Issues verification.
- Blockchain/OpenTimestamps anchoring.
- Encrypted evidence disclosure.

The current design is intentionally compatible with these layers because it uses detached attestations, explicit key roles, public registries, canonical hashes, and separate signatures.
