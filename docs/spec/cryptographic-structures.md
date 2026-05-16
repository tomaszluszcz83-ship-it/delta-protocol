# DELTA-0 Cryptographic Structures

Version: `v0.9.0-draft`  
Protocol family: `DELTA-0`  
Status: Formal draft for review

---

## 1. Encoding Conventions

Hash values:

```text
sha256:<64 lowercase hexadecimal characters>
```

Ed25519 public keys:

```text
ed25519:<base64url raw 32-byte public key without padding>
```

Ed25519 signatures:

```text
ed25519sig:<base64url raw 64-byte signature without padding>
```

Protocol version:

```text
DELTA-0
```

Genesis previous entry hash:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This constant MAY be referred to as:

```text
GENESIS_PREV_ENTRY_HASH
```

---

## 2. delta_claim

### 2.1 JSON Schema

```json
{
  "type": "delta_claim",
  "protocol_version": "DELTA-0",
  "created_at": "2026-05-16T00:00:00Z",
  "executor_pubkey": "ed25519:...",
  "before_hash": "sha256:...",
  "action": "declared action",
  "after_hash": "sha256:...",
  "evidence_hash": "sha256:..."
}
```

### 2.2 Field Requirements

| Field | Required | Type | Description |
|---|---:|---|---|
| `type` | yes | string | MUST equal `delta_claim`. |
| `protocol_version` | yes | string | MUST equal `DELTA-0`. |
| `created_at` | yes | string | Timestamp metadata in UTC ISO-8601 form. |
| `executor_pubkey` | yes | string | Ed25519 public key of the Executor. |
| `before_hash` | yes | string | Hash of the before-state object or bytes. |
| `action` | yes | string | Declared change/action. MUST NOT be empty. |
| `after_hash` | yes | string | Hash of the after-state object or bytes. |
| `evidence_hash` | yes | string | Hash of supporting evidence bytes or object. |

### 2.3 Prohibited Fields

A Claim MUST NOT contain:

```text
signature
claim_hash
claim_id
```

A hash-derived `claim_id` would create circular hashing and is non-compliant.

---

## 3. delta_signature

### 3.1 JSON Schema

```json
{
  "type": "delta_signature",
  "protocol_version": "DELTA-0",
  "role": "executor",
  "alg": "Ed25519",
  "target_type": "delta_claim",
  "target_hash": "sha256:...",
  "public_key": "ed25519:...",
  "signature": "ed25519sig:...",
  "signed_at": "2026-05-16T00:00:00Z"
}
```

### 3.2 Field Requirements

| Field | Required | Type | Description |
|---|---:|---|---|
| `type` | yes | string | MUST equal `delta_signature`. |
| `protocol_version` | yes | string | MUST equal `DELTA-0`. |
| `role` | yes | string | Signer role. |
| `alg` | yes | string | MUST equal `Ed25519`. |
| `target_type` | yes | string | Type of signed payload. |
| `target_hash` | yes | string | SHA-256 hash of canonical target payload. |
| `public_key` | yes | string | Ed25519 public key used to verify signature. |
| `signature` | yes | string | Ed25519 signature bytes over canonical target payload. |
| `signed_at` | yes | string | Timestamp metadata in UTC ISO-8601 form. |

### 3.3 Allowed Roles

The following roles are defined in DELTA-0:

```text
executor
verifier
checkpoint_signer
```

### 3.4 Target Type Mapping

| Role | target_type | Signed payload |
|---|---|---|
| `executor` | `delta_claim` | `claim.json` |
| `verifier` | `delta_attestation` | `attestation.json` |
| `checkpoint_signer` | `delta_signed_checkpoint` | `checkpoint.json` |

---

## 4. Executor Signature

The Executor signature envelope MUST satisfy:

```text
role = "executor"
target_type = "delta_claim"
target_hash = sha256(canonical_json_bytes(claim.json))
public_key = claim.executor_pubkey
signature = Ed25519.sign(canonical_json_bytes(claim.json))
```

Expected file name:

```text
executor_signature.json
```

---

## 5. delta_attestation

### 5.1 JSON Schema

```json
{
  "type": "delta_attestation",
  "protocol_version": "DELTA-0",
  "verifier_pubkey": "ed25519:...",
  "target_claim_hash": "sha256:...",
  "target_executor_sig_hash": "sha256:...",
  "verification_policy_hash": "sha256:...",
  "evidence_hash": "sha256:...",
  "publication_mode": "ledger_required",
  "intended_ledger_id": "delta-ledger:local",
  "result": "VERIFIED",
  "verified_at": "2026-05-16T00:00:00Z"
}
```

### 5.2 Field Requirements

| Field | Required | Type | Description |
|---|---:|---|---|
| `type` | yes | string | MUST equal `delta_attestation`. |
| `protocol_version` | yes | string | MUST equal `DELTA-0`. |
| `verifier_pubkey` | yes | string | Ed25519 public key of the Verifier. |
| `target_claim_hash` | yes | string | Hash of `claim.json`. |
| `target_executor_sig_hash` | yes | string | Hash of `executor_signature.json`. |
| `verification_policy_hash` | yes | string | Hash of the verification policy. |
| `evidence_hash` | yes | string | Evidence hash copied or derived from the Claim. |
| `publication_mode` | yes | string | For DELTA-0 Write Mode, MUST equal `ledger_required`. |
| `intended_ledger_id` | yes | string | Ledger identifier intended for publication. |
| `result` | yes | string | Verification result, e.g. `VERIFIED`. |
| `verified_at` | yes | string | Timestamp metadata in UTC ISO-8601 form. |

### 5.3 Precondition

A Verifier MUST verify the Executor signature before creating an Attestation.

If the Executor signature fails, the Verifier MUST NOT create an Attestation.

---

## 6. Verifier Signature

The Verifier signature envelope MUST satisfy:

```text
role = "verifier"
target_type = "delta_attestation"
target_hash = sha256(canonical_json_bytes(attestation.json))
public_key = attestation.verifier_pubkey
signature = Ed25519.sign(canonical_json_bytes(attestation.json))
```

Expected file name:

```text
verifier_signature.json
```

---

## 7. delta_ledger_entry

### 7.1 JSON Schema

```json
{
  "type": "delta_ledger_entry",
  "protocol_version": "DELTA-0",
  "ledger_id": "delta-ledger:local",
  "seq": 0,
  "prev_entry_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "claim_hash": "sha256:...",
  "executor_sig_hash": "sha256:...",
  "attestation_hash": "sha256:...",
  "verifier_sig_hash": "sha256:...",
  "included_at": "2026-05-16T00:00:00Z"
}
```

### 7.2 Field Requirements

| Field | Required | Type | Description |
|---|---:|---|---|
| `type` | yes | string | MUST equal `delta_ledger_entry`. |
| `protocol_version` | yes | string | MUST equal `DELTA-0`. |
| `ledger_id` | yes | string | Ledger identifier. |
| `seq` | yes | integer | Non-negative sequence number. |
| `prev_entry_hash` | yes | string | Previous Ledger Entry hash. |
| `claim_hash` | yes | string | Hash of `claim.json`. |
| `executor_sig_hash` | yes | string | Hash of `executor_signature.json`. |
| `attestation_hash` | yes | string | Hash of `attestation.json`. |
| `verifier_sig_hash` | yes | string | Hash of `verifier_signature.json`. |
| `included_at` | yes | string | Timestamp metadata for ledger inclusion. |

### 7.3 Genesis Entry

For the first entry in a ledger:

```text
prev_entry_hash = GENESIS_PREV_ENTRY_HASH
```

where:

```text
GENESIS_PREV_ENTRY_HASH = sha256:0000000000000000000000000000000000000000000000000000000000000000
```

### 7.4 No Ledger Signature

A `delta_ledger_entry` is not signed in DELTA-0.

It is canonicalized and hashed:

```text
ledger_entry_hash = sha256(canonical_json_bytes(ledger_entry.json))
```

---

## 8. delta_signed_checkpoint

### 8.1 JSON Schema

```json
{
  "type": "delta_signed_checkpoint",
  "protocol_version": "DELTA-0",
  "checkpoint_seq": 0,
  "head_entry_hash": "sha256:...",
  "entry_count": 1,
  "published_at": "2026-05-16T00:00:00Z"
}
```

### 8.2 Field Requirements

| Field | Required | Type | Description |
|---|---:|---|---|
| `type` | yes | string | MUST equal `delta_signed_checkpoint`. |
| `protocol_version` | yes | string | MUST equal `DELTA-0`. |
| `checkpoint_seq` | yes | integer | Non-negative checkpoint sequence number. |
| `head_entry_hash` | yes | string | Hash of current ledger head entry. |
| `entry_count` | yes | integer | Number of entries covered by checkpoint. MUST be >= 1. |
| `published_at` | yes | string | Timestamp metadata for checkpoint publication. |

---

## 9. Checkpoint Signature

The Checkpoint signature envelope MUST satisfy:

```text
role = "checkpoint_signer"
target_type = "delta_signed_checkpoint"
target_hash = sha256(canonical_json_bytes(checkpoint.json))
signature = Ed25519.sign(canonical_json_bytes(checkpoint.json))
```

Expected file name:

```text
checkpoint_signature.json
```

---

## 10. File Set for a Complete DELTA-0 Proof

A complete minimal proof set contains:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

Optional supporting objects include:

```text
before_state.json
after_state.json
evidence_manifest.json
verification_policy.json
public_keys.json
hashes.json
hashes.txt
chain_proof.json
```

---

## 11. Verification Relations

A verifier MUST check the following relations:

```text
sha256(canonical(claim.json)) == executor_signature.target_hash
executor_signature.public_key == claim.executor_pubkey
verify_ed25519(executor_signature, canonical(claim.json))

sha256(canonical(claim.json)) == attestation.target_claim_hash
sha256(canonical(executor_signature.json)) == attestation.target_executor_sig_hash
claim.evidence_hash == attestation.evidence_hash

sha256(canonical(attestation.json)) == verifier_signature.target_hash
verifier_signature.public_key == attestation.verifier_pubkey
verify_ed25519(verifier_signature, canonical(attestation.json))

ledger_entry.claim_hash == sha256(canonical(claim.json))
ledger_entry.executor_sig_hash == sha256(canonical(executor_signature.json))
ledger_entry.attestation_hash == sha256(canonical(attestation.json))
ledger_entry.verifier_sig_hash == sha256(canonical(verifier_signature.json))

checkpoint.head_entry_hash == sha256(canonical(ledger_entry.json))
sha256(canonical(checkpoint.json)) == checkpoint_signature.target_hash
verify_ed25519(checkpoint_signature, canonical(checkpoint.json))
```

---

## 12. Non-Compliant Legacy or Experimental Fields

The following fields are not part of the frozen DELTA-0 structures:

```text
claim_id
recorded_at
checkpointed_at
embedded signature fields inside payload objects
```

Implementations MUST NOT emit these fields in core DELTA-0 proof objects.

A verifier MAY reject objects containing these fields.
