# DELTA-0 v0.5.2 Core Structures

DELTA is an open, zero-token cryptographic protocol for proving digital change.

This document defines the minimum executable data model for the DELTA-0 Genesis Release.

DELTA-0 uses a four-layer model:

```text
Delta Claim → Delta Attestation → Ledger Entry → Signed Checkpoint
```

DELTA-0 uses a linear hash-chain plus signed checkpoints.

DELTA-0 does not use tokens, cryptocurrencies, gas fees, NFTs, wallets, or a blockchain as a required base layer.

---

## 1. Cryptographic Rules

DELTA-0 uses:

- JSON Canonicalization Scheme according to RFC 8785 / JCS
- SHA-256 for content hashes
- Ed25519 for digital signatures
- lowercase hexadecimal encoding for SHA-256 digests
- UTF-8 encoded canonical JSON bytes as the signed message

Hash format:

```text
sha256:<64 lowercase hex chars>
```

Example:

```text
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Public key format:

```text
ed25519:<base64url-public-key>
```

Signature format:

```text
ed25519sig:<base64url-signature>
```

DELTA-0 signs canonical JSON bytes directly.

Rule:

```text
Hash identifies the object.
Signature signs the canonical object.
```

The protocol MUST NOT mix two different signing modes for the same object.

---

## 2. Object Separation Rule

Signatures MUST NOT be embedded inside the canonical object they sign.

Each signed object has three separate parts:

```text
1. canonical object body
2. object hash
3. detached signature envelope
```

This prevents circular hashing and signature ambiguity.

For example, a Delta Claim is signed separately:

```text
delta_claim
claim_hash
executor_signature_envelope
```

The signature envelope is not part of the object being signed.

---

## 3. Delta Claim

A Delta Claim is created by the Executor.

The Claim describes what changed.

It answers:

```text
What existed before?
What action was performed?
What exists after?
What evidence supports the change?
Who claims execution?
```

Example Delta Claim:

```json
{
  "type": "delta_claim",
  "protocol_version": "DELTA-0",
  "claim_type": "genesis_release",
  "executor_pubkey": "ed25519:...",
  "before_hash": "sha256:...",
  "action": "DELTA-0 protocol genesis release created",
  "after_hash": "sha256:...",
  "evidence_hash": "sha256:...",
  "created_at": "2026-05-16T00:00:00Z"
}
```

Hash calculation:

```text
claim_hash = sha256(JCS(delta_claim))
```

Signature calculation:

```text
executor_sig = Ed25519_sign(JCS(delta_claim))
```

The Executor signature proves that the holder of the Executor private key signed this exact canonical Claim.

Status after this step:

```text
CLAIM_SIGNED
```

Important:

```text
CLAIM_SIGNED does not mean the change has been verified.
CLAIM_SIGNED only means that the Executor signed the Claim.
```

---

## 4. Executor Signature Envelope

The Executor signature is stored outside the Delta Claim.

Example:

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

Hash calculation:

```text
executor_sig_hash = sha256(JCS(executor_signature_envelope))
```

The `executor_sig_hash` may be referenced by later objects.

---

## 5. Delta Attestation

A Delta Attestation is created by the Verifier.

The Verifier does not sign the Executor’s Claim as if the Verifier performed the action.

Instead, the Verifier signs a separate verification statement.

The Attestation answers:

```text
Which Claim was checked?
Which Executor signature was checked?
Which evidence was checked?
Which verification policy was used?
What was the verification result?
Who verified it?
```

Example Delta Attestation:

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
  "intended_ledger_id": "delta-ledger:genesis-local",
  "result": "VERIFIED",
  "verified_at": "2026-05-16T00:00:00Z"
}
```

Hash calculation:

```text
attestation_hash = sha256(JCS(delta_attestation))
```

Signature calculation:

```text
verifier_sig = Ed25519_sign(JCS(delta_attestation))
```

Status after this step:

```text
ATTESTATION_SIGNED_UNPUBLISHED
```

Important:

```text
A signed Attestation proves that the Verifier key signed a verification statement.
It does not automatically prove that the Attestation was included in a public ledger.
```

---

## 6. Verification Result Values

Allowed Attestation result values:

```text
VERIFIED
REJECTED
INCONCLUSIVE
DISPUTED
REVOKED
```

Formal meaning of `VERIFIED`:

```text
The evidence satisfied the declared verification policy.
```

Formal meaning of `REJECTED`:

```text
The evidence did not satisfy the declared verification policy.
```

Important:

```text
REJECTED does not mean fraud.
REJECTED does not mean deception.
REJECTED does not mean bad faith.
REJECTED only means that the evidence did not satisfy the declared verification policy.
```

This distinction is required to keep the protocol legally and logically precise.

---

## 7. Publication Mode

The field `publication_mode` defines whether an Attestation is expected to be published in a ledger.

Allowed value for DELTA-0:

```text
ledger_required
```

If:

```text
publication_mode = ledger_required
```

then a signed Attestation is not enough for public `DELTA_VERIFIED` status.

The Attestation must also be included in a Ledger Entry and covered by a Signed Checkpoint.

If an Attestation is signed but not published, the status is:

```text
ATTESTATION_SIGNED_UNPUBLISHED
```

It must not be displayed as:

```text
DELTA_VERIFIED
```

---

## 8. Verifier Signature Envelope

The Verifier signature is stored outside the Delta Attestation.

Example:

```json
{
  "type": "delta_signature",
  "protocol_version": "DELTA-0",
  "role": "verifier",
  "alg": "Ed25519",
  "target_type": "delta_attestation",
  "target_hash": "sha256:...",
  "public_key": "ed25519:...",
  "signature": "ed25519sig:...",
  "signed_at": "2026-05-16T00:00:00Z"
}
```

Hash calculation:

```text
verifier_sig_hash = sha256(JCS(verifier_signature_envelope))
```

The `verifier_sig_hash` is referenced by the Ledger Entry.

---

## 9. Genesis Previous Entry Hash

The first Ledger Entry has no previous entry.

DELTA-0 does not use `null` for the first `prev_entry_hash`.

The first Ledger Entry MUST use this fixed value:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This value is called:

```text
GENESIS_PREV_ENTRY_HASH
```

For the first Ledger Entry:

```json
{
  "seq": 1,
  "prev_entry_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
```

This removes ambiguity across implementations.

---

## 10. Ledger Entry

A Ledger Entry is created by the verifier node.

It places a verified Attestation into a local tamper-evident ledger.

DELTA-0 uses a linear hash-chain.

A Ledger Entry MUST bind both the signed objects and their detached signature envelopes by hash.

This means the Ledger Entry contains:

```text
claim_hash
executor_sig_hash
attestation_hash
verifier_sig_hash
```

The signatures remain detached, but their hashes are part of the Ledger Entry.

This ensures the ledger chain protects the presence of the exact signatures, not only the unsigned object bodies.

Example genesis Ledger Entry:

```json
{
  "type": "delta_ledger_entry",
  "protocol_version": "DELTA-0",
  "ledger_id": "delta-ledger:genesis-local",
  "seq": 1,
  "prev_entry_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "claim_hash": "sha256:...",
  "executor_sig_hash": "sha256:...",
  "attestation_hash": "sha256:...",
  "verifier_sig_hash": "sha256:...",
  "included_at": "2026-05-16T00:00:00Z"
}
```

For entries after genesis:

```json
{
  "prev_entry_hash": "sha256:<previous-entry-hash>"
}
```

Hash calculation:

```text
entry_hash = sha256(JCS(delta_ledger_entry))
```

Status after this step:

```text
LEDGER_INCLUDED
```

Important:

```text
LEDGER_INCLUDED means that the Attestation was placed in a local ledger.
It does not yet mean that the ledger head was publicly checkpointed.
```

---

## 11. Linear Hash-Chain Rule

Each Ledger Entry after the first entry must contain the hash of the previous Ledger Entry.

Example:

```text
Entry 1 → entry_hash_1
Entry 2 → prev_entry_hash = entry_hash_1
Entry 3 → prev_entry_hash = entry_hash_2
Entry 4 → prev_entry_hash = entry_hash_3
```

If an old entry is changed, its hash changes.

That breaks every later `prev_entry_hash`.

This makes the ledger tamper-evident.

Important limitation:

```text
A linear hash-chain detects manipulation inside a shown chain.
It does not by itself prevent a malicious Verifier from maintaining two different chains.
```

This is why DELTA-0 requires Signed Checkpoints for public status.

---

## 12. Signed Checkpoint

A Signed Checkpoint is created by the Verifier.

It publicly signs the current head of the ledger.

DELTA-0 uses `head_entry_hash`, not `root_hash`.

The term `root_hash` is reserved for possible future Merkle Tree versions.

Example Signed Checkpoint:

```json
{
  "type": "delta_signed_checkpoint",
  "protocol_version": "DELTA-0",
  "ledger_id": "delta-ledger:genesis-local",
  "checkpoint_seq": 1,
  "entry_count": 1,
  "head_entry_hash": "sha256:...",
  "published_at": "2026-05-16T00:00:00Z",
  "verifier_pubkey": "ed25519:..."
}
```

Signature calculation:

```text
checkpoint_sig = Ed25519_sign(JCS(delta_signed_checkpoint))
```

Status after this step:

```text
DELTA_VERIFIED
```

But only if the chain proof is available.

---

## 13. Checkpoint Signature Envelope

The Checkpoint signature is stored outside the Signed Checkpoint.

Example:

```json
{
  "type": "delta_signature",
  "protocol_version": "DELTA-0",
  "role": "checkpoint_signer",
  "alg": "Ed25519",
  "target_type": "delta_signed_checkpoint",
  "target_hash": "sha256:...",
  "public_key": "ed25519:...",
  "signature": "ed25519sig:...",
  "signed_at": "2026-05-16T00:00:00Z"
}
```

Hash calculation:

```text
checkpoint_sig_hash = sha256(JCS(checkpoint_signature_envelope))
```

---

## 14. Chain Proof

A Signed Checkpoint alone is not enough.

To verify a Ledger Entry against a checkpoint, the verifier must have a chain proof.

For DELTA-0, a chain proof is:

```text
the target Ledger Entry plus all later Ledger Entries required to reach the checkpoint head_entry_hash
```

For a small local ledger, the full ledger may be used as the chain proof.

The verifier checks:

```text
1. hash(target Ledger Entry)
2. next entry contains prev_entry_hash equal to previous hash
3. continue until head_entry_hash from Signed Checkpoint is reached
4. verify the Signed Checkpoint signature
```

If this succeeds, the Ledger Entry is covered by the Signed Checkpoint.

For the Genesis Ledger Entry, the chain proof may contain only the Genesis Ledger Entry if:

```text
hash(genesis Ledger Entry) = head_entry_hash from Signed Checkpoint
```

---

## 15. DELTA_VERIFIED Status

Public status:

```text
DELTA_VERIFIED
```

requires all of the following:

```text
1. valid Delta Claim
2. valid Executor signature
3. valid Delta Attestation
4. valid Verifier signature
5. Delta Attestation result = VERIFIED
6. valid Ledger Entry
7. Ledger Entry contains claim_hash
8. Ledger Entry contains executor_sig_hash
9. Ledger Entry contains attestation_hash
10. Ledger Entry contains verifier_sig_hash
11. valid linear chain proof from Ledger Entry to checkpoint head_entry_hash
12. valid Signed Checkpoint
13. valid Checkpoint signature
```

Formal meaning:

```text
DELTA_VERIFIED means that a signed Claim, signed Attestation, Ledger Entry, chain proof, and Signed Checkpoint are cryptographically consistent.
```

Important limitation:

```text
DELTA_VERIFIED does not mean absolute truth about the physical world.
DELTA_VERIFIED does not mean the Verifier cannot be wrong.
DELTA_VERIFIED does not mean the evidence is publicly visible.
DELTA_VERIFIED means the declared change, evidence hash, signatures, ledger entry, and checkpoint are cryptographically bound and tamper-evident.
```

---

## 16. Anchor Confirmed

External anchoring is optional in DELTA-0.

Status:

```text
ANCHOR_CONFIRMED
```

requires that the checkpoint hash, checkpoint signature, or `head_entry_hash` has been published in an independent external system.

Examples:

```text
public Git commit
public release artifact
public timestamping service
Bitcoin OP_RETURN
independent mirror
Internet Archive snapshot
```

Formal meaning:

```text
ANCHOR_CONFIRMED means that the checkpoint or ledger head was externally witnessed by an independent system.
```

Important:

```text
ANCHOR_CONFIRMED is stronger than DELTA_VERIFIED.
DELTA_VERIFIED requires internal ledger consistency.
ANCHOR_CONFIRMED adds external timestamping or external witnessing.
```

---

## 17. Status Lifecycle

DELTA-0 status lifecycle:

```text
CLAIM_SIGNED
↓
ATTESTATION_SIGNED_UNPUBLISHED
↓
LEDGER_INCLUDED
↓
DELTA_VERIFIED
↓
ANCHOR_CONFIRMED
```

Additional exceptional status:

```text
REVOKED_OR_DISPUTED
```

This may apply if a key is revoked, a record is disputed, or a later correction record is issued.

---

## 18. Genesis Record Purpose

The DELTA Genesis Record symbolically records the creation of the first public Proof of Change structure.

Genesis Claim:

```text
Before:
The internet could prove ownership, identity, transactions, and file hashes, but had no universal proof layer for change.

Action:
DELTA-0 protocol genesis release created.

After:
The first DELTA Proof of Change record exists.

Evidence:
Manifest hash, protocol specification hash, source code hash, and genesis bundle hash.

Verifier:
Genesis local verifier key.
```

The Genesis Record is not a financial transaction.

It is not a token.

It is not a cryptocurrency event.

It is the first signed and checkpointed proof of change in the DELTA-0 model.

---

## 19. DELTA-0 Non-Goals

DELTA-0 does not attempt to prove:

```text
absolute truth
moral correctness
legal ownership
physical-world facts without trusted evidence
that the Verifier is always honest
that evidence was not fabricated before hashing
```

DELTA-0 proves:

```text
the Claim was signed by the Executor key
the Executor signature envelope hash was bound into the Ledger Entry
the Attestation was signed by the Verifier key
the Verifier signature envelope hash was bound into the Ledger Entry
the evidence hash was bound to the Claim and Attestation
the Ledger Entry includes the Claim hash and Attestation hash
the Ledger Entry is connected to a Signed Checkpoint
the Checkpoint was signed by the Verifier key
the shown ledger segment is tamper-evident
```

---

## 20. Minimum Genesis Bundle Files

A DELTA-0 Genesis Bundle should contain:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
genesis_bundle.json
```

Optional later files:

```text
verification_policy.json
evidence_manifest.json
ledger.json
chain_proof.json
anchor.json
```

---

## 21. DELTA-0 Summary

DELTA-0 is the first executable version of the DELTA Protocol.

It is based on:

```text
Claim
Attestation
Ledger Entry
Signed Checkpoint
```

It uses:

```text
JCS canonical JSON
SHA-256 hashes
Ed25519 signatures
linear hash-chain
detached signatures
signature envelope hashes bound into ledger entries
private evidence hashes
fixed genesis previous hash
optional external anchoring
```

Core statement:

```text
The internet can prove ownership.
DELTA proves change.
```

Precise technical statement:

```text
DELTA creates cryptographically signed, hash-bound, tamper-evident records of declared and verified digital change.
```