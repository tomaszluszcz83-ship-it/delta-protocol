# DELTA-0 Yellow Paper

**A Cryptographic Proof-of-Change Protocol for Verifiable Digital Actions**

Version: `v0.9.0-draft`  
Protocol family: `DELTA-0`  
Status: Formal draft for review  
Normative language: RFC 2119 style (`MUST`, `MUST NOT`, `SHOULD`, `MAY`)

---

## 1. Abstract

DELTA-0 is a zero-token cryptographic protocol for producing, verifying, and publishing tamper-evident records of declared digital change.

The protocol does not create a cryptocurrency, token, marketplace, account system, or blockchain-dependent application. It defines a minimal set of signed and hashed data structures that allow independent verifiers to determine whether a declared change, its evidence commitment, a verification decision, a ledger entry, and a checkpoint are cryptographically consistent.

DELTA-0 is based on four ordered layers:

```text
Claim -> Attestation -> Ledger Entry -> Checkpoint
```

The protocol axiom is:

```text
DELTA does not prove absolute truth about the physical world.
DELTA proves cryptographic consistency of declarations, evidence commitments,
verification decisions, ledger inclusion, and checkpoint publication.
```

---

## 2. Terminology

### 2.1 Claim

A `delta_claim` is a canonical JSON object created by an Executor. It declares:

- the state before a change,
- the action that was performed,
- the state after the change,
- an evidence hash,
- the Executor public key.

A Claim is not self-authenticating. It becomes attributable only when paired with a detached Executor signature envelope.

### 2.2 Executor

An Executor is the cryptographic actor that declares a change. An Executor MAY represent a human, service, software process, CI pipeline, AI agent, or organization-controlled key.

### 2.3 Evidence

Evidence is any byte sequence or structured object that supports the Claim. DELTA-0 binds evidence by hash. Evidence MAY remain private. Public verifiers do not require access to private evidence bytes if they can verify the hash commitment and the surrounding signatures.

### 2.4 Attestation

A `delta_attestation` is a canonical JSON object created by a Verifier. It records a verification result for a target Claim and its Executor signature.

An Attestation is not self-authenticating. It becomes attributable only when paired with a detached Verifier signature envelope.

### 2.5 Verifier

A Verifier is the cryptographic actor that verifies a Claim under a declared policy. A Verifier MAY represent a human reviewer, audit service, QA system, compliance system, or organization-controlled key.

### 2.6 Ledger Entry

A `delta_ledger_entry` binds the hashes of the Claim, Executor signature, Attestation, and Verifier signature into a hash-chain entry. The Ledger Entry itself is hash-chain data. It is not signed in DELTA-0.

### 2.7 Checkpoint

A `delta_signed_checkpoint` publishes a commitment to a ledger head. A Checkpoint is signed by a Checkpoint Signer using a detached `delta_signature` envelope.

### 2.8 Canonical JSON

Canonical JSON is the deterministic UTF-8 byte representation used for hashing and signing. DELTA-0 implementations MUST use the canonicalization rules defined in `canonicalization.md`.

---

## 3. Design Goals

DELTA-0 has the following design goals:

1. Provide a minimal, auditable proof-of-change primitive.
2. Separate payload objects from signatures.
3. Support private evidence through hash commitments.
4. Permit independent verification without a backend.
5. Avoid circular hashing and self-referential identifiers.
6. Be implementable across languages.
7. Support command-line, SDK, CI, agent, and browser-based verification.
8. Avoid token economics and blockchain dependency.

---

## 4. Non-Goals

DELTA-0 does not attempt to prove:

- absolute truth about the physical world,
- legal validity,
- financial value,
- ownership,
- subjective correctness,
- that a Verifier cannot be wrong,
- that evidence was not fabricated before hashing,
- that an AI output is objectively true,
- that a key was not compromised before revocation.

DELTA-0 also does not define:

- a cryptocurrency,
- a token,
- a consensus protocol,
- a mandatory registry,
- a user-account platform,
- a marketplace,
- a global PKI.

---

## 5. Protocol Axiom

The central axiom is:

```text
A DELTA record proves that a declared change was cryptographically bound
to evidence, signed by an Executor, reviewed or validated by a Verifier,
included in a Ledger Entry, and committed by a Signed Checkpoint.
```

The protocol proves consistency and attribution within a cryptographic record. It does not prove that the contents of the declaration are externally true.

---

## 6. Four-Layer Model

### 6.1 Layer 1: Claim

The Executor creates a `delta_claim` and signs its canonical JSON bytes with Ed25519.

The signature envelope references the Claim through:

```text
target_type = "delta_claim"
target_hash = sha256(canonical_json_bytes(claim.json))
```

The Claim MUST NOT contain its own signature.

The Claim MUST NOT contain a `claim_id` derived from the Claim hash, because that would introduce circular hashing.

### 6.2 Layer 2: Attestation

The Verifier MUST verify the Executor signature before creating an Attestation.

The Attestation binds:

- the target Claim hash,
- the target Executor signature hash,
- the verification policy hash,
- the evidence hash,
- the publication mode,
- the intended ledger identifier,
- the verification result.

The Verifier signs the canonical JSON bytes of `attestation.json`.

The Attestation MUST NOT contain its own signature.

### 6.3 Layer 3: Ledger Entry

The Ledger Entry binds the signed Claim and signed Attestation into a hash-chain record.

The Ledger Entry is not signed. It is only canonicalized and hashed.

A Ledger Entry contains:

- `ledger_id`,
- `seq`,
- `prev_entry_hash`,
- `claim_hash`,
- `executor_sig_hash`,
- `attestation_hash`,
- `verifier_sig_hash`,
- `included_at`.

For a genesis ledger entry, `prev_entry_hash` MUST be:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

### 6.4 Layer 4: Checkpoint

A Checkpoint commits to a ledger head.

The Checkpoint contains:

- `checkpoint_seq`,
- `head_entry_hash`,
- `entry_count`,
- `published_at`.

The Checkpoint is signed by a Checkpoint Signer using a detached signature envelope with:

```text
role = "checkpoint_signer"
target_type = "delta_signed_checkpoint"
```

---

## 7. Signature Model

DELTA-0 uses detached signatures.

A payload object is signed by computing:

```text
signature = Ed25519.sign(canonical_json_bytes(payload_object))
```

The detached signature envelope stores:

```text
target_hash = sha256(canonical_json_bytes(payload_object))
```

The target hash is not the signature input. It is a binding reference.

DELTA-0 MUST NOT sign prehashed bytes unless a future version explicitly defines a new signature input mode.

---

## 8. Hash Model

All object hashes use SHA-256 over canonical JSON bytes unless the object is raw evidence bytes.

Object hash:

```text
sha256(canonical_json_bytes(json_object))
```

Raw evidence hash:

```text
sha256(raw_evidence_bytes)
```

All hashes MUST be encoded as:

```text
sha256:<64 lowercase hexadecimal characters>
```

---

## 9. Identity by Proof, Not Exposure

DELTA-0 follows the principle:

```text
Identity by proof, not exposure.
```

A public ledger SHOULD expose public keys and hashes, not unnecessary private identity data.

An identity MAY be associated with a key through external evidence such as:

- DNS TXT records,
- certificates,
- signed organizational statements,
- registry entries,
- offline legal agreements.

DELTA-0 does not require private identity documents to be published.

This principle also applies to private payloads. DELTA-0 can commit to private documents by publishing only hashes and metadata. This is a privacy-preserving hash-commitment model. It is not a general-purpose zero-knowledge proof system in the formal cryptographic sense.

---

## 10. Proof Without Exposure

In private-payload mode, evidence bytes are not published.

The public record contains:

- evidence hash,
- manifest hash,
- Claim,
- Executor signature,
- Attestation,
- Verifier signature,
- Ledger Entry,
- Checkpoint.

A party that later reveals the private payload can prove it was the same payload by recomputing the evidence hash.

The protocol therefore supports:

```text
Proof without exposure.
```

---

## 11. Verification Algorithm

A verifier SHOULD perform the following checks:

1. Parse all JSON objects.
2. Reject malformed JSON.
3. Canonicalize each object.
4. Recompute the Claim hash.
5. Verify the Executor signature over canonical Claim bytes.
6. Recompute the Executor signature envelope hash.
7. Recompute the Attestation hash.
8. Verify the Verifier signature over canonical Attestation bytes.
9. Check that Attestation target hashes match the Claim artifacts.
10. Recompute the Ledger Entry hash.
11. Check that Ledger Entry hashes match Claim and Attestation artifacts.
12. Recompute the Checkpoint hash.
13. Verify the Checkpoint signature over canonical Checkpoint bytes.
14. Check that Checkpoint `head_entry_hash` equals the Ledger Entry hash.
15. For a chain, check that each `prev_entry_hash` matches the previous entry hash.

Failure at any step MUST cause verification failure.

---

## 12. Compliance Levels

### 12.1 DELTA-0 Payload Compliance

An implementation is payload-compliant if it can create canonical JSON objects with the required field names and value constraints.

### 12.2 DELTA-0 Signature Compliance

An implementation is signature-compliant if it signs and verifies canonical JSON bytes using Ed25519 and the detached signature envelope format.

### 12.3 DELTA-0 Ledger Compliance

An implementation is ledger-compliant if it can construct and validate `delta_ledger_entry` objects and hash chains.

### 12.4 DELTA-0 Checkpoint Compliance

An implementation is checkpoint-compliant if it can create and verify `delta_signed_checkpoint` objects and their detached signatures.

### 12.5 DELTA-0 Full Verification Compliance

An implementation is fully verification-compliant if it can verify a complete record:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

---

## 13. Implementation Status

At the time of this draft, the reference repository contains:

- Python CLI verifier,
- Python CLI Write Mode,
- public example records,
- browser-based Web Explorer MVP,
- examples for code change, private payload, and AI-agent execution.

This document freezes the terminology and structure for DELTA-0 formal review.

---

## 14. Security Boundary

The security of a DELTA record depends on:

- canonicalization correctness,
- SHA-256 collision resistance,
- Ed25519 signature correctness,
- private key confidentiality,
- evidence byte stability,
- checkpoint publication integrity.

A valid DELTA verification result means:

```text
The presented objects are cryptographically consistent.
```

It does not mean:

```text
The external world necessarily matches the declarations.
```
