# DELTA v2.5.4 Security Foundation — Threat Model

**Status:** Draft  
**Version:** v2.5.4  
**Scope:** DELTA Protocol technical alpha / reference implementation  
**Purpose:** Define the attacker model, assets, trust assumptions, threats, current mitigations, and remaining risks before public review.

---

## 1. Security posture

DELTA is an open, zero-token Proof of Change protocol. DELTA is designed to prove cryptographic consistency around digital change:

```text
Before → Action → After → Evidence → Verification → Ledger
```

DELTA uses hashes, signatures, record binding, replay verification, intent attestation, audit packages, publication proofs, trust ledgers, and wallet proofs. It does not attempt to prove all real-world truth.

This document intentionally describes limitations and risks before external reviewers do. The goal is a defensible, auditable protocol boundary.

---

## 2. Assets protected by DELTA

DELTA aims to protect or make tampering detectable for:

- `delta-record.json` and other DELTA proof objects.
- Full-record hash bindings.
- Public/private evidence commitments.
- Measurement method definitions and result hashes.
- Replay instructions and replay outputs.
- Intent attestations and intent key registry bindings.
- Audit package manifests, ciphertext hashes, AAD hashes, and record bindings.
- Publication proof target hashes and external evidence hashes.
- Trust ledger entry hashes, previous-entry links, and ledger body self-checks.
- Wallet proof challenge hashes, address bindings, signature checks, and record bindings.

DELTA does not directly protect the truthfulness of raw evidence before hashing. It makes later alteration detectable.

---

## 3. Trust assumptions

DELTA assumes:

1. Cryptographic primitives used by the implementation remain secure for the intended period.
2. Private keys are generated and stored securely by users/systems.
3. Canonicalization rules are deterministic and compatible across implementations.
4. Verifiers use the declared proof profile and do not silently upgrade/downgrade verification mode.
5. Evidence, once hashed and committed, cannot be changed without detection.
6. Replay environments are sufficiently close to the declared environment for the declared measurement method.
7. External systems such as GitHub, OpenTimestamps, wallets, issue trackers, and CI systems have their own trust boundaries and failure modes.

---

## 4. Attacker model

An attacker may attempt to:

- Modify a DELTA record after signing.
- Replace evidence files while preserving filenames.
- Replace or alter replay output.
- Replace an intent attestation with one targeting a different record.
- Use a valid intent for a different change.
- Tamper with audit package ciphertext, AAD, recipient keys, or record bindings.
- Create a publication proof that points to a different record hash.
- Break a trust ledger by modifying `previous_entry_hash` or entry body.
- Reuse a wallet signature for a different record.
- Present a Bitcoin external proof as fully cryptographically verified when it is only shape-checked.
- Backdate events or manipulate local timestamps.
- Use compromised keys to create apparently valid proofs.
- Claim legal/compliance meaning beyond the cryptographic statement proven.

---

## 5. Threats and current mitigations

### 5.1 Record tampering

**Threat:** An attacker modifies `delta-record.json` after it has been created.

**Mitigations:**

- Canonical SHA-256 full-record hash binding.
- Signature checks over canonical payloads.
- Self-check hashes in proof objects.
- Replay verification checks expected hashes and outputs.

**Residual risk:** If canonicalization is inconsistent across languages, verifiers may disagree. This is addressed in the planned v2.6.0 RFC 8785/JCS compatibility milestone.

---

### 5.2 Evidence fabrication before hashing

**Threat:** A malicious actor creates false evidence, hashes it, and then presents it as immutable evidence.

**Mitigations:**

- DELTA makes evidence tampering after commitment detectable.
- Replay can verify some technical outputs independently.
- Proof of Intent can link a change to a signed approval object.
- Proof of Audit can disclose private evidence to an authorized auditor.

**Residual risk:** DELTA does not prove that evidence was truthful before hashing. This is an explicit security boundary.

---

### 5.3 Repudiation

**Threat:** A signer denies signing a record, intent, audit package, wallet proof, or trust entry.

**Mitigations:**

- Digital signatures bind keys to payload hashes.
- Intent and wallet proofs bind signatures to a full record hash.
- Trust ledger entries preserve hash-chain order.

**Residual risk:** DELTA does not prove the real-world identity or legal authority of a signer unless an external governance/identity system binds that key to an entity.

---

### 5.4 Key compromise

**Threat:** An executor, verifier, intent, audit, publication, trust, or wallet key is compromised.

**Mitigations:**

- Public key hashes are recorded.
- Intent registry can identify allowed keys.
- Future registry/revocation profiles can mark keys as revoked.
- Incident response process SHOULD publish revocation/invalidation records.

**Residual risk:** DELTA cannot distinguish a legitimate signature from a signature made by an attacker who possesses the private key before revocation time.

---

### 5.5 Time manipulation

**Threat:** An actor manipulates local timestamps, backdates proof creation, or uses ambiguous time sources.

**Mitigations:**

- Publication proofs can anchor record hashes externally.
- OpenTimestamps/pending publication profiles can provide external timestamp evidence when upgraded/verified.
- Trust ledger ordering can preserve internal sequence.

**Residual risk:** Local timestamps alone are not authoritative. DELTA does not prove absolute time unless linked to a trusted external timestamping mechanism.

---

### 5.6 Replay manipulation

**Threat:** A replay result is falsified or replay environment differs in ways that change the result.

**Mitigations:**

- Replay compares commit, method definition hash, stdout/stderr hashes, result status, and expected outputs.
- Isolated fresh clone / clean directory replay reduces local-state contamination.

**Residual risk:** Replay does not prove real-world truth or complete build reproducibility unless the environment is fully controlled and specified.

---

### 5.7 Proof of Intent misuse

**Threat:** A valid intent is reused for a different record, or an intent is presented as legal/business approval.

**Mitigations:**

- Intent targets full `delta-record.json` hash.
- Signature and registry checks bind intent to a key and target.
- Intent policy reporting marks missing/invalid intent.

**Residual risk:** DELTA does not prove that the ticket, approver identity, corporate authority, or legal approval is valid outside the cryptographic record.

---

### 5.8 Proof of Audit privacy risk

**Threat:** Private evidence is leaked, committed accidentally, or decrypted by the wrong party.

**Mitigations:**

- Audit evidence can be encrypted for an auditor.
- Packages include ciphertext hashes, AAD hashes, recipient public key hash, and record binding.
- Private keys and decrypted evidence MUST NOT be committed.

**Residual risk:** Encryption does not protect evidence once voluntarily disclosed. Key compromise can expose encrypted evidence.

---

### 5.9 Proof of Publication overclaiming

**Threat:** A publication proof is interpreted as proving the truth of the change rather than existence of a record hash.

**Mitigations:**

- Publication proofs bind a record hash to a publication/external evidence object.
- Documentation states Proof of Publication does not prove correctness of the underlying change.

**Residual risk:** Users may overstate publication as legal truth unless documentation and UI clearly warn against it.

---

### 5.10 Proof of Trust manipulation

**Threat:** A trust ledger entry is modified, removed, reordered, or linked to a different previous entry.

**Mitigations:**

- Each entry includes entry body hash/self-check.
- Entries are hash-chained using `previous_entry_hash`.
- Ledger body hash detects global tampering.

**Residual risk:** A trust ledger does not prove real-world authority of actors unless actor keys are governed by an external policy/registry.

---

### 5.11 Proof of Wallet misuse

**Threat:** A wallet proof is misrepresented as legal ownership, balance proof, identity proof, or regulatory compliance.

**Mitigations:**

- Wallet challenge includes full record hash.
- Ethereum EIP-191/EIP-712 signatures recover and verify address control.
- Bitcoin external profile explicitly reports `shape_only`, `external_pending`, and `CRYPTO_SIGNATURE_VERIFIED=False`.

**Residual risk:** DELTA does not prove legal ownership, wallet balance, source of funds, or compliance. Bitcoin external mode does not perform local cryptographic BIP-322 verification.

---

## 6. Feature freeze security rationale

During the v2.5.x/v2.6.x hardening sprint, DELTA should avoid adding new blockchain adapters, sensors, or proof layers. The priority is:

1. Security foundation.
2. Canonicalization compatibility.
3. Frozen test vectors.
4. JSON Schemas.
5. Conformance levels.
6. Reviewer-ready documentation.

This reduces attack surface and stabilizes the protocol before public review.

---

## 7. Future security work

Planned work:

- RFC 8785/JCS compatibility validation.
- Frozen cross-language test vectors.
- JSON Schema registry.
- Conformance test suite.
- Key revocation/invalidation record profile.
- Production verifier hardening in Rust/Go.
- ZK Provenance research track for private public-verifiable audit claims.

---

## 8. Summary

DELTA is designed to make tampering, mismatch, replay inconsistency, invalid binding, and unsupported verification modes visible. DELTA is not designed to prove legal truth, business truth, identity, wallet balance, or regulatory compliance by itself.
