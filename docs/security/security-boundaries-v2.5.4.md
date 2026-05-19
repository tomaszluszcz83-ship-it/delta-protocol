# DELTA v2.5.4 Security Foundation — Security Boundaries

**Status:** Draft  
**Version:** v2.5.4  
**Purpose:** Define what DELTA proves, what DELTA does not prove, and what MUST NOT be claimed by users, integrations, or reports.

---

## 1. Core boundary

DELTA proves cryptographic consistency around digital change. DELTA does not prove all real-world truth.

DELTA can prove statements such as:

- this object has this canonical SHA-256 hash,
- this signature verifies against this public key,
- this proof object is bound to this full `delta-record.json` hash,
- this replay result matches the recorded method/output hashes,
- this intent attestation targets this record hash,
- this audit package is structurally bound to this record hash,
- this publication proof targets this record hash,
- this trust ledger hash chain is internally consistent,
- this Ethereum address signed this DELTA challenge,
- this Bitcoin external proof object is shape-valid and bound to this record hash when using `bitcoin_bip322_external_v1`.

---

## 2. DELTA does not prove

DELTA does **not** prove:

- legal truth,
- real-world truth,
- business truth,
- regulatory compliance by itself,
- MiCA/GDPR/SOC2/ISO27001 compliance by itself,
- human identity by itself,
- employee authority by itself,
- CEO/board/legal approval by itself,
- that evidence was truthful before hashing,
- that a ticket in Jira/GitHub Issues was validly approved,
- that a server, CI runner, or external service was uncompromised,
- that a wallet is legally owned by a person or organization,
- wallet balance unless a dedicated balance proof profile exists,
- source of funds,
- full Bitcoin BIP-322 cryptographic verification in external mode,
- correctness of arbitrary source code,
- absolute timestamp truth without external timestamp verification,
- absence of all vulnerabilities.

Any integration, report, badge, README, release note, or marketing text MUST NOT claim the above unless an additional external system and corresponding proof profile explicitly provides it.

---

## 3. Proof-layer boundaries

### 3.1 Proof of Change

Proves: recorded before/action/after/evidence commitments are bound by hashes/signatures.

Does not prove: that the action was good, legal, authorized, or truthful in a real-world sense.

### 3.2 Proof of Replay

Proves: declared measurement can be replayed and compared with recorded outputs under the declared method/environment assumptions.

Does not prove: legal truth, full reproducible builds, or complete environmental equivalence unless separately specified.

### 3.3 Proof of Intent

Proves: an intent attestation was signed and bound to a specific record hash.

Does not prove: legal approval, human identity, corporate authorization, MFA, or ticket truth unless external governance is added.

### 3.4 Proof of Audit

Proves: encrypted/private evidence package structure, hash bindings, recipient binding, ciphertext/AAD integrity, and optional decryption by authorized auditor.

Does not prove: that the evidence content was truthful before encryption/hash commitment.

### 3.5 Proof of Publication

Proves: a record hash was included in a publication/external evidence proof object.

Does not prove: truth or correctness of the underlying record.

### 3.6 Proof of Trust

Proves: hash-chain consistency of trust entries and bindings to records.

Does not prove: real-world authority of actor labels such as executor, verifier, auditor, or regulator.

### 3.7 Proof of Wallet

Proves: a supported key/address profile signed or supplied a proof object bound to a DELTA record challenge.

Does not prove: legal wallet ownership, identity, balance, compliance, custody, source of funds, or solvency.

---

## 4. Bitcoin external profile boundary

For `bitcoin_bip322_external_v1`:

- `verification_level` MUST be `shape_only` unless a local cryptographic verifier is implemented.
- `verification_status` SHOULD be `external_pending` for shape-only external proof objects.
- `CRYPTO_SIGNATURE_VERIFIED=False` MUST be reported.
- A verifier MUST NOT claim full local BIP-322 cryptographic verification.

This profile currently proves structural validity and record binding of an external Bitcoin proof object. It does not validate Bitcoin Script, Taproot, witness stacks, PSBTs, or proof-of-funds.

---

## 5. Public reporting boundaries

DELTA reports, badges, exports, or certificates SHOULD use wording such as:

```text
DELTA verified cryptographic binding and integrity for this record.
```

They MUST NOT use wording such as:

```text
This company is legally compliant.
This wallet is legally owned by this entity.
This process is fully secure.
This evidence is true.
This Bitcoin signature was locally verified.
```

unless a separate proof profile and governance layer explicitly support the claim.

---

## 6. Alpha reference implementation boundary

The current Python implementation is an **Alpha Reference Implementation**. It demonstrates and tests protocol behavior. It is not yet a hardened enterprise verifier.

Production-grade implementations SHOULD eventually:

- pass frozen DELTA test vectors,
- pass conformance tests,
- implement the canonicalization profile exactly,
- validate JSON Schemas,
- provide deterministic builds and release signatures,
- consider Rust/Go or other hardened deployment targets for CI/CD environments.

---

## 7. Summary

DELTA is strongest when it is precise. The protocol MUST clearly distinguish cryptographic proof from legal, organizational, financial, and regulatory claims. This boundary is not a weakness; it is what makes DELTA auditable and credible.
