# DELTA-0 Threat Model

Version: `v0.9.0-draft`  
Protocol family: `DELTA-0`  
Status: Formal draft for review

---

## 1. Scope

This document defines the threat model for DELTA-0.

The protected asset is the integrity of a cryptographic Proof-of-Change record:

```text
Claim -> Attestation -> Ledger Entry -> Checkpoint
```

The protocol attempts to prevent undetected tampering with declared changes, evidence commitments, signatures, ledger inclusion, and checkpoint publication.

DELTA-0 does not attempt to prevent all real-world fraud. It provides cryptographic accountability for the objects presented.

---

## 2. Trust Assumptions

DELTA-0 assumes:

1. SHA-256 remains collision-resistant for protocol purposes.
2. Ed25519 remains secure against practical forgery.
3. Private keys are generated securely.
4. Private keys are not compromised before use.
5. Canonicalization is deterministic and equivalent across compliant implementations.
6. Verifiers reject malformed or non-compliant records.
7. Checkpoints can be published in a durable location.

---

## 3. Adversary Capabilities

An adversary may attempt to:

- modify JSON files after signing,
- modify evidence bytes after hashing,
- change line endings or byte encodings,
- replace public keys,
- swap signatures between records,
- present different ledger heads to different parties,
- compromise Executor or Verifier keys,
- create misleading but cryptographically valid Claims,
- omit inconvenient ledger entries,
- backdate or reorder local records,
- exploit canonicalization differences across languages.

---

## 4. Evidence Malleability

### 4.1 Threat

Evidence malleability occurs when the byte sequence used to compute an evidence hash changes unexpectedly.

Common sources include:

- CRLF/LF line-ending conversion,
- editor auto-formatting,
- Unicode normalization,
- compression differences,
- metadata changes,
- filesystem or Git filters.

If evidence bytes change, the evidence hash changes.

### 4.2 DELTA-0 Mitigation

DELTA-0 treats evidence as bytes, not as visual text.

Implementations SHOULD protect evidence bytes from automatic rewriting. In Git repositories, evidence paths SHOULD be configured to prevent text normalization.

Example:

```text
examples/code-change-proof/evidence/* -text
```

The verifier MUST compute the evidence hash over the exact bytes.

### 4.3 Residual Risk

DELTA-0 cannot prove that evidence was not fabricated before hashing. It proves only that the presented or later-revealed evidence matches the committed hash.

---

## 5. Split-View Attack / Forking

### 5.1 Threat

A split-view attack occurs when an operator presents different ledger histories to different observers.

For example:

```text
Observer A sees ledger head H1.
Observer B sees ledger head H2.
Both histories appear internally consistent.
```

### 5.2 DELTA-0 Mitigation

A Ledger Entry alone is not sufficient to prove a globally recognized state.

DELTA-0 requires Signed Checkpoints to commit to ledger heads.

A Checkpoint binds:

- checkpoint sequence,
- head entry hash,
- entry count,
- publication timestamp.

A durable checkpoint publication channel can make forks observable.

### 5.3 Residual Risk

DELTA-0 does not define a global consensus mechanism. A deployment requiring global non-equivocation SHOULD publish checkpoints to multiple independent channels such as:

- public repository tags,
- transparency logs,
- DNS records,
- timestamping services,
- notarized archives.

---

## 6. Key Compromise

### 6.1 Executor Key Compromise

If an Executor private key is compromised, an attacker can create valid Claims as that Executor.

DELTA-0 cannot distinguish a legitimate signature from a forged signature made with a stolen key.

Mitigations:

- rotate keys,
- publish revocation evidence,
- bind keys to short validity windows,
- use hardware-backed keys where possible,
- require Verifier Attestation for high-risk Claims,
- record key fingerprints and creation metadata.

### 6.2 Verifier Key Compromise

If a Verifier private key is compromised, an attacker can create valid Attestations.

Mitigations:

- separate Executor and Verifier keys,
- require multi-party verification for high-risk workflows,
- checkpoint revocation events,
- publish Verifier key rotations,
- scope Verifier keys by policy and domain.

### 6.3 Checkpoint Signer Key Compromise

If a Checkpoint Signer key is compromised, an attacker can publish fraudulent checkpoints.

Mitigations:

- use separate checkpoint keys,
- monitor checkpoint streams,
- publish checkpoints to independent channels,
- use multi-signature checkpoint policies in future versions,
- rotate checkpoint keys after suspected compromise.

### 6.4 Residual Risk

Compromise before revocation cannot be cryptographically undone. Later records can mark the compromise, but old signatures remain mathematically valid unless policy invalidates them.

---

## 7. Circular Hashing

### 7.1 Threat

Circular hashing occurs when an object contains a hash or signature of itself.

Example of unsafe design:

```text
claim.json contains claim_hash.
claim_hash is computed over claim.json.
```

This is circular and ambiguous.

### 7.2 DELTA-0 Mitigation

DELTA-0 uses detached signature envelopes.

Payload objects do not contain their own signatures.

The hash of a payload is stored in a separate object:

```text
executor_signature.target_hash = sha256(canonical_json_bytes(claim.json))
```

Likewise, `claim.json` MUST NOT contain `claim_id` if `claim_id` is derived from the Claim hash.

### 7.3 Residual Risk

Implementations that add non-standard self-hash fields can break cross-language verification. Such objects are non-compliant.

---

## 8. Signature Substitution

### 8.1 Threat

An adversary may attempt to pair a valid signature envelope with the wrong payload.

### 8.2 DELTA-0 Mitigation

The verifier MUST check:

- `target_type`,
- `target_hash`,
- `public_key`,
- role,
- Ed25519 verification over canonical payload bytes.

A signature envelope is valid only for the exact canonical payload whose hash equals `target_hash`.

---

## 9. Public Key Substitution

### 9.1 Threat

An adversary may replace a public key in a signature envelope.

### 9.2 DELTA-0 Mitigation

For Claims:

```text
executor_signature.public_key MUST equal claim.executor_pubkey
```

For Attestations:

```text
verifier_signature.public_key MUST equal attestation.verifier_pubkey
```

For Checkpoints:

```text
checkpoint_signature.public_key identifies the Checkpoint Signer
```

Future PKI layers may bind public keys to domains, organizations, or registries.

---

## 10. Canonicalization Drift

### 10.1 Threat

Different programming languages may serialize equivalent JSON differently.

Examples:

- object key order,
- whitespace,
- escaping,
- Unicode normalization,
- number rendering.

### 10.2 DELTA-0 Mitigation

DELTA-0 defines canonical JSON rules in `canonicalization.md`.

Implementations MUST sign and hash canonical JSON bytes, not pretty-printed or parser-native representations.

### 10.3 Residual Risk

A non-compliant implementation can produce records that verify only in its own runtime. Cross-language conformance tests are REQUIRED for production SDKs.

---

## 11. Timestamp Misuse

### 11.1 Threat

An implementation may present local timestamps as absolute proof of time.

### 11.2 DELTA-0 Mitigation

DELTA timestamps are metadata unless anchored externally.

A timestamp in `created_at`, `verified_at`, `included_at`, or `published_at` does not by itself prove time of occurrence.

For stronger time guarantees, deployments SHOULD use external timestamping or public checkpoint publication.

---

## 12. Private Payload Disclosure

### 12.1 Threat

A private payload may be accidentally uploaded or committed.

### 12.2 DELTA-0 Mitigation

DELTA-0 supports publishing only hashes and manifests.

Reference tooling SHOULD refuse to write private keys inside public repositories and SHOULD avoid storing private payload bytes in public proof artifacts.

The Web Explorer MUST perform verification client-side and MUST NOT upload JSON or payload bytes to a backend.

### 12.3 Residual Risk

If a user manually uploads private payload bytes to a public location, DELTA cannot undo disclosure.

---

## 13. AI-Agent Output Risk

### 13.1 Threat

An AI agent may produce false or hallucinated output.

### 13.2 DELTA-0 Mitigation

DELTA-0 can prove:

- which prompt and input data were declared,
- which output was produced,
- which key signed the Claim,
- which Verifier attested the output,
- which ledger/checkpoint committed the record.

DELTA-0 does not prove the AI output is objectively true.

---

## 14. Security Conclusion

DELTA-0 is a cryptographic accountability protocol.

It is strong against tampering of presented protocol objects. It is not a substitute for:

- real-world investigation,
- legal judgment,
- key management,
- external timestamping,
- consensus,
- evidence authenticity controls.
