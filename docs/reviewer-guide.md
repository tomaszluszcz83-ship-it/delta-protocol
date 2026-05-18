# DELTA External Reviewer Guide

**Status:** Public review guide  
**Version:** v2.5.3  
**Audience:** security reviewers, protocol reviewers, auditors, contributors

This guide gives reviewers a structured path for evaluating DELTA Protocol.

DELTA is an open, zero-token **Proof of Change** protocol. It aims to prove cryptographic consistency around digital change, not legal truth or real-world truth.

---

## 1. Review goals

A useful review should answer:

1. Are the protocol claims clear and not overstated?
2. Are hashes and signatures bound to the correct payloads?
3. Are security boundaries explicit?
4. Are positive and negative test paths documented?
5. Are private keys and sensitive artifacts kept out of the repository?
6. Are wallet profiles accurately described, especially Bitcoin external mode?
7. Is the implementation aligned with RFC-01 and RFC-02?

---

## 2. Non-goals

A review should not treat DELTA as proving more than it claims.

DELTA does **not** prove by itself:

- legal truth;
- real-world truth;
- legal ownership;
- personal identity;
- wallet balance;
- regulatory compliance;
- correctness of external governance;
- truth of evidence before hashing;
- local Bitcoin BIP-322 script-level validity for `bitcoin_bip322_external_v1`.

---

## 3. Quick repository health check

Run:

```bash
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

Then check working tree state:

```bash
git status
```

Expected result for a clean release checkout:

```text
nothing to commit, working tree clean
```

---

## 4. Recommended reading order

1. [`README.md`](../README.md)
2. [`docs/README.md`](README.md)
3. [`docs/rfc/RFC-01-delta-core-protocol.md`](rfc/RFC-01-delta-core-protocol.md)
4. [`docs/positioning/what-delta-proves.md`](positioning/what-delta-proves.md)
5. [`docs/rfc/RFC-02-proof-of-wallet.md`](rfc/RFC-02-proof-of-wallet.md)
6. [`docs/test-vectors/README.md`](test-vectors/README.md)
7. [`docs/audit/audit-checklist-v2.5.2.md`](audit/audit-checklist-v2.5.2.md)
8. [`SECURITY.md`](../SECURITY.md)
9. [`CONTRIBUTING.md`](../CONTRIBUTING.md)

---

## 5. Core protocol review checklist

Review RFC-01 for the following:

- [ ] DELTA is described as a Proof of Change protocol.
- [ ] The model `Before → Action → After → Evidence → Verification → Ledger` is present.
- [ ] Canonical JSON rules are explicit.
- [ ] SHA-256 hash format is explicit.
- [ ] Full `delta-record.json` hash binding is described.
- [ ] Proof of Replay is described with security boundaries.
- [ ] Proof of Intent is described with target record hash binding.
- [ ] Proof of Audit is described as encrypted/private evidence with hash binding.
- [ ] Proof of Publication is described without overclaiming legal or external truth.
- [ ] Proof of Trust is described as a hash-chain ledger.
- [ ] Proof of Wallet profiles are summarized accurately.
- [ ] The document distinguishes implemented profiles from future roadmap.

---

## 6. Canonical JSON and hash binding review

Check whether each proof object uses a stable hash target.

Review questions:

- Is the signed or hashed payload clear?
- Is the hash calculated over canonical JSON bytes?
- Is the record binding based on full `delta-record.json` where required?
- Can a verifier detect if a target record is swapped after proof creation?
- Are self-check hashes present where expected?

Expected property:

```text
Changing record_hash, proof_body_hash, entry hash, previous_entry_hash, AAD, ciphertext hash, or signed challenge should cause verification failure where applicable.
```

---

## 7. Proof of Replay review

Review goals:

- Confirm replay does not overclaim legal or real-world truth.
- Confirm replay compares recorded outputs/hashes with reproduced outputs.
- Confirm replay is documented as environment-sensitive.
- Confirm replay status is distinct from intent, audit, publication, and wallet status.

---

## 8. Proof of Intent review

Review goals:

- Intent is detached from the sensor record.
- Intent has its own signature/key material.
- Intent binds to the full record hash.
- Missing, invalid, or tampered intent produces explicit failure/status.
- Intent policy reporting does not silently imply legal approval.

Negative cases to inspect:

- missing signature;
- tampered ticket or attestation;
- mismatched record hash;
- inactive or missing registry key.

---

## 9. Proof of Audit review

Review goals:

- Private evidence is not committed in decrypted form.
- Audit packages bind to the full record hash.
- Ciphertext hash and AAD hash are verified.
- Package verification can occur without decryption.
- Auditor-side decryption is separated from public verification.

Negative cases to inspect:

- tampered ciphertext hash;
- tampered AAD;
- mismatched record hash;
- missing evidence file behavior.

---

## 10. Proof of Publication review

Review goals:

- Publication proof binds to full record hash.
- `proof_body_hash` self-check is present.
- External evidence hash checks are explicit.
- OpenTimestamps pending mode is not presented as final timestamp verification.

Negative cases to inspect:

- tampered record hash;
- tampered proof body hash;
- tampered external `.ots` file.

---

## 11. Proof of Trust review

Review goals:

- Each entry has an entry hash / body hash.
- Each non-genesis entry links to previous entry hash.
- Ledger body hash self-check exists.
- Record binding exists for entries.
- Tampering with previous entry hash fails verification.

Negative cases to inspect:

- `previous_entry_hash` mismatch;
- entry body hash mismatch;
- ledger body hash mismatch;
- sequence violations.

---

## 12. Proof of Wallet review

Review RFC-02 and wallet test vectors.

Profiles:

```text
ed25519_address_control_v1
ethereum_eip191_personal_sign_v1
ethereum_eip712_typed_data_v1
bitcoin_bip322_external_v1
```

Review goals:

- Challenge contains or derives binding to full record hash.
- Wallet proof binds address, challenge hash, signature/proof object, and record hash.
- Ethereum EIP-191 recovers the declared Ethereum address.
- Ethereum EIP-712 signs structured typed data.
- Bitcoin external mode is explicitly shape-only / external-pending.

Bitcoin external boundary:

```text
bitcoin_bip322_external_v1 does not perform local cryptographic BIP-322 verification.
CRYPTO_SIGNATURE_VERIFIED=False is required and expected.
verification_level=shape_only and verification_status=external_pending are intentional.
```

Negative cases to inspect:

- tampered record hash;
- tampered challenge;
- tampered signature;
- empty Bitcoin external proof/signature;
- unsupported Bitcoin signature format.

---

## 13. Security review focus areas

Important areas for external security review:

1. Canonical JSON consistency across future implementations.
2. Signature payload clarity.
3. Hash binding correctness.
4. Key registry and revocation semantics.
5. Replay environment assumptions.
6. Evidence privacy and disclosure boundaries.
7. Wallet proof overclaim prevention.
8. Bitcoin BIP-322 external profile wording.
9. Separation between normative RFC and reference implementation.
10. Missing formal JSON schemas and test vectors as executable fixtures.

---

## 14. Expected reviewer deliverables

A reviewer may provide:

- list of security findings;
- RFC wording corrections;
- proof-layer threat model comments;
- test vector improvements;
- schema recommendations;
- implementation/code findings;
- suggested conformance levels;
- public-launch readiness assessment.

Suggested finding format:

```text
Title:
Severity: Informational / Low / Medium / High / Critical
Affected area:
Description:
Expected behavior:
Actual behavior:
Reproduction steps:
Recommended fix:
```

---

## 15. Current maturity statement

DELTA is currently:

```text
technical alpha reference implementation
+
RFC-style draft standard
+
public-review-ready open-source repository
```

It is ready for external architecture/security review. It is not yet a final standard or an enterprise production system.
