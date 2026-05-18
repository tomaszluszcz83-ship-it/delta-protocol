# DELTA Audit Checklist v2.5.2

**Status:** Draft  
**Purpose:** provide a reviewer checklist for DELTA technical-alpha audit and RFC review.

## 1. Repository state

- [ ] `main` branch is clean.
- [ ] `python src/delta_cli.py verify-all` returns `DELTA CLI RESULT: OK`.
- [ ] No generated `.delta/*-tests/` artifacts are committed.
- [ ] No private keys, seed phrases, access tokens, decrypted evidence, or local secrets are committed.
- [ ] Releases and tags match the documented feature history.

## 2. Core protocol / RFC review

- [ ] `docs/rfc/RFC-01-delta-core-protocol.md` exists.
- [ ] RFC-01 clearly defines DELTA as an open zero-token Proof of Change protocol.
- [ ] RFC-01 includes the `Before → Action → After → Evidence → Verification → Ledger` model.
- [ ] RFC-01 distinguishes the abstract core model from implemented profiles.
- [ ] RFC-01 documents DELTA Canonical JSON Profile v1.
- [ ] RFC-01 documents SHA-256 hash binding.
- [ ] RFC-01 documents full `delta-record.json` hash binding.
- [ ] RFC-01 states what DELTA proves and does not prove.

## 3. Canonical JSON / hash binding

- [ ] Hash strings use `sha256:<64 lowercase hex chars>`.
- [ ] Hashed/signed JSON uses the declared DELTA canonical JSON profile.
- [ ] Payload hashes are checked against stored self-check hashes.
- [ ] Full record hash binding is used for intent/audit/publication/trust/wallet where required.

## 4. Sensor record / replay

- [ ] Signed sensor record contains method, source, change, measurement result, evidence commitments, replay instructions, and verification policy.
- [ ] Replay verifier checks record signature and method/evidence/result bindings.
- [ ] Replay failure cases are documented and do not overclaim legal truth.

## 5. Intent

- [ ] Intent attestation is signed separately.
- [ ] Intent target binds to full `delta-record.json` hash.
- [ ] Intent registry is checked for key presence and active/revoked status.
- [ ] Missing intent files result in `INTENT_MISSING`, not an unhandled exception.
- [ ] Tampered intent results in `INTENT_INVALID`.

## 6. Audit

- [ ] Audit package binds to full record hash.
- [ ] Audit package can be verified without decryption.
- [ ] Auditor private key is never committed.
- [ ] Decrypted evidence is never committed.
- [ ] Tampered ciphertext/AAD/binding is detected.

## 7. Publication

- [ ] Publication proof binds to full record hash.
- [ ] Proof body hash/self-check is verified.
- [ ] External file hash checks detect tampering.
- [ ] OpenTimestamps pending profile does not overclaim final calendar anchoring.

## 8. Trust ledger

- [ ] Ledger entries include entry hashes and previous-entry links.
- [ ] Tampered `previous_entry_hash` fails verification.
- [ ] Entry hash, ledger body hash, and self-check failures are reported.
- [ ] Proof of Trust does not claim legal authority or identity.

## 9. Wallet proof

- [ ] `ed25519_address_control_v1` verifies signature/address/challenge/record binding.
- [ ] `ethereum_eip191_personal_sign_v1` recovers and verifies Ethereum address.
- [ ] `ethereum_eip712_typed_data_v1` recovers and verifies Ethereum address from typed data.
- [ ] `bitcoin_bip322_external_v1` reports `shape_only` / `external_pending`.
- [ ] Bitcoin external profile reports `CRYPTO_SIGNATURE_VERIFIED=False`.
- [ ] Tampered record hash fails wallet proof verification.
- [ ] Tampered signature fails cryptographic wallet profiles.
- [ ] Empty Bitcoin external signature and unsupported Bitcoin signature format fail shape checks.

## 10. Security boundaries

- [ ] DELTA does not claim legal truth.
- [ ] DELTA does not claim real-world truth.
- [ ] DELTA does not claim identity by itself.
- [ ] DELTA does not claim wallet balance by itself.
- [ ] DELTA does not claim regulatory compliance by itself.
- [ ] DELTA does not claim Bitcoin local BIP-322 verification for `bitcoin_bip322_external_v1`.

## 11. Public readiness

- [ ] README explains DELTA in under one minute.
- [ ] README links to RFC-01 and RFC-02.
- [ ] CHANGELOG exists.
- [ ] SECURITY policy exists.
- [ ] CONTRIBUTING guide exists.
- [ ] Issue templates for security review and RFC feedback exist.

## 12. Recommended next audit outputs

- [ ] Formal JSON Schemas.
- [ ] Machine-readable test vectors.
- [ ] Threat model / risk register.
- [ ] Compatibility matrix for proof versions.
- [ ] Independent cryptographic review.
- [ ] Implementation/specification separation plan.

## Final reviewer note

DELTA v2.5.2 test vectors are documentation-level audit vectors.
They are intended to make verifier behavior repeatable and reviewable without committing sensitive generated artifacts.
