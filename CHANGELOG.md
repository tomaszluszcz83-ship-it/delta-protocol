# CHANGELOG

All notable DELTA Protocol milestones are summarized here.

DELTA is currently a technical alpha / reference implementation / RFC draft. Version entries below document protocol milestones, not enterprise production readiness.

---

## v2.5.1 — Public Readiness Documentation

Public-readiness documentation update.

Adds or updates:

- README.md
- CHANGELOG.md
- SECURITY.md
- CONTRIBUTING.md
- GitHub issue templates for RFC feedback and security review

Purpose:

- make the repository understandable to public reviewers,
- clarify what DELTA is and is not,
- point to RFC-01/RFC-02,
- document security reporting and contribution rules,
- prepare for public technical feedback.

---

## v2.5.0 — Core Protocol RFC-01

Standardization milestone.

Adds:

- RFC-01: DELTA Core Protocol Specification
- RFC-02: Proof of Wallet draft
- What DELTA Proves positioning document
- Proof of Reserves use case
- CI/CD Audit use case

Purpose:

- define DELTA as an open Proof of Change protocol,
- document the Before → Action → After → Evidence → Verification → Ledger model,
- describe canonical JSON and SHA-256 hash binding,
- distinguish the abstract protocol model from implemented profiles,
- document proof layers and security boundaries.

---

## v2.4.0 — Bitcoin BIP-322 External Wallet Proof

Adds:

- `bitcoin_bip322_external_v1`
- Bitcoin wallet challenge generation
- external Bitcoin proof object support
- signature/proof shape verification
- signature format validation
- full `delta-record.json` hash binding
- explicit `external_pending` verification mode
- explicit `CRYPTO_SIGNATURE_VERIFIED=False` reporting

Security boundary:

- no local cryptographic BIP-322 script-level verification is claimed in v2.4.0,
- this profile is `shape_only` / `external_pending`.

---

## v2.3.2 — Ethereum EIP-712 Wallet Proof

Adds:

- `ethereum_eip712_typed_data_v1`
- EIP-712 typed-data challenge generation
- EIP-712 typed-data signing with local demo ETH key
- Ethereum typed-data signature recovery verification
- full `delta-record.json` hash binding
- typed-data hash reporting

---

## v2.3.1 — Ethereum EIP-191 Wallet Proof

Adds:

- `ethereum_eip191_personal_sign_v1`
- `eth-keygen` for local demo testing
- `create-proof --eth-private-key`
- externally supplied `--signature`
- Ethereum `personal_sign` address recovery verification
- full `delta-record.json` hash binding
- record hash inside signed challenge body

---

## v2.3.0 — Proof of Crypto Wallet / Address Control

Adds:

- `ed25519_address_control_v1`
- wallet challenge generation
- wallet proof creation
- wallet proof verification
- full `delta-record.json` hash binding
- record hash inside signed challenge body
- tamper detection for record hash and signature

---

## v2.2.0 — Proof of Trust

Adds:

- hash-chain trust ledger,
- append-entry flow,
- verify-ledger flow,
- role and event-type checks,
- record binding,
- previous-entry hash checks,
- tamper detection.

---

## v2.0.1 — OpenTimestamps Pending Adapter

Adds:

- OpenTimestamps pending-style external evidence adapter,
- external file hash verification,
- publication proof binding to full DELTA record hash.

---

## v2.0.0 — Proof of Publication

Adds:

- `tools/delta_publish.py`
- record hash calculation,
- publication proof creation,
- publication proof verification,
- local timestamp proof profile,
- self-check and proof-body hash verification.

---

## v1.9.0 — Proof of Audit

Adds:

- `tools/delta_audit.py`
- auditor X25519 key generation,
- evidence encryption for auditors,
- audit package verification without decryption,
- auditor-side decryption,
- full `delta-record.json` hash binding,
- ciphertext/AAD hash verification.

---

## v1.8.2 — Intent Policy Reporting

Adds:

- `intent_policy` reporting in signed sensor records,
- `--intent-required`,
- `--intent-deadline`,
- `--intent-policy-id`,
- report-only policy statuses,
- full record-hash binding preserved.

---

## v1.8.1 — Replay Intent Verification

Adds:

- optional Proof of Intent bundle verification inside replay,
- full `delta-record.json` hash binding,
- intent verification status reporting.

---

## v1.8.0 — Proof of Intent

Adds:

- detached intent attestation,
- intent public key registry,
- intent signature verification,
- intent binding to full DELTA record hash,
- manipulation detection.

---

## Earlier milestones

Earlier milestones established:

- DELTA-0 public proof verification,
- Python CLI verification,
- signed GitHub Action sensor records,
- embedded executor public key in signed sensor records,
- canonical JSON hashing tests,
- file-audit sensor records,
- replay verification from a fresh clone,
- RFC-00 for the Sensor Record layer.

