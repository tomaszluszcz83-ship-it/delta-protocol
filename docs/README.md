# DELTA Documentation Index

**Status:** Public review documentation index  
**Version:** v2.5.3  
**Audience:** reviewers, security auditors, contributors, implementers

This directory is the entry point for DELTA Protocol documentation.

DELTA is an open, zero-token **Proof of Change** protocol. It is designed to create, verify, publish, audit, and chain cryptographic evidence about digital change.

DELTA is not a cryptocurrency, token, SaaS, marketplace, or account platform.

---

## 1. Start here

New reviewers should read these documents in order:

1. [`../README.md`](../README.md) — public project overview and quick start.
2. [`rfc/RFC-01-delta-core-protocol.md`](rfc/RFC-01-delta-core-protocol.md) — DELTA Core Protocol draft.
3. [`positioning/what-delta-proves.md`](positioning/what-delta-proves.md) — what DELTA proves and does not prove.
4. [`test-vectors/README.md`](test-vectors/README.md) — audit and test vector entry point.
5. [`reviewer-guide.md`](reviewer-guide.md) — guided review path for external reviewers.

---

## 2. Core model

DELTA is organized around the model:

```text
Before → Action → After → Evidence → Verification → Ledger
```

The core idea is that a digital change can be represented as a signed, hash-bound, replayable, auditable record.

Important security boundary:

```text
DELTA proves cryptographic consistency.
DELTA does not prove legal truth, real-world truth, identity, wallet balance, or regulatory compliance by itself.
```

---

## 3. RFC documents

| Document | Purpose |
|---|---|
| [`rfc/RFC-01-delta-core-protocol.md`](rfc/RFC-01-delta-core-protocol.md) | Core protocol model, terminology, canonical JSON profile, hash binding, proof layers, conformance levels. |
| [`rfc/RFC-02-proof-of-wallet.md`](rfc/RFC-02-proof-of-wallet.md) | Wallet/address-control profiles including Ed25519, Ethereum EIP-191, Ethereum EIP-712, and Bitcoin external/BIP-322-ready skeleton. |

RFC status is draft. RFC documents describe current implemented profiles and the intended core protocol model. They are not yet a final external standard.

---

## 4. Proof layers

DELTA currently documents and/or implements the following proof layers:

| Layer | Purpose |
|---|---|
| Proof of Change | Signed, hash-bound record of a digital change. |
| Proof of Replay | Re-run declared verification steps and compare outputs/hashes. |
| Proof of Intent | Bind a signed intent/approval object to a specific DELTA record hash. |
| Proof of Audit | Encrypt private evidence for an auditor while preserving hash binding. |
| Proof of Publication | Bind a record hash to a publication proof object. |
| Proof of Trust | Hash-chain trust ledger entries. |
| Proof of Wallet | Bind a wallet/address signature or external proof to a DELTA record hash. |

---

## 5. Wallet proof profiles

Proof of Wallet is documented in RFC-02 and currently includes:

| Standard | Status | Local cryptographic verification |
|---|---:|---:|
| `ed25519_address_control_v1` | reference/demo address-control profile | yes |
| `ethereum_eip191_personal_sign_v1` | Ethereum personal_sign profile | yes |
| `ethereum_eip712_typed_data_v1` | Ethereum typed-data profile | yes |
| `bitcoin_bip322_external_v1` | Bitcoin external/BIP-322-ready profile | no, shape-only/external-pending |

Bitcoin boundary:

```text
bitcoin_bip322_external_v1 is shape_only / external_pending.
CRYPTO_SIGNATURE_VERIFIED=False is intentional for this profile.
DELTA v2.4.0+ does not claim local script-level BIP-322 verification.
```

---

## 6. Audit and test vectors

Audit-oriented documentation:

| Document | Purpose |
|---|---|
| [`test-vectors/README.md`](test-vectors/README.md) | Overview of test vector documents. |
| [`test-vectors/TV-001-sensor-record.md`](test-vectors/TV-001-sensor-record.md) | Signed Sensor Record / Proof of Change. |
| [`test-vectors/TV-002-proof-of-intent.md`](test-vectors/TV-002-proof-of-intent.md) | Proof of Intent positive and negative checks. |
| [`test-vectors/TV-003-proof-of-audit.md`](test-vectors/TV-003-proof-of-audit.md) | Proof of Audit checks. |
| [`test-vectors/TV-004-proof-of-publication.md`](test-vectors/TV-004-proof-of-publication.md) | Proof of Publication checks. |
| [`test-vectors/TV-005-proof-of-trust.md`](test-vectors/TV-005-proof-of-trust.md) | Proof of Trust hash-chain checks. |
| [`test-vectors/TV-006-proof-of-wallet.md`](test-vectors/TV-006-proof-of-wallet.md) | Proof of Wallet checks. |
| [`audit/audit-checklist-v2.5.2.md`](audit/audit-checklist-v2.5.2.md) | Audit checklist for reviewers. |

---

## 7. Use cases

| Document | Purpose |
|---|---|
| [`use-cases/proof-of-reserves.md`](use-cases/proof-of-reserves.md) | How DELTA may support proof-of-reserves workflows. |
| [`use-cases/ci-cd-audit.md`](use-cases/ci-cd-audit.md) | CI/CD audit and change verification workflows. |

Use case documents are explanatory and do not by themselves create regulatory, legal, or financial claims.

---

## 8. Security and contribution

| Document | Purpose |
|---|---|
| [`../SECURITY.md`](../SECURITY.md) | Security reporting policy and sensitive data guidance. |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Contribution rules and proof-layer discipline. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Version history. |

Never commit private keys, seed phrases, tokens, generated decrypted evidence, or sensitive audit artifacts.

---

## 9. Minimal verification command

The simplest public verification command is:

```bash
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

---

## 10. Current status

DELTA is currently best described as:

```text
technical alpha reference implementation
+
RFC-style draft standard
+
public-review-ready open-source repository
```

It is ready for first external technical review. It is not yet a final external standard or an enterprise production system.
