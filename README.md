# DELTA Protocol

[![Latest release](https://img.shields.io/github/v/release/tomaszluszcz83-ship-it/delta-protocol?sort=semver)](https://github.com/tomaszluszcz83-ship-it/delta-protocol/releases)
[![License](https://img.shields.io/github/license/tomaszluszcz83-ship-it/delta-protocol)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.x-blue)](https://www.python.org/)

> **The internet can prove ownership. DELTA proves change.**

DELTA Protocol is an open, zero-token cryptographic protocol for creating and verifying **Proofs of Change**.

It is designed to prove that a declared digital change is bound to a specific record, evidence, verification result, replay method, intent, audit package, publication proof, trust chain entry, or wallet/address-control proof.

DELTA is **not** a cryptocurrency, token, SaaS, marketplace, or user-account platform.

---

## Current status

**Current maturity:** technical alpha / reference implementation / RFC draft.

DELTA is not yet a final external standard or enterprise-ready product. It is a working reference implementation and protocol draft suitable for public technical review, security review, audit discussion, and RFC-style feedback.

Current milestone:

```text
v2.5.0 — DELTA Core RFC-01 / Protocol Specification
```

---

## What DELTA proves

DELTA is based on the model:

```text
Before → Action → After → Evidence → Verification → Ledger
```

DELTA can prove cryptographic consistency between:

- a declared change,
- a signed DELTA record,
- before/after hashes,
- measurement method metadata,
- evidence commitments,
- replay verification output,
- signed intent,
- encrypted audit evidence,
- publication proof,
- trust-ledger entry,
- wallet/address-control proof.

DELTA proves **cryptographic binding**, not legal or real-world truth.

---

## What DELTA does not prove

DELTA does **not** prove by itself:

- legal ownership,
- legal approval,
- identity of a real-world person,
- wallet balance,
- regulatory compliance,
- truth of a ticket, invoice, contract, or external database,
- that evidence was not fabricated before hashing,
- external-world truth,
- full Bitcoin BIP-322 script-level correctness for `bitcoin_bip322_external_v1`.

External governance, legal interpretation, identity systems, audits, and regulatory processes may be layered on top of DELTA, but they are not automatically created by DELTA.

See:

```text
docs/positioning/what-delta-proves.md
```

---

## Core proof layers

DELTA currently includes the following proof layers:

| Layer | Status | Purpose |
|---|---:|---|
| Signed Sensor Record | implemented | signed machine-created Proof-of-Change record |
| Proof of Replay | implemented | reproduce declared measurement from a clean/fresh context |
| Proof of Intent | implemented | bind signed approval/intent to a full DELTA record hash |
| Intent Policy Reporting | implemented | report whether intent policy is declared/satisfied |
| Proof of Audit | implemented | encrypt private evidence for auditors and bind it to a record |
| Proof of Publication | implemented | bind a publication/timestamp proof object to a record |
| OpenTimestamps pending adapter | implemented | external timestamp evidence shape/binding layer |
| Proof of Trust | implemented | hash-chain trust ledger for record events |
| Proof of Wallet | implemented | wallet/address-control proof bound to a DELTA record |
| RFC-01 Core Protocol | draft | standardization document for DELTA core |
| RFC-02 Proof of Wallet | draft | standardization document for wallet proof profiles |

---

## Proof of Wallet profiles

DELTA currently supports these wallet/address-control profiles:

| Standard | Status | Verification level |
|---|---:|---|
| `ed25519_address_control_v1` | implemented | local signature verification |
| `ethereum_eip191_personal_sign_v1` | implemented | local Ethereum address recovery |
| `ethereum_eip712_typed_data_v1` | implemented | local typed-data signature recovery |
| `bitcoin_bip322_external_v1` | implemented skeleton | `shape_only` / `external_pending` |

Important Bitcoin boundary:

```text
bitcoin_bip322_external_v1 does not yet perform local cryptographic BIP-322 script-level verification.
CRYPTO_SIGNATURE_VERIFIED=False is intentional for this profile.
```

---

## Quick start

The simplest public verification path requires no private keys.

```bash
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

A minimal GitHub Actions verification workflow can be as small as:

```yaml
name: DELTA Verify

on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - name: Verify DELTA public proof artifacts
        run: python src/delta_cli.py verify-all
```

---

## Repository map

Key paths:

```text
src/delta_cli.py                         Core CLI verification entrypoint
tools/delta_sensor.py                    Sensor record creation tools
tools/delta_replay.py                    Replay verification
tools/delta_audit.py                     Proof of Audit encrypted evidence
tools/delta_publish.py                   Proof of Publication
tools/delta_trust.py                     Proof of Trust hash-chain ledger
tools/delta_wallet.py                    Proof of Wallet / Address Control
docs/rfc/RFC-01-delta-core-protocol.md   DELTA Core Protocol RFC draft
docs/rfc/RFC-02-proof-of-wallet.md       Proof of Wallet RFC draft
docs/positioning/what-delta-proves.md    Security boundary and positioning
docs/use-cases/proof-of-reserves.md      Proof of Reserves use case
docs/use-cases/ci-cd-audit.md            CI/CD audit use case
```

---

## RFC documents

Start here:

```text
docs/rfc/RFC-01-delta-core-protocol.md
```

Then read:

```text
docs/rfc/RFC-02-proof-of-wallet.md
docs/positioning/what-delta-proves.md
docs/use-cases/proof-of-reserves.md
docs/use-cases/ci-cd-audit.md
```

RFC-01 is a draft standardization document. It describes the current implemented DELTA profiles and the intended core protocol model, but it is not yet a final external standard.

---

## Security model

DELTA uses:

- SHA-256 hash binding,
- canonical JSON profile,
- detached signatures,
- full `delta-record.json` hash binding,
- evidence hashes,
- replay comparison,
- encrypted audit packages,
- hash-chain ledger entries,
- wallet signature proofs where supported.

Security boundaries are part of the protocol. DELTA must not claim more than it can verify cryptographically.

See:

```text
SECURITY.md
docs/positioning/what-delta-proves.md
docs/rfc/RFC-01-delta-core-protocol.md
```

---

## Roadmap

Near-term priorities:

1. Formal JSON schemas.
2. Stable test vectors for every proof type.
3. Threat model as a dedicated document.
4. Hardening canonical JSON rules.
5. Local Bitcoin BIP-322 verification for selected address/proof types.
6. GitHub Action packaging.
7. GitLab CI and Docker image.
8. Independent security review.
9. RFC feedback from security, audit, and open-source communities.

---

## Contributing

DELTA is in technical alpha. Feedback is welcome, especially from:

- cryptographers,
- security engineers,
- auditors,
- CI/CD maintainers,
- wallet developers,
- standards reviewers,
- open-source maintainers.

Read:

```text
CONTRIBUTING.md
SECURITY.md
```

Use the issue templates for RFC feedback and security-review requests.

---

## License

See:

```text
LICENSE
```
