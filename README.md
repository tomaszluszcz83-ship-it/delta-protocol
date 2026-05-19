# DELTA Protocol

> **The internet can prove ownership. DELTA proves change.**

DELTA Protocol is an open, zero-token cryptographic protocol for creating, binding, packaging, publishing, and verifying **Proofs of Change**.

It is designed for software, CI/CD, audit trails, sensor systems, private enterprise evidence, public verification, and future privacy-preserving ZK provenance.

DELTA is not a cryptocurrency, token, blockchain, SaaS platform, marketplace, or user-account system.

It is a protocol and reference implementation for cryptographically proving that a declared change is bound to declared evidence, verification results, signatures, intent, audit artifacts, publication proofs, trust context, and private evidence commitments.

---

## Current status

```text
Current public milestone: v2.15.0
Current readiness refresh: v2.15.1
Next technical milestone: v2.16.0 — ZK Statement Design
```

DELTA currently includes:

- Core Proof of Change model
- Canonical JSON / JCS-compatible profile
- JSON Schema registry
- Proof of Replay
- Proof of Intent
- Proof of Audit
- Proof of Publication
- Proof of Trust foundations
- Wallet / address-control proof profiles
- Portable `.delta` bundles
- Detached signed bundles
- TypeScript verifier profiles
- TypeScript CLI JSON output contracts
- TypeScript Proof of Intent verification chain
- Private Evidence Commitments
- Private Evidence Merkle Set
- ZK-ready public-root / private-witness preparation layer

---

## Core model

DELTA represents change as:

```text
Before → Action → After → Evidence → Verification → Ledger
```

A DELTA record binds:

```text
what existed before,
what action was performed,
what existed after,
what evidence supports the claim,
how verification was performed,
and how the result is chained, signed, packaged, published, or audited.
```

---

## What DELTA proves

DELTA proves cryptographic relationships between artifacts.

Depending on the enabled profile, DELTA can prove that:

- a record has a specific cryptographic hash,
- a signature was made by a specific cryptographic key,
- an intent attestation is bound to a record,
- a detached intent signature is valid,
- a signing key is present in a declared registry,
- a local policy/deadline check was satisfied under declared time,
- a bundle has not been tampered with,
- a bundle was signed by a specific Ed25519 key,
- a publication proof is bound to a record hash,
- a private evidence commitment matches disclosed evidence and opening data,
- a disclosed evidence item belongs to a public Merkle evidence root.

---

## What DELTA does not prove

DELTA does not automatically prove:

- legal identity,
- signer authority,
- regulatory compliance,
- real-world truth,
- sensor honesty,
- organizational approval,
- evidence completeness outside the committed set,
- policy correctness,
- legal validity of evidence,
- absence of other evidence,
- correctness of input data before signing or committing.

This is intentional.

DELTA is a cryptographic proof layer, not an oracle of reality or law.

---

## Why DELTA is zero-token

DELTA does not require a native token.

The protocol is designed around:

- SHA-256 hashes,
- canonical JSON,
- digital signatures,
- local verification,
- public/private key cryptography,
- append-only records,
- optional publication proofs,
- optional bundles,
- optional private evidence commitments,
- optional future ZK proofs.

External chains or timestamping systems may be used as optional anchors, but DELTA itself does not require a blockchain or token.

---

## Main proof layers

### Proof of Change

Core DELTA record binding:

```text
Before → Action → After → Evidence → Verification → Ledger
```

### Proof of Intent

Proof that a human or authorized system declared intent for a specific change.

Current TypeScript verifier support includes:

- record hash binding,
- detached Ed25519 intent signature verification,
- local registry public key binding,
- local policy/deadline checks,
- machine-readable JSON output,
- contract tests.

### Proof of Replay

A replay result can verify that a declared procedure reproduces expected outputs under declared assumptions.

Replay does not prove that the original environment was identical.

### Proof of Audit

Private evidence can be encrypted for an auditor and verified for binding without public disclosure.

### Proof of Publication

A record hash can be bound to a publication proof or external timestamp-like proof.

### Proof of Trust

DELTA supports trust-ledger and delegation concepts while preserving a strict distinction between cryptographic validity and trust validity.

### Proof of Wallet / Address Control

DELTA supports wallet/address proof profiles.

Ethereum EIP-191 `personal_sign` verification is supported.

Bitcoin external / BIP-322-ready profile remains conservative and must be treated as `shape_only` / `external_pending` unless full local cryptographic verification is implemented.

Expected boundary:

```text
CRYPTO_SIGNATURE_VERIFIED=False
```

### Private Evidence Commitments

DELTA can publish commitments to private evidence without publishing the raw evidence.

This is not encryption and not ZK.

### Private Evidence Merkle Set

DELTA can publish a Merkle root over multiple private evidence commitments and later selectively disclose one evidence item with a private opening and Merkle proof.

This prepares the public-root / private-witness structure required for future ZK provenance.

---

## TypeScript verifier

The TypeScript verifier is an experimental cross-language verifier focused on selected profiles.

It currently supports:

- canonical JSON vector verification,
- schema validation,
- Ed25519 signed-record verification,
- `.delta` bundle verification,
- signed bundle verification,
- CLI JSON output wrappers,
- CLI contract tests,
- Proof of Intent verification chain:
  - record binding,
  - detached signature,
  - registry binding,
  - policy/deadline checks,
  - intent contract tests.

The TypeScript verifier does not yet implement every Python reference feature.

---

## Private evidence and future ZK

DELTA has reached the preparation layer for privacy-preserving public verification.

Current foundation:

```text
v2.14.0 — Private Evidence Commitment Profile
v2.15.0 — Private Evidence Merkle Set
```

Next design milestone:

```text
v2.16.0 — ZK Statement Design / Public Inputs vs Private Witness
```

The first candidate ZK statement is:

```text
I know private evidence included under this public Merkle root,
and that evidence satisfies policy P,
without revealing the evidence.
```

DELTA will not treat ZK as magic.

Future ZK proofs must specify:

- exact public inputs,
- exact private witness,
- exact circuit statement,
- exact proof profile,
- exact limitations,
- exact trust assumptions.

---

## Repository structure

```text
docs/                 Protocol documentation and milestone docs
docs/security/        Threat model, risk register, boundaries, incident guidance
docs/rfc/             RFC-style protocol documents
docs/standard/        Canonical JSON, schema registry, conformance foundations
docs/intent/          Proof of Intent documentation
docs/audit/           Proof of Audit documentation
docs/publication/     Proof of Publication documentation
docs/private-evidence/ Private evidence commitment and Merkle set docs
docs/zk/              ZK design documents
schemas/              JSON Schema registry
tools/                Python reference tools
src/                  Python CLI/reference implementation
verifier/ts/          Experimental TypeScript verifier
tests/                Vectors and test materials
```

---

## Quick verification commands

Python reference checks:

```powershell
python src/delta_cli.py verify-all

python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
```

TypeScript verifier checks:

```powershell
cd verifier\ts

npm install
npm run build
npm run verify-vectors
npm run verify-schemas
```

TypeScript contract checks:

```powershell
cd C:\path\to\delta-protocol

python tools\delta_ts_cli_contract_tests.py
python tools\delta_ts_intent_contract_tests.py
```

Private evidence commitment checks:

```powershell
python tools\delta_private_evidence_commitment.py verify-public --public path\to\private-evidence-commitment.public.json
```

Private evidence Merkle set checks:

```powershell
python tools\delta_private_evidence_set.py verify-public --public path\to\private-evidence-set.public.json
```

---

## Security posture

DELTA uses a strict anti-overclaiming model.

Every proof layer must distinguish:

```text
cryptographic validity
trust validity
legal validity
real-world truth
policy sufficiency
regulatory sufficiency
```

A cryptographically valid artifact can still be legally insufficient, operationally misleading, or based on false input data.

DELTA makes these boundaries explicit.

---

## Implementation status

Current Python code is an Alpha Reference Implementation.

Current TypeScript verifier is an experimental cross-language verifier for selected profiles.

Production-grade verifiers may later be implemented in Rust, Go, or other languages with frozen vectors and conformance suites.

---

## Roadmap snapshot

Near-term:

```text
v2.15.1 — Public README / documentation readiness refresh
v2.16.0 — ZK Statement Design / Public Inputs vs Private Witness
v2.17.0 — ZK Threat Model + Circuit Candidate Specification
v3.0.0-alpha — ZK Provenance Proof of Concept
```

Future:

```text
ZK proof packages
ZK report export
browser-verifiable ZK summaries
policy circuit registry
signed policy artifacts
private enterprise audit certificates
```

---

## License

Apache-2.0.

---

## Project positioning

DELTA Protocol is built for environments where the most important question is not only:

```text
Who owns what?
```

but:

```text
What changed, who intended it, what evidence supports it, how was it verified, and can that be proven later?
```

DELTA proves change.
