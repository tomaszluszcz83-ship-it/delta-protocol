# DELTA Protocol — TypeScript Verifier Matrix (v2.9.5)

Status: Release readiness / verifier capability matrix  
Implementation path: `verifier/ts/`  
Type: Documentation and public-readiness milestone

## 1. Purpose

v2.9.5 freezes the current TypeScript verifier capability map after the v2.9.0–v2.9.4 implementation sequence.

This document explains what the TypeScript verifier currently verifies, what it does not verify, and how it compares with the Python Alpha Reference Implementation.

The purpose is to prevent overclaiming before public review.

## 2. TypeScript verifier status

The TypeScript verifier is an **experimental independent verifier**.

It is not yet the primary DELTA reference implementation.

The Python implementation remains the Alpha Reference Implementation.

The TypeScript implementation is important because it proves that DELTA verification rules can be implemented outside Python and can move toward browser, CI/CD, and cross-language verification.

## 3. v2.9.x capability matrix

| Area | Python implementation | TypeScript verifier | TS status |
| --- | --- | --- | --- |
| Canonical JSON vectors | Supported | Supported | Implemented in v2.9.0 |
| SHA-256 hashing | Supported | Supported | Implemented in v2.9.0 |
| Basic record hash recomputation | Supported | Supported, narrow profile | Implemented in v2.9.0 |
| JSON Schema validation | Supported as pre-verification | Supported as pre-verification | Implemented in v2.9.1 |
| Ed25519 signed record verification | Supported in Python profiles | Supported for TS MVP profile | Implemented in v2.9.2 |
| `.delta` public bundle verification | Supported | Supported | Implemented in v2.9.3 |
| Signed `.delta` bundle verification | Supported | Supported | Implemented in v2.9.4 |
| Proof of Replay | Supported in Python tooling | Not implemented | Future work |
| Replay environment check | Supported in Python tooling | Not implemented | Future work |
| Proof of Intent signature verification | Supported in Python tooling | Not implemented | Future work |
| Proof of Audit package verification/decryption | Supported in Python tooling | Not implemented | Future work |
| Proof of Publication verification | Supported in Python tooling | Not implemented | Future work |
| Trust Ledger verification | Supported in Python tooling | Not implemented | Future work |
| Wallet proof profiles | Supported in Python tooling | Not implemented | Future work |
| Ethereum EIP-191 | Supported in Python tooling | Not implemented | Future work |
| Bitcoin external/BIP-322-ready shape profile | Supported in Python tooling | Not implemented | Future work |
| Proof-specific verification of bundle contents | Supported by separate Python tools | Not implemented in bundle verifier | Future work |

## 4. TypeScript verifier levels

### L0 — Canonical data layer

Implemented.

Includes:

- DELTA Canonical JSON Profile v1 compatibility checks,
- SHA-256 hashing,
- frozen test vector verification,
- rejection of duplicate keys, floats, NaN, Infinity, and unsafe integers.

### L1 — Structural and basic record layer

Partially implemented.

Includes:

- basic record required-field checks,
- basic record hash recomputation,
- JSON Schema pre-verification.

Important boundary:

Schema validation is not cryptographic verification.

### L2 — Signature and container layer

Partially implemented.

Includes:

- Ed25519 signed record verification for the TypeScript MVP profile,
- public `.delta` bundle verification,
- signed `.delta` bundle verification.

Important boundary:

Signed bundle verification proves that an Ed25519 key signed data bound to the exact bundle hash.

It does not prove legal identity, signer authority, real-world truth, or validity of contained proofs.

### L3 — Proof-specific verification layer

Not yet implemented in TypeScript.

Includes future work such as:

- Replay verification,
- Intent verification,
- Audit verification,
- Publication verification,
- Trust Ledger verification,
- Wallet proof verification.

### L4 — Policy and trust layer

Not yet implemented in TypeScript.

Includes future work such as:

- registry policy,
- key revocation,
- trust delegation,
- verifier policy profiles,
- enterprise policy gates.

## 5. What TypeScript verifies today

As of v2.9.5, the TypeScript verifier can independently verify:

```text
canonical JSON vectors
SHA-256 hash outputs
basic record hash recomputation
JSON Schema registry compileability
named JSON Schema validation
Ed25519 signed record MVP profile
public .delta bundle integrity
signed .delta bundle integrity and detached Ed25519 signature binding
```

## 6. What TypeScript does not verify today

As of v2.9.5, the TypeScript verifier does not verify:

```text
Proof of Replay
Replay environment assumptions
Proof of Intent authority or policy
Proof of Audit encrypted evidence correctness
Proof of Publication anchoring truth
Trust Ledger policy
Wallet ownership
Ethereum EIP-191 or EIP-712
Bitcoin BIP-322 cryptographic verification
regulatory compliance
legal identity
signer authority
real-world truth of evidence
```

## 7. Bundle verification boundary

The TypeScript `.delta` bundle verifier checks container integrity:

- ZIP readability,
- required `bundle_manifest.json`,
- artifact SHA-256 checks,
- duplicate filename rejection,
- path traversal rejection,
- forbidden sensitive filename fragment rejection,
- unreferenced artifact rejection.

It does not verify the proof-specific correctness of each artifact inside the bundle.

## 8. Signed bundle verification boundary

The TypeScript signed bundle verifier checks:

- bundle integrity through the v2.9.3 bundle verifier,
- exact `.delta` file hash binding,
- `signature_body_hash` self-check,
- public key hash compatibility with Python `delta_bundle_sign.py`,
- Ed25519 detached signature verification.

It does not prove:

- legal identity,
- signer authority,
- real-world truth,
- wallet ownership,
- regulatory compliance,
- trust validity,
- correctness of contained proofs.

## 9. Public-readiness statement

The TypeScript verifier is ready to be presented as an **experimental independent verifier** for selected DELTA verification layers.

It is not yet a complete verifier for the entire DELTA Protocol.

Recommended public wording:

```text
DELTA includes an experimental TypeScript verifier for canonical JSON, schema pre-verification, basic record checks, Ed25519 signed records, public .delta bundles, and signed .delta bundles.
The Python implementation remains the Alpha Reference Implementation.
Proof-specific TypeScript verification for replay, intent, audit, publication, trust, and wallet profiles remains future work.
```

## 10. Recommended next milestones

Recommended next steps after v2.9.5:

```text
v2.10.0 — TypeScript Verifier Public README Refresh
v2.10.1 — TypeScript CLI Error Codes / Machine-Readable JSON Output
v2.10.2 — TypeScript Proof of Intent Verification MVP
v2.10.3 — TypeScript Replay Environment Check MVP
```

Do not add all proof layers at once.

Continue incremental, testable milestones.
