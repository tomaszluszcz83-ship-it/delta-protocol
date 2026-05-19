# DELTA Protocol — Capability Matrix (v2.15.1)

Status: Public-readiness documentation refresh  
Scope: What DELTA verifies today and what remains out of scope

## 1. Capability table

| Layer | Current status | What it verifies | What it does not prove |
|---|---:|---|---|
| Core Proof of Change | Implemented | Record/artifact binding | Real-world truth |
| Canonical JSON | Implemented | Deterministic JSON hashing profile | Semantic correctness of data |
| JSON Schemas | Implemented | Structural pre-verification | Cryptographic validity |
| Proof of Replay | Implemented | Replay result under declared assumptions | Identical original environment |
| Proof of Intent | Implemented | Intent-record binding and signed intent chain | Legal authority |
| Proof of Audit | Implemented | Audit package/evidence encryption binding | Public truth of private evidence |
| Proof of Publication | Implemented | Record hash bound to publication proof | External source truth beyond profile |
| Proof of Trust | Foundation | Trust/delegation record structure | Global trust by itself |
| Wallet proof | Partial profiles | Selected address-control profiles | Universal wallet truth |
| `.delta` bundle | Implemented | Public artifact container integrity | Validity of contained proofs by itself |
| Signed bundle | Implemented | Ed25519 signature over bundle hash | Legal identity of signer |
| TypeScript verifier | Partial / expanding | Selected cross-language verification profiles | Full Python parity |
| Private evidence commitment | Implemented | Disclosed evidence matches commitment/opening | Evidence truth |
| Private evidence Merkle set | Implemented | Disclosed item belongs to public root | Completeness outside committed set |
| ZK provenance | Design next | Not implemented yet | No ZK claims yet |

## 2. TypeScript verifier matrix

| TypeScript capability | Status |
|---|---:|
| Canonical JSON vectors | Implemented |
| Schema validation | Implemented |
| Signed record verification | Implemented |
| `.delta` bundle verification | Implemented |
| Signed bundle verification | Implemented |
| CLI JSON output | Implemented |
| CLI contract tests | Implemented |
| Intent record binding | Implemented |
| Intent detached signature | Implemented |
| Intent registry binding | Implemented |
| Intent policy/deadline check | Implemented |
| Intent contract tests | Implemented |
| Audit verification parity | Not implemented |
| Publication proof parity | Not implemented |
| Wallet proof parity | Not implemented |
| ZK verification | Not implemented |

## 3. Recommended public wording

Use:

```text
DELTA verifies cryptographic binding and verification results under declared assumptions.
```

Avoid:

```text
DELTA proves legal compliance.
DELTA proves the evidence is true.
DELTA proves the signer was authorized.
DELTA proves the organization is trustworthy.
```
