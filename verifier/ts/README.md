# DELTA TypeScript Verifier v2.9.4

Status: **experimental independent verifier**
Scope: **L0/L1 + schema + Ed25519 signed record + `.delta` bundle + signed bundle verification**

## What this verifies

v2.9.4 verifies:

- canonical JSON vectors,
- schema compilation,
- Ed25519 signed records under the narrow v2.9.2 MVP profile,
- public `.delta` bundle container integrity,
- detached signed bundle signatures.

## Signed bundle verification scope

v2.9.4 checks:

- the `.delta` bundle passes v2.9.3 bundle verification,
- the detached signature JSON file is readable,
- the signature binds to the exact bundle file hash,
- public key hash is checked when declared,
- `signature_body_hash` is checked when declared,
- Ed25519 signature shape and cryptographic verification.

## Command

```bash
npm run verify-signed-bundle -- --bundle path/to/sample.delta --signature path/to/sample.delta.sig.json
```

Optional public key override:

```bash
npm run verify-signed-bundle -- --bundle path/to/sample.delta --signature path/to/sample.delta.sig.json --public-key ed25519:<hex>
```

## Security boundary

Signed bundle verification proves only that an Ed25519 key signed data bound to the exact `.delta` bundle hash.

It does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, trust validity, or correctness of contained proofs.

## 17. Audit notes and known hardening areas

External reviewers should pay special attention to three areas: canonical JSON, replay determinism, and wallet proof boundaries.

### 17.1 Canonical JSON

Canonical JSON is a critical cross-language risk area.

DELTA addresses this through the DELTA Canonical JSON Profile v1, aligned with the RFC 8785 / JCS direction, frozen test vectors, and strict rejection of ambiguous inputs such as duplicate keys, floating-point numbers, NaN, Infinity, and unsafe integers.

The TypeScript verifier independently checks the same canonical JSON vectors as the Python implementation.

Relevant command:

```powershell
npm run verify-vectors
```

Expected result:

```text
DELTA_TS_VERIFY_OK=True
```

### 17.2 Replay determinism

Proof of Replay is sensitive to nondeterminism.

Replay can be affected by:

- wall-clock time,
- random number generation,
- environment variables,
- dependency versions,
- operating system differences,
- network calls,
- external APIs,
- hardware-specific behavior.

DELTA treats this as a security boundary.

A successful replay does not automatically prove that the original execution environment was identical. Replay environment assumptions must be declared and checked separately. Unsupported or nondeterministic conditions should result in manual review rather than overclaiming.

### 17.3 Bitcoin BIP-322 boundary

The Bitcoin external / BIP-322-ready profile is intentionally conservative.

Unless full local cryptographic BIP-322 verification is implemented, Bitcoin external proofs must remain clearly marked as shape-only / external-pending and must not claim local cryptographic verification.

The expected boundary is:

```text
CRYPTO_SIGNATURE_VERIFIED=False
```

This is not a weakness if documented honestly. It is a deliberate anti-overclaiming boundary.

### 17.4 Public claim discipline

DELTA should continue to state that it proves cryptographic binding and verification results under declared assumptions.

It does not automatically prove:

- legal identity,
- signer authority,
- real-world truth,
- regulatory compliance,
- wallet ownership beyond the specific verified wallet profile,
- correctness of input data before signing,
- absence of systematic errors in measurement methods.
