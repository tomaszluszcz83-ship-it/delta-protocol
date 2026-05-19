# DELTA TypeScript Verifier v2.9.0

Status: **experimental independent verifier**  
Scope: **L0/L1 only**

## What this verifies

v2.9.0 verifies:

- DELTA Canonical JSON Profile v1 subset,
- SHA-256 over canonical bytes,
- frozen canonical JSON vectors from `tests/vectors/canonical-json/vectors.json`,
- basic DELTA record required fields,
- basic record hash recomputation by removing `record_hash` and hashing the remaining canonical JSON.

## What this does not verify

v2.9.0 does not verify:

- JSON Schema registry conformance,
- Ed25519 signatures,
- Proof of Replay,
- Proof of Intent,
- Proof of Audit,
- Proof of Publication,
- Proof of Trust,
- Proof of Wallet,
- `.delta` bundles,
- signed bundles,
- Ethereum EIP-191/EIP-712,
- Bitcoin BIP-322.

Those are intentionally out of scope.

## Install

```bash
cd verifier/ts
npm install
```

## Run L0 vectors

```bash
npm run verify-vectors
```

Expected final output:

```text
DELTA_TS_VERIFY_OK=True
```

## Run basic record check

```bash
npm run verify-record -- path/to/delta-record.json
```

Expected output for a matching basic record hash:

```text
DELTA_TS_RECORD_VERIFY_OK=True
```

## Security boundary

This verifier is an experimental cross-language verifier for canonicalization and basic hashing.

It does not replace the Python reference implementation.

It does not prove legal truth, real-world truth, identity, signer authority, wallet ownership, regulatory compliance, or validity of higher proof layers.
