# DELTA TypeScript Verifier v2.9.1

Status: **experimental independent verifier**  
Scope: **L0/L1 + schema pre-verification**

## What this verifies

v2.9.1 verifies:

- DELTA Canonical JSON Profile v1 subset,
- SHA-256 over canonical bytes,
- frozen canonical JSON vectors from `tests/vectors/canonical-json/vectors.json`,
- basic DELTA record required fields,
- basic record hash recomputation by removing `record_hash`,
- JSON Schema compilation from the repository-local `schemas/` registry,
- JSON Schema validation for selected proof artifacts.

## What this does not verify

v2.9.1 does not verify:

- Ed25519 signatures,
- Proof of Replay,
- Proof of Intent cryptographic signatures,
- Proof of Audit encryption/decryption,
- Proof of Publication anchoring truth,
- Proof of Trust authority policy,
- Proof of Wallet cryptographic profile verification,
- `.delta` bundles,
- signed bundles,
- Ethereum EIP-191/EIP-712,
- Bitcoin BIP-322.

Schema validation is a **pre-verification step only**.

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

## Compile schemas

```bash
npm run verify-schemas
```

Expected final output:

```text
DELTA_TS_SCHEMA_VERIFY_OK=True
```

## Validate a file against a named schema

```bash
npm run validate-schema -- --schema delta-record --file path/to/delta-record.json
```

Supported schema names:

```text
delta-common
delta-record
intent-attestation
audit-package
publication-proof
trust-ledger
wallet-proof
schema-registry
```

## Security boundary

This verifier is experimental.

JSON Schema validation does not prove:

- hash correctness,
- canonical JSON correctness,
- signature correctness,
- replay correctness,
- intent authority,
- audit evidence truth,
- publication truth,
- wallet ownership,
- legal truth,
- regulatory compliance.

Schema validation only checks that JSON shape is compatible with a declared schema.
