# DELTA Protocol — TypeScript JSON Schema Validation (v2.9.1)

Status: Experimental TypeScript schema pre-verification  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.9.1 extends the experimental TypeScript verifier with JSON Schema validation.

This keeps the TypeScript roadmap disciplined:

```text
v2.9.0 = canonical JSON + SHA-256 + basic record hash
v2.9.1 = JSON Schema pre-verification
v2.9.2 = Ed25519 signed record verification
```

## 2. Scope

v2.9.1 includes:

- loading repository-local schemas from `schemas/`,
- compiling schemas with AJV 2020,
- validating selected JSON artifacts against named schemas,
- validating schema registry compileability,
- reporting `DELTA_TS_SCHEMA_VERIFY_OK=True` when all schemas compile.

## 3. Supported named schemas

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

## 4. Commands

Install:

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC\verifier\ts
npm install
```

Compile all schemas:

```powershell
npm run verify-schemas
```

Validate a JSON file:

```powershell
npm run validate-schema -- --schema delta-record --file C:\path\to\delta-record.json
```

## 5. Security boundary

JSON Schema validation is pre-verification only.

It does not replace:

- canonical JSON validation,
- hash recomputation,
- signature verification,
- replay verification,
- intent verification,
- audit verification,
- publication verification,
- trust policy checks,
- wallet proof verification,
- bundle verification,
- signed bundle verification.

A schema-valid artifact can still be cryptographically invalid or untrusted.

## 6. Out of scope

v2.9.1 does not add:

- Ed25519 signature verification,
- Ethereum verification,
- Bitcoin BIP-322 verification,
- bundle verification,
- signed bundle verification,
- replay environment verification.

Those remain future milestones.
