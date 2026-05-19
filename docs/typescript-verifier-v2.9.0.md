# DELTA Protocol — TypeScript Verifier L0/L1 (v2.9.0)

Status: Experimental independent verifier  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.9.0 introduces a minimal TypeScript verifier for DELTA.

The goal is not to reimplement all DELTA proof layers.

The goal is to prove that the core DELTA canonicalization and hashing profile can be verified outside Python.

Strategic statement:

```text
DELTA is no longer Python-only at the canonical JSON / hash layer.
```

## 2. Scope

v2.9.0 includes:

- L0 canonical JSON vector verification,
- L0 SHA-256 verification,
- strict JSON parsing for duplicate key rejection,
- rejection of floating point numbers, NaN/Infinity, and unsafe integers,
- L1 basic DELTA record required-field check,
- L1 basic record hash recomputation by removing `record_hash`.

## 3. Out of scope

v2.9.0 does not verify:

- full JSON Schema registry,
- Ed25519 signatures,
- Proof of Replay,
- replay environment checks,
- Proof of Intent,
- Proof of Audit,
- Proof of Publication,
- Proof of Trust,
- Proof of Wallet,
- `.delta` bundle verification,
- signed bundle verification,
- Ethereum EIP-191/EIP-712,
- Bitcoin BIP-322.

These are intentionally deferred to later versions.

## 4. Install

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC\verifier\ts
npm install
```

## 5. Verify canonical vectors

```powershell
npm run verify-vectors
```

Expected final output:

```text
DELTA_TS_VERIFY_OK=True
```

## 6. Verify a basic record

```powershell
npm run verify-record -- C:\path\to\delta-record.json
```

This only checks the basic v2.9.0 L1 record hash model.

It does not verify signatures or higher proof layers.

## 7. Security boundary

The TypeScript verifier is experimental.

It does not replace the Python alpha reference implementation.

It does not prove legal truth, real-world truth, identity, signer authority, wallet ownership, regulatory compliance, or trust validity.

## 8. Future roadmap

Suggested next steps:

- v2.9.1 — TypeScript JSON Schema validation,
- v2.9.2 — TypeScript Ed25519 signed record verification,
- v2.9.3 — TypeScript `.delta` bundle verification,
- v2.9.4 — TypeScript signed bundle verification,
- v3.x — replay, intent, audit, publication, trust, and wallet profiles.
