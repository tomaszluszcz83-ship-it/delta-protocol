# DELTA TypeScript Verifier v2.9.2

Status: **experimental independent verifier**  
Scope: **L0/L1 + schema pre-verification + Ed25519 signed record MVP**

## What this verifies

v2.9.2 verifies:

- DELTA Canonical JSON Profile v1 subset,
- SHA-256 over canonical bytes,
- frozen canonical JSON vectors,
- basic DELTA record required fields,
- basic record hash recomputation,
- JSON Schema compilation and validation,
- Ed25519 signed record verification for the v2.9.2 TypeScript MVP profile.

## Ed25519 signed record MVP profile

For v2.9.2, signed record verification is intentionally narrow:

- `record_hash` is recomputed over the record with signature metadata fields removed,
- Ed25519 signature is verified over the UTF-8 bytes of the declared `record_hash`,
- `public_key_hash` is SHA-256 over the raw 32-byte Ed25519 public key,
- this verifier does not claim compatibility with all historical Python record profiles.

## Commands

Install:

```bash
cd verifier/ts
npm install
```

Run canonical vectors:

```bash
npm run verify-vectors
```

Run schema compilation:

```bash
npm run verify-schemas
```

Create a local signed record demo:

```bash
npm run create-signed-record-demo -- --out .delta/ts-signed-record-tests/R-292/signed-record.json
```

Verify a signed record:

```bash
npm run verify-signed-record -- --record .delta/ts-signed-record-tests/R-292/signed-record.json
```

Expected output:

```text
DELTA_TS_SIGNED_RECORD_VERIFY_OK=True
DELTA_TS_SIGNED_RECORD_SIGNATURE_OK=True
```

## What this does not verify

v2.9.2 does not verify:

- Proof of Replay,
- Proof of Intent authority or policy,
- Proof of Audit encryption/decryption,
- Proof of Publication anchoring truth,
- Proof of Trust authority policy,
- Proof of Wallet cryptographic profiles,
- `.delta` bundles,
- signed bundles,
- Ethereum EIP-191/EIP-712,
- Bitcoin BIP-322.

## Security boundary

This verifier is experimental.

Ed25519 verification proves that a raw Ed25519 public key verified a signature over the declared record hash under the narrow v2.9.2 TypeScript MVP profile.

It does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, or trust validity.
