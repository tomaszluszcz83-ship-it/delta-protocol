# DELTA TypeScript Verifier v2.9.3

Status: **experimental independent verifier**  
Scope: **L0/L1 + schema pre-verification + Ed25519 signed record MVP + `.delta` bundle verification**

## What this verifies

v2.9.3 verifies:

- DELTA Canonical JSON Profile v1 subset,
- SHA-256 over canonical bytes,
- frozen canonical JSON vectors,
- basic DELTA record hash checks,
- JSON Schema compilation and validation,
- Ed25519 signed record verification for the v2.9.2 TypeScript MVP profile,
- `.delta` ZIP bundle structure and manifest integrity.

## Bundle verification scope

v2.9.3 checks:

- ZIP can be opened,
- `bundle_manifest.json` exists,
- duplicate filenames are rejected,
- path traversal is rejected,
- forbidden sensitive filename fragments are rejected,
- manifest-declared artifact SHA-256 hashes match,
- manifest-declared artifact sizes match,
- unreferenced artifacts are rejected.

## Commands

Install:

```bash
cd verifier/ts
npm install
```

Run existing checks:

```bash
npm run verify-vectors
npm run verify-schemas
```

Verify a `.delta` bundle:

```bash
npm run verify-bundle -- --bundle path/to/sample.delta
```

Expected successful output:

```text
DELTA_TS_BUNDLE_VERIFY_OK=True
```

## What this does not verify

v2.9.3 does not verify:

- signed bundle signatures,
- Proof of Replay,
- Proof of Intent authority or policy,
- Proof of Audit encryption/decryption,
- Proof of Publication anchoring truth,
- Proof of Trust authority policy,
- Proof of Wallet cryptographic profiles,
- Ethereum EIP-191/EIP-712,
- Bitcoin BIP-322.

## Security boundary

Bundle verification proves only that the `.delta` ZIP container matches its public manifest and anti-leak guardrails.

It does not prove that contained proofs are cryptographically valid.

It does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, or trust validity.
