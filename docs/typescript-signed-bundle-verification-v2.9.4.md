# DELTA Protocol — TypeScript Signed Bundle Verification (v2.9.4)

Status: Experimental TypeScript signed bundle verifier  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.9.4 adds TypeScript verification for detached signed `.delta` bundles.

This builds directly on:

```text
v2.9.3 — TypeScript .delta Bundle Verification
v2.8.0 — Python Signed DELTA Bundle
```

## 2. Scope

v2.9.4 includes:

- reading `.delta` bundle files,
- reusing TypeScript bundle integrity verification,
- reading detached signature JSON files,
- computing exact bundle file SHA-256,
- checking bundle hash binding,
- checking `signature_body_hash` when available,
- checking public key hash when available,
- verifying Ed25519 signatures using the existing TypeScript Ed25519 verifier.

## 3. Command

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC\verifier\ts

npm run verify-signed-bundle -- --bundle C:\path\to\sample.delta --signature C:\path\to\sample.delta.sig.json
```

Optional public key override:

```powershell
npm run verify-signed-bundle -- --bundle C:\path\to\sample.delta --signature C:\path\to\sample.delta.sig.json --public-key ed25519:<hex>
```

## 4. Expected output

```text
DELTA_TS_SIGNED_BUNDLE_VERIFY_OK=True
DELTA_TS_SIGNED_BUNDLE_BUNDLE_INTEGRITY_OK=True
DELTA_TS_SIGNED_BUNDLE_BUNDLE_HASH_BINDING_OK=True
DELTA_TS_SIGNED_BUNDLE_SIGNATURE_OK=True
```

## 5. Negative conditions

The verifier should reject:

- tampered bundle files,
- tampered detached signature files,
- bundle hash mismatch,
- public key hash mismatch,
- signature body hash mismatch,
- malformed Ed25519 signatures,
- invalid signatures,
- bundle container integrity failures.

## 6. Security boundary

v2.9.4 verifies that an Ed25519 key signed data bound to the exact `.delta` bundle hash.

It does not prove:

- legal identity,
- signer authority,
- real-world truth,
- regulatory compliance,
- wallet ownership,
- trust policy validity,
- proof-specific correctness of contained artifacts.

A signed bundle can still contain proofs that fail their own proof-specific verification.
