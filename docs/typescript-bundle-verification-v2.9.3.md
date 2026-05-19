# DELTA Protocol — TypeScript .delta Bundle Verification (v2.9.3)

Status: Experimental TypeScript bundle verifier  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.9.3 adds TypeScript verification for public `.delta` bundle containers.

This is the TypeScript equivalent of public bundle structure and manifest integrity checks.

It does not verify signed bundles yet.

## 2. Scope

v2.9.3 includes:

- reading `.delta` as ZIP,
- requiring `bundle_manifest.json`,
- detecting duplicate filenames,
- detecting path traversal,
- detecting forbidden sensitive filename fragments,
- checking artifact SHA-256 against the manifest,
- checking artifact size against the manifest,
- rejecting unreferenced artifacts.

## 3. Command

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC\verifier\ts

npm run verify-bundle -- --bundle C:\path\to\sample.delta
```

Expected:

```text
DELTA_TS_BUNDLE_VERIFY_OK=True
```

## 4. Negative conditions

The verifier should reject:

- missing `bundle_manifest.json`,
- invalid manifest JSON,
- duplicate ZIP filenames,
- `../` path traversal,
- absolute paths,
- sensitive filename fragments such as `private`, `secret`, `.pem`, `.key`, `token`,
- artifact SHA-256 mismatch,
- artifact size mismatch,
- artifacts not referenced by the manifest.

## 5. Security boundary

v2.9.3 verifies the public `.delta` bundle container only.

It does not verify:

- signed bundle detached signatures,
- proof-specific cryptographic validity,
- replay correctness,
- intent authority,
- audit evidence truth,
- publication anchoring truth,
- trust policy acceptance,
- wallet ownership.

A valid bundle container can still contain invalid or untrusted proofs.

## 6. Future work

The next logical milestone is:

```text
v2.9.4 — TypeScript Signed Bundle Verification
```

That should verify detached Ed25519 signatures over exact bundle hashes.
