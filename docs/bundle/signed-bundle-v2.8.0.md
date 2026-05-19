# DELTA Protocol — Signed Bundle Profile (v2.8.0)

Status: Technical Alpha / detached signature profile  
Profile: `delta_signed_bundle_v2_8_0`

## 1. Purpose

v2.7.2 introduced portable `.delta` bundles.

v2.8.0 adds a detached Ed25519 signature profile for those bundles.

The goal is to let a sender sign the exact `.delta` bundle bytes so that a receiver can verify that:

- the exact bundle file hash was signed,
- the signature body has not changed,
- the Ed25519 signature verifies against the declared public key,
- the signer public key hash is stable and auditable.

## 2. What this proves

A valid signed bundle proves that:

- an Ed25519 private key signed a signature body,
- that signature body contains the SHA-256 hash of the exact `.delta` file,
- the bundle file supplied to the verifier matches that signed hash.

## 3. What this does not prove

A signed bundle does not prove:

- legal identity,
- signer authority,
- regulatory compliance,
- real-world truth,
- wallet balance,
- that the contained DELTA proofs are valid,
- that the sender is trustworthy,
- that the private signing key was not compromised.

A receiver MUST still run:

```powershell
python tools\delta_bundle.py verify --bundle sample.delta --dir extracted
```

and all proof-specific DELTA verifiers for the contained artifacts.

## 4. Private key handling

Private signing keys MUST NOT be committed.

Private signing keys MUST NOT be pasted into chat, tickets, reports, or bundles.

Recommended local path:

```text
C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\
```

## 5. Commands

Generate a local signing key:

```powershell
python tools\delta_bundle_sign.py keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_BUNDLE_SIGNING_PRIVATE_KEY.json `
  --public-out .delta\bundle-tests\B-280\bundle-signing-public.json `
  --force
```

Sign a bundle:

```powershell
python tools\delta_bundle_sign.py sign `
  --bundle .delta\bundle-tests\B-280\sample.delta `
  --private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_BUNDLE_SIGNING_PRIVATE_KEY.json `
  --out .delta\bundle-tests\B-280\sample.delta.sig.json `
  --signer local-bundle-signer `
  --purpose "DELTA v2.8.0 signed bundle test"
```

Verify:

```powershell
python tools\delta_bundle_sign.py verify `
  --bundle .delta\bundle-tests\B-280\sample.delta `
  --signature .delta\bundle-tests\B-280\sample.delta.sig.json
```

Expected:

```text
DELTA_SIGNED_BUNDLE_VERIFY_OK=True
DELTA_SIGNED_BUNDLE_SIGNATURE_OK=True
DELTA_SIGNED_BUNDLE_BUNDLE_HASH_OK=True
```

## 6. Negative test expectation

If the `.delta` file changes after signing, verification MUST fail:

```text
DELTA_SIGNED_BUNDLE_VERIFY_OK=False
DELTA_SIGNED_BUNDLE_BUNDLE_HASH_OK=False
DELTA_SIGNED_BUNDLE_REASON_BUNDLE_HASH_OK=bundle_hash_mismatch
```

## 7. Relationship to v2.7.2

v2.7.2 verifies bundle-level integrity.

v2.8.0 adds sender-key signature binding to the exact bundle file.

Both checks are needed:

- `delta_bundle.py verify` checks container structure and manifest artifact hashes,
- `delta_bundle_sign.py verify` checks detached signature binding to the bundle bytes.

## 8. Future work

Future versions may add:

- signed bundle key registry,
- revocation and invalidation entries,
- trust-ledger integration,
- multiple signatures,
- threshold signatures,
- hardware key support,
- public bundle publication proofs.
