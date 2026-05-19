# DELTA Protocol — TypeScript Ed25519 Signed Record Verification (v2.9.2)

Status: Experimental TypeScript signature verification MVP  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.9.2 adds the first TypeScript Ed25519 signature verification layer.

This is deliberately narrow.

It does not implement wallet proofs, bundle signatures, replay, intent, audit, publication, or trust policy.

## 2. Scope

v2.9.2 includes:

- Ed25519 signature verification using Node.js crypto,
- raw 32-byte Ed25519 public key handling,
- SHA-256 public key hash check,
- signed record hash recomputation,
- signed record CLI verification,
- local signed record demo generation.

## 3. Signed record MVP profile

For this release:

```text
message = UTF-8 bytes of declared record_hash
record_hash = SHA-256(canonical JSON of record with signature metadata removed)
public_key_hash = SHA-256(raw 32-byte Ed25519 public key)
```

The signature metadata fields excluded from record hash include:

```text
record_hash
signature
ed25519_signature
public_key
signer_public_key
public_key_hash
signer_public_key_hash
signature_algorithm
signature_profile
signature_target
signature_status
signature_verified
signature_body_hash
```

## 4. Commands

Create local demo:

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC\verifier\ts

npm run create-signed-record-demo -- --out ..\..\.delta\ts-signed-record-tests\R-292\signed-record.json
```

Verify local demo:

```powershell
npm run verify-signed-record -- --record ..\..\.delta\ts-signed-record-tests\R-292\signed-record.json
```

Expected:

```text
DELTA_TS_SIGNED_RECORD_VERIFY_OK=True
DELTA_TS_SIGNED_RECORD_SIGNATURE_OK=True
```

## 5. Negative tests

A verifier should reject:

- changed record body,
- changed signature,
- changed public key,
- changed record hash,
- changed public key hash.

## 6. Security boundary

This release verifies a narrow Ed25519 signed record profile.

It does not prove:

- legal identity,
- signer authority,
- real-world truth,
- regulatory compliance,
- trust policy acceptance,
- wallet ownership,
- that the record was created by a specific human,
- that the signed record is valid under all DELTA proof profiles.

## 7. Future work

Future TypeScript verifier milestones may add:

- Python-compatible historical signed sensor record profiles,
- Ed25519 registry checks,
- signed bundle verification,
- Proof of Intent verification,
- Trust Ledger policy checks.
