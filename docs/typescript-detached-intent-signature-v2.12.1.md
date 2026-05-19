# DELTA Protocol — TypeScript Detached Intent Signature Verification (v2.12.1)

Status: Experimental TypeScript Proof of Intent signature verification milestone  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.12.1 extends the TypeScript Proof of Intent verifier with detached Ed25519 intent signature verification.

v2.12.0 verified record hash binding between an intent attestation and a DELTA record.

v2.12.1 adds detached signature verification over a canonical signature body that binds to the canonical intent attestation hash.

## 2. Scope

v2.12.1 verifies:

- record hash binding from v2.12.0,
- detached intent signature JSON readability,
- `signature_body_hash` self-check,
- intent hash binding,
- optional signature-body record hash consistency,
- public key hash check when declared,
- Ed25519 signature shape,
- Ed25519 signature verification over canonical `signature_body`.

## 3. Commands

Create a local signed intent demo:

```powershell
cd verifier\ts

npm run create-signed-intent-demo -- --out-dir ..\..\.delta\ts-intent-signature-tests\I-2121
```

Verify human-readable output:

```powershell
npm run verify-intent -- --record ..\..\.delta\ts-intent-signature-tests\I-2121\delta-record.json --intent ..\..\.delta\ts-intent-signature-tests\I-2121\intent-attestation.json --signature ..\..\.delta\ts-intent-signature-tests\I-2121\intent-signature.json
```

Verify JSON output:

```powershell
npm run verify-intent-json -- --record ..\..\.delta\ts-intent-signature-tests\I-2121\delta-record.json --intent ..\..\.delta\ts-intent-signature-tests\I-2121\intent-attestation.json --signature ..\..\.delta\ts-intent-signature-tests\I-2121\intent-signature.json
```

Expected flags:

```text
DELTA_TS_INTENT_VERIFY_OK=True
DELTA_TS_INTENT_RECORD_HASH_BINDING_OK=True
DELTA_TS_INTENT_SIGNATURE_VERIFICATION_STATUS=VERIFIED
DELTA_TS_INTENT_SIGNATURE_INTENT_HASH_BINDING_OK=True
DELTA_TS_INTENT_SIGNATURE_BODY_HASH_OK=True
DELTA_TS_INTENT_SIGNATURE_PUBLIC_KEY_HASH_OK=True
DELTA_TS_INTENT_SIGNATURE_OK=True
```

## 4. What this does not prove

v2.12.1 does not prove:

- legal approval,
- signer authority,
- real-world identity,
- registry trust,
- role validity,
- policy compliance,
- wallet ownership,
- regulatory compliance.

It verifies that an Ed25519 key signed a canonical signature body bound to the intent attestation hash.

## 5. Security boundary

This milestone verifies detached signature cryptography and intent hash binding only.

It is not a governance, identity, or compliance oracle.

Future milestones should add registry and policy checks separately.
