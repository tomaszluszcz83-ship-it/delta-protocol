# DELTA Protocol — TypeScript Intent Registry / Public Key Binding (v2.12.2)

Status: Experimental TypeScript Proof of Intent trust-boundary milestone  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.12.2 extends TypeScript Proof of Intent verification with registry-based signer public key binding.

v2.12.1 verifies that an Ed25519 key signed a canonical signature body bound to an intent attestation.

v2.12.2 verifies that the signer key used in that detached signature is present in a local intent registry and marked active.

## 2. Scope

v2.12.2 verifies:

- record hash binding from v2.12.0,
- detached Ed25519 intent signature verification from v2.12.1,
- registry JSON readability,
- registry entry lookup by signer label and/or public key hash,
- registry public key hash match,
- registry public key match when declared,
- registry entry status such as `active`.

## 3. Registry fixture format

The MVP supports a simple registry format:

```json
{
  "profile": "delta_intent_registry_test_v2_12_2",
  "entries": [
    {
      "label": "typescript-local-demo-signer",
      "public_key": "ed25519:...",
      "public_key_hash": "sha256:...",
      "role": "tester",
      "status": "active"
    }
  ]
}
```

The verifier also accepts `signers`, `keys`, or `public_keys` arrays, plus simple object maps for `signers` or `keys`.

## 4. Commands

Create local demo artifacts:

```powershell
cd verifier\ts

npm run create-signed-intent-demo -- --out-dir ..\..\.delta\ts-intent-registry-tests\I-2122
```

Verify human-readable output:

```powershell
npm run verify-intent -- --record ..\..\.delta\ts-intent-registry-tests\I-2122\delta-record.json --intent ..\..\.delta\ts-intent-registry-tests\I-2122\intent-attestation.json --signature ..\..\.delta\ts-intent-registry-tests\I-2122\intent-signature.json --registry ..\..\.delta\ts-intent-registry-tests\I-2122\intent-registry.json
```

Verify JSON output:

```powershell
npm run verify-intent-json -- --record ..\..\.delta\ts-intent-registry-tests\I-2122\delta-record.json --intent ..\..\.delta\ts-intent-registry-tests\I-2122\intent-attestation.json --signature ..\..\.delta\ts-intent-registry-tests\I-2122\intent-signature.json --registry ..\..\.delta\ts-intent-registry-tests\I-2122\intent-registry.json
```

Expected flags:

```text
DELTA_TS_INTENT_VERIFY_OK=True
DELTA_TS_INTENT_SIGNATURE_VERIFICATION_STATUS=VERIFIED
DELTA_TS_INTENT_REGISTRY_VERIFICATION_STATUS=VERIFIED
DELTA_TS_INTENT_REGISTRY_ENTRY_FOUND=True
DELTA_TS_INTENT_REGISTRY_PUBLIC_KEY_HASH_OK=True
DELTA_TS_INTENT_REGISTRY_STATUS_OK=True
```

## 5. What this does not prove

v2.12.2 does not prove:

- legal identity,
- signer authority,
- role validity outside the registry file,
- organizational approval,
- policy compliance,
- regulatory compliance,
- real-world truth.

It verifies that the signing public key is present and active in a declared registry artifact.

## 6. Security boundary

The registry itself is an input artifact.

If the registry is untrusted, stale, compromised, or unsigned, the result only proves consistency with that registry file.

Future milestones should add:

```text
signed registry
registry hash binding
registry revocation events
intent policy/deadline checks
```
