# DELTA Protocol — TypeScript Proof of Intent Verification MVP (v2.12.0)

Status: Experimental TypeScript proof-specific verification MVP  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.12.0 adds the first TypeScript Proof of Intent verification MVP.

This milestone focuses on the most important safe first step: verifying that an intent attestation is cryptographically or structurally bound to a specific DELTA record hash.

It does not attempt to verify legal approval, signer authority, identity, or full policy compliance.

## 2. Scope

v2.12.0 adds:

- `verifier/ts/src/intentVerifier.ts`
- `verifier/ts/scripts/verify-intent.ts`
- `verifier/ts/scripts/verify-intent-json.ts`
- package scripts for human-readable and JSON output
- documentation and changelog

## 3. What is verified

The MVP verifies:

- the intent attestation JSON is readable,
- the DELTA record file is readable,
- the intent declares a record hash,
- the declared record hash matches the computed DELTA record hash,
- JSON output is available through the v2.10.2 CLI contract style.

The verifier supports record hash binding against:

```text
file_sha256
canonical_json_sha256
```

The preferred binding is `file_sha256` because DELTA has standardized around full `delta-record.json` hash binding in multiple proof layers.

`canonical_json_sha256` is accepted with a warning for compatibility with narrowly structured test fixtures.

## 4. What is not verified

v2.12.0 does not verify:

- legal approval,
- signer authority,
- real-world identity,
- organizational role validity,
- registry trust,
- intent policy satisfaction,
- detached intent signature cryptography,
- wallet ownership,
- regulatory compliance.

If a signature-like field is present, v2.12.0 reports:

```text
intent_signature_present_but_signature_verification_not_implemented_in_v2_12_0_mvp
```

This is intentional anti-overclaiming.

## 5. Commands

Human-readable output:

```powershell
cd verifier\ts

npm run verify-intent -- --record C:\path\to\delta-record.json --intent C:\path\to\intent-attestation.json
```

Machine-readable JSON output:

```powershell
npm run verify-intent-json -- --record C:\path\to\delta-record.json --intent C:\path\to\intent-attestation.json
```

Expected successful human-readable flags:

```text
DELTA_TS_INTENT_VERIFY_OK=True
DELTA_TS_INTENT_RECORD_HASH_BINDING_OK=True
```

Expected successful JSON top-level fields:

```json
{
  "ok": true,
  "code": 0,
  "code_name": "OK"
}
```

## 6. Security boundary

This milestone verifies record hash binding only.

It does not prove that the intent was legally valid, authorized by a real-world entity, or sufficient under any policy.

It is a proof-specific verification step, not a governance or compliance oracle.

## 7. Recommended next step

Future milestones should add one capability at a time:

```text
TypeScript detached intent signature verification
TypeScript intent registry verification
TypeScript intent policy/deadline checks
TypeScript integration with replay reports
```
