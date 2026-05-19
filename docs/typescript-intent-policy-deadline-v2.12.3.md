# DELTA Protocol — TypeScript Intent Policy / Deadline Check (v2.12.3)

Status: Experimental TypeScript Proof of Intent policy-boundary milestone  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.12.3 extends TypeScript Proof of Intent verification with local policy and deadline checks.

v2.12.0 verified record hash binding.  
v2.12.1 verified detached Ed25519 intent signatures.  
v2.12.2 verified local registry public key binding.  
v2.12.3 verifies that the intent references a local policy and that the intent is still within the declared deadline.

## 2. Scope

v2.12.3 verifies:

- local policy JSON readability,
- intent `policy_id` matches policy `policy_id`,
- policy status is active/valid/enabled/enforced,
- intent/policy deadline is parseable,
- verification time is not after the effective deadline,
- human-readable and JSON CLI output.

## 3. Policy fixture format

The MVP supports a simple policy file:

```json
{
  "profile": "delta_intent_policy_test_v2_12_3",
  "policy_id": "typescript-intent-policy-v2.12.3",
  "deadline": "2999-12-31T23:59:59Z",
  "status": "active"
}
```

## 4. Commands

Create local demo artifacts:

```powershell
cd verifier\ts

npm run create-signed-intent-demo -- --out-dir ..\..\.delta\ts-intent-policy-tests\I-2123
```

Verify human-readable output:

```powershell
npm run verify-intent -- --record ..\..\.delta\ts-intent-policy-tests\I-2123\delta-record.json --intent ..\..\.delta\ts-intent-policy-tests\I-2123\intent-attestation.json --signature ..\..\.delta\ts-intent-policy-tests\I-2123\intent-signature.json --registry ..\..\.delta\ts-intent-policy-tests\I-2123\intent-registry.json --policy ..\..\.delta\ts-intent-policy-tests\I-2123\intent-policy.json --now 2026-01-01T00:00:00Z
```

Verify JSON output:

```powershell
npm run verify-intent-json -- --record ..\..\.delta\ts-intent-policy-tests\I-2123\delta-record.json --intent ..\..\.delta\ts-intent-policy-tests\I-2123\intent-attestation.json --signature ..\..\.delta\ts-intent-policy-tests\I-2123\intent-signature.json --registry ..\..\.delta\ts-intent-policy-tests\I-2123\intent-registry.json --policy ..\..\.delta\ts-intent-policy-tests\I-2123\intent-policy.json --now 2026-01-01T00:00:00Z
```

Expected flags:

```text
DELTA_TS_INTENT_VERIFY_OK=True
DELTA_TS_INTENT_POLICY_VERIFICATION_STATUS=SATISFIED
DELTA_TS_INTENT_POLICY_ID_OK=True
DELTA_TS_INTENT_POLICY_DEADLINE_OK=True
DELTA_TS_INTENT_POLICY_STATUS_OK=True
```

## 5. Security boundary

v2.12.3 checks a local policy artifact.

It does not prove:

- legal approval,
- regulatory compliance,
- signer authority,
- real-world identity,
- that the policy itself is correct,
- that the registry is globally trusted,
- that an organization approved the action.

It proves consistency with the provided policy file under the declared time.

## 6. Future work

Future milestones should add:

```text
signed policy artifacts
policy hash binding
policy registry
revocation/invalidation checks
intent policy contract tests
```
