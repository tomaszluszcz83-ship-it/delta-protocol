# DELTA Protocol — TypeScript Proof of Intent Contract Tests (v2.13.0)

Status: TypeScript Proof of Intent readiness / contract test milestone  
Implementation path: `tools/delta_ts_intent_contract_tests.py`

## 1. Purpose

v2.13.0 freezes the TypeScript Proof of Intent machine-readable contract after v2.12.0 through v2.12.3.

The goal is to test end-to-end TypeScript Proof of Intent behavior across:

- record hash binding,
- detached Ed25519 signature verification,
- registry public key binding,
- local policy/deadline checks,
- JSON output and exit-code behavior.

This milestone adds tests only. It adds no new cryptographic functionality.

## 2. Scope

The contract test validates:

- TypeScript build,
- canonical JSON vectors,
- schema verification,
- signed intent demo generation,
- positive `verify-intent-json` result,
- expired-deadline negative `verify-intent-json` result,
- top-level JSON output fields,
- expected verification statuses,
- expected exit codes.

## 3. Positive path expectations

The positive path must return:

```text
ok=true
code=0
code_name=OK
signatureVerificationStatus=VERIFIED
registryVerificationStatus=VERIFIED
policyVerificationStatus=SATISFIED
recordHashBindingOk=true
signatureOk=true
registryStatusOk=true
policyIdOk=true
deadlineOk=true
policyStatusOk=true
```

## 4. Negative path expectations

The expired-deadline path must return:

```text
ok=false
code=1
code_name=VERIFICATION_FAILED
policyVerificationStatus=INVALID
deadlineOk=false
intent_policy_deadline_expired
```

## 5. Command

From repository root:

```powershell
python tools\delta_ts_intent_contract_tests.py
```

Expected output includes:

```text
DELTA_TS_INTENT_CONTRACT_VERIFY_OK=True
DELTA_TS_INTENT_CONTRACT_POSITIVE_OK=True
DELTA_TS_INTENT_CONTRACT_EXPIRED_DEADLINE_REJECTED_OK=True
```

## 6. Security boundary

This milestone tests verifier behavior only.

It does not add trust, cryptography, identity verification, legal approval, or compliance verification.

It does not make TypeScript a complete DELTA verifier.

The existing Proof of Intent boundaries remain:

- registry is an input artifact,
- policy is an input artifact,
- signature proves key control over canonical signature body only,
- legal identity and signer authority remain out of scope.

## 7. Next recommended step

After v2.13.0, DELTA can move toward a private evidence / commitment profile as preparation for later ZK provenance research.
