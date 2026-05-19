# DELTA Conformance Test Plan v2.6.2

**Status:** Draft  
**Version:** v2.6.2  
**Scope:** Test plan for DELTA Conformance Levels

## 1. Purpose

This document defines a practical test plan for validating DELTA conformance claims.

The goal is to help reviewers answer:

```text
What does this implementation support?
Which DELTA level does it claim?
Which vectors and checks prove the claim?
Where does it fail closed?
```

## 2. Test categories

The v2.6.2 conformance plan is organized into the following categories:

| Category | Purpose | Related level |
|---|---|---|
| Canonical JSON vectors | Verify deterministic canonical bytes and hashes | L0 |
| Schema registry checks | Verify object shape validation | L1 |
| Signed record checks | Verify hashes and signatures | L1 |
| Replay checks | Verify reproducibility of declared measurement results | L2 |
| Advanced proof checks | Verify Intent, Audit, Publication, Trust bindings | L3 |
| Wallet proof checks | Verify address-control proof behavior | L4 |
| Full conformance suite | Verify all mandatory implemented profiles | L5 |

## 3. L0 test plan: Canonical JSON

### Command

```powershell
python tools\delta_canonical_json.py verify-vectors `
  --vectors tests\vectors\canonical-json\vectors.json
```

### Expected result

```text
DELTA_JCS_VERIFY_OK=True
```

### Required negative cases

The implementation MUST reject:

- Floating-point numbers.
- NaN.
- Infinity.
- Duplicate object keys.
- Unsafe integers.

## 4. L1 test plan: Schemas and signed records

### JSON parse check

```powershell
@'
import json
from pathlib import Path

ok = True
for p in sorted(Path("schemas").glob("*.json")):
    try:
        json.loads(p.read_text(encoding="utf-8"))
        print(f"SCHEMA_JSON_PARSE_OK={p}")
    except Exception as exc:
        ok = False
        print(f"SCHEMA_JSON_PARSE_OK=False path={p} reason={type(exc).__name__}:{exc}")

if not ok:
    raise SystemExit(1)

print("DELTA_SCHEMA_JSON_PARSE_OK=True")
'@ | python -
```

### Expected result

```text
DELTA_SCHEMA_JSON_PARSE_OK=True
```

### Signed public proof verification

```powershell
python src\delta_cli.py verify-all
```

### Expected result

```text
DELTA CLI RESULT: OK
```

## 5. L2 test plan: Replay verification

An implementation claiming L2 MUST document:

- Which measurement method IDs it supports.
- How it obtains replay inputs.
- How it isolates replay execution.
- Which environment assumptions affect reproducibility.
- Which fields are compared after replay.

A replay-capable verifier MUST fail closed when required replay inputs are missing or when replay output does not match the signed record.

## 6. L3 test plan: Advanced proofs

### Proof of Intent

Positive tests SHOULD confirm:

- Intent attestation shape OK.
- Intent signature OK.
- Intent registry binding OK.
- Full record hash binding OK.

Negative tests SHOULD include:

- Missing intent signature.
- Tampered intent attestation.
- Record hash mismatch.
- Unknown or inactive intent key.

### Proof of Audit

Positive tests SHOULD confirm:

- Audit package shape OK.
- Record binding OK.
- AAD hashes OK.
- Ciphertext hashes OK.
- Recipient public key hash OK.

Negative tests SHOULD include:

- Tampered ciphertext hash.
- Tampered AAD hash.
- Record hash mismatch.
- Wrong auditor public key.

### Proof of Publication

Positive tests SHOULD confirm:

- Proof shape OK.
- Proof body hash OK.
- Record binding OK.
- External evidence hash OK where applicable.

Negative tests SHOULD include:

- Tampered record hash.
- Tampered proof body hash.
- Tampered external file hash.

### Proof of Trust

Positive tests SHOULD confirm:

- Ledger self-check OK.
- Entry hashes OK.
- Previous-entry links OK.
- Sequence OK.
- Record binding OK.

Negative tests SHOULD include:

- Tampered previous-entry hash.
- Tampered entry body.
- Ledger body hash mismatch.

## 7. L4 test plan: Wallet proofs

Wallet proof tests SHOULD cover:

- `ed25519_address_control_v1`
- `ethereum_eip191_personal_sign_v1`
- `ethereum_eip712_typed_data_v1`
- `bitcoin_bip322_external_v1`

### Required common checks

- Challenge binding OK.
- Record binding OK.
- Address binding OK where applicable.
- Signature shape OK.
- Signature verification OK where a local verifier is implemented.

### Bitcoin external boundary

For `bitcoin_bip322_external_v1`, tests MUST confirm:

```text
CRYPTO_SIGNATURE_VERIFIED=False
DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL=shape_only
DELTA_WALLET_SIGNATURE_VERIFICATION_MODE=external_pending
```

Negative tests MUST include:

- Empty signature.
- Unsupported signature format.
- Tampered record hash.

## 8. L5 test plan: Full reference suite

DELTA-L5 remains a future target. A future L5 runner SHOULD produce a machine-readable conformance report such as:

```json
{
  "implementation": "delta-python-reference",
  "claimed_level": "DELTA-L5",
  "canonical_json": true,
  "schemas": true,
  "signed_records": true,
  "replay": true,
  "intent": true,
  "audit": true,
  "publication": true,
  "trust": true,
  "wallet": true
}
```

## 9. Failure behavior

A conformant verifier MUST fail closed for unsupported or malformed required profiles.

A verifier MAY provide report-only mode, but report-only mode MUST be clearly marked and MUST NOT be represented as cryptographic acceptance.

## 10. Security boundaries

Passing conformance tests does not prove:

- Legal truth.
- Real-world truth.
- Identity by itself.
- Wallet balance by itself.
- Regulatory compliance by itself.
- Evidence origin truth.
- Business process correctness.

Conformance proves only that an implementation follows the tested DELTA protocol rules for the claimed level.
