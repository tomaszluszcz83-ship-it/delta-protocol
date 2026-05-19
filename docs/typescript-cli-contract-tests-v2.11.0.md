# DELTA Protocol — TypeScript CLI Contract Tests (v2.11.0)

Status: Integration / contract test milestone  
Implementation path: `tools/delta_ts_cli_contract_tests.py`

## 1. Purpose

v2.11.0 freezes the machine-readable TypeScript CLI JSON contract introduced in v2.10.2.

The goal is not to claim full Python ↔ TypeScript feature parity.

The goal is to test the selected TypeScript JSON CLI contract so CI/CD integrations can rely on stable result fields and exit-code categories.

## 2. Scope

v2.11.0 adds a Python integration test runner for TypeScript verifier CLI JSON output.

It validates:

- TypeScript build,
- canonical JSON vector verification,
- schema verification,
- signed record demo creation,
- `verify-signed-record-json` success behavior,
- `verify-signed-record-json` usage error behavior,
- `verify-signed-record-json` verification failure behavior,
- top-level JSON fields,
- stable exit-code categories.

## 3. Tested top-level JSON fields

Every tested JSON command must expose:

```text
ok
code
code_name
profile
command
result
errors
warnings
```

## 4. Tested exit codes

| Exit code | Code name | Meaning |
| --- | --- | --- |
| 0 | `OK` | Verification passed |
| 1 | `VERIFICATION_FAILED` | Verification ran but failed |
| 2 | `USAGE_ERROR` | Required arguments were missing or invalid |
| 3 | `INTERNAL_ERROR` | Unexpected runtime error |

## 5. Command

From repository root:

```powershell
python tools\delta_ts_cli_contract_tests.py
```

Expected output includes:

```text
DELTA_TS_CLI_CONTRACT_VERIFY_OK=True
DELTA_TS_CLI_CONTRACT_JSON_PARSE_OK=True
DELTA_TS_CLI_CONTRACT_EXIT_CODE_OK_TRUE=0
DELTA_TS_CLI_CONTRACT_EXIT_CODE_USAGE_ERROR=2
DELTA_TS_CLI_CONTRACT_EXIT_CODE_VERIFICATION_FAILED=1
```

## 6. Security boundary

This milestone adds no cryptographic functionality.

It does not make TypeScript a complete DELTA verifier.

It tests the machine-readable CLI contract for selected TypeScript verifier commands only.

The same verification boundaries documented in v2.10.2 remain in force.

## 7. Why this matters

JSON output is useful only if automation can trust the shape and exit codes.

v2.11.0 turns the v2.10.2 output format into a tested contract.
