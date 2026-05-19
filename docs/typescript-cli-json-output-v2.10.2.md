# DELTA Protocol — TypeScript CLI Error Codes / Machine-Readable JSON Output (v2.10.2)

Status: Experimental TypeScript verifier CI/CD usability milestone  
Implementation path: `verifier/ts/`

## 1. Purpose

v2.10.2 adds machine-readable JSON output wrappers for selected TypeScript verifier commands.

The goal is to make the TypeScript verifier easier to use in CI/CD, scripts, dashboards, and external integrations.

This milestone does not change the underlying cryptographic verification rules.

## 2. Scope

v2.10.2 adds:

- `verifier/ts/src/cliResult.ts`
- `verifier/ts/scripts/verify-signed-record-json.ts`
- `verifier/ts/scripts/verify-bundle-json.ts`
- `verifier/ts/scripts/verify-signed-bundle-json.ts`
- package scripts for JSON output commands.

## 3. Exit codes

The JSON wrappers use stable exit-code categories:

| Exit code | Code name | Meaning |
| --- | --- | --- |
| 0 | `OK` | Verification passed |
| 1 | `VERIFICATION_FAILED` | Verification ran but failed |
| 2 | `USAGE_ERROR` | Required CLI arguments were missing or invalid |
| 3 | `INTERNAL_ERROR` | Unexpected runtime error |

## 4. JSON output shape

All JSON wrappers return this top-level shape:

```json
{
  "ok": true,
  "code": 0,
  "code_name": "OK",
  "profile": "delta_typescript_cli_json_v2_10_2",
  "command": "verify-bundle-json",
  "result": {},
  "errors": [],
  "warnings": []
}
```

## 5. Commands

### 5.1 Signed record JSON output

```powershell
cd verifier\ts

npm run create-signed-record-demo -- --out ..\..\.delta\ts-cli-json-tests\R-2102\signed-record.json

npm run verify-signed-record-json -- --record ..\..\.delta\ts-cli-json-tests\R-2102\signed-record.json
```

Expected top-level fields:

```json
{
  "ok": true,
  "code": 0,
  "code_name": "OK"
}
```

### 5.2 Public bundle JSON output

```powershell
npm run verify-bundle-json -- --bundle C:\path\to\sample.delta
```

### 5.3 Signed bundle JSON output

```powershell
npm run verify-signed-bundle-json -- --bundle C:\path\to\sample.delta --signature C:\path\to\sample.delta.sig.json
```

## 6. Security boundary

Machine-readable JSON output does not add new trust.

It only changes how verifier results are emitted.

The same security boundaries apply:

- schema validation is pre-verification only,
- bundle verification does not prove contained proofs are valid,
- signed bundle verification does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, or trust validity,
- Python remains the Alpha Reference Implementation.

## 7. Future work

Future milestones may add:

- `--json` support directly to existing human-readable CLIs,
- JSON output for schema validation and vector verification,
- stable machine-readable error codes per verifier subsystem,
- GitHub Actions annotations,
- SARIF or other CI reporting profiles.
