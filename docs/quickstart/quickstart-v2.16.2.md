# DELTA Protocol Quick Start v2.16.2

## Purpose

This quick-start document provides the first practical verification path for external developers, auditors, security reviewers, maintainers, and technically curious early adopters.

The objective is to make DELTA reproducible within minutes while preserving the seriousness of the protocol’s security boundaries.

This document does not attempt to explain every proof layer. It provides the shortest credible path from repository checkout to successful verification.

## Prerequisites

Recommended tools:

- Git,
- Python 3,
- Node.js and npm for TypeScript verifier checks,
- PowerShell on Windows or an equivalent terminal on Linux/macOS.

## Clone the repository

```powershell
git clone https://github.com/tomaszluszcz83-ship-it/delta-protocol.git
cd delta-protocol
```

If the repository is already available locally, enter the project directory:

```powershell
cd "C:\Users\PC\Desktop\DELTA-0-PUBLIC"
```

## Run the Python reference verification

```powershell
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

This verifies the current Python reference checks included in the repository.

## Run Canonical JSON / JCS-compatible vector verification

```powershell
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
```

Expected result:

```text
DELTA_JCS_VERIFY_OK=True
```

This verifies DELTA's canonical JSON profile test vectors and confirms rejection of malformed or unsafe inputs such as floats, NaN, Infinity, duplicate keys, and unsafe integers.

## Run TypeScript verifier checks

```powershell
cd verifier\ts
npm install
npm run build
npm run verify-vectors
npm run verify-schemas
cd ..\..
```

Expected results include successful build output and successful vector/schema verification.

The TypeScript verifier is an experimental cross-language verifier for selected profiles. It does not yet implement every Python reference capability.

## Run TypeScript CLI contract tests

From the repository root:

```powershell
python tools\delta_ts_cli_contract_tests.py
python tools\delta_ts_intent_contract_tests.py
```

Expected results include machine-readable TypeScript CLI contract verification and Proof of Intent contract verification.

## Check whitespace and repository cleanliness

```powershell
git diff --check
git status
```

Expected result:

```text
nothing to commit, working tree clean
```

for an unchanged checkout.

## What this quick start demonstrates

This quick start demonstrates that an external reviewer can independently run the current DELTA verification stack and confirm that the repository's baseline checks pass.

It demonstrates:

- Python reference verification,
- canonical JSON / JCS-compatible vector verification,
- TypeScript verifier build and vector checks,
- schema verification,
- CLI contract testing,
- basic reproducibility of the public repository state.

## What this quick start does not prove

This quick start does not prove legal identity, signer authority, regulatory compliance, real-world truth, sensor honesty, organizational approval, evidence completeness, policy correctness, legal validity, or external institutional trust.

It proves only that the included verification commands pass under the local environment in which they are executed.

## Recommended next reading

After completing the quick start, readers should review:

- `README.md`,
- `docs/positioning/what-delta-proves.md`,
- `docs/rfc/RFC-01-delta-core-protocol.md`,
- `docs/security/security-boundaries-v2.5.4.md`,
- `docs/standard/canonical-json-profile-v2.6.0.md`,
- `docs/standard/schema-registry-v2.6.1.md`,
- `docs/public-adoption/public-adoption-strategy-v2.16.1.md`,
- `docs/private-evidence/private-evidence-merkle-set-v2.15.0.md`,
- `docs/zk/zk-statement-design-v2.16.0.md`.

## Expected reviewer posture

DELTA should be reviewed as a technical alpha, an open protocol candidate, and a reference implementation.

Reviewers are encouraged to challenge assumptions, test tampering scenarios, examine canonicalization behavior, inspect signature and hash-binding rules, review documentation boundaries, and identify places where the protocol or implementation could be made more precise.
