# DELTA Protocol CI/CD Integration Examples v2.16.3

## Purpose

This document defines the first public CI/CD integration examples for DELTA Protocol.

The objective is to demonstrate how DELTA can be introduced into existing software delivery workflows as a cryptographic verification layer, without requiring a native token, blockchain dependency, SaaS account model, marketplace, or centralized user identity system.

These examples are intentionally conservative. They are designed for public review, education, and integration planning rather than production certification.

## Integration philosophy

DELTA should fit into existing developer workflows.

A CI/CD system should be able to execute DELTA verification commands, observe deterministic outputs, fail the pipeline when verification fails, and preserve machine-readable results for later review.

DELTA does not replace source control, build systems, artifact repositories, signing systems, SBOM tooling, or compliance programs.

It provides an additional cryptographic proof layer for declared change relationships.

## Minimum integration pattern

A minimal DELTA-aware CI/CD workflow should perform the following steps:

1. Check out the repository.
2. Install the required runtime dependencies.
3. Run the Python reference verification commands.
4. Optionally run TypeScript verifier checks.
5. Fail the workflow if verification fails.
6. Store verification logs as build artifacts when appropriate.
7. Avoid exposing private keys, secrets, production evidence, or confidential audit material.

## GitHub Actions example

The following example is a conservative documentation-level workflow pattern.

```yaml
name: DELTA Verification

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  delta-verify:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Run DELTA Python reference verification
        run: |
          python src/delta_cli.py verify-all
          python tools/delta_canonical_json.py verify-vectors --vectors tests/vectors/canonical-json/vectors.json

      - name: Check whitespace and patch cleanliness
        run: |
          git diff --check
```

## Optional TypeScript verifier example

For repositories using the TypeScript verifier profile, an additional job can be added.

```yaml
name: DELTA TypeScript Verifier

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  delta-ts-verify:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Build and verify TypeScript profiles
        working-directory: verifier/ts
        run: |
          npm install
          npm run build
          npm run verify-vectors
          npm run verify-schemas
```

## GitLab CI example

The following example shows the same conservative verification concept in GitLab CI syntax.

```yaml
stages:
  - verify

delta-python-verify:
  stage: verify
  image: python:3
  script:
    - python src/delta_cli.py verify-all
    - python tools/delta_canonical_json.py verify-vectors --vectors tests/vectors/canonical-json/vectors.json
    - git diff --check
```

Optional TypeScript verifier job:

```yaml
delta-typescript-verify:
  stage: verify
  image: node:20
  script:
    - cd verifier/ts
    - npm install
    - npm run build
    - npm run verify-vectors
    - npm run verify-schemas
```

## Machine-readable verification direction

Where available, DELTA verifier outputs should support machine-readable CI/CD decisions.

The TypeScript CLI JSON output profile is especially important for automation because it can expose structured fields such as:

- `ok`,
- `code`,
- `code_name`,
- `profile`,
- `command`,
- `result`,
- `errors`,
- `warnings`.

Automation should treat these outputs as verification results, not as legal or business conclusions.

## Recommended CI/CD security boundaries

A CI/CD integration should clearly distinguish between:

- cryptographic validity,
- trust validity,
- legal validity,
- policy sufficiency,
- regulatory sufficiency,
- operational approval,
- real-world truth.

A passing DELTA verification step means that the checked cryptographic relationships satisfied the declared verification rules.

It does not mean that the change was legally authorized, institutionally approved, compliant with a regulation, truthful in the real world, complete as evidence, or free from policy mistakes.

## Private keys and CI/CD

Private keys must not be committed to the repository.

Private keys must not be printed in CI logs.

Private keys must not be pasted into issues, pull requests, comments, or public build output.

If signing is later performed inside automation, signing keys should be stored using the CI/CD provider's secret-management mechanism or an external hardware-backed key-management system.

Public keys may be committed only when intentionally part of a public registry, demo profile, or verifier configuration.

## Adoption recommendation

The first public CI/CD examples should remain simple.

The recommended public path is:

1. run verification,
2. show successful results,
3. show a tamper case,
4. explain exactly what was proven,
5. explain exactly what was not proven.

This approach builds technical credibility without implying production certification or legal assurance.
