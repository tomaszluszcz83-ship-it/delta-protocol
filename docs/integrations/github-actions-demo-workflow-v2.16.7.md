# DELTA v2.16.7 — GitHub Actions Demo Workflow

## Executive summary

This document describes the first GitHub Actions demonstration workflow for DELTA Protocol.

The workflow is intentionally narrow and public-facing. Its purpose is to turn the minimal public tamper-detection artifact introduced in v2.16.6 into an automated CI signal that external reviewers, developers, auditors, and early adopters can observe directly in GitHub.

The workflow does not claim to be a complete production DELTA verifier. It automates a deliberately scoped demonstration:

```text
checkout repository → run minimal demo → verify expected hash → tamper artifact → detect mismatch → run baseline DELTA verification → run canonical JSON vector checks
```

## Added workflow

The workflow is located at:

```text
.github/workflows/delta-minimal-demo.yml
```

## What the workflow does

The workflow performs three public-facing checks:

1. runs the minimal public tamper-detection demonstration from `demo/minimal-demo/verify.ps1`;
2. runs the Python reference baseline verification with `python src/delta_cli.py verify-all`;
3. runs Canonical JSON / JCS vector verification with `python tools/delta_canonical_json.py verify-vectors --vectors tests/vectors/canonical-json/vectors.json`.

## Why this matters

v2.16.6 made DELTA demonstrable locally.

v2.16.7 makes that demonstration visible in a standard CI environment.

This is strategically important because public adoption depends on more than documentation. A reviewer should be able to see that the project can run a basic tamper-detection demonstration and core verification checks automatically in a normal repository workflow.

## Trigger model

The workflow runs on:

- manual `workflow_dispatch`,
- pull requests touching the demo, workflow, tools, source, or canonical JSON vectors,
- pushes to `main` touching the same relevant paths.

This keeps the workflow focused on the material it is intended to demonstrate.

## Security boundary

This workflow is not a production certification system.

It does not prove:

- legal identity,
- signer authority,
- regulatory compliance,
- real-world truth,
- sensor honesty,
- evidence completeness,
- policy correctness,
- institutional approval,
- or business authority.

The workflow demonstrates that the minimal public demo detects tampering and that the existing baseline verification commands continue to execute successfully in CI.

It does not replace full signed bundle verification, Proof of Intent verification, Proof of Audit verification, Proof of Publication verification, Proof of Trust verification, wallet proof verification, or future ZK verification.

## Expected result

A successful workflow run should show:

```text
[OK] Original artifact hash matches expected value.
[FAIL] Tampered artifact hash mismatch detected.
[OK] Demo succeeded: tampering was detected.
DELTA CLI RESULT: OK
DELTA_JCS_VERIFY_OK=True
```

## Public adoption role

This workflow is a bridge between the minimal demo artifact and more mature integrations.

It prepares the repository for future work such as:

- a dedicated public example repository,
- a reusable GitHub Action,
- a signed bundle verification workflow,
- a release integrity workflow,
- a machine-readable CI verification report,
- and a recorded five-minute demonstration for reviewers.

## Implementation status

This is an initial public demonstration workflow.

It is intentionally simple, transparent, and reviewable.
