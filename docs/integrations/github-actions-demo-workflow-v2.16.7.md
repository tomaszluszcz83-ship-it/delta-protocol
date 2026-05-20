# DELTA v2.16.7 — GitHub Actions Demo Workflow

## Purpose

This document describes the minimal GitHub Actions demonstration workflow introduced in DELTA v2.16.7.

The workflow is intentionally narrow, deterministic, and independent of the full DELTA reference implementation. Its only purpose is to demonstrate the foundational tamper-detection intuition behind Proof of Change in a public CI environment:

```text
known artifact bytes → verification OK → tamper → hash mismatch → verification FAIL
```

The check passes only if the workflow successfully detects that the tampered artifact has a different SHA-256 hash from the original artifact.

## Why the workflow is intentionally minimal

Earlier public-adoption milestones already document DELTA’s broader proof model, review process, quick-start path, and local tamper-detection walkthrough.

This workflow is not intended to replace full DELTA verification.

Instead, it creates a stable CI-visible demonstration that external readers can understand quickly without needing Python dependencies, PowerShell behavior assumptions, local checkout line-ending behavior, or platform-specific scripts.

## Runtime profile

The workflow uses:

- `ubuntu-latest`,
- standard `bash`,
- `sha256sum`,
- temporary runner-local files,
- no Python dependencies,
- no private keys,
- no external services,
- no blockchain infrastructure,
- no native token,
- no SaaS account,
- no marketplace component.

## Security boundary

This workflow does not claim to perform full DELTA signed bundle verification.

It does not verify:

- Ed25519 signatures,
- signed `.delta` bundles,
- full record chains,
- Proof of Intent,
- Proof of Audit,
- Proof of Publication,
- Proof of Trust,
- wallet proofs,
- legal identity,
- signer authority,
- regulatory compliance,
- real-world truth,
- sensor honesty,
- evidence completeness,
- policy correctness,
- legal validity,
- institutional approval,
- business authority.

It demonstrates exactly one foundational property:

```text
if artifact bytes change, the SHA-256 hash changes, and verification can detect that mismatch
```

## Expected CI result

A successful run should show:

```text
OK: Original artifact hash matches expected value.
OK: Tampered artifact hash mismatch detected.
OK: Demo succeeded: tampering was detected.
```

The workflow should fail only if the tampered artifact unexpectedly produces the same hash as the original artifact or if the CI environment cannot execute the minimal shell commands.

## Relationship to future DELTA workflows

This workflow is a public demonstration layer.

Future workflows may add stronger protocol-specific verification, including:

- full signed `.delta` bundle verification,
- TypeScript verifier execution,
- signed bundle verification,
- publication proof checks,
- private evidence commitment checks,
- CI/CD release integrity examples.

Those should be added as separate, clearly scoped workflows so that the minimal public demo remains stable, readable, and suitable for first-time reviewers.
