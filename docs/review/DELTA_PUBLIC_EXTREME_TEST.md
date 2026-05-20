# DELTA Public Extreme Test

DELTA Public Extreme Test is a local-only, high-rigor public-readiness and regression test for DELTA Protocol.

It is intentionally more demanding than the minimal public demo and the earlier heavy test.

## Purpose

The test verifies that the public repository is ready for serious external technical review.

It checks repository cleanliness, public review assets, README/reviewer markers, release tags, schema/vector parseability, baseline proof verification, canonical JSON vectors, Python compile health, selected tool help surfaces, GitHub workflow markers, the minimal public tamper-detection demo, TypeScript verifier checks, TypeScript contract tests, cleanup behavior, and final working-tree cleanliness.

## Current status

The corrected local `DELTA Public Extreme Test v1-fixed` passed successfully on `main` with TypeScript enabled and cleanup enabled.

Result:

```text
DELTA_PUBLIC_EXTREME_TEST_SOFT_WARNINGS=0
DELTA_PUBLIC_EXTREME_TEST_HARD_FAILURES=0
DELTA_PUBLIC_EXTREME_TEST_OK=True
```

## Command used

```powershell
python "C:\Users\PC\Downloads\delta-public-extreme-test-v1-fixed\delta_public_extreme_test.py" --repo "C:\Users\PC\Desktop\DELTA-0-PUBLIC" --include-ts --cleanup
```

## Coverage

The successful run confirmed:

- Git baseline and repository root path
- `main` branch
- clean working tree at start
- required public-review assets
- README and reviewer-document markers
- release tags from `v2.16.6` through `v2.16.10`
- sensitive artifact filename guard
- JSON schema and vector parseability
- `python src/delta_cli.py verify-all`
- canonical JSON vector verification
- Python `py_compile` smoke test
- selected tool `--help` surfaces
- GitHub workflow markers
- minimal public tamper-detection demo
- TypeScript `npm ci`
- TypeScript build
- TypeScript canonical JSON vector verification
- TypeScript schema verification
- TypeScript CLI contract tests
- TypeScript intent contract tests
- cleanup of local TypeScript artifacts
- final `git diff --check`
- clean working tree at end

## Security boundary

This test does not prove that DELTA is secure, audited, legally valid, compliant, production-ready, or correct in the real world.

It is a local readiness and regression test for repository integrity, public-review assets, verifier health, canonicalization vectors, demos, TypeScript verification paths, and public technical review readiness.

The test result should be interpreted as a strong engineering readiness signal, not as a certification or external audit.
