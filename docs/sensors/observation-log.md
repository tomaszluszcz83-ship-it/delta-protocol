# DELTA Sensor Observation Log

This file tracks observed signed sensor records collected during DELTA Stage C.

## C-003

- Purpose: first real documentation-only change after C-001/C-002 baseline runs.
- Expected result: GitHub Actions DELTA Sensor produces a signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Notes: This is a low-risk docs-only change used to create a new commit for sensor observation.

## C-004

- Purpose: second documentation-only change for DELTA Stage C observation.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Notes: This record checks whether another small docs-only commit creates a new signed sensor record with a new commit_after and record_body_hash.

## C-005

- Purpose: add first observation summary after collecting C-001 through C-004.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Observation focus:
  - baseline record generation
  - repeatability on the same commit/state
  - documentation-only commit detection
  - embedded executor_public_key presence
  - Ed25519 signature verification
- Notes: This creates another low-risk documentation commit while recording lessons for the future Sensor Record RFC.

## C-006

- Purpose: add a compact Stage C observation table.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Observation focus:
  - record numbering
  - commit transitions
  - measurement result stability
  - signature verification stability
  - executor public key presence

| Record | Type | Expected result |
| --- | --- | --- |
| C-001 | baseline | success |
| C-002 | repeatability rerun | success |
| C-003 | docs-only change | success |
| C-004 | docs-only change | success |
| C-005 | observation summary | success |
| C-006 | observation table | success |

## C-008

- Purpose: recovery check after controlled failure C-007.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Observation focus:
  - recovery after failed measurement record
  - successful return to main
  - signature verification remains stable
  - executor_public_key remains embedded
- Notes: C-008 confirms that the negative C-007 case did not affect the normal main branch sensor flow.

## C-009

- Purpose: document the success/failure observation from C-007 and C-008.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Observation focus:
  - C-007 showed measurement_ok=false with signature_verification_ok=true
  - C-008 showed recovery back to measurement_ok=true on main
  - The sensor signs the observed measurement result instead of hiding failures
- Notes: This is important for the future Sensor Record RFC because failed measurements must remain verifiable records.

## C-010

- Purpose: final clean Stage C observation record for the first 10-record dataset.
- Expected result: GitHub Actions DELTA Sensor produces a new signed delta-record.json artifact.
- Expected measurement_result.ok: true
- Observation focus:
  - first 10-record dataset completion
  - stable signature verification
  - stable executor public key embedding
  - stable measurement method hash commitment
  - useful evidence hash commitments
- Notes: This record closes the first Stage C dataset and prepares the ground for a Sensor Record RFC-00.
