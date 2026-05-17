# DELTA Stage C Observation Report

This report summarizes the first observed dataset of signed DELTA GitHub Action Sensor records.

The dataset contains records collected from real GitHub Actions runs during Stage C.

## Dataset summary

- Total records: 10
- measurement_ok=True: 9
- measurement_ok=False: 1
- signature_verification_ok=True: 10
- executor_public_key present: 10

## Record table

| Record | measurement_ok | signature_ok | executor_public_key | commit_before | commit_after | method_id | method_version |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-001 | True | True | True | 7ea404d | 00fc426 | delta-cli-verify-all-v1 | 1.0.0 |
| C-002 | True | True | True | 7ea404d | 00fc426 | delta-cli-verify-all-v1 | 1.0.0 |
| C-003 | True | True | True | 00fc426 | db6d2be | delta-cli-verify-all-v1 | 1.0.0 |
| C-004 | True | True | True | db6d2be | 85a3963 | delta-cli-verify-all-v1 | 1.0.0 |
| C-005 | True | True | True | 85a3963 | c5b1995 | delta-cli-verify-all-v1 | 1.0.0 |
| C-006 | True | True | True | c5b1995 | a4069fc | delta-cli-verify-all-v1 | 1.0.0 |
| C-007 | False | True | True | a4069fc | 8e45bda | delta-cli-verify-all-v1 | 1.0.0 |
| C-008 | True | True | True | a4069fc | a50f736 | delta-cli-verify-all-v1 | 1.0.0 |
| C-009 | True | True | True | a50f736 | f33fc88 | delta-cli-verify-all-v1 | 1.0.0 |
| C-010 | True | True | True | f33fc88 | 665195d | delta-cli-verify-all-v1 | 1.0.0 |

## Key observations

1. The signed sensor record format handled both successful and failed measurements.
2. C-007 intentionally produced `measurement_ok=False`, while signature verification remained valid.
3. This confirms that the sensor signs the observed measurement result instead of hiding or rewriting failures.
4. All collected records included an embedded executor public key.
5. All collected records had valid signature verification.
6. Documentation-only commits produced new records with new commit transitions and new record body hashes.
7. Re-running the sensor on the same commit/state produced a distinct record because runtime metadata changed.

## Fields that appear necessary

- `record_body_hash`
- `record_body`
- `record_signature`
- `record_signature.public_key`
- `record_signature.public_key_hash`
- `record_signature.executor_public_key`
- `record_signature.executor_public_key_hash`
- `record_signature.signature`
- `record_signature_verification`
- `record_body.change.commit_before`
- `record_body.change.commit_after`
- `record_body.change.before_state_hash`
- `record_body.change.after_state_hash`
- `record_body.measurement_method.method_id`
- `record_body.measurement_method.method_version`
- `record_body.measurement_method.method_definition_hash`
- `record_body.measurement_result.ok`
- `record_body.private_evidence_commitments`
- `record_body.replay_instructions`
- `record_body.schema.schema_hash`

## Fields requiring further RFC review

- Whether `verification_policy` should remain descriptive or become executable.
- Whether `verifier_public_key` is required in later versions.
- Whether replay instructions should be executable scripts, structured steps, or both.
- Whether evidence artifacts should be optionally encrypted.
- Whether runtime metadata should be separated from deterministic record content.

## RFC readiness

The first 10-record Stage C dataset is sufficient to begin RFC-00 for the DELTA Sensor Record layer.

The RFC should define the sensor record only, not the full DELTA-0 protocol.

Out of scope for this RFC:

- key registry
- anchoring
- mirror nodes
- challenge/dispute
- trust graph
- final DELTA Record bundle

## Security boundary

These records are signed sensor-layer records.

They are not yet full signed DELTA-0 bundles:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

Private keys are not committed. Generated artifacts remain outside the repository.
