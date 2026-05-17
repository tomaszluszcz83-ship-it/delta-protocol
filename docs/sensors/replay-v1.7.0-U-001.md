# DELTA Replay Verification Report

Status: PASS

## Record

- Record path: `C:\Users\PC\Desktop\DELTA-V1-5-RECORDS\U-001\delta-sensor-record-unittest\delta-record.json`
- Method id: `python-unittest-v1`
- Commit after: `ea431b764ea5c574eaca91645c4b4a7e57528470`
- Fresh clone: `C:\Users\PC\AppData\Local\Temp\delta-replay-93_yg6po\repo`

## Checks

| Check | Result | Detail |
| --- | --- | --- |
| record_signature | `True` | `ok` |
| after_state_hash | `True` | `expected=sha256:d3acf21781cdbef5bf5226434ab441253564cff3aefedd95a07d8a9e018fbf9c actual=sha256:d3acf21781cdbef5bf5226434ab441253564cff3aefedd95a07d8a9e018fbf9c` |
| method_definition_hash | `True` | `expected=sha256:a01d9d037909aed5e9d1bee3f2e220d49942e2b9eca1b4450bfdb4bc69f2cd36 actual=sha256:a01d9d037909aed5e9d1bee3f2e220d49942e2b9eca1b4450bfdb4bc69f2cd36` |
| measurement_result_ok | `True` | `expected=True actual=True` |
| stdout_hash | `True` | `expected=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 actual=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 strict=False` |
| stderr_hash | `True` | `expected=sha256:bda8099b899da71700fca87323bfe99d3a11a9fa056d55a44b4690a851e38817 actual=sha256:f6db064e843d7d127dcab82490aa7223b1feb05e93c43f0e2355969499141dff strict=False` |

## Command

```text
python -m unittest discover -s packages/python/delta_protocol/tests -v
```

## Measurement output

### Return code

```text
0
```

### STDOUT tail

```text

```

### STDERR tail

```text
test_canonical_equality_across_formatting_and_key_order (test_sdk_core.DeltaSDKCoreTests.test_canonical_equality_across_formatting_and_key_order) ... ok
test_canonical_json_orders_keys_and_hashes_deterministically (test_sdk_core.DeltaSDKCoreTests.test_canonical_json_orders_keys_and_hashes_deterministically) ... ok
test_canonical_json_rejects_float_values (test_sdk_core.DeltaSDKCoreTests.test_canonical_json_rejects_float_values) ... ok
test_load_json_file_rejects_utf8_bom (test_sdk_core.DeltaSDKCoreTests.test_load_json_file_rejects_utf8_bom) ... ok
test_verify_attestation_pair_from_files (test_sdk_core.DeltaSDKCoreTests.test_verify_attestation_pair_from_files) ... ok
test_verify_attestation_pair_from_memory (test_sdk_core.DeltaSDKCoreTests.test_verify_attestation_pair_from_memory) ... ok
test_verify_checkpoint_pair_from_files (test_sdk_core.DeltaSDKCoreTests.test_verify_checkpoint_pair_from_files) ... ok
test_verify_checkpoint_pair_from_memory (test_sdk_core.DeltaSDKCoreTests.test_verify_checkpoint_pair_from_memory) ... ok
test_verify_claim_pair_from_files (test_sdk_core.DeltaSDKCoreTests.test_verify_claim_pair_from_files) ... ok
test_verify_claim_pair_from_memory (test_sdk_core.DeltaSDKCoreTests.test_verify_claim_pair_from_memory) ... ok
test_wrong_role_fails (test_sdk_core.DeltaSDKCoreTests.test_wrong_role_fails) ... ok
test_wrong_target_hash_fails (test_sdk_core.DeltaSDKCoreTests.test_wrong_target_hash_fails) ... ok

----------------------------------------------------------------------
Ran 12 tests in 0.023s

OK

```

## Security boundary

This replay verification does not create a new signed replay proof.

It checks whether the signed sensor record can be replayed from a fresh clone and whether the declared measurement result matches.
