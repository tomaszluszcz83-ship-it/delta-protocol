# DELTA Replay Verification Report

Status: PASS

## Record

- Record path: `C:\Users\PC\Desktop\DELTA-C-RECORDS\C-001\delta-sensor-record\delta-record.json`
- Method id: `delta-cli-verify-all-v1`
- Commit after: `00fc4264b027bec924cb32631b792273d8b6e7f9`
- Fresh clone: `C:\Users\PC\AppData\Local\Temp\delta-replay-d716lkyg\repo`

## Checks

| Check | Result | Detail |
| --- | --- | --- |
| record_signature | `True` | `ok` |
| after_state_hash | `True` | `expected=sha256:9c58ca3e4b4abe8fac147929cd1b4e04763f193f5a9a7748b7d768e401ea28d5 actual=sha256:9c58ca3e4b4abe8fac147929cd1b4e04763f193f5a9a7748b7d768e401ea28d5` |
| method_definition_hash | `True` | `expected=sha256:1cf3163a796bd4aaf4151fe85d28c273fac0fd17189b1f170d448c51514e827d actual=sha256:1cf3163a796bd4aaf4151fe85d28c273fac0fd17189b1f170d448c51514e827d` |
| measurement_result_ok | `True` | `expected=True actual=True` |
| stdout_hash | `True` | `expected=sha256:b5dd2d1b8d39fd9d4e1825d19208155f89706234e7aa34fd3fc38bccb3c88018 actual=sha256:b5dd2d1b8d39fd9d4e1825d19208155f89706234e7aa34fd3fc38bccb3c88018 strict=False` |
| stderr_hash | `True` | `expected=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 actual=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 strict=False` |

## Command

```text
python src/delta_cli.py verify-all
```

## Measurement output

### Return code

```text
0
```

### STDOUT tail

```text
DELTA CLI v0.7.0-write-mode
Command: verify-all

Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK

DELTA CLI RESULT: OK

```

### STDERR tail

```text

```

## Security boundary

This replay verification does not create a new signed replay proof.

It checks whether the signed sensor record can be replayed from a fresh clone and whether the declared measurement result matches.
