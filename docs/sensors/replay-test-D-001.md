# DELTA Replay Test D-001

Status: PASS

This document records the first replay test for the DELTA Sensor Record layer.

The test uses a fresh clone in a temporary directory and replays the measurement method declared in record C-010.

## Source record

- Record id: `C-010`
- Record path: `C:\Users\PC\Desktop\DELTA-C-RECORDS\C-010\delta-sensor-record (14)\delta-record.json`
- Record body hash: `sha256:1f7e87aea1f0cf4f02e6cd788b9c13a6396db214b43a0909b9b144667f395440`
- Commit after: `665195d000534ca9f8a1aa256149999a084bb811`
- Expected measurement_result.ok: `True`

## Replay environment

- Repository URL: `https://github.com/tomaszluszcz83-ship-it/delta-protocol.git`
- Fresh clone path: `C:\Users\PC\AppData\Local\Temp\delta-d001-replay-1x993mv6\repo`
- Method definition path: `.delta/methods/delta-cli-verify-all-v1.json`
- Command: `python src/delta_cli.py verify-all`

## Checks

| Check | Expected | Actual | Result |
| --- | --- | --- | --- |
| after_state_hash | `sha256:7d2e74de880700eb1346698abfb7be1b6effd5ef1eaa1312a73795c8d4545034` | `sha256:7d2e74de880700eb1346698abfb7be1b6effd5ef1eaa1312a73795c8d4545034` | `True` |
| method_definition_hash | `sha256:1cf3163a796bd4aaf4151fe85d28c273fac0fd17189b1f170d448c51514e827d` | `sha256:1cf3163a796bd4aaf4151fe85d28c273fac0fd17189b1f170d448c51514e827d` | `True` |
| measurement_result.ok | `True` | `True` | `True` |

## Measurement output

### Return code

```text
0
```

### STDOUT

```text
DELTA CLI v0.7.0-write-mode
Command: verify-all

Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK

DELTA CLI RESULT: OK

```

### STDERR

```text

```

## Conclusion

D-001 confirms that the C-010 sensor record can be replayed from a fresh clone and that the declared measurement method produces the expected result.

This strengthens the DELTA Sensor Record model from signed CI observation toward replayable signed proof of change.

## Security boundary

This replay test does not use private keys and does not create a new signed sensor record.

It only verifies whether an existing signed sensor record can be independently replayed from a fresh clone.
