# DELTA Replay Verification Report

Status: PASS

## Record

- Record path: `C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json`
- Method id: `local-file-audit-v1`
- Commit after: `82398197d48d38bba9bada9f56d727ff35cb005b`
- Fresh clone: `C:\Users\PC\AppData\Local\Temp\delta-replay-hia3o1fs\repo`

## Checks

| Check | Result | Detail |
| --- | --- | --- |
| record_signature | `True` | `ok` |
| after_state_hash | `True` | `expected=sha256:8ec79747350f523cc399153c65108d4aa89990f024ac47eac2ca7bb777771045 actual=sha256:8ec79747350f523cc399153c65108d4aa89990f024ac47eac2ca7bb777771045` |
| method_definition_hash | `True` | `expected=sha256:0c2738ac6dfae8beacac3977a9ca1bbb4719004bdf45ca11e9ffce2d61c29faa actual=sha256:0c2738ac6dfae8beacac3977a9ca1bbb4719004bdf45ca11e9ffce2d61c29faa` |
| measurement_result_ok | `True` | `expected=True actual=True` |
| file_audit_manifest_hash | `True` | `expected=sha256:156580e7a1bae153c678ec433f48d0cc562a7a89286ba5469904209efd968cd5 actual=sha256:156580e7a1bae153c678ec433f48d0cc562a7a89286ba5469904209efd968cd5` |
| stdout_hash | `True` | `expected=sha256:b94bd15f5b80f29b7f875e23b30c80b729432171bf54598fe87cf637b8c5fd78 actual=sha256:b94bd15f5b80f29b7f875e23b30c80b729432171bf54598fe87cf637b8c5fd78 strict=False` |
| stderr_hash | `True` | `expected=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 actual=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 strict=False` |

## Command

```text
python tools/delta_file_audit.py --target README.md --manifest-out .delta/artifacts-file-audit/file-audit-manifest.json
```

## Measurement output

### Return code

```text
0
```

### STDOUT tail

```text
DELTA_FILE_AUDIT_RESULT: OK
DELTA_FILE_AUDIT_METHOD_ID=local-file-audit-v1
DELTA_FILE_AUDIT_METHOD_VERSION=1.0.0
DELTA_FILE_AUDIT_TARGET=README.md
DELTA_FILE_AUDIT_TARGET_KIND=file
DELTA_FILE_AUDIT_ENTRY_COUNT=1
DELTA_FILE_AUDIT_SKIPPED_COUNT=0
DELTA_FILE_AUDIT_MANIFEST_HASH=sha256:156580e7a1bae153c678ec433f48d0cc562a7a89286ba5469904209efd968cd5
DELTA_FILE_AUDIT_MANIFEST_PATH=.delta/artifacts-file-audit/file-audit-manifest.json

```

### STDERR tail

```text

```

## Security boundary

This replay verification does not create a new signed replay proof.

It checks whether the signed sensor record can be replayed from a fresh clone and whether the declared measurement result matches.
