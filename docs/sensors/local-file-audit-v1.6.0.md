# DELTA v1.6.0: Local File Audit Sensor

Status: Draft implementation  
Layer: Sensor layer  
Milestone: v1.6.0  
Method id: `local-file-audit-v1`

## Purpose

This milestone adds a local file audit measurement method.

Until v1.5.0, DELTA Sensor measurements were based on verification and tests:

- `delta-cli-verify-all-v1`
- `python-unittest-v1`

`local-file-audit-v1` extends DELTA toward file and directory auditing.

The goal is to prove that a sensor observed specific file content hashes without exposing private file contents.

## Security boundary

A file audit record proves that the sensor observed and signed declared file hashes.

It does not prove:

- legal truth of the file contents
- external-world truth
- that the file was complete for a business process
- that the signer is legally trusted
- registry trust
- anchoring finality

## Measurement method

Definition file:

```text
.delta/methods/local-file-audit-v1.json
```

Default CI target:

```text
README.md
```

Command:

```text
python tools/delta_file_audit.py --target README.md --manifest-out .delta/artifacts-file-audit/file-audit-manifest.json
```

Expected success condition:

```text
return_code == 0
stdout contains DELTA_FILE_AUDIT_RESULT: OK
```

## Manifest policy

The manifest is deterministic and content-only.

It includes:

- method id
- method version
- target
- target kind
- hash algorithm
- metadata policy
- sorted file entries
- per-file SHA-256 hashes
- skipped path list

It intentionally excludes:

- atime
- ctime
- mtime
- owner
- group
- permissions

## Directory support

The tool supports both:

- single file audit
- recursive directory audit

For the first v1.6.0 MVP, the CI workflow uses a single stable file target: `README.md`.

Directory-tree tests can be added after the first CI artifact is verified.

## Output artifact

The workflow uploads:

```text
delta-sensor-record-file-audit
```

The artifact should include:

```text
delta-record.json
delta-sensor-summary.md
delta-sensor-output.log
delta-sensor-error.log
delta-replay.sh
file-audit-manifest.json
```

## Expected sensor output

```text
DELTA_SENSOR_MEASUREMENT_OK=True
DELTA_SENSOR_SELF_CHECK_OK=True
DELTA_SENSOR_SIGNATURE_PRESENT=True
DELTA_SENSOR_SIGNATURE_VERIFICATION_OK=True
DELTA_SENSOR_EXECUTOR_PUBLIC_KEY_PRESENT=True
```

The file audit command output should include:

```text
DELTA_FILE_AUDIT_RESULT: OK
DELTA_FILE_AUDIT_MANIFEST_HASH=sha256:<hex>
```

## Why this matters

This is the first DELTA sensor method focused on file state instead of tests.

It moves DELTA closer to broader audit use cases:

- configuration file audits
- policy file audits
- dataset snapshot commitments
- model artifact hash commitments
- deployment manifest checks

## Future work

Potential v1.6.x or v1.7.0 improvements:

- `.deltaignore`
- structured replay steps
- directory-tree CI target
- manifest hash commitment as a first-class sensor evidence item
- encrypted evidence artifacts
- replay hardening for file audit records
