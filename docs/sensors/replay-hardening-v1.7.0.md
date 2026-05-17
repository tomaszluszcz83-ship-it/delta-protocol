# DELTA v1.7.0 Replay Hardening

Status: Draft implementation  
Layer: Replay verification  
Milestone: v1.7.0  
Tool: `tools/delta_replay.py`

## Purpose

This milestone turns replay from documentation into an executable verification step.

Before v1.7.0, sensor records contained replay instructions, and D-001 showed that a replay could be performed manually from a fresh clone.

v1.7.0 introduces a dedicated replay tool:

```text
python tools/delta_replay.py --record path/to/delta-record.json
```

## What replay verifies

The MVP verifies:

- `record_body_hash`
- Ed25519 record signature
- `after_state_hash`
- `measurement_method.method_definition_hash`
- declared measurement result
- local file audit manifest hash when available

The tool returns:

```text
DELTA_REPLAY_RESULT: OK
```

or:

```text
DELTA_REPLAY_RESULT: FAILED
```

## Supported measurement methods

The replay tool is designed to replay the three current sensor methods:

```text
delta-cli-verify-all-v1
python-unittest-v1
local-file-audit-v1
```

## Security boundary

Replay verification proves that a signed sensor record can be re-executed from a fresh clone and that the replayed measurement agrees with the signed record.

It does not prove:

- legal trust in the signer
- external-world truth
- registry trust
- anchoring finality
- trust graph membership
- auditor approval

## Output hash policy

Some command outputs may contain runtime-dependent timing information, especially Python unittest output.

Therefore v1.7.0 treats stdout/stderr hash checks as optional by default.

Use this flag to make output hash mismatches fail replay:

```text
--strict-output-hashes
```

## Example

```powershell
python tools/delta_replay.py `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --report-out docs\sensors\replay-v1.7.0-F-001.md
```

Expected result:

```text
DELTA_REPLAY_RESULT: OK
```

## Future work

Future versions may add:

- signed replay proof
- `replay_verified_at`
- `replay_signature`
- structured replay instructions
- replay environment manifest
- deterministic container replay
