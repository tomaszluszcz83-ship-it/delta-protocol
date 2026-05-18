# TV-001: Signed Sensor Record / Proof of Change

**Layer:** Sensor Record / Proof of Change  
**Status:** Draft test vector  
**Purpose:** verify that a signed DELTA sensor record is hash-bound, signature-bound, and replay-checkable.

## Positive test objective

A valid signed sensor record should pass its core integrity checks:

- record body hash self-check,
- record signature presence,
- record signature verification,
- measurement method hash presence,
- evidence hash commitments,
- after-state hash consistency where applicable,
- `python src/delta_cli.py verify-all` still passes.

## Reference command

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC
python src/delta_cli.py verify-all
```

Expected:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK
DELTA CLI RESULT: OK
```

## Replay-related command pattern

For an existing signed record, replay verification follows this pattern:

```powershell
python tools\delta_replay.py `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --skip-install
```

Expected positive indicators vary by record profile, but should include the replay result and relevant checks such as:

```text
DELTA_REPLAY_RESULT: OK
DELTA_REPLAY_CHECK_RECORD_SIGNATURE=True
DELTA_REPLAY_CHECK_AFTER_STATE_HASH=True
DELTA_REPLAY_CHECK_METHOD_DEFINITION_HASH=True
DELTA_REPLAY_CHECK_MEASUREMENT_RESULT_OK=True
```

## Negative test: tampered record body

Auditor action:

1. Copy a valid `delta-record.json` to a temporary test file.
2. Modify one field inside `record_body`.
3. Run the appropriate verifier/replay command.

Expected result:

```text
DELTA_REPLAY_RESULT: FAIL
```

or a failed self-check/signature check such as:

```text
DELTA_REPLAY_CHECK_RECORD_SIGNATURE=False
```

The exact failure reason may depend on the record type and verifier version.

## Security boundary

This test vector proves cryptographic consistency of a signed sensor record and its declared replay-related commitments.
It does not prove legal truth, external-world truth, identity, authority, or that evidence was not fabricated before hashing.
