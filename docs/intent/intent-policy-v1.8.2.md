# DELTA v1.8.2 — Intent Policy Reporting

v1.8.2 introduces report-only intent policy metadata for signed DELTA Sensor Records.

## Goal

A sensor record can declare whether a detached Proof of Intent bundle is required and, if so, the deadline by which the intent should be supplied.

This release does not change the main replay success criterion. It reports policy status for audit visibility.

## Sensor fields

`tools/delta_sensor.py` writes a signed `record_body.intent_policy` object:

```json
{
  "type": "delta_record_intent_policy",
  "version": "1.0.0",
  "policy_id": "intent-policy-v1",
  "mode": "detached_intent_required",
  "status": "declared",
  "intent_required": true,
  "intent_deadline": "2026-05-19T00:00:00Z",
  "enforcement": "report_only_v1_8_2",
  "binding": "intent.target.record_hash must match the SHA-256 hash of the full delta-record.json"
}
```

The object is part of `record_body`, so it is covered by `record_body_hash` and the Ed25519 sensor signature.

## Sensor CLI

```powershell
python tools/delta_sensor.py `
  --intent-required `
  --intent-deadline "2026-05-19T00:00:00Z" `
  --intent-policy-id intent-policy-v1
```

Without `--intent-required`, the sensor still writes an explicit report-only policy with `intent_required=false`.

## Replay reporting

`tools/delta_replay.py` reports:

```text
DELTA_REPLAY_RECORD_INTENT_REQUIRED=True/False
DELTA_REPLAY_RECORD_INTENT_DEADLINE=<timestamp/null>
DELTA_REPLAY_RECORD_INTENT_POLICY_ID=<id/null>
DELTA_REPLAY_RECORD_INTENT_POLICY_STATUS=NOT_DECLARED/DECLARED/SATISFIED/MISSING/INVALID
DELTA_REPLAY_RECORD_INTENT_DEADLINE_OK=True/False
```

Policy status meanings:

- `NOT_DECLARED`: old record or no `record_body.intent_policy`.
- `DECLARED`: policy exists and does not require intent.
- `SATISFIED`: policy requires intent and the supplied intent bundle is verified.
- `MISSING`: policy requires intent but no verified intent bundle was supplied.
- `INVALID`: policy requires intent and an invalid intent bundle was supplied.

## Security boundary

Proof of Intent policy reporting does not prove legal consent, ticket truth, real-world identity, MFA truth, registry governance, anchoring, or external-world truth.

It reports whether the signed record declared an intent requirement and whether the replay received a matching verified intent bundle. The intent binding remains `target.record_hash`, the SHA-256 hash of the full `delta-record.json`.
