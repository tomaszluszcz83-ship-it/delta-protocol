# DELTA GitHub Action Sensor v1.3.x Dirty Prototype

This document describes the first DELTA sensor-layer prototype.

The goal is not to finalize the Delta Record RFC. The goal is to run a real sensor in GitHub Actions and learn what fields are required before the RFC is frozen.

## Status

Experimental dirty prototype.

It does not replace the DELTA-0 model:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

Instead, it generates a sensor-level artifact:

```text
.delta/artifacts/delta-record.json
```

This artifact is a signed, hash-committed sensor record envelope. It is not yet a full signed DELTA-0 bundle.

## Required signing key

The sensor requires an Ed25519 private key in the environment:

```text
DELTA_SENSOR_PRIVATE_KEY
```

Generate a keypair locally:

```bash
python tools/delta_sensor_keygen.py
```

Store:

```text
DELTA_SENSOR_PRIVATE_KEY -> GitHub Actions secret
DELTA_EXECUTOR_PUBLIC_KEY -> GitHub repository variable
```

The private key must never be committed.

The generated sensor record includes both generic signature fields and explicit executor aliases:

```text
record_signature.public_key
record_signature.public_key_hash
record_signature.executor_public_key
record_signature.executor_public_key_hash
record_signature.signature
record_signature_verification.ok
```

`executor_public_key` is intentionally duplicated as an audit-friendly alias of `public_key`.

## Separate schema namespace

The sensor record uses its own schema:

```text
.delta/schemas/delta-sensor-record-v1.3.0-dirty.schema.json
```

This schema is separate from DELTA-0 core objects:

- Claim
- Attestation
- Ledger Entry
- Signed Checkpoint

## What the sensor does

The workflow runs:

```bash
python tools/delta_sensor.py \
  --method .delta/methods/delta-cli-verify-all-v1.json \
  --schema .delta/schemas/delta-sensor-record-v1.3.0-dirty.schema.json \
  --out-dir .delta/artifacts
```

The sensor:

1. resolves before/after commits,
2. computes state hashes using Git tree listings,
3. loads an executable measurement method definition,
4. runs the measurement command,
5. writes stdout/stderr evidence logs,
6. hashes evidence logs,
7. writes isolated replay instructions,
8. signs the canonical `record_body` with Ed25519,
9. writes a `delta-record.json` artifact,
10. verifies its own `record_body_hash` and Ed25519 signature.

## Replay isolation

Replay instructions are designed to run in an isolated fresh clone.

They must not mutate the verifier's active worktree.

## Measurement method

The measurement method is defined in:

```text
.delta/methods/delta-cli-verify-all-v1.json
```

The method definition itself is hash-committed in the record as:

```text
measurement_method.method_definition_hash
```

The record also includes:

```text
measurement_method.method_id
measurement_method.method_version
measurement_method.description
measurement_method.replay_notes
```

## Evidence commitments

The sensor stores local/private artifact commitments:

```text
delta-sensor-output.log
delta-sensor-error.log
delta-replay.sh
```

Each artifact receives a `sha256:<hex>` hash.

## Security boundary

This prototype does not implement:

- public key registry,
- anchoring,
- mirror nodes,
- challenge/dispute,
- trust graph,
- full Delta Record bundle verification.

Those layers remain future work.
