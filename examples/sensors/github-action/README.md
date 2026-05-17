# DELTA GitHub Action Sensor Example

The repository workflow `.github/workflows/delta-sensor.yml` generates a signed dirty DELTA sensor record.

It runs on:

- `workflow_dispatch`
- pushes to `main`
- pushes to `sensors/**`
- pull requests into `main`

The generated artifact is named:

```text
delta-sensor-record
```

It contains:

```text
delta-record.json
delta-sensor-output.log
delta-sensor-error.log
delta-replay.sh
delta-sensor-summary.md
```

This is the first sensor-layer prototype.

It is not the final Delta Record RFC.

## Required signing key

Generate a keypair:

```bash
python tools/delta_sensor_keygen.py
```

Store the private key as a GitHub Actions secret:

```text
DELTA_SENSOR_PRIVATE_KEY
```

Store the public key as a GitHub repository variable:

```text
DELTA_EXECUTOR_PUBLIC_KEY
```

The sensor record includes:

```text
record_signature.public_key
record_signature.signature
record_signature_verification.ok
```

Do not commit private keys.

## Replay isolation

Generated replay instructions are designed to run in a temporary fresh clone.

They must not mutate a verifier's active worktree.
