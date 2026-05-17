# DELTA GitHub Action Sensor v1.3.0 Dirty Prototype

This document describes the first DELTA sensor-layer prototype.

The goal is not to finalize the Delta Record RFC.

The goal is to run a real sensor in GitHub Actions and learn what fields are required before the RFC is frozen.

---

## Status

Experimental.

This is a dirty prototype.

It does not replace the DELTA-0 model:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

Instead, it generates a sensor-level artifact:

```text
.delta/artifacts/delta-record.json
```

This artifact is a hash-committed sensor record envelope. It is not yet a signed DELTA-0 bundle.

---

## What the sensor does

The workflow runs:

```bash
python tools/delta_sensor.py \
  --method .delta/methods/delta-cli-verify-all-v1.json \
  --out-dir .delta/artifacts
```

The sensor:

1. resolves before/after Git references,
2. computes state hashes using Git tree listings,
3. loads an executable measurement method definition,
4. runs the measurement command,
5. writes stdout/stderr evidence logs,
6. hashes evidence logs,
7. writes replay instructions,
8. writes a `delta-record.json` artifact,
9. verifies its own `record_body_hash` using DELTA SDK canonical JSON.

---

## Measurement method

The measurement method is defined in:

```text
.delta/methods/delta-cli-verify-all-v1.json
```

It declares the executable command:

```json
["python", "src/delta_cli.py", "verify-all"]
```

The method definition itself is hash-committed in the record as:

```text
measurement_method.method_definition_hash
```

This is the first step toward executable measurement methods.

---

## Replay instructions

The generated artifact includes:

```text
.delta/artifacts/delta-replay.sh
```

The replay script is also embedded into `delta-record.json` and hash-committed as private evidence.

This is not yet a sandboxed replay verifier.

It is a practical executable replay artifact for the next RFC iteration.

---

## Evidence commitments

The sensor stores local/private artifact commitments:

```text
delta-sensor-output.log
delta-sensor-error.log
delta-replay.sh
```

Each artifact receives a `sha256:<hex>` hash.

The record exposes hashes and paths, not external uploads to a DELTA server.

---

## Security boundary

This prototype does not implement:

- private key signing,
- public key registry,
- anchoring,
- mirror nodes,
- challenge/dispute,
- trust graph,
- full Delta Record bundle verification.

Those layers remain future work.

---

## Why this comes before RFC

The sensor should expose real implementation pressure before the Delta Record RFC is frozen.

Expected learning areas:

- how to represent `measurement_method`,
- how to define executable replay,
- what runner/environment metadata matters,
- how to structure private evidence commitments,
- what should be signed later,
- what should remain artifact-only.

---

## Run locally

From the repository root:

```bash
python -m pip install -e ./packages/python/delta_protocol
python tools/delta_sensor.py --method .delta/methods/delta-cli-verify-all-v1.json --out-dir .delta/artifacts
```

Then inspect:

```text
.delta/artifacts/delta-record.json
.delta/artifacts/delta-sensor-output.log
.delta/artifacts/delta-replay.sh
```
