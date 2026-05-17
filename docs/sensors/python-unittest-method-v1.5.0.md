# DELTA v1.5.0: Python unittest measurement method

Status: Draft implementation  
Layer: Sensor layer  
Milestone: v1.5.0  
Method id: `python-unittest-v1`

## Purpose

This milestone adds a second measurement method to the DELTA Sensor layer.

Until v1.4.x, the signed GitHub Action Sensor primarily used:

```text
delta-cli-verify-all-v1
```

That method is still valid, but it does not prove that the sensor format can support multiple independent measurement methods.

`python-unittest-v1` adds a separate method based on the Python SDK unittest suite.

## Measurement method

Definition file:

```text
.delta/methods/python-unittest-v1.json
```

Command:

```text
python -m unittest discover -s packages/python/delta_protocol/tests -v
```

Expected success condition:

```text
return_code == 0
```

## CI workflow

The new workflow is:

```text
.github/workflows/delta-sensor-unittest.yml
```

It generates an artifact named:

```text
delta-sensor-record-unittest
```

The artifact should contain a signed DELTA Sensor Record generated from the unittest method.

## Security boundary

This method does not create a new protocol layer.

It only proves that the existing DELTA Sensor Record format can carry a second measurement method.

It still depends on:

- canonical record body hashing
- Ed25519 sensor signature
- embedded executor public key
- evidence hash commitments
- replay instructions

## Expected result

A successful run should produce:

```text
DELTA_SENSOR_MEASUREMENT_OK=True
DELTA_SENSOR_SELF_CHECK_OK=True
DELTA_SENSOR_SIGNATURE_PRESENT=True
DELTA_SENSOR_SIGNATURE_VERIFICATION_OK=True
DELTA_SENSOR_EXECUTOR_PUBLIC_KEY_PRESENT=True
```

## Why this matters

This is the first step toward showing that DELTA Sensor Records are method-agnostic.

A sensor record should not be limited to one command or one kind of proof.

Future methods may include:

- pytest
- file audit
- security scan
- benchmark/performance measurement
- Web3 read-only balance observation
