# DELTA README v1.4.1 Refresh

<!-- DELTA_README_STATUS_START -->

## Current status

DELTA is an open, zero-token Proof-of-Change protocol.

The current implementation includes:

- DELTA-0 public proof verification
- Python SDK with in-memory verification helpers
- canonical JSON hashing tests
- GitHub Actions public verification
- signed GitHub Action Sensor records
- embedded executor public key in every signed sensor record
- Stage C observation dataset with 10 real CI records
- RFC-00 for the DELTA Sensor Record layer
- D-001 replay test from a fresh clone

DELTA is not a cryptocurrency, token, SaaS, marketplace, or account platform.

Current positioning:

```text
The internet can prove ownership.
DELTA proves change.
```

---

## Quick start: public verification

The simplest public verification path requires no private keys.

```bash
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

A minimal GitHub Actions verification workflow can be as small as:

```yaml
name: DELTA Verify

on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - name: Verify DELTA public proof artifacts
        run: python src/delta_cli.py verify-all
```

Byte-exact Git policy checks, `.gitattributes` checks, and repository-specific line-ending checks are optional hardening steps. They are not required for a minimal DELTA verification workflow.

---

## Automated Proof of Change with sensors

Starting with the signed GitHub Action Sensor work, DELTA can generate machine-created Proof-of-Change records from CI.

A sensor record captures:

- before/after commit references
- before/after state hashes
- measurement method id and version
- measurement method definition hash
- measurement result, including failures
- evidence hash commitments
- replay instructions
- canonical record body hash
- Ed25519 signature
- embedded executor public key and public key hash

A valid signed sensor record proves that the holder of the sensor private key signed the exact canonical record body.

It does not prove absolute truth about the physical world or legal trust in the signer.

Important Stage C finding:

```text
A failed measurement can still produce a valid signed record.
```

This is intentional. DELTA records what was observed. It does not hide failures.

---

## Specifications and reports

Key documents:

- [RFC-00: DELTA Sensor Record](docs/rfc/RFC-00-delta-sensor-record.md)
- [Stage C Observation Report](docs/sensors/observation-report-stage-C.md)
- [Replay Test D-001](docs/sensors/replay-test-D-001.md)
- [GitHub Action Sensor documentation](docs/sensors/github-action-sensor-v1.3.0.md)
- [Python SDK documentation](docs/sdk/python-sdk.md)

Sensor-layer RFC scope:

```text
DELTA Sensor Record
```

Full DELTA-0 bundle scope remains separate:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

---

## Recent milestones

- `v1.2.0-python-sdk-core` — Python SDK core
- `v1.2.1-python-sdk-ergonomics` — in-memory SDK verification and canonical JSON tests
- `v1.3.0-signed-github-action-sensor` — first signed GitHub Action Sensor
- `v1.3.1-signed-sensor` — embedded executor public key aliases for auditability
- `v1.4.0-sensor-record-rfc-00` — RFC-00 Sensor Record based on Stage C observations
- `D-001` — replay test from a fresh clone, confirming replayability of record C-010

---

## Security boundary

DELTA currently proves cryptographic consistency of declared records.

It can prove:

- canonical record body hash
- Ed25519 signature validity
- public key embedded in the record
- declared before/after references
- declared measurement result
- evidence hash commitments
- replay instructions availability

It does not yet implement:

- full DELTA-0 signed bundle finalization
- public key registry
- anchoring
- mirror nodes
- challenge/dispute
- trust graph
- final standardization of all record types

---

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file.

Trademark, attribution, and notice information is described in `NOTICE` when present.

<!-- DELTA_README_STATUS_END -->


Extract into repository root and run:

```powershell
cd C:\Users\PC\Desktop\DELTA-0-PUBLIC

python .\apply_readme_v1_4_1_refresh.py
```

Then verify and commit:

```powershell
Remove-Item .\apply_readme_v1_4_1_refresh.py -Force

python src/delta_cli.py verify-all

git status

git add README.md

git commit -m "docs: refresh README for sensors and RFC-00"

git push
```
