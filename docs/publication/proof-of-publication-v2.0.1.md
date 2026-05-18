# DELTA v2.0.1 — OpenTimestamps Pending Adapter

## Purpose

DELTA v2.0.1 extends Proof of Publication with an offline OpenTimestamps pending adapter.

The goal is intentionally narrow:

```text
delta-record.json
→ SHA-256 of full canonical record
→ OpenTimestamps .ots artifact hash
→ DELTA publication proof
→ offline verifier checks record binding + .ots file hash binding
```

## Security boundary

`opentimestamps_pending_v1` does **not** prove final Bitcoin anchoring.

It proves only that:

1. a DELTA publication proof is bound to the SHA-256 hash of a full `delta-record.json`;
2. the proof declares `opentimestamps_pending_v1`;
3. the supplied `.ots` artifact hash matches the hash recorded in the publication proof.

Final timestamp confirmation requires a later online OpenTimestamps verification step. That can be added in a future release such as `v2.0.2`.

## Commands

### Hash record

```powershell
python tools\delta_publish.py hash-record `
  --record C:\path\to\delta-record.json
```

### Create a publication proof bound to an OTS artifact

```powershell
python tools\delta_publish.py create-proof `
  --record C:\path\to\delta-record.json `
  --out .delta\publication-tests\OTS-001\delta-publication-proof.json `
  --method opentimestamps_pending_v1 `
  --publisher local-publisher `
  --external-file .delta\publication-tests\OTS-001\delta-record.ots `
  --note "DELTA v2.0.1 OpenTimestamps pending adapter test"
```

### Verify a proof and its external file binding

```powershell
python tools\delta_publish.py verify-proof `
  --record C:\path\to\delta-record.json `
  --proof .delta\publication-tests\OTS-001\delta-publication-proof.json `
  --external-file .delta\publication-tests\OTS-001\delta-record.ots
```

Expected key lines:

```text
DELTA_PUBLICATION_VERIFY_OK=True
DELTA_PUBLICATION_RECORD_BINDING_OK=True
DELTA_PUBLICATION_PROOF_BODY_HASH_OK=True
DELTA_PUBLICATION_EXTERNAL_FILE_HASH_OK=True
DELTA_PUBLICATION_OPENTIMESTAMPS_PENDING_SHAPE_OK=True
```

## What changed from v2.0.0

v2.0.0 could store an external evidence URI/hash.

v2.0.1 adds explicit local external-file binding:

```text
--external-file <path>
```

When `--external-file` is provided, DELTA computes:

```text
sha256(file_bytes)
```

and records it as:

```json
"external_evidence_hash": "sha256:..."
```

For `opentimestamps_pending_v1`, DELTA also records:

```json
"external_evidence_type": "opentimestamps_ots_file",
"opentimestamps": {
  "status": "pending_or_unverified",
  "artifact_bound": true,
  "online_verification_performed": false
}
```

## What DELTA proves

DELTA v2.0.1 proves:

```text
This publication proof is bound to this exact DELTA record hash and to this exact external OTS artifact hash.
```

## What DELTA does not prove

DELTA v2.0.1 does not prove:

- legal truth;
- ticket truth;
- audit truth;
- real-world identity;
- external-world truth;
- final OpenTimestamps / Bitcoin anchoring.

## Tests for OTS-001

Recommended tests:

1. create proof with `--method opentimestamps_pending_v1` and `--external-file`;
2. verify proof with the same record and same external file;
3. tamper the external file and verify that `DELTA_PUBLICATION_EXTERNAL_FILE_HASH_OK=False`;
4. tamper `proof_body_hash` and verify failure;
5. tamper `record_hash` and verify failure;
6. run `python src/delta_cli.py verify-all`.

## Commit policy

Do commit:

```text
tools/delta_publish.py
docs/publication/proof-of-publication-v2.0.1.md
```

Do not commit:

```text
.delta/publication-tests/
*.ots
generated local publication artifacts
```
