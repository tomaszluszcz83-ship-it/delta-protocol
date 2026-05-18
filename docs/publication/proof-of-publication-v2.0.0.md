# DELTA v2.0.0 — Proof of Publication / Anchoring

## Purpose

Proof of Publication adds a publication/anchoring layer to DELTA.

It lets a verifier check that a standalone publication proof is cryptographically bound to the SHA-256 hash of a full `delta-record.json` object.

The core claim is narrow and intentional:

> DELTA can create and verify a publication proof object cryptographically bound to a specific DELTA record hash.

When that proof or hash is later published in an external venue such as a GitHub Release, IPFS, OpenTimestamps, a website, or another archival system, the external venue can provide independent evidence that the record hash existed no later than that publication time.

## Security boundary

Proof of Publication does **not** prove:

- legal truth;
- ticket truth;
- audit truth;
- real-world identity;
- correctness of the underlying change;
- absolute timestamp truth;
- external-world truth.

It proves only that a publication proof object refers to a specific DELTA record hash and passes local integrity checks.

External timestamp strength depends on the selected publication method and evidence.

## Hash binding

v2.0.0 preserves the same binding model used by Proof of Intent and Proof of Audit:

```text
sha256(canonical_json(full_delta_record_json))
```

The proof binds to the full `delta-record.json`, not only `record_body_hash`.

## Tool

`tools/delta_publish.py`

Commands:

```text
hash-record
create-proof
verify-proof
```

## Supported methods in v2.0.0

```text
local_timestamp_v1
github_release_asset_v1
opentimestamps_pending_v1
external_anchor_reference_v1
```

v2.0.0 verifies these methods offline as declared publication methods. It does not perform network calls and does not validate remote services.

## Example flow

```powershell
python tools\delta_publish.py hash-record `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json
```

```powershell
python tools\delta_publish.py create-proof `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --out .delta\publication-tests\P-001\delta-publication-proof.json `
  --method local_timestamp_v1 `
  --publisher local-publisher `
  --note "DELTA v2.0.0 Proof of Publication MVP test"
```

```powershell
python tools\delta_publish.py verify-proof `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --proof .delta\publication-tests\P-001\delta-publication-proof.json
```

Expected:

```text
DELTA_PUBLICATION_VERIFY_OK=True
DELTA_PUBLICATION_RECORD_BINDING_OK=True
DELTA_PUBLICATION_PROOF_BODY_HASH_OK=True
DELTA_PUBLICATION_SELF_CHECK_OK=True
```

## Tamper tests

If `proof_body.target.record_hash` is changed, `verify-proof` must fail with:

```text
DELTA_PUBLICATION_VERIFY_OK=False
DELTA_PUBLICATION_RECORD_BINDING_OK=False
```

If the proof body is changed without updating `proof_body_hash`, `verify-proof` must fail with:

```text
DELTA_PUBLICATION_VERIFY_OK=False
DELTA_PUBLICATION_PROOF_BODY_HASH_OK=False
```

## Design notes

- No token.
- No cryptocurrency.
- No SaaS account requirement.
- No blockchain dependency.
- Offline verification first.
- External anchors can be attached later as evidence.

## Future work

Possible future releases:

- v2.0.1: OpenTimestamps adapter.
- v2.0.2: GitHub Release asset verification metadata.
- v2.1.0: multi-anchor publication bundles.
- v2.2.0: optional publisher signatures.
