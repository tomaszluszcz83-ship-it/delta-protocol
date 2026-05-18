# TV-004: Proof of Publication

**Layer:** Proof of Publication  
**Status:** Draft test vector  
**Purpose:** verify that a publication proof is bound to the full `delta-record.json` hash and optional external evidence.

## Positive test objective

A valid publication proof should verify:

```text
DELTA_PUBLICATION_VERIFY_OK=True
DELTA_PUBLICATION_RECORD_BINDING_OK=True
DELTA_PUBLICATION_PROOF_BODY_HASH_OK=True
DELTA_PUBLICATION_SELF_CHECK_OK=True
DELTA_PUBLICATION_METHOD_OK=True
DELTA_PUBLICATION_TIMESTAMP_OK=True
```

For OpenTimestamps pending adapter / external file mode:

```text
DELTA_PUBLICATION_EXTERNAL_FILE_HASH_OK=True
DELTA_PUBLICATION_OPENTIMESTAMPS_PENDING_SHAPE_OK=True
```

## Command pattern: create proof

```powershell
python tools\delta_publish.py create-proof `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\publication-tests\P-001\delta-publication-proof.json `
  --method local_timestamp_v1 `
  --publisher local-publisher `
  --note "DELTA publication test"
```

## Command pattern: verify proof

```powershell
python tools\delta_publish.py verify-proof `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --proof .delta\publication-tests\P-001\delta-publication-proof.json
```

## OpenTimestamps pending/external file pattern

```powershell
python tools\delta_publish.py create-proof `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\publication-tests\OTS-001\delta-publication-proof.json `
  --method opentimestamps_pending_v1 `
  --publisher local-publisher `
  --external-file .delta\publication-tests\OTS-001\delta-record.ots `
  --note "DELTA OpenTimestamps pending adapter test"
```

```powershell
python tools\delta_publish.py verify-proof `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --proof .delta\publication-tests\OTS-001\delta-publication-proof.json `
  --external-file .delta\publication-tests\OTS-001\delta-record.ots
```

## Negative test A: tampered record hash

Modify `record_hash` inside the publication proof.

Expected:

```text
DELTA_PUBLICATION_VERIFY_OK=False
DELTA_PUBLICATION_RECORD_BINDING_OK=False
```

## Negative test B: tampered proof body hash

Modify `proof_body_hash`.

Expected:

```text
DELTA_PUBLICATION_VERIFY_OK=False
DELTA_PUBLICATION_PROOF_BODY_HASH_OK=False
```

## Negative test C: tampered external `.ots` file

Modify the external file after proof creation.

Expected:

```text
DELTA_PUBLICATION_VERIFY_OK=False
DELTA_PUBLICATION_EXTERNAL_FILE_HASH_OK=False
```

## Security boundary

Proof of Publication proves binding between a publication proof object, a record hash, and optional external evidence hash.
It does not prove legal truth, real-world truth, ticket truth, audit truth, or final Bitcoin/OpenTimestamps calendar anchoring unless a future verifier explicitly performs such verification.
