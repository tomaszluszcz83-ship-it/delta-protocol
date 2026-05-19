# DELTA External Reviewer Guide Addendum (v2.7.3)

This addendum updates the reviewer path after v2.7.0, v2.7.1, and v2.7.2.

## 1. New reviewer flow

A reviewer can now ask for one `.delta` bundle instead of separate files.

The bundle should contain:

- `delta-record.json`
- `intent-attestation-draft.json`
- `delta-report.html` or `delta-report.md`
- `bundle_manifest.json`

The reviewer SHOULD verify the bundle first, then verify the contained artifacts.

## 2. Recommended checks

```powershell
python src/delta_cli.py verify-all
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
python tools\delta_bundle.py verify --bundle sample.delta --dir extracted
```

If the bundle contains an intent draft:

```powershell
python tools\delta_intent_create.py verify --attestation extracted\intent-attestation-draft.json --record extracted\delta-record.json
```

## 3. Important limitations

A valid bundle does not mean the contained proofs are valid.

A valid unsigned intent draft does not mean there is a signed Proof of Intent.

A valid report does not mean the report is a legal certificate.

A valid bundle manifest does not prove sender identity.

Sender-key authenticity is future work and is expected to be addressed by Signed Bundle in a later milestone.

## 4. Security boundary reminders

DELTA does not prove:

- legal truth,
- real-world truth,
- identity by itself,
- wallet balance by itself,
- regulatory compliance by itself,
- signer authority by itself.

Bitcoin external profile remains:

```text
shape_only / external_pending / CRYPTO_SIGNATURE_VERIFIED=False
```
