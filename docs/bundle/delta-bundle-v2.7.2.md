# DELTA Protocol — Portable Bundle Standard (v2.7.2)

Status: Technical Alpha / reference utility  
Profile: `delta_bundle_v2_7_2`

## 1. Purpose

The DELTA `.delta` bundle is a portable public-verification package for DELTA proof artifacts.

It exists to make DELTA evidence easier to share with auditors, clients, managers, and reviewers without sending a loose collection of files.

A `.delta` bundle is a ZIP container with a `.delta` extension.

## 2. Security boundary

A `.delta` bundle is public by design.

It MUST NOT contain:

- private keys,
- seed phrases,
- API tokens,
- credentials,
- raw private evidence,
- decrypted evidence,
- secrets,
- private wallet keys,
- generated local sensitive artifacts.

The bundle does not create new cryptographic proofs. It packages existing public artifacts and verifies bundle-level integrity.

A DELTA verifier MUST still run proof-specific verification for the record, intent, audit, publication, trust, wallet, and replay layers.

## 3. Required contents

A v2.7.2 bundle contains:

| File | Purpose |
| --- | --- |
| `bundle_manifest.json` | Bundle manifest with artifact hashes and security policy. |
| `delta-record.json` | Public DELTA record artifact. |
| `intent-attestation-draft.json` | Unsigned intent draft created by `delta_intent_create.py`. |
| `delta-report.html` or `delta-report.md` | Human-readable report created by `delta_export.py`. |

Filenames MAY vary, but every artifact MUST be declared in `bundle_manifest.json`.

## 4. Manifest requirements

The manifest MUST include:

- `manifest_profile`,
- `manifest_body`,
- `manifest_body_hash`,
- `self_check.manifest_body_hash`,
- `bundle_profile`,
- `protocol_version`,
- `created_at`,
- artifact list,
- artifact SHA-256 hashes,
- artifact sizes,
- security policy.

The verifier MUST recompute the manifest body hash.

The verifier MUST recompute the SHA-256 hash of every declared artifact.

The verifier MUST reject bundles with missing manifest, duplicate filenames, path traversal, unsafe filenames, hash mismatches, or size mismatches.

## 5. Anti-leak guardrails

The v2.7.2 reference tool rejects archive names containing sensitive fragments such as:

- `private`,
- `secret`,
- `seed`,
- `token`,
- `password`,
- `credential`,
- `private_key`,
- `id_rsa`,
- `id_ed25519`,
- `decrypted`,
- `evidence.raw`.

This is not a substitute for human review. Users MUST inspect bundle contents before sharing externally.

## 6. Usage

Create a bundle:

```powershell
python tools\delta_bundle.py create `
  --output .delta\bundles\sample.delta `
  --record C:\path\to\delta-record.json `
  --intent .delta\intent-tests\I-271\intent-attestation.json `
  --report .delta\exports\delta-report.html
```

Verify and extract:

```powershell
python tools\delta_bundle.py verify `
  --bundle .delta\bundles\sample.delta `
  --dir .delta\bundles\extracted
```

Expected result:

```text
DELTA_BUNDLE_VERIFY_OK=True
DELTA_BUNDLE_PROFILE=delta_bundle_v2_7_2
```

## 7. What this does not prove

A DELTA bundle does not prove:

- legal truth,
- real-world truth,
- human identity,
- wallet balance,
- regulatory compliance,
- signer authority,
- correctness of private evidence,
- that the contained report is complete,
- that a full signed Proof of Intent exists.

It only packages declared public artifacts and verifies bundle-level integrity.

## 8. Relationship to previous milestones

v2.7.2 builds on:

- v2.7.0 `delta_export.py`,
- v2.7.1 `delta_intent_create.py`,
- v2.6.0 JCS canonical JSON vectors,
- v2.6.1 JSON Schema Registry,
- v2.6.2 conformance planning.

## 9. Future work

Future versions may add:

- detached bundle signatures,
- public bundle hash publication,
- bundle schema validation,
- bundle conformance tests,
- browser-based bundle verification,
- optional ZK-friendly commitments.

Those are out of scope for v2.7.2.
