# DELTA UX / Adoption Workflow (v2.7.3)

Status: Reviewer-facing workflow guide

## 1. Goal

This guide explains how DELTA artifacts move from internal proof generation to external review.

The intended adoption path is simple:

```text
create / verify proof
→ generate readable report
→ package public artifacts
→ send one portable bundle
→ reviewer verifies locally
```

## 2. Artifact roles

| Artifact | Created by | Purpose |
| --- | --- | --- |
| `delta-record.json` | sensor / existing proof workflow | Core record of observed change. |
| `intent-attestation.json` | `tools/delta_intent_create.py` | Unsigned intent draft bound to the record hash. |
| `delta-report.html` / `.md` | `tools/delta_export.py` | Human-readable technical report. |
| `sample.delta` | `tools/delta_bundle.py` | Portable public artifact container. |
| `bundle_manifest.json` | inside `.delta` bundle | Hash and size manifest for bundle artifacts. |

## 3. What a reviewer should do

A reviewer SHOULD:

1. inspect the bundle contents,
2. run bundle verification,
3. run proof-specific verification on contained artifacts,
4. verify canonical JSON vectors,
5. compare results to expected CLI outputs,
6. treat all reports as technical proof reports, not legal certificates.

## 4. What must never be included

A `.delta` bundle MUST NOT include:

- private keys,
- seed phrases,
- API tokens,
- passwords,
- raw private evidence,
- decrypted evidence,
- internal secrets,
- private wallet material.

The bundle tool includes anti-leak filename guardrails, but human review remains required.

## 5. Security boundary

DELTA UX tools are designed to reduce friction, not to weaken verification.

`delta_export.py` does not create a proof.

`delta_intent_create.py` creates unsigned drafts only.

`delta_bundle.py` packages public artifacts and verifies bundle-level integrity only.

A complete review still requires the relevant DELTA verifiers.
