# Review DELTA in 10 Minutes

## Purpose

This guide is a short public reviewer path for DELTA Protocol.

It is intended for first-time reviewers, security researchers, auditors, protocol reviewers, CI/CD maintainers, software supply-chain engineers, potential integrators, and serious early adopters who want to understand DELTA quickly before performing a deeper review.

This document is not a certification checklist, legal assessment, regulatory assessment, production approval, or formal audit report.

It is a practical route through the public review surface created during the v2.16.x public-adoption phase.

## What DELTA is

DELTA Protocol is an open, zero-token cryptographic Proof of Change protocol.

It is designed to help prove relationships between declared digital artifacts, evidence, verification results, signatures, intent, audit artifacts, publication proofs, trust context, private evidence commitments, bundles, and future privacy-preserving proof layers.

DELTA is not a cryptocurrency, token, blockchain, SaaS platform, marketplace, identity provider, legal authority, compliance engine, oracle of reality, or institutional approval mechanism.

## What this 10-minute review should achieve

After this short review, a reader should understand:

- what DELTA is trying to prove,
- what DELTA explicitly does not prove,
- how to run the minimal public demo,
- how to observe automated tamper detection in CI,
- how to run the baseline public verification command,
- where canonical JSON vectors are verified,
- where the reviewer checklist lives,
- how to submit structured external feedback,
- why ZK implementation is intentionally deferred.

## 0. Start from the README

Begin at the repository README.

Confirm that the README contains the public demo and reviewer entry point.

Expected high-level path:

```text
README → local demo → CI demo → quick-start → reviewer checklist → external review feedback
```

Look for:

- the minimal public demo link,
- the GitHub Actions tamper-detection workflow link,
- the quick-start link,
- the reviewer checklist link,
- the external review request link.

## 1. Run the minimal local demo

Open the repository root and run the minimal demo.

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File demo\minimal-demo\verify.ps1
```

Expected result:

```text
Original artifact hash matches expected value.
Tampered artifact hash mismatch detected.
Demo succeeded: tampering was detected.
```

Review boundary:

This demo demonstrates hash-based tamper detection only.

It does not prove Ed25519 signatures, full `.delta` bundle verification, complete record-chain verification, Proof of Intent, Proof of Audit, Proof of Publication, Proof of Trust, wallet proof validity, legal identity, signer authority, regulatory compliance, real-world truth, evidence completeness, policy correctness, institutional approval, or business authority.

## 2. Review the automated CI demo

Open the GitHub Actions workflow:

```text
.github/workflows/delta-minimal-demo.yml
```

Review that the workflow demonstrates the same minimal property:

```text
known bytes → hash OK → tamper → hash mismatch → CI succeeds only if tampering is detected
```

Expected final design:

- `ubuntu-latest`,
- `bash`,
- `sha256sum`,
- no private keys,
- no production secrets,
- no blockchain dependency,
- no SaaS account dependency,
- no external proof service.

Review boundary:

The workflow is a public demonstration of tamper detection, not a full DELTA proof verifier.

## 3. Run baseline DELTA public verification

From the repository root:

```powershell
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA CLI RESULT: OK
```

This verifies the repository’s public DELTA proof artifacts using the Python reference implementation.

Review boundary:

This command verifies public repository artifacts. It does not imply legal identity, signer authority, institutional approval, regulatory compliance, real-world truth, sensor honesty, evidence completeness, or policy sufficiency.

## 4. Run Canonical JSON / JCS vector verification

From the repository root:

```powershell
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
```

Expected result:

```text
DELTA_JCS_VERIFY_OK=True
```

Review focus:

- duplicate-key rejection,
- floating-point rejection,
- NaN rejection,
- Infinity rejection,
- unsafe-integer rejection,
- stable canonical serialization,
- stable SHA-256 vector behavior.

Canonicalization is critical because DELTA hashes and signatures depend on deterministic bytes.

## 5. Review the public reviewer checklist

Read:

```text
docs/review/REVIEWER_CHECKLIST.md
```

Use it for a deeper methodical review.

Key review areas:

- protocol model clarity,
- hash-binding correctness,
- signature verification boundaries,
- schema registry boundaries,
- TypeScript verifier scope,
- private evidence commitment limits,
- private evidence Merkle set behavior,
- wallet proof boundaries,
- replay environment assumptions,
- CI/CD integration clarity,
- anti-overclaiming discipline.

## 6. Read the external review request

Read:

```text
docs/review/EXTERNAL_REVIEW_REQUEST.md
```

This document explains what kind of review DELTA is requesting and how reviewers should classify findings.

Appropriate feedback categories include:

- critical security issue,
- verification correctness issue,
- canonicalization issue,
- signature or hash-binding issue,
- documentation correction,
- RFC or protocol-design feedback,
- implementation defect,
- integration feedback,
- usability feedback,
- future feature proposal.

Do not post private keys, seed phrases, production secrets, customer data, private evidence, tokens, or sensitive artifacts in public issues.

## 7. Inspect the quick-start

Read:

```text
docs/quickstart/quickstart-v2.16.2.md
```

Review whether a new developer can understand the basic DELTA flow without needing internal project context.

Suggested reviewer question:

```text
Can a first-time user understand how to verify something before learning every DELTA proof layer?
```

## 8. Check the core security boundary

A reviewer should confirm that DELTA consistently separates:

- cryptographic validity,
- trust validity,
- legal validity,
- operational validity,
- real-world truth,
- regulatory sufficiency,
- policy sufficiency.

A cryptographically valid DELTA artifact may still be legally insufficient, operationally misleading, based on false input data, produced by a compromised system, or unsupported by an organization’s actual authority model.

This distinction is intentional and should remain visible in the documentation.

## 9. Check the ZK boundary

DELTA has ZK-related design work and private-evidence preparation, but production ZK implementation is intentionally deferred.

Review expected boundary:

- private evidence commitments are not encryption,
- private evidence Merkle sets are not ZK proofs,
- future ZK must define exact public inputs,
- future ZK must define exact private witnesses,
- future ZK must define exact circuit statements,
- future ZK must define exact proof profile and assumptions,
- DELTA must not claim production ZK provenance before implementation and review.

## 10. Submit feedback

Use the external review feedback issue template:

```text
.github/ISSUE_TEMPLATE/external-review-feedback.md
```

When submitting feedback, include:

- what you reviewed,
- which command or document was involved,
- expected behavior,
- observed behavior,
- impact,
- whether the issue is security-critical, verification-critical, documentation-related, RFC-related, integration-related, or usability-related.

For sensitive security issues, use private vulnerability reporting if available or contact the maintainer privately before posting public details.

## Minimal 10-minute path

For a very short first pass, follow this sequence:

```text
1. Read the README public demo entry point.
2. Run demo/minimal-demo/verify.ps1.
3. Open the DELTA Minimal Public Demo GitHub Actions workflow.
4. Run python src/delta_cli.py verify-all.
5. Run canonical JSON vector verification.
6. Read docs/review/REVIEWER_CHECKLIST.md.
7. Read docs/review/EXTERNAL_REVIEW_REQUEST.md.
8. Submit structured feedback if something is unclear or incorrect.
```

## Expected reviewer mindset

DELTA should be reviewed as a protocol candidate, not as a marketing claim.

Strong review is welcome.

A useful review may identify:

- unclear trust boundaries,
- ambiguous proof semantics,
- overclaiming language,
- missing negative tests,
- canonicalization weaknesses,
- verifier inconsistencies,
- unsafe key-handling assumptions,
- misleading examples,
- unclear CI behavior,
- incomplete public reviewer onboarding.

The goal is not to avoid criticism.

The goal is to make DELTA more precise, more reviewable, more reproducible, and harder to misuse.
