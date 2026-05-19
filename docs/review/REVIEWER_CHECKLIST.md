# DELTA Protocol Public Reviewer Checklist

## Purpose

This checklist is a structured external review guide for DELTA Protocol.

It is intended for security researchers, auditors, protocol reviewers, software supply-chain engineers, CI/CD maintainers, potential integrators, and technically serious early adopters who want to evaluate DELTA in a methodical way.

This document is not a certification.

Completing this checklist does not mean that DELTA is legally compliant, production-certified, formally audited, or safe for every possible use case. It is a practical review instrument designed to help reviewers identify strengths, weaknesses, ambiguities, implementation defects, documentation gaps, security-boundary concerns, and future standardization issues.

The expected reviewer mindset is:

- verify claims rather than trust descriptions,
- distinguish protocol design from implementation behavior,
- distinguish cryptographic validity from legal or organizational truth,
- look for places where documentation could overclaim,
- look for inconsistent verification behavior across implementations,
- report concrete, reproducible findings.

## Recommended review scope

A meaningful first review should cover:

- repository structure,
- current tagged release,
- README and public documentation,
- RFC-style protocol documents,
- security boundary documentation,
- canonical JSON / JCS profile,
- JSON Schema registry,
- Python Alpha Reference Implementation,
- TypeScript experimental verifier,
- signed records and signed bundles,
- intent verification,
- audit and private evidence documentation,
- private evidence commitments,
- private evidence Merkle set,
- CI/CD documentation,
- public demonstration flow,
- wallet proof profile boundaries,
- ZK roadmap boundaries.

## 1. Reviewer preparation

### 1.1 Clone and inspect the repository

- [ ] Clone the public repository.
- [ ] Confirm that the remote origin is the expected DELTA Protocol repository.
- [ ] Inspect the latest release tag.
- [ ] Confirm which release is marked as the latest public milestone.
- [ ] Confirm that the local working tree is clean before running review commands.

Suggested commands:

```powershell
git clone https://github.com/tomaszluszcz83-ship-it/delta-protocol.git
cd delta-protocol
git status
git tag --list "v*"
git log -1 --oneline
```

### 1.2 Verify the current tag or review target

- [ ] Identify the exact tag, branch, or commit under review.
- [ ] Record the commit hash.
- [ ] Record whether the review targets a tagged release, main branch, or development branch.
- [ ] Confirm that review conclusions are tied to a specific commit or tag.

Reviewer notes:

```text
Reviewed tag:
Reviewed commit:
Review date:
Reviewer:
Review scope:
```

### 1.3 Install required dependencies

- [ ] Confirm Python is available.
- [ ] Confirm Node.js and npm are available if reviewing the TypeScript verifier.
- [ ] Install TypeScript verifier dependencies if TypeScript review is included.
- [ ] Record tool versions.

Suggested commands:

```powershell
python --version
node --version
npm --version

cd verifier\ts
npm install
cd ..\..
```

## 2. Baseline verification

### 2.1 Python reference checks

- [ ] Run the main DELTA Python verification command.
- [ ] Confirm that the command completes successfully.
- [ ] Record the exact output.
- [ ] Investigate any warning, failure, or unexpected behavior.

Suggested command:

```powershell
python src/delta_cli.py verify-all
```

Expected high-level result:

```text
DELTA CLI RESULT: OK
```

### 2.2 Canonical JSON / JCS vector verification

- [ ] Run canonical JSON vector verification.
- [ ] Confirm valid vectors pass.
- [ ] Confirm invalid vectors are rejected.
- [ ] Confirm duplicate keys are rejected.
- [ ] Confirm floating-point values, NaN, Infinity, and unsafe integers are rejected.
- [ ] Confirm the declared profile is `delta_jcs_json_v1`.

Suggested command:

```powershell
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
```

Expected high-level result:

```text
DELTA_JCS_VERIFY_OK=True
```

### 2.3 Repository whitespace and formatting check

- [ ] Run `git diff --check`.
- [ ] Confirm no trailing whitespace or whitespace error is reported.

Suggested command:

```powershell
git diff --check
```

## 3. Protocol understanding

### 3.1 Core Proof of Change model

Review the core model:

```text
Before → Action → After → Evidence → Verification → Ledger
```

Checklist:

- [ ] Confirm that the model is consistently described across README and protocol documentation.
- [ ] Confirm that the model does not claim to prove real-world truth by itself.
- [ ] Confirm that the record structure binds declared artifacts rather than making unsupported factual claims.
- [ ] Confirm that “proof of change” is distinguished from “proof of ownership.”
- [ ] Confirm that DELTA is consistently positioned as a protocol and reference implementation, not a SaaS platform or token system.

### 3.2 What DELTA proves

- [ ] Confirm documentation clearly states that DELTA proves cryptographic relationships between artifacts.
- [ ] Confirm documentation explains record hashes, signatures, bundle hashes, publication proofs, evidence commitments, and Merkle roots as cryptographic bindings.
- [ ] Confirm documentation does not imply that cryptographic validity automatically proves legal sufficiency, organizational authority, regulatory compliance, or truth of source data.

### 3.3 What DELTA does not prove

- [ ] Confirm that DELTA explicitly does not prove legal identity.
- [ ] Confirm that DELTA explicitly does not prove signer authority.
- [ ] Confirm that DELTA explicitly does not prove regulatory compliance.
- [ ] Confirm that DELTA explicitly does not prove real-world truth.
- [ ] Confirm that DELTA explicitly does not prove sensor honesty.
- [ ] Confirm that DELTA explicitly does not prove evidence completeness outside the committed set.
- [ ] Confirm that DELTA explicitly does not prove policy correctness.
- [ ] Confirm that DELTA explicitly does not prove legal validity of evidence.

## 4. Canonicalization and hash-binding review

### 4.1 Canonical JSON profile

- [ ] Review the canonical JSON profile documentation.
- [ ] Confirm that deterministic serialization rules are explicit.
- [ ] Confirm that duplicate object keys are rejected.
- [ ] Confirm that floats are rejected under the DELTA profile.
- [ ] Confirm that unsafe integers are rejected.
- [ ] Confirm that string encoding and Unicode handling are tested.
- [ ] Confirm that vectors include raw input, canonical output, and expected SHA-256 hash.

### 4.2 Hash-binding assumptions

- [ ] Confirm that proof objects bind to the full relevant DELTA record hash where claimed.
- [ ] Confirm that the documentation avoids ambiguous “body hash” versus “full record hash” language.
- [ ] Confirm that bundle signatures bind to the exact bundle file hash.
- [ ] Confirm that publication proofs bind to a record hash.
- [ ] Confirm that private evidence commitments bind disclosed evidence to public commitments and Merkle roots.

### 4.3 Tamper-detection expectations

- [ ] Identify at least one signed artifact or proof object.
- [ ] Modify an input intentionally.
- [ ] Confirm that verification fails or produces an explicit invalid status.
- [ ] Confirm that the failure is understandable to an external reviewer.
- [ ] Confirm that documentation does not hide tamper-detection limitations.

## 5. Signature verification review

### 5.1 Ed25519 signed records and bundles

- [ ] Identify the signed-record verification path.
- [ ] Identify the signed-bundle verification path.
- [ ] Confirm that public key hash checks are performed where declared.
- [ ] Confirm that detached signatures bind to the intended canonical object.
- [ ] Confirm that self-check hashes are recomputed.
- [ ] Confirm that tampered payloads fail verification.

### 5.2 Intent signatures

- [ ] Review Proof of Intent documentation.
- [ ] Confirm that intent attestations are bound to the full DELTA record hash.
- [ ] Confirm that detached intent signatures are verified over the intended canonical signature body.
- [ ] Confirm that registry binding is described as local input validation, not global identity proof.
- [ ] Confirm that policy and deadline checks are described under declared assumptions.

### 5.3 Key handling boundaries

- [ ] Confirm that private keys are not committed.
- [ ] Confirm that documentation warns against committing private keys, tokens, seed phrases, or sensitive evidence.
- [ ] Confirm that demo keys are clearly disposable if present.
- [ ] Confirm that public keys are committed only when intentionally part of public demo or registry material.

## 6. TypeScript verifier review

### 6.1 Build and baseline checks

- [ ] Install TypeScript dependencies.
- [ ] Run the TypeScript build.
- [ ] Run vector verification.
- [ ] Run schema verification.
- [ ] Record outputs.

Suggested commands:

```powershell
cd verifier\ts
npm install
npm run build
npm run verify-vectors
npm run verify-schemas
cd ..\..
```

### 6.2 TypeScript and Python consistency

- [ ] Confirm that TypeScript verifier scope is documented as experimental and profile-limited.
- [ ] Confirm that TypeScript verifier does not claim full Python feature parity.
- [ ] Confirm that TypeScript machine-readable JSON outputs are documented.
- [ ] Confirm that positive and negative contract tests exist for supported profiles.
- [ ] Confirm that unsupported profiles fail clearly or are documented as unsupported.

### 6.3 TypeScript Proof of Intent chain

- [ ] Review TypeScript record hash binding behavior.
- [ ] Review detached intent signature verification.
- [ ] Review registry public key binding.
- [ ] Review policy and deadline checks.
- [ ] Confirm that contract tests cover at least one positive path and one negative path.

## 7. Schema registry review

- [ ] Review `schemas/schema-registry.json`.
- [ ] Confirm schemas use stable `$id`.
- [ ] Confirm schemas declare draft 2020-12 or the documented schema dialect.
- [ ] Confirm schema validation is described as pre-verification only.
- [ ] Confirm schema validation is not presented as a substitute for cryptographic verification.
- [ ] Confirm each proof family has appropriate structural validation where available.

## 8. Private evidence and Merkle set review

### 8.1 Private evidence commitments

- [ ] Confirm that private evidence commitments are described as commitments, not encryption.
- [ ] Confirm that disclosed evidence can be checked against public commitment material.
- [ ] Confirm that salts/opening data are treated as private disclosure material.
- [ ] Confirm that documentation does not claim evidence truth or completeness merely from a commitment.

### 8.2 Private evidence Merkle set

- [ ] Confirm that the public package contains commitment material and a Merkle root.
- [ ] Confirm that selective disclosure uses a private opening package.
- [ ] Confirm that disclosed evidence can be checked against its commitment and Merkle proof.
- [ ] Confirm that the Merkle set does not claim to prove absence of other evidence outside the committed set.
- [ ] Confirm that the public-root / private-witness structure is accurately described as ZK preparation, not current ZK.

## 9. Audit and publication review

### 9.1 Proof of Audit

- [ ] Confirm that audit packages bind encrypted evidence to a record hash.
- [ ] Confirm that audit package verification without decryption is clearly distinguished from auditor-side decryption.
- [ ] Confirm that encrypted evidence is not presented as public proof of evidence truth.
- [ ] Confirm that AAD and ciphertext hash checks are described where relevant.

### 9.2 Proof of Publication

- [ ] Confirm that publication proofs bind to a record hash.
- [ ] Confirm that local timestamp proofs are clearly scoped.
- [ ] Confirm that optional external anchoring is described as optional.
- [ ] Confirm that DELTA does not require a blockchain or token for publication proofs.

## 10. Wallet proof profile review

- [ ] Review wallet/address-control documentation.
- [ ] Confirm Ethereum EIP-191 support is accurately described if present.
- [ ] Confirm Bitcoin external / BIP-322-ready profile is described conservatively.
- [ ] Confirm `bitcoin_bip322_external_v1` is not described as locally cryptographically verified unless that implementation exists.
- [ ] Confirm `CRYPTO_SIGNATURE_VERIFIED=False` is preserved for shape-only / external-pending Bitcoin proof profiles.
- [ ] Confirm wallet proof profiles do not claim to prove wallet balance, legal ownership, or financial solvency unless explicitly supported and verified.

## 11. Replay and environment assumptions

- [ ] Review Proof of Replay documentation.
- [ ] Confirm replay is described as reproduction under declared assumptions.
- [ ] Confirm replay does not claim the original environment was identical unless separately proven.
- [ ] Review environment declaration/check documentation if present.
- [ ] Confirm unsupported environment fields require manual review or produce cautious status.
- [ ] Confirm nondeterministic or network-dependent behavior is acknowledged where relevant.

## 12. CI/CD integration review

- [ ] Review CI/CD integration documentation.
- [ ] Confirm GitHub Actions examples are clearly identified as examples or templates if not packaged as an official action.
- [ ] Confirm GitLab CI examples are clearly identified as examples or templates if not packaged as an official integration.
- [ ] Confirm `.delta` bundle verification is described in automation-friendly terms.
- [ ] Confirm machine-readable JSON outputs are recommended for automation where available.
- [ ] Confirm CI/CD documentation does not imply that passing DELTA verification proves legal compliance or deployment safety.

## 13. Public demonstration review

- [ ] Review the public demonstration flow.
- [ ] Confirm the demonstration has a clear starting point.
- [ ] Confirm the demonstration has a clear successful verification result.
- [ ] Confirm the demonstration explains what success means.
- [ ] Confirm the demonstration explains what success does not mean.
- [ ] Confirm tamper detection is included or planned.
- [ ] Confirm the demonstration avoids private keys, customer data, secrets, or sensitive evidence.

## 14. ZK roadmap review

- [ ] Confirm ZK is described as future design/research unless implementation exists.
- [ ] Confirm ZK statements distinguish public inputs from private witness.
- [ ] Confirm ZK limitations and trust assumptions are documented.
- [ ] Confirm no current release claims production ZK provenance.
- [ ] Confirm private evidence commitments and Merkle sets are described as preparation for future ZK, not as ZK themselves.
- [ ] Confirm future ZK implementation is tied to concrete requirements and not treated as universal proof magic.

## 15. Documentation clarity review

- [ ] Identify any unclear phrase.
- [ ] Identify any overclaiming phrase.
- [ ] Identify any duplicated or inconsistent terminology.
- [ ] Identify any missing link between README, RFCs, security docs, schemas, vectors, verifier docs, quick-start docs, and review docs.
- [ ] Identify any place where a first-time reader may misunderstand DELTA as a blockchain, token, SaaS, marketplace, or identity system.

## 16. Issue reporting guidance

Reviewers should classify findings into one of the following categories.

### Critical security issue

Use this category for findings such as:

- signature verification bypass,
- hash-binding bypass,
- record substitution vulnerability,
- bundle substitution vulnerability,
- private key exposure risk,
- canonicalization inconsistency that changes verification result,
- false positive verification of tampered artifacts.

### High-priority protocol issue

Use this category for findings such as:

- ambiguous normative rule,
- inconsistent proof semantics,
- unclear trust boundary,
- cross-language verifier disagreement,
- schema behavior conflicting with protocol documentation.

### Documentation correction

Use this category for findings such as:

- unclear explanation,
- outdated milestone reference,
- misleading phrasing,
- overclaiming,
- missing security boundary,
- broken link,
- incomplete quick-start instruction.

### RFC feedback

Use this category for findings such as:

- proposed terminology change,
- conformance-level suggestion,
- compatibility concern,
- future profile recommendation,
- standards-track improvement.

### Feature proposal

Use this category for findings such as:

- new integration request,
- new verifier language,
- new output format,
- new CI/CD workflow,
- new policy profile,
- new evidence commitment profile.

## 17. Reviewer final checklist

Before submitting a review summary, confirm:

- [ ] I reviewed a specific tag, branch, or commit.
- [ ] I recorded the exact review target.
- [ ] I ran baseline Python verification or documented why I did not.
- [ ] I ran canonical JSON vector verification or documented why I did not.
- [ ] I reviewed the security boundaries.
- [ ] I checked that DELTA does not overclaim legal, regulatory, identity, or real-world truth.
- [ ] I reviewed at least one proof layer in detail.
- [ ] I reviewed TypeScript verifier scope if included in my review.
- [ ] I reviewed private evidence boundaries if included in my review.
- [ ] I reviewed CI/CD and public demonstration documentation if included in my review.
- [ ] I classified each finding by severity or feedback type.
- [ ] I avoided posting private keys, secrets, customer data, or sensitive evidence publicly.

## 18. Suggested review summary format

```markdown
# DELTA Protocol Review Summary

## Review target

- Tag:
- Commit:
- Date:
- Reviewer:
- Scope:

## Commands run

```text
python src/delta_cli.py verify-all
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
git diff --check
```

## Findings

### Critical

- None / list findings

### High priority

- None / list findings

### Documentation corrections

- None / list findings

### RFC feedback

- None / list findings

### Feature proposals

- None / list findings

## Security-boundary observations

- Notes here

## Overall conclusion

- Notes here
```

## 19. Submission guidance

For sensitive vulnerabilities, do not open a public issue before contacting the maintainer through the preferred security reporting channel.

For non-sensitive findings, use the appropriate GitHub issue template.

Do not include:

- private keys,
- seed phrases,
- production secrets,
- customer data,
- undisclosed sensitive evidence,
- internal infrastructure data,
- private audit packages,
- private evidence openings unless explicitly intended for disclosure.

## 20. Reviewer conclusion

A successful review does not require agreeing with every DELTA design choice.

A successful review should make the protocol clearer, safer, more precise, more reproducible, more honestly bounded, and easier for independent implementers and early adopters to evaluate.

DELTA should be judged by whether it precisely proves the cryptographic relationships it claims to prove, and whether it clearly refuses to claim what cryptography alone cannot establish.
