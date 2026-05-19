# DELTA v2.5.4 Security Foundation — Risk Register

**Status:** Draft  
**Version:** v2.5.4  
**Purpose:** Track known risks, current mitigations, residual risks, and planned controls for DELTA Protocol.

---

## Risk scoring

Likelihood and impact are qualitative:

- **Low** — unlikely or limited blast radius.
- **Medium** — plausible, requires mitigation or monitoring.
- **High** — likely or severe, must be addressed before broad adoption.

---

| ID | Risk | Affected layer | Likelihood | Impact | Current mitigation | Residual risk | Planned mitigation | Status |
|---|---|---|---:|---:|---|---|---|---|
| R-001 | Canonical JSON mismatch across implementations | Core hashing/signing | Medium | High | Reference Python canonicalization and existing hash checks | Different languages may compute different bytes/hashes | v2.6.0 RFC 8785/JCS compatibility and frozen vectors | Open |
| R-002 | Private key compromise | Records, Intent, Audit, Wallet, Trust | Medium | High | Public key hashes, signatures, intent registry | Attacker can sign valid objects before revocation | Incident response, revocation/invalidation record profile, key rotation docs | Open |
| R-003 | Evidence fabricated before hashing | Evidence/Audit | Medium | High | Evidence commitments, replay for verifiable outputs | DELTA cannot prove pre-hash truth | Explicit security boundary, auditor disclosure, independent data-source checks | Accepted/Documented |
| R-004 | Time manipulation/backdating | Publication, Intent, Trust | Medium | Medium | Publication proofs, trust ledger order | Local timestamps are not authoritative | External timestamp profiles, timestamp-source policy | Open |
| R-005 | Replay environment mismatch | Replay | Medium | Medium | Fresh clone, method hash, stdout/stderr/result comparison | Replay may not be deterministic across environments | Method environment metadata, containers, stricter replay profiles | Open |
| R-006 | Intent overclaiming as legal approval | Intent | Medium | High | Intent signature and record binding only | Users may claim legal/business approval | Security boundaries, governance profiles, policy docs | Accepted/Documented |
| R-007 | Audit evidence leakage | Audit | Medium | High | X25519/AES-GCM encrypted packages, do-not-commit guidance | Decryption disclosure and key compromise remain risks | Evidence handling policy, audit key rotation, disclosure logs | Open |
| R-008 | Publication proof overclaiming | Publication | Medium | Medium | Publication binds hash, docs warn it does not prove truth | Users may misrepresent timestamp/publication as correctness | UI/report warnings, reviewer guide | Accepted/Documented |
| R-009 | Trust ledger actor authority ambiguity | Trust | Medium | Medium | Hash-chain integrity and role fields | Ledger does not prove real-world authority | Registry/delegation/governance profiles | Open |
| R-010 | Wallet proof overclaiming | Wallet | High | High | Record-bound challenge, explicit proof standards | Users may claim legal ownership, balance, or compliance | Security boundaries and report warnings | Accepted/Documented |
| R-011 | Bitcoin external mode misinterpreted as full verification | Wallet/Bitcoin | Medium | High | `shape_only`, `external_pending`, `CRYPTO_SIGNATURE_VERIFIED=False` | Users may ignore warning | Full BIP-322 local verifier in future, stricter UI wording | Open |
| R-012 | Unknown fields causing verifier disagreement | Schemas/Conformance | Medium | Medium | Current reference implementation behavior | Future implementations may differ | JSON Schemas, unknown-field policy, conformance tests | Open |
| R-013 | Algorithm agility confusion | Crypto | Low | High | Algorithms are explicit in code/docs | Silent algorithm changes would break trust | Cryptographic agility policy with alg/version ids | Open |
| R-014 | Generated sensitive artifacts committed accidentally | Audit/Wallet/Keys | Medium | High | Documentation warnings and gitignore patterns where present | Human error remains likely | Pre-commit secret scan guidance, CI secret scanning | Open |
| R-015 | Dependency compromise | Python reference implementation | Medium | High | Minimal dependencies in core; optional wallet deps | Optional dependencies may add supply-chain risk | Lockfiles/SBOM/security review for production profiles | Open |
| R-016 | ZK overclaiming in future roadmap | ZK Research | Medium | High | ZK is marked as future research | Marketing may exceed precise proof statements | ZK threat model, circuit-specific statements only | Planned |
| R-017 | Public launch before hardening | Project/process | Medium | Medium | Feature freeze plan | Reviewers may find avoidable gaps | Complete v2.5.4/v2.6.x before launch | Open |

---

## Incident priority mapping

| Severity | Examples | Response target |
|---|---|---|
| Critical | Private signing key committed, verifier accepts tampered record, crypto verification bypass | Immediate private triage; public advisory after mitigation |
| High | Wrong canonical hash, wallet proof false positive, audit package binding bypass | Triage before next release; patch release likely |
| Medium | Documentation overclaim, ambiguous verifier status, incomplete warning | Fix in docs or minor release |
| Low | Typo, non-security wording issue, missing example | Normal documentation process |

---

## Risk ownership

During technical alpha, the maintainer owns security triage. Before enterprise/public standardization, DELTA SHOULD define:

- security contact process,
- maintainer signing/release process,
- revocation publication process,
- schema/conformance governance,
- external audit process.

---

## Summary

The highest near-term risks are canonicalization interoperability, key compromise response, verifier disagreement, and overclaiming. The current sprint addresses these risks through threat modeling, risk registration, security boundaries, RFC 8785/JCS work, frozen test vectors, schemas, and conformance levels.
