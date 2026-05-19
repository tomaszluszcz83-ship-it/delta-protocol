# DELTA Protocol — Public Overview (v2.15.1)

Status: Public-readiness documentation refresh  
Scope: Overview and positioning

## 1. One-sentence summary

DELTA Protocol is an open, zero-token cryptographic protocol for proving change.

## 2. Core phrase

```text
The internet can prove ownership. DELTA proves change.
```

## 3. What DELTA is

DELTA is:

- a Proof of Change protocol,
- a cryptographic artifact format,
- a verification model,
- a Python alpha reference implementation,
- a growing TypeScript verifier,
- a foundation for private evidence and future ZK provenance.

## 4. What DELTA is not

DELTA is not:

- a cryptocurrency,
- a token,
- a blockchain,
- a SaaS platform,
- a marketplace,
- a user-account product,
- a legal authority,
- a compliance oracle.

## 5. Why it matters

Modern systems create logs, commits, CI/CD outputs, audit evidence, sensor readings, incident records, and operational claims.

The hard question is:

```text
Can we prove what changed, what evidence existed, what verification was performed, and what assumptions were declared?
```

DELTA answers that question with cryptographic binding.

## 6. Current maturity

As of v2.15.1, DELTA includes:

- canonical JSON profile,
- JSON schemas,
- Proof of Replay,
- Proof of Intent,
- Proof of Audit,
- Proof of Publication,
- bundles,
- signed bundles,
- TypeScript verifier profiles,
- CLI JSON contracts,
- private evidence commitments,
- Merkle evidence sets.

This makes DELTA ready for serious review before entering ZK design.

## 7. Why the anti-overclaiming boundary is a strength

DELTA explicitly states what it does not prove.

This increases trust.

A valid DELTA proof means that the cryptographic relationship is valid under declared assumptions.

It does not automatically mean that the world was truthful, the law was satisfied, or the signer had legal authority.

## 8. Public reviewer checklist

A reviewer should evaluate:

- canonicalization rules,
- schema stability,
- hash binding,
- signature binding,
- replay assumptions,
- intent boundaries,
- registry trust assumptions,
- policy/deadline assumptions,
- private evidence commitment hiding properties,
- Merkle proof correctness,
- security documentation,
- overclaiming risk.

## 9. Next step

The next technical milestone is:

```text
v2.16.0 — ZK Statement Design / Public Inputs vs Private Witness
```
