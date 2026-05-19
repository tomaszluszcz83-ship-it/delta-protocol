# DELTA Protocol Public Landing Page v2.16.2

## Executive purpose

This document defines the public landing-page structure for DELTA Protocol after the v2.16.1 public adoption freeze.

The purpose of the landing page is to present DELTA as a serious, open, zero-token cryptographic Proof of Change protocol that is already usable, reviewable, reproducible, and suitable for external technical evaluation without requiring blockchain infrastructure, a native token, a SaaS account model, or a marketplace layer.

The landing page must help a first-time reader understand DELTA in minutes, not hours, while preserving the discipline required of a protocol intended for security-sensitive verification, audit, CI/CD, private evidence, publication proof, trust-context modeling, and future privacy-preserving provenance.

## Primary headline

```text
The internet can prove ownership.
DELTA proves change.
```

## One-sentence positioning

DELTA Protocol is an open, zero-token cryptographic protocol for creating, binding, packaging, publishing, and verifying Proofs of Change across software, CI/CD, audit trails, private evidence flows, sensor systems, signed release processes, and future privacy-preserving verification environments.

## What DELTA is

DELTA is a protocol and reference implementation for proving cryptographic relationships between declared artifacts.

It binds records, hashes, signatures, evidence, intent attestations, audit artifacts, publication proofs, trust context, bundles, verifier output, and private evidence commitments into a structured Proof of Change model.

The core model is:

```text
Before → Action → After → Evidence → Verification → Ledger
```

DELTA is designed for environments where the most important question is not only who owns a digital object, but what changed, what evidence supports that change, how the result was verified, and whether the proof can be independently checked later.

## What DELTA is not

DELTA is not:

- a cryptocurrency,
- a native token,
- a speculative blockchain project,
- a SaaS account platform,
- a marketplace,
- a legal identity provider,
- a regulatory compliance oracle,
- a universal truth machine.

DELTA may optionally bind to external publication or timestamping systems, but the protocol itself does not require a blockchain or token.

## What works today

DELTA already provides a substantial v2.x Proof of Change foundation:

- core Proof of Change records,
- Canonical JSON / JCS-compatible profile,
- repository-local JSON Schema registry,
- Proof of Replay foundations,
- Proof of Intent,
- detached Ed25519 intent signatures,
- intent registry binding,
- policy and deadline verification,
- Proof of Audit,
- Proof of Publication,
- Proof of Trust foundations,
- wallet and address-control proof profiles,
- portable `.delta` bundles,
- detached signed bundles,
- TypeScript verifier profiles,
- TypeScript machine-readable CLI JSON output,
- TypeScript contract tests,
- private evidence commitments,
- private evidence Merkle set,
- public-root / private-witness preparation for future ZK provenance.

## First verification path

A new reader should be directed to the quick-start document:

```text
docs/quickstart/quickstart-v2.16.2.md
```

The first successful experience should be simple:

1. clone the repository,
2. run the Python reference verification,
3. run the canonical JSON vectors,
4. optionally run the TypeScript verifier,
5. observe that verification succeeds,
6. understand that tampering with protected artifacts causes verification failure.

## Public message after v2.16.2

The public message should be clear and disciplined:

```text
DELTA already proves cryptographic change relationships today.

ZK remains strategically important, but implementation is intentionally deferred until the existing v2.x Proof of Change stack receives enough external review, integration feedback, and real-world usage to justify the first concrete circuit.
```

## Security-boundary message

The landing page must preserve DELTA's anti-overclaiming model.

DELTA proves cryptographic consistency and binding between declared artifacts.

DELTA does not automatically prove legal identity, signer authority, regulatory compliance, real-world truth, sensor honesty, evidence completeness, policy correctness, legal validity, wallet balance, organizational approval, or institutional trust.

This boundary is not a weakness. It is a necessary condition for building a credible cryptographic protocol.

## Recommended landing-page sections

A public landing page should contain the following sections:

1. headline and one-sentence positioning,
2. what DELTA is,
3. what DELTA is not,
4. the core model,
5. what works today,
6. quick-start command block,
7. proof-layer summary,
8. security boundaries,
9. implementation status,
10. links to RFCs, schemas, vectors, security docs, and verifier docs,
11. public adoption roadmap,
12. contribution and review invitation.

## Expected outcome

After this milestone, DELTA should be easier to present publicly, easier to try locally, easier to review technically, and easier to understand as an open protocol candidate rather than as an application, token ecosystem, SaaS project, or speculative blockchain proposal.
