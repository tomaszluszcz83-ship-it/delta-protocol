# DELTA Protocol — Roadmap Snapshot (v2.15.1)

Status: Public-readiness documentation refresh

## 1. Completed foundation

```text
Core Proof of Change
Canonical JSON / JCS-compatible profile
JSON schemas
Security foundation
Proof of Replay
Proof of Intent
Proof of Audit
Proof of Publication
Bundles and signed bundles
TypeScript verifier profiles
CLI JSON contracts
Private evidence commitments
Private evidence Merkle set
```

## 2. Immediate next phase

```text
v2.16.0 — ZK Statement Design / Public Inputs vs Private Witness
v2.17.0 — ZK Threat Model + Circuit Candidate Specification
v3.0.0-alpha — ZK Provenance Proof of Concept
```

## 3. ZK direction

DELTA ZK should provide privacy-preserving public verification of precise statements.

First candidate statement:

```text
I know private evidence included under this public Merkle root,
and that evidence satisfies policy P,
without revealing the evidence.
```

## 4. ZK discipline

The first ZK work must remain scoped.

Do not start with:

- full JSON parsing in circuit,
- broad compliance claims,
- legal claims,
- arbitrary policy language,
- production badges,
- vague "secure/private/compliant" wording.

Start with:

- Merkle membership,
- one simple policy,
- frozen public inputs,
- frozen private witness shape,
- test vectors,
- explicit limitations.

## 5. Future adoption layer

Future public adoption work may include:

- Markdown/HTML proof reports,
- signed bundles,
- private audit packages,
- ZK verified report sections,
- browser verification,
- CI/CD integration,
- policy circuit registry,
- enterprise key registry and dashboards.

All adoption mechanisms must remain transparent, opt-in, and non-spammy.
