# DELTA ZK — Roadmap (v2.16.0)

Status: Planning document  
Scope: ZK provenance roadmap after v2.16.0

## 1. Current position

DELTA has reached the point where ZK design can begin.

Completed foundations:

```text
Core Proof of Change
Canonical JSON / schemas
Proof of Intent
Proof of Audit
Proof of Publication
Bundles / signed bundles
TypeScript verifier profiles
Private evidence commitments
Private evidence Merkle set
```

## 2. v2.16.0

Document-only milestone:

```text
ZK Statement Design / Public Inputs vs Private Witness
```

Outputs:

```text
docs/zk/zk-statement-design-v2.16.0.md
docs/zk/public-inputs-vs-private-witness-v2.16.0.md
docs/zk/zk-limitations-v2.16.0.md
docs/zk/zk-candidate-circuits-v2.16.0.md
docs/zk/zk-roadmap-v2.16.0.md
```

## 3. v2.17.0

Recommended next milestone:

```text
ZK Threat Model + Circuit Candidate Specification
```

Scope:

```text
- threat model for ZK provenance
- circuit-specific assumptions
- trusted setup risk
- metadata leakage
- circuit/canonicalization mismatch
- malicious prover/verifier cases
- invalid witness cases
```

## 4. v3.0.0-alpha

First implementation milestone:

```text
ZK Provenance Proof of Concept
```

Recommended scope:

```text
- one small circuit
- Merkle membership
- one simple policy check
- test vectors
- local proof generation
- local proof verification
- no production claims
```

## 5. v3.1.0-alpha

CLI integration:

```text
delta zk prove
delta zk verify
```

Expected artifacts:

```text
zk-proof.json
zk-public-inputs.json
zk-witness.PRIVATE.json
```

## 6. v3.2.0-alpha

Report/export integration:

```text
DELTA ZK VERIFIED report section
```

But must include:

```text
- exact statement
- public inputs
- proof profile
- limitations
- verification result
```

## 7. v3.3.0-alpha

TypeScript/browser verification research:

```text
browser-verifiable public ZK reports
```

## 8. Long-term

Potential future directions:

```text
- private enterprise audit certificates
- selective disclosure with auditor keys
- recursive aggregation
- policy circuit registry
- proof-of-compliance support under strict legal disclaimers
- transparent proof systems
```
