# DELTA ZK — Candidate Circuits (v2.16.0)

Status: Design document  
Scope: Candidate circuits for future v3.0.0-alpha PoC

## 1. Purpose

This document lists candidate ZK circuits for DELTA.

No circuit is implemented in v2.16.0.

## 2. Circuit 1 — Merkle membership only

Statement:

```text
I know a private opening that produces a leaf included under public Merkle root R.
```

Public inputs:

```text
evidence_merkle_root
commitment_method_id
leaf_method_id
tree_method_id
```

Private witness:

```text
evidence_hash
salt
label_hash
commitment
leaf_hash
merkle_path
```

Use:

```text
privacy-preserving membership proof
```

Limit:

```text
does not prove policy satisfaction
```

## 3. Circuit 2 — Numeric threshold policy

Statement:

```text
I know private evidence value x included under root R,
and x > threshold.
```

Public inputs:

```text
evidence_merkle_root
policy_hash
threshold
```

Private witness:

```text
x
salt
label_hash
merkle_path
```

Use:

```text
private sensor/audit threshold proof
```

Limit:

```text
does not prove x was honestly measured
```

## 4. Circuit 3 — Boolean approval policy

Statement:

```text
I know private evidence containing approved=true,
and it is included under root R.
```

Public inputs:

```text
evidence_merkle_root
policy_hash
```

Private witness:

```text
approved_boolean
salt
label_hash
merkle_path
```

Use:

```text
private ticket/control approval
```

Limit:

```text
does not prove approver authority unless tied to intent/registry layers
```

## 5. Circuit 4 — Test pass policy

Statement:

```text
I know private evidence where tests_passed == tests_total,
and it is included under root R.
```

Public inputs:

```text
evidence_merkle_root
policy_hash
```

Private witness:

```text
tests_passed
tests_total
salt
label_hash
merkle_path
```

Use:

```text
private CI/CD quality proof
```

Limit:

```text
does not prove tests were complete or meaningful
```

## 6. Recommended v3.0.0-alpha choice

The recommended first PoC is:

```text
Circuit 1 + simple numeric threshold policy
```

Reason:

```text
- easy to audit
- minimal parsing complexity
- demonstrates public root / private witness model
- avoids full JSON parsing in circuit
```

## 7. Avoid in first PoC

The first PoC should avoid:

```text
- full JSON parsing in circuit
- arbitrary string matching
- complex policy languages
- dynamic arrays without fixed bounds
- production claims
```

## 8. Circuit versioning

Each circuit must have:

```text
circuit_id
circuit_version
proof_profile
public_input_schema
witness_schema
hash/canonicalization profile
test vectors
security boundary
```
