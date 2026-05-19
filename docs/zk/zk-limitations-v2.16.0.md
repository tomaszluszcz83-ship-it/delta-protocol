# DELTA ZK — Limitations and Anti-Overclaiming (v2.16.0)

Status: Design document  
Scope: What DELTA ZK does not prove

## 1. Purpose

This document states the limits of DELTA ZK provenance.

ZK can improve privacy, but it does not magically create trust, legal truth, or correctness.

## 2. What DELTA ZK can prove

A DELTA ZK proof can prove a precise mathematical statement, such as:

```text
The prover knows private evidence and opening data that match a public Merkle root,
and the private evidence satisfies a specific policy circuit.
```

## 3. What DELTA ZK does not prove

DELTA ZK does not automatically prove:

- that the evidence is true in the real world,
- that the sensor was honest,
- that the input data was correct before commitment,
- that the policy is legally sufficient,
- that the policy implementation is correct,
- that the signer had authority,
- that the organization approved the action,
- that the proof satisfies a regulation,
- that no other evidence exists,
- that the committed evidence set is complete,
- that a person is legally identified,
- that the verifier should trust the registry globally.

## 4. Garbage in, garbage out

ZK can prove that private evidence satisfies a circuit.

It cannot prove that the private evidence was honestly generated unless the evidence generation process is separately trusted, audited, signed, replayed, or observed.

## 5. Policy correctness risk

If a circuit implements the wrong policy, a proof may be valid but meaningless.

Mitigations:

```text
- policy circuit review
- policy hash/versioning
- frozen test vectors
- independent implementations
- public circuit source
- reproducible circuit compilation
```

## 6. Trusted setup risk

If Groth16 is used, trusted setup must be addressed.

Mitigations:

```text
- documented setup ceremony
- toxic waste handling assumptions
- use of public ceremonies when possible
- later migration to universal setup or transparent systems
```

## 7. Metadata leakage risk

Even if raw evidence is hidden, public inputs may leak:

```text
- which policy was evaluated
- which record is involved
- how many evidence items exist
- timing/context
- organization-specific workflow patterns
```

Mitigations:

```text
- policy hashes instead of names
- context hashes instead of verbose context
- privacy profiles
- optional aggregation
```

## 8. Required wording

DELTA ZK reports should say:

```text
This proof verifies a specific cryptographic statement under declared assumptions.
```

They must not say:

```text
This proves compliance.
This proves legal approval.
This proves the evidence is true.
This proves the organization is trustworthy.
```
