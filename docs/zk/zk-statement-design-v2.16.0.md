# DELTA Protocol — ZK Statement Design (v2.16.0)

Status: Document-only ZK design milestone  
Scope: Design only, no circuit implementation  
Depends on: v2.14.0 Private Evidence Commitment Profile and v2.15.0 Private Evidence Merkle Set

## 1. Purpose

v2.16.0 defines the first Zero-Knowledge statement model for DELTA Protocol.

The purpose is to specify what a future DELTA ZK proof should prove, what it should keep private, and what it must not overclaim.

This milestone does not implement a ZK circuit, prover, verifier, trusted setup, or CLI integration.

## 2. Core ZK statement

The first DELTA ZK statement candidate is:

```text
I know private evidence included under this public evidence Merkle root,
and that evidence satisfies policy P,
without revealing the evidence.
```

More formally:

```text
Given public inputs:
- evidence_merkle_root R
- policy_id or policy_hash P
- record_hash H_record
- selected public commitment / leaf hash when disclosure granularity requires it
- optional verification_context_hash C

Prove knowledge of private witness:
- raw evidence e
- salt s
- evidence hash H_e
- commitment c
- Merkle path π
- policy-relevant private fields

Such that:
1. H_e = SHA-256(e)
2. c = Commitment(e, s, label, method_id)
3. leaf = Leaf(index, label, c)
4. VerifyMerklePath(leaf, π, R) = true
5. PolicyCheck(e, P) = true
6. Optional: the statement is bound to H_record and C
```

## 3. Why v2.14.0 and v2.15.0 matter

v2.14.0 introduced salted commitments to private evidence.

v2.15.0 extended this into a Merkle evidence set:

```text
public:
- commitments
- leaf hashes
- Merkle root

private:
- evidence
- evidence hashes
- salts
- Merkle proofs
```

This gives DELTA the public-root / private-witness structure needed for future ZK work.

## 4. Public verifier goal

A public verifier should eventually be able to verify:

```text
This proof is valid for public root R and policy P.
```

without learning:

```text
- the raw evidence
- the salt
- the full private opening
- internal ticket/log/server/user identifiers
- sensitive CI/CD output
- private audit details
```

## 5. Non-goals

The first ZK statement does not prove:

- evidence truth in the real world,
- sensor honesty,
- legal identity,
- signer authority,
- global registry trust,
- policy correctness,
- regulatory compliance,
- completeness outside the committed evidence set,
- absence of other evidence,
- that the organization was legally authorized to act.

## 6. Candidate first policy examples

The first ZK policy candidates should be intentionally simple.

### Policy A — private JSON numeric threshold

```text
Evidence JSON contains:
{
  "temperature": number
}

Policy:
temperature > 100
```

### Policy B — private boolean approval

```text
Evidence JSON contains:
{
  "approved": true
}
```

### Policy C — private test count threshold

```text
Evidence JSON contains:
{
  "tests_passed": n,
  "tests_total": m
}

Policy:
tests_passed == tests_total
```

### Policy D — private audit control satisfied

```text
Evidence JSON contains:
{
  "control_id": "...",
  "satisfied": true
}

Policy:
satisfied == true
```

## 7. Recommended first circuit shape

The first proof-of-concept circuit should be modular:

```text
Circuit 1:
- commitment recomputation
- Merkle path verification

Circuit 2:
- simple policy check

Circuit 3:
- combined commitment + Merkle + policy statement
```

The first PoC should avoid complex string parsing and full JSON parsing inside the circuit.

Instead, v3.0.0-alpha should use a simplified canonical witness format derived from JSON, such as:

```text
field_name_hash
field_value_numeric
policy_id_hash
```

## 8. Recommended implementation strategy

v2.16.0 chooses an abstract statement model only.

Future implementation candidates:

```text
Groth16:
- small proofs
- fast verification
- requires trusted setup
- good for first PoC

Plonk/Halo2:
- more flexible
- more complex
- better later

STARK:
- no trusted setup
- larger proofs
- future research
```

Recommendation for first PoC:

```text
v3.0.0-alpha: Groth16/Circom or Arkworks prototype
```

but without hard-binding DELTA to one proving system yet.

## 9. Security boundary

DELTA ZK should be described as:

```text
privacy-preserving verification of a precise cryptographic statement
```

not as:

```text
automatic truth
automatic compliance
automatic legal approval
automatic trust
```

Every ZK report must include the exact statement being proven and the assumptions under which the proof is meaningful.

## 10. Next step

The next milestone should be:

```text
v2.17.0 — ZK Threat Model + Circuit Candidate Specification
```

Then:

```text
v3.0.0-alpha — ZK Provenance Proof of Concept
```
