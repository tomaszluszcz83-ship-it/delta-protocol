# DELTA Protocol — Security Boundary Summary (v2.15.1)

Status: Public-readiness documentation refresh

## 1. Core boundary

DELTA proves cryptographic relationships.

DELTA does not automatically prove real-world truth.

## 2. Validity layers

A DELTA artifact can have several different validity layers:

```text
syntactic validity
schema validity
canonicalization validity
hash validity
signature validity
replay validity
intent validity
registry validity
policy validity
trust validity
legal validity
real-world truth
```

These are not the same.

## 3. Common mistake

A signed DELTA artifact means:

```text
a key signed specific bytes or a specific hash.
```

It does not automatically mean:

```text
the signer was legally authorized.
```

## 4. Private evidence boundary

Private evidence commitments and Merkle sets prove matching relationships after disclosure.

They do not prove:

- evidence truth,
- evidence completeness outside the committed set,
- legal admissibility,
- policy sufficiency,
- compliance.

## 5. ZK boundary

Future ZK proofs will prove exact mathematical statements.

They will not prove truth outside the statement.

Every ZK report must include:

- proof profile,
- public inputs,
- statement,
- assumptions,
- limitations,
- verification result.

## 6. Required discipline

DELTA documentation and reports should avoid vague claims such as:

```text
fully trusted
fully compliant
legally verified
tamper-proof in all senses
truth guaranteed
```

Preferred terms:

```text
cryptographically bound
signature verified
hash verified
policy satisfied under declared assumptions
private evidence commitment matched
Merkle membership verified
```
