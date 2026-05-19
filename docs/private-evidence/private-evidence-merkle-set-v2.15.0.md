# DELTA Protocol — Private Evidence Package / Merkle Evidence Set (v2.15.0)

Status: Private evidence / ZK preparation milestone  
Implementation path: `tools/delta_private_evidence_set.py`

## 1. Purpose

v2.15.0 extends v2.14.0 from a single private evidence commitment to a multi-evidence Merkle set.

The goal is to commit publicly to a set of private evidence items while allowing selective disclosure later.

This is the final practical evidence-commitment layer before ZK statement design.

## 2. What this adds

v2.15.0 adds:

- public Merkle evidence set package,
- private opening package,
- salted commitments per evidence item,
- Merkle leaf hashes,
- Merkle root,
- per-entry Merkle proofs,
- public package verification,
- selective disclosure verification.

## 3. What this does not add

v2.15.0 is not:

- encryption,
- zero-knowledge proof,
- proof of legal truth,
- proof of evidence completeness beyond the committed set,
- proof of policy satisfaction,
- replacement for Proof of Audit encryption.

## 4. Commitment and Merkle model

Each evidence item is committed as:

```text
commitment = SHA-256(canonical_json({
  domain,
  evidence_hash,
  label,
  method_id,
  salt
}))
```

Each public Merkle leaf is:

```text
leaf_hash = SHA-256(canonical_json({
  domain,
  index,
  label,
  commitment,
  method_id
}))
```

The public package contains:

```text
commitments
leaf_hashes
merkle_root
self_check.package_body_hash
```

The private opening package contains:

```text
evidence_hashes
salts
commitments
leaf_hashes
merkle proofs
```

## 5. Commands

Create a public package and private opening:

```powershell
python tools\delta_private_evidence_set.py create `
  --evidence-dir .delta\private-evidence-set-tests\S-2150\evidence `
  --pattern "*.txt" `
  --out-public .delta\private-evidence-set-tests\S-2150\private-evidence-set.public.json `
  --out-opening .delta\private-evidence-set-tests\S-2150\private-evidence-set-opening.PRIVATE.json `
  --record-hash sha256:0000000000000000000000000000000000000000000000000000000000000000 `
  --policy-id private-evidence-set-demo-v2.15.0
```

Verify the public package:

```powershell
python tools\delta_private_evidence_set.py verify-public `
  --public .delta\private-evidence-set-tests\S-2150\private-evidence-set.public.json
```

Verify one disclosed evidence item:

```powershell
python tools\delta_private_evidence_set.py disclose `
  --public .delta\private-evidence-set-tests\S-2150\private-evidence-set.public.json `
  --opening .delta\private-evidence-set-tests\S-2150\private-evidence-set-opening.PRIVATE.json `
  --evidence .delta\private-evidence-set-tests\S-2150\evidence\ci-log.txt `
  --label "ci-log.txt"
```

Expected result:

```text
DELTA_PRIVATE_EVIDENCE_SET_DISCLOSE_VERIFY_OK=True
DELTA_PRIVATE_EVIDENCE_SET_MERKLE_PROOF_OK=True
```

## 6. Security boundary

The public Merkle root commits to a set of private evidence commitments.

It does not reveal the evidence, evidence hashes, or salts.

Disclosure verification proves that one disclosed item matches:

- the private opening,
- the public commitment entry,
- the public Merkle root.

It does not prove that the evidence is true, complete, legally valid, policy-sufficient, or regulatorily compliant.

## 7. Why this matters for ZK

Future ZK statements need a public commitment root and private witnesses.

v2.15.0 prepares:

```text
public inputs:
- record_hash
- policy_id
- evidence_merkle_root
- selected commitment/leaf hash
```

Private witnesses:

```text
- raw evidence
- evidence hash
- salt
- Merkle path
- policy-relevant private fields
```

A future ZK statement can build on this:

```text
I know private evidence included under this public Merkle root,
and that evidence satisfies policy P,
without revealing the evidence.
```
