# DELTA Protocol — Private Evidence Commitment Profile (v2.14.0)

Status: Private evidence / ZK preparation milestone  
Implementation path: `tools/delta_private_evidence_commitment.py`

## 1. Purpose

v2.14.0 introduces a Private Evidence Commitment Profile.

The goal is to let DELTA publish a public commitment to private evidence without publishing the raw evidence.

This is a foundation for future private audit and ZK provenance work.

## 2. What this adds

v2.14.0 adds:

- public commitment package,
- private opening package,
- public self-check verification,
- disclosed evidence verification,
- salted evidence commitments,
- explicit security boundaries.

## 3. What this does not add

v2.14.0 is not:

- encryption,
- zero-knowledge proof,
- proof of legal truth,
- proof of policy satisfaction,
- proof that private evidence is complete,
- replacement for Proof of Audit encryption.

It is a commitment layer.

## 4. Commitment model

The public package contains a salted commitment:

```text
commitment = SHA-256(canonical_json({
  domain,
  evidence_hash,
  label,
  method_id,
  salt
}))
```

The public package does not include the salt or raw evidence hash.

The private opening contains:

```text
evidence_hash
salt
label
method_id
commitment
```

The opening must remain private unless intentionally disclosed to an auditor.

## 5. Commands

Create a public commitment and private opening:

```powershell
python tools\delta_private_evidence_commitment.py create `
  --evidence .delta\private-evidence-tests\E-2140\evidence.txt `
  --label "private-ci-log" `
  --out-public .delta\private-evidence-tests\E-2140\private-evidence-commitment.public.json `
  --out-opening .delta\private-evidence-tests\E-2140\private-evidence-opening.PRIVATE.json `
  --record-hash sha256:0000000000000000000000000000000000000000000000000000000000000000 `
  --policy-id private-evidence-demo-v2.14.0
```

Verify the public package:

```powershell
python tools\delta_private_evidence_commitment.py verify-public `
  --public .delta\private-evidence-tests\E-2140\private-evidence-commitment.public.json
```

Verify disclosed evidence against the public commitment and private opening:

```powershell
python tools\delta_private_evidence_commitment.py disclose `
  --public .delta\private-evidence-tests\E-2140\private-evidence-commitment.public.json `
  --opening .delta\private-evidence-tests\E-2140\private-evidence-opening.PRIVATE.json `
  --evidence .delta\private-evidence-tests\E-2140\evidence.txt `
  --label "private-ci-log"
```

Expected result:

```text
DELTA_PRIVATE_EVIDENCE_DISCLOSE_VERIFY_OK=True
```

## 6. Security boundary

The public commitment proves only that a commitment was made to some evidence/opening pair.

Disclosure verification proves that the disclosed evidence and opening match the public commitment.

It does not prove that the evidence is true, complete, legally valid, or policy-sufficient.

## 7. Why this matters for ZK

Future ZK statements need public inputs and private witnesses.

This milestone prepares the public input side:

```text
public input:
- record_hash
- policy_id
- evidence_commitment
```

And the private witness side:

```text
private witness:
- raw evidence
- salt
- opening data
```

A future ZK statement can build on this:

```text
I know private evidence and opening data that match this public commitment,
and the private evidence satisfies policy P,
without revealing the evidence.
```
