# Use Case: CI/CD Audit

## Goal

Use DELTA to prove that a code or deployment change went through a verifiable chain of measurement, replay, intent, audit, publication, and trust events.

## Example Flow

```text
1. Developer opens a pull request.
2. CI runs a measurement method.
3. DELTA creates a signed record.
4. Replay verifies the result from a fresh clone.
5. Proof of Intent binds an approval to the record.
6. Private logs are encrypted for an auditor.
7. Publication proof anchors the record hash.
8. Trust ledger records execution and verification events.
```

## What DELTA Proves

DELTA can prove:

- a specific CI/CD proof record existed;
- the record hash is stable;
- the declared method and output hashes match;
- replay can reproduce the verification result;
- an intent proof was bound to the record;
- encrypted evidence was bound for an auditor;
- publication proof refers to the record hash;
- trust ledger entries are hash-chain consistent.

## What DELTA Does Not Prove

DELTA does not prove:

- the change is bug-free;
- the code is secure;
- the reviewer was legally authorized;
- the CI runner was not compromised;
- the business decision was correct;
- the deployment is safe in all environments.

## Enterprise Direction

Future enterprise integration may include:

- GitHub/GitLab PR comments;
- verifier badges;
- audit certificates;
- central key registry;
- key rotation;
- team roles;
- policy enforcement;
- dashboard for records and trust ledgers.
