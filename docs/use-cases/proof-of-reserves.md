# Use Case: Proof of Reserves / Proof of Balance Roadmap

## Status

This document describes a future DELTA application profile. It is not yet a production Proof of Reserves system.

## Goal

Use DELTA to bind asset-state observations, wallet proofs, audit evidence, and publication proofs into a verifiable change record.

## Possible Flow

```text
1. Exchange or custodian defines a reserve reporting scope.
2. Wallet/control proofs are collected.
3. Balance observations are captured by sensors.
4. Evidence is committed by hash.
5. Sensitive evidence is encrypted for an auditor.
6. A DELTA record is signed.
7. A publication proof anchors the record hash.
8. A trust ledger records verifier/auditor events.
```

## What DELTA Could Prove

DELTA could prove:

- a specific reserve report record existed;
- the report is hash-bound and signed;
- evidence commitments are bound to the record;
- auditor evidence was encrypted and bound;
- wallet-control proofs are linked to the record;
- publication proof anchors the record hash;
- trust events form a tamper-evident chain.

## What DELTA Would Not Prove Alone

DELTA would not automatically prove:

- assets are unencumbered;
- liabilities are complete;
- all wallets are included;
- auditor legal authority;
- exchange solvency;
- regulatory compliance;
- continuous reserves after publication.

## Required Future Work

A serious Proof of Reserves profile would require:

- balance sensor records;
- finalized block references;
- RPC/source evidence;
- liability commitment model;
- auditor workflow;
- publication requirements;
- wallet-control policy;
- legal/compliance mapping.
