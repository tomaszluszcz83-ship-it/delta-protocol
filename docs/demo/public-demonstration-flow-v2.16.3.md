# DELTA Protocol Public Demonstration Flow v2.16.3

## Purpose

This document defines a simple public demonstration flow for DELTA Protocol.

The purpose is to help an external reviewer, developer, auditor, or early adopter observe DELTA's verification model in a short and reproducible way.

The demonstration is intentionally conservative. It is designed to show the core idea of cryptographic change verification without claiming that DELTA proves legal identity, regulatory compliance, real-world truth, or production security by itself.

## Demonstration message

The intended demonstration message is:

```text
DELTA Protocol can make digital change relationships cryptographically reviewable.
```

The public demo should avoid presenting DELTA as a cryptocurrency, token system, blockchain application, SaaS platform, marketplace, or user-account product.

DELTA is a protocol and reference implementation for proving relationships between declared artifacts.

## Recommended five-minute demo structure

### Step 1 — Clone the repository

```powershell
git clone https://github.com/tomaszluszcz83-ship-it/delta-protocol.git
cd delta-protocol
```

### Step 2 — Run the Python reference verification

```powershell
python src/delta_cli.py verify-all
```

Expected high-level result:

```text
DELTA CLI RESULT: OK
```

### Step 3 — Run canonical JSON / JCS vector verification

```powershell
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
```

Expected high-level result:

```text
DELTA_JCS_VERIFY_OK=True
```

### Step 4 — Explain what the viewer has seen

At this point, explain that the viewer has observed local verification of the reference proof checks and canonical JSON test vectors.

This demonstrates that the repository includes executable verification logic and deterministic canonicalization tests.

It does not prove legal truth, identity, compliance, or real-world correctness.

### Step 5 — Show tamper-evident intuition

The public demonstration should include a simple tamper case when a stable demo artifact is available.

The message should be:

```text
If a bound artifact changes, verification should fail or the recorded hash relationship should no longer match.
```

Until a dedicated tamper-demo script is added, avoid improvising destructive changes in the repository during public presentations. Instead, explain the principle and point to existing negative tests and tamper-detection documentation.

### Step 6 — Show how DELTA fits CI/CD

Present the CI/CD integration examples as the next step:

- Python reference verification in CI,
- canonical JSON vector verification in CI,
- optional TypeScript verifier checks,
- future signed bundle verification examples,
- future machine-readable JSON output integration.

### Step 7 — End with the security boundary

The demo should end with a strict boundary statement:

```text
DELTA proves cryptographic relationships between declared artifacts.
It does not by itself prove legal identity, signer authority, regulatory compliance, real-world truth, or institutional approval.
```

This is not a weakness. It is a deliberate security boundary.

## Suggested public narration

A professional public narration may use the following structure:

> The internet is already very good at proving ownership, identity handles, accounts, addresses, and assets. DELTA focuses on a different question: what changed, what evidence supports that change, how was it verified, and can the relationship be checked later?
>
> DELTA does not require a token, blockchain, SaaS account, or marketplace. It uses conventional cryptographic foundations: hashes, canonical JSON, signatures, bundles, verification records, publication proofs, audit artifacts, and private evidence commitments.
>
> This demo shows the current public verification baseline. It is intentionally conservative. We are not claiming that DELTA proves legal truth or regulatory compliance. We are showing that digital change relationships can be made cryptographically reviewable.

## What to avoid during public demos

Avoid saying:

- DELTA proves everything.
- DELTA proves legal truth.
- DELTA proves identity.
- DELTA proves regulatory compliance.
- DELTA proves the sensor was honest.
- DELTA replaces auditors.
- DELTA eliminates trust.
- DELTA is a blockchain.
- DELTA is a token.
- DELTA is production ZK provenance.

Prefer saying:

- DELTA proves cryptographic relationships between declared artifacts.
- DELTA makes change evidence reviewable.
- DELTA separates cryptographic validity from legal, operational, and institutional validity.
- DELTA is a protocol and reference implementation.
- DELTA is currently in technical alpha and public review.

## Recommended demo assets

Future public demo assets should include:

- a short terminal recording,
- a minimal CI workflow example,
- one signed bundle verification example,
- one private evidence commitment example,
- one Merkle evidence set example,
- one tamper case with expected failure output,
- a short explanation of what was and was not proven.

## Status

This document is the first public demonstration-flow guide.

It intentionally documents the demonstration strategy before adding more automation, because public clarity and security-boundary discipline are more important than producing an impressive but ambiguous demo.
