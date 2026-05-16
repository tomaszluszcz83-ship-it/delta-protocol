# DELTA Protocol

Proof of Change for the Internet.

DELTA is an open, zero-token cryptographic protocol for proving digital change.

DELTA is not a cryptocurrency.
DELTA is not a token.
DELTA is not an NFT project.
DELTA is not a blockchain-dependent application.
DELTA is not a SaaS platform.
DELTA is not a marketplace.

DELTA is a protocol layer for cryptographically proving that a declared change was made, evidenced, signed, verified, and recorded in a tamper-evident ledger.

Core statement:

The internet can prove ownership.
DELTA proves change.

---

## What DELTA proves

DELTA does not claim to prove absolute truth.

DELTA proves that:

- a Claim was created,
- a Claim was signed by an Executor key,
- evidence was bound by hash,
- an Attestation was signed by a Verifier key,
- the Attestation was included in a Ledger Entry,
- the Ledger Entry was connected to a Signed Checkpoint,
- the shown ledger segment is tamper-evident.

In short:

DELTA proves a cryptographically bound record of declared and verified digital change.

---

## DELTA-0 Genesis Release Candidate

This repository contains the DELTA-0 Genesis Release Candidate.

Protocol version:

DELTA-0 v0.5.2

Current status:

Public verifier OK
Private keys not included
Zero-token protocol
Non-cryptocurrency
Proof of Change

The Genesis package is located in:

release/DELTA-0-genesis-public.zip

The distribution hash is located in:

release/DELTA-0-genesis-public.zip.sha256.txt

---

## Genesis proof flow

DELTA-0 uses this minimum proof structure:

Delta Claim
→ Delta Attestation
→ Ledger Entry
→ Signed Checkpoint
→ Public Verification

The Genesis Record demonstrates the first complete DELTA proof flow.

---

## Repository structure

Expected structure:

DELTA-0/
├── README.md
├── .gitignore
├── spec/
│   └── DELTA-0-v0.5.2-core-structures.md
├── src/
│   ├── genesis_generator.py
│   └── genesis_public_verifier.py
├── genesis/
│   ├── claim.json
│   ├── executor_signature.json
│   ├── attestation.json
│   ├── verifier_signature.json
│   ├── ledger_entry.json
│   ├── ledger.json
│   ├── chain_proof.json
│   ├── checkpoint.json
│   ├── checkpoint_signature.json
│   ├── genesis_bundle.json
│   ├── evidence_manifest.json
│   ├── verification_policy.json
│   ├── public_keys.json
│   ├── hashes.txt
│   └── SELF_CHECK_OK.txt
├── release/
│   ├── DELTA-0-genesis-public/
│   ├── DELTA-0-genesis-public.zip
│   └── DELTA-0-genesis-public.zip.sha256.txt
└── examples/

---

## Important security rule

Do not publish private keys.

The local development folder may contain:

genesis/private_keys/

This folder must never be published, committed, uploaded, or shared.

The public ZIP must not contain:

private_keys
.pem
.key
.secret
.env

The `.gitignore` file blocks these paths and file types.

---

## How to verify the public Genesis package

Install Python 3.12 or newer.

Install the required cryptography package:

python -m pip install cryptography

Extract the public package:

release/DELTA-0-genesis-public.zip

Run the public verifier from inside the extracted package:

python .\src\genesis_public_verifier.py

Expected final result:

DELTA PUBLIC VERIFIER RESULT: OK

---

## What the public verifier checks

The public verifier checks:

1. The public package does not contain private keys.
2. JSON objects are loaded and canonicalized before hashing.
3. Hashes use sha256:<64 lowercase hex chars>.
4. Delta Claim hash is recomputed.
5. Executor signature verifies against the Delta Claim.
6. Delta Attestation hash is recomputed.
7. Verifier signature verifies against the Delta Attestation.
8. Ledger Entry binds:
   - claim_hash
   - executor_sig_hash
   - attestation_hash
   - verifier_sig_hash
9. Genesis prev_entry_hash uses the fixed zero hash.
10. Checkpoint head_entry_hash matches the Ledger Entry hash.
11. Checkpoint signature verifies.
12. Chain proof links the Ledger Entry to the checkpoint.
13. Genesis bundle hash summary matches recomputed hashes.
14. hashes.txt matches recomputed hashes.
15. SELF_CHECK_OK.txt is ignored as proof.

---

## Cryptographic model

DELTA-0 uses:

- JCS-style canonical JSON
- SHA-256 hashes
- Ed25519 signatures
- detached signature envelopes
- linear hash-chain
- signed checkpoints
- private evidence hashes

Rule:

Hash identifies the object.
Signature signs the canonical object.

Signatures are not embedded inside the objects they sign.

This avoids circular hashing and signature ambiguity.

---

## What DELTA_VERIFIED means

In DELTA-0 Genesis, DELTA_VERIFIED means that the following are cryptographically consistent:

- Delta Claim
- Executor signature
- Delta Attestation
- Verifier signature
- Ledger Entry
- Chain proof
- Signed Checkpoint
- Checkpoint signature
- Genesis bundle hash summary

It means the declared change, evidence hash, signatures, ledger entry, and checkpoint are cryptographically bound and tamper-evident.

---

## What DELTA_VERIFIED does not mean

DELTA_VERIFIED does not mean:

- absolute truth about the physical world,
- that the verifier cannot be wrong,
- that evidence is publicly visible,
- that evidence could not have been fabricated before hashing,
- legal ownership,
- financial value,
- token ownership,
- cryptocurrency issuance.

DELTA is not a magic truth machine.

DELTA proves a cryptographically bound record of a declared and verified change.

---

## Genesis purpose

The DELTA Genesis Record symbolically records the creation of the first public Proof of Change structure.

Before:

The internet could prove ownership, identity, transactions, and file hashes, but had no universal proof layer for change.

Action:

DELTA-0 protocol genesis release created.

After:

The first DELTA Proof of Change record exists.

Evidence:

Protocol specification hash, generator source hash, before statement hash, after statement hash, and verification policy hash.

Verifier:

Genesis local verifier key.

---

## Release status

DELTA-0 Genesis Release Candidate

Protocol version:

DELTA-0 v0.5.2

Status:

Public verifier OK
Private keys not included
Zero-token protocol
Non-cryptocurrency
Proof of Change

---

## Founder / originator

DELTA Protocol was initiated by Tomasz Łuszcz.

Private identity evidence should not be placed directly into the public ledger.

Identity should be proven by signed evidence and hashes, not by unnecessary exposure of private personal data.

Principle:

Identity by proof, not exposure.
