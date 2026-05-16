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

## Quick start

Run the DELTA CLI from the repository root:

```bash
python src/delta_cli.py version
python src/delta_cli.py verify-all
```

Expected result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
DELTA CLI RESULT: OK
```

For individual verification:

```bash
python src/delta_cli.py verify-genesis
python src/delta_cli.py verify-code-change
python src/delta_cli.py verify-private-payload
```

Current CLI milestone:

`v0.6-alpha-cli`

---

## Developer Adoption Example

The first practical DELTA adoption example is available here:

`examples/code-change-proof`

This example shows how DELTA can work above Git and CI/CD.

Flow:

```text
Before: failing test
Action: code fix
After: passing test
Evidence: CI-style test_results.log
Verifier: Local CI Server Verification Key
Result: cryptographically verifiable Proof of Change
```

Run the example verifier:

```bash
python examples/code-change-proof/code_change_public_verifier.py
```

Expected result:

```text
DELTA CODE CHANGE PROOF VERIFIER RESULT: OK
```

This example demonstrates:

- Git commit before the fix
- Git commit after the fix
- SHA-256 evidence hash of a test log
- Developer key as Executor
- Local CI Server Verification Key as Verifier
- Delta Claim
- Delta Attestation
- Ledger Entry
- Signed Checkpoint
- Public verifier
- Evidence byte stability protected by `.gitattributes`

This example does not modify or replace the DELTA-0 Genesis Release Candidate v0.5.2.

---

## Private Payload Proof Example

DELTA also includes a privacy-focused adoption example:

`examples/private-payload-proof`

This example shows how DELTA can prove a private digital change without publishing the private payload.

Core principle:

```text
Proof without exposure.
```

Flow:

```text
Before: private document draft
Action: private document accepted and countersigned
After: private document signed
Evidence: SHA-256 hash commitment to private payload
Verifier: Local Compliance Verification Key
Result: public proof without exposing private bytes
```

Run the example verifier:

```bash
python examples/private-payload-proof/private_payload_public_verifier.py
```

Or use DELTA CLI:

```bash
python src/delta_cli.py verify-private-payload
python src/delta_cli.py verify-all
```

Expected result:

```text
DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: OK
```

This example demonstrates:

- private payload hash commitment
- public private-payload manifest
- before and after private state records
- Delta Claim
- Executor signature
- Delta Attestation
- Verifier signature
- Ledger Entry
- Signed Checkpoint
- Chain Proof
- public verification without private payload disclosure

This example does not modify or replace the DELTA-0 Genesis Release Candidate v0.5.2.

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

- Public verifier OK
- Private keys not included
- Zero-token protocol
- Non-cryptocurrency
- Proof of Change

The Genesis package is located in:

`release/DELTA-0-genesis-public.zip`

The distribution hash is located in:

`release/DELTA-0-genesis-public.zip.sha256.txt`

---

## Genesis proof flow

DELTA-0 uses this minimum proof structure:

```text
Delta Claim
-> Delta Attestation
-> Ledger Entry
-> Signed Checkpoint
-> Public Verification
```

The Genesis Record demonstrates the first complete DELTA proof flow.

---

## Repository structure

Expected structure:

```text
DELTA-0/
├── README.md
├── .gitignore
├── .gitattributes
├── spec/
│   └── DELTA-0-v0.5.2-core-structures.md
├── src/
│   ├── delta_cli.py
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
    ├── code-change-proof/
    │   ├── README.md
    │   ├── code_change_public_verifier.py
    │   ├── evidence/
    │   │   └── test_results.log
    │   └── records/
    │       ├── before_state.json
    │       ├── after_state.json
    │       ├── claim.json
    │       ├── executor_signature.json
    │       ├── attestation.json
    │       ├── verifier_signature.json
    │       ├── ledger_entry.json
    │       ├── ledger.json
    │       ├── chain_proof.json
    │       ├── checkpoint.json
    │       ├── checkpoint_signature.json
    │       ├── public_keys.json
    │       ├── verification_policy.json
    │       ├── hashes.json
    │       ├── hashes.txt
    │       └── evidence_hash.txt
    └── private-payload-proof/
        ├── README.md
        ├── private_payload_public_verifier.py
        └── records/
            ├── before_state.json
            ├── after_state.json
            ├── private_payload_manifest.json
            ├── verification_policy.json
            ├── public_keys.json
            ├── claim.json
            ├── executor_signature.json
            ├── attestation.json
            ├── verifier_signature.json
            ├── ledger_entry.json
            ├── ledger.json
            ├── chain_proof.json
            ├── checkpoint.json
            ├── checkpoint_signature.json
            ├── hashes.json
            └── hashes.txt
```

---

## Important security rule

Do not publish private keys.

The local development folder may contain:

`genesis/private_keys/`

This folder must never be published, committed, uploaded, or shared.

The public ZIP must not contain:

```text
private_keys
.pem
.key
.secret
.env
```

The `.gitignore` file blocks these paths and file types.

---

## Evidence byte rule

DELTA evidence files are protocol evidence bytes.

Git must not rewrite them.

The repository uses `.gitattributes` to protect evidence files from automatic line-ending conversion.

For the Code Change Proof example:

```text
examples/code-change-proof/evidence/* -text
```

This protects the raw bytes used to compute:

- `evidence_hash`
- Delta Claim binding
- Delta Attestation binding
- Ledger Entry binding
- Signed Checkpoint binding

---

## Private payload rule

DELTA can prove private payload changes without publishing private payload bytes.

For the Private Payload Proof example, the private payload is not committed to the repository and is not written to disk as a payload file.

The public proof contains only:

- private payload hash
- private payload manifest
- before state
- after state
- Delta Claim
- Executor signature
- Delta Attestation
- Verifier signature
- Ledger Entry
- Signed Checkpoint
- Chain Proof

Rule:

Evidence by hash, not exposure.

---

## How to verify with DELTA CLI

Run all public verifiers:

```bash
python src/delta_cli.py verify-all
```

Expected final result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
DELTA CLI RESULT: OK
```

Run individual verifiers:

```bash
python src/delta_cli.py verify-genesis
python src/delta_cli.py verify-code-change
python src/delta_cli.py verify-private-payload
```

Show CLI version:

```bash
python src/delta_cli.py version
```

---

## How to verify the public Genesis package directly

Install Python 3.12 or newer.

Install the required cryptography package:

```bash
python -m pip install cryptography
```

Extract the public package:

`release/DELTA-0-genesis-public.zip`

Run the public verifier:

```bash
python src/genesis_public_verifier.py
```

Expected final result:

```text
DELTA PUBLIC VERIFIER RESULT: OK
```

---

## How to verify the Code Change Proof example directly

Run:

```bash
python examples/code-change-proof/code_change_public_verifier.py
```

Expected final result:

```text
DELTA CODE CHANGE PROOF VERIFIER RESULT: OK
```

---

## How to verify the Private Payload Proof example directly

Run:

```bash
python examples/private-payload-proof/private_payload_public_verifier.py
```

Expected final result:

```text
DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: OK
```

---

## What the public Genesis verifier checks

The public Genesis verifier checks:

1. The public package does not contain private keys.
2. JSON objects are loaded and canonicalized before hashing.
3. Hashes use `sha256:<64 lowercase hex chars>`.
4. Delta Claim hash is recomputed.
5. Executor signature verifies against the Delta Claim.
6. Delta Attestation hash is recomputed.
7. Verifier signature verifies against the Delta Attestation.
8. Ledger Entry binds:
   - `claim_hash`
   - `executor_sig_hash`
   - `attestation_hash`
   - `verifier_sig_hash`
9. Genesis `prev_entry_hash` uses the fixed zero hash.
10. Checkpoint `head_entry_hash` matches the Ledger Entry hash.
11. Checkpoint signature verifies.
12. Chain proof links the Ledger Entry to the checkpoint.
13. Genesis bundle hash summary matches recomputed hashes.
14. `hashes.txt` matches recomputed hashes.
15. `SELF_CHECK_OK.txt` is ignored as proof.

---

## What the Code Change Proof verifier checks

The Code Change Proof verifier checks:

1. The example does not contain private keys or secret files.
2. `before_state.json` and `after_state.json` are valid Git-based states.
3. Git commit references use 40-character lowercase hexadecimal format.
4. The evidence log contains `FAIL -> PASS`.
5. State and evidence hashes are recomputed.
6. Delta Claim hash is recomputed.
7. Executor signature verifies against the Delta Claim.
8. Delta Attestation hash is recomputed.
9. Verifier signature verifies against the Delta Attestation.
10. Ledger Entry binds:
    - `claim_hash`
    - `executor_sig_hash`
    - `attestation_hash`
    - `verifier_sig_hash`
11. Checkpoint hash is recomputed.
12. Checkpoint signature verifies.
13. Chain proof links the Ledger Entry to the checkpoint.
14. `hashes.json` and `hashes.txt` match recomputed hashes.
15. Evidence bytes are protected from Git line-ending rewriting.

---

## What the Private Payload Proof verifier checks

The Private Payload Proof verifier checks:

1. The example does not contain private payload files or secret files.
2. The private payload is represented by a SHA-256 hash commitment only.
3. `before_state.json` and `after_state.json` describe a private payload state change.
4. The private payload manifest is public but does not contain private payload bytes.
5. Delta Claim binds:
   - before state hash
   - after state hash
   - private payload hash
   - private payload manifest hash
6. Executor signature verifies against the Delta Claim.
7. Delta Attestation verifies the hash commitment without payload disclosure.
8. Verifier signature verifies against the Delta Attestation.
9. Ledger Entry binds:
   - `claim_hash`
   - `executor_sig_hash`
   - `attestation_hash`
   - `verifier_sig_hash`
   - `private_payload_manifest_hash`
10. Checkpoint hash is recomputed.
11. Checkpoint signature verifies.
12. Chain proof links the private payload entry to the checkpoint.
13. `hashes.json` and `hashes.txt` match recomputed hashes.

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

- Public verifier OK
- Private keys not included
- Zero-token protocol
- Non-cryptocurrency
- Proof of Change

---

## Tags

Current public protocol milestones:

- `v0.5.2-genesis-rc`
- `v0.5.3-code-change-proof`
- `v0.5.4-evidence-line-endings`
- `v0.6-alpha-cli`
- `v0.6.1-private-payload-proof`

---

## Founder / originator

DELTA Protocol was initiated by Tomasz Łuszcz.

Private identity evidence should not be placed directly into the public ledger.

Identity should be proven by signed evidence and hashes, not by unnecessary exposure of private personal data.

Principle:

Identity by proof, not exposure.