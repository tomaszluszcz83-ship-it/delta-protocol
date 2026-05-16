# DELTA-0 Private Payload Proof Example

Proof without exposure.

This example demonstrates how DELTA can prove a private digital change without publishing the private payload.

## Use case

A private document changed state:

```text
Before: NDA draft
Action: NDA accepted and countersigned
After: NDA signed
Evidence: SHA-256 hash commitment to private payload
Verifier: Local Compliance Verification Key
Result: proof without exposing the document
```

## Privacy model

The private payload is not committed to this repository.

In this demo, private payload bytes are generated in memory during proof generation and are not written as a payload file.

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

## What this proves

The public verifier proves that:

- a private payload hash was declared,
- the private payload hash has valid SHA-256 format,
- the Claim binds the before state, action, after state, and private payload hash,
- the Executor signed the Claim,
- the Verifier attested to the hash commitment,
- the Ledger Entry binds the Claim, signatures, Attestation, and payload manifest,
- the Signed Checkpoint commits to the Ledger Entry,
- the proof chain is tamper-evident.

## What this does not prove

This example does not prove:

- the private payload content,
- legal validity,
- real-world truth,
- identity outside the included public keys,
- that the hidden private document is correct.

DELTA proves the public cryptographic commitment and verification chain.

It does not magically reveal or validate hidden facts.

## Run the verifier

From the repository root:

```bash
python examples/private-payload-proof/private_payload_public_verifier.py
```

Expected result:

```text
DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: OK
```

## Principle

Evidence by hash, not exposure.
