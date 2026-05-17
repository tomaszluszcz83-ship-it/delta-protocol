# DELTA Protocol Python SDK Core

This package is the minimal Python SDK core for DELTA Protocol.

It provides:

- canonical JSON bytes
- SHA-256 prefixed hashes
- Ed25519 detached signature verification
- in-memory verification helpers
- Claim + Executor signature verification
- Attestation + Verifier signature verification
- Signed Checkpoint + Checkpoint Signer signature verification

It does not provide a backend, account system, token system, database, or marketplace.

---

## Install from repository checkout

From the repository root:

```bash
python -m pip install -e ./packages/python/delta_protocol
```

---

## What is claim.json?

`claim.json` is a DELTA Claim payload.

It is not a complete Delta Record bundle.

In DELTA-0, the complete proof chain is composed of separate payloads and detached signatures:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

A future Delta Record bundle format may wrap these artifacts into one higher-level object.

---

## Quick example: file pair

```python
from delta_protocol import verify_claim_pair

result = verify_claim_pair(
    "genesis/claim.json",
    "genesis/executor_signature.json",
)

print(result.ok)
print(result.reason)
print(result.payload_hash)
```

---

## Quick example: in-memory data

```python
from delta_protocol import load_json_file, verify_claim_data

claim = load_json_file("genesis/claim.json")
signature = load_json_file("genesis/executor_signature.json")

result = verify_claim_data(claim, signature)

print(result.ok)
print(result.reason)
print(result.payload_hash)
```

This path is intended for backend systems, AI agents, API middleware, and sensors that already have DELTA objects in memory.

---

## SDK scope

This SDK verifies existing DELTA objects.

It does not generate private keys, create signatures, or write new proof records.

Signing belongs to CLI Write Mode, application code with access to a private key, or future sensor integrations.

---

## Result object

Most SDK functions return `VerificationResult`.

Important fields:

```text
ok            True if verification succeeded
reason        "OK" or a human-readable failure reason
payload_hash  recomputed sha256:<hex> hash of the canonical payload
target_hash   hash declared by the detached signature envelope
role          executor / verifier / checkpoint_signer
target_type   delta_claim / delta_attestation / delta_signed_checkpoint
public_key    public key declared by the signature envelope
```

---

## Run tests

From the repository root:

```bash
python -m unittest discover -s ./packages/python/delta_protocol/tests -v
```

---

## Security boundary

This SDK verifies cryptographic consistency.

It does not prove absolute truth about the physical world.
