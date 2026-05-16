# DELTA Protocol Python SDK Core

This package is the minimal Python SDK core for DELTA Protocol.

It provides:

- canonical JSON bytes
- SHA-256 prefixed hashes
- Ed25519 detached signature verification
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

## Quick example

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

Expected:

```text
True
OK
sha256:...
```

---

## Security boundary

This SDK verifies cryptographic consistency.

It can prove that:

- a payload hash matches the canonical JSON bytes of the payload,
- a detached signature envelope targets that payload hash,
- an Ed25519 signature verifies over the canonical JSON bytes.

It does not prove absolute truth about the physical world.

It does not prove that:

- private evidence was not fabricated before hashing,
- a human statement is true,
- an AI output is factually correct,
- a compromised key was not misused before revocation.

---

## Public API

```python
canonical_json_bytes(value) -> bytes
sha256_prefixed(data: bytes) -> str
load_json_file(path) -> object
verify_signature(payload, signature_envelope, ...) -> VerificationResult
verify_pair(payload_path, signature_path, ...) -> VerificationResult
verify_claim_pair(claim_path, executor_signature_path) -> VerificationResult
verify_attestation_pair(attestation_path, verifier_signature_path) -> VerificationResult
verify_checkpoint_pair(checkpoint_path, checkpoint_signature_path) -> VerificationResult
```
