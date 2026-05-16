# DELTA Python SDK Core

The DELTA Python SDK Core provides small, auditable verification primitives for DELTA-0.

It is intentionally minimal.

It does not replace the DELTA CLI. It exposes the same cryptographic verification concepts as importable Python functions.

---

## Install

From the repository root:

```bash
python -m pip install -e ./packages/python/delta_protocol
```

---

## Verify a Claim pair

```python
from delta_protocol import verify_claim_pair

result = verify_claim_pair(
    "genesis/claim.json",
    "genesis/executor_signature.json",
)

if result.ok:
    print("OK")
    print(result.payload_hash)
else:
    print("FAILED")
    print(result.reason)
```

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

---

## Security boundary

The SDK verifies cryptographic consistency.

It does not prove absolute truth about the physical world.
