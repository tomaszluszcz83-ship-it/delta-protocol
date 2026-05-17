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

## What is claim.json?

`claim.json` is a DELTA Claim payload.

It is not a full Delta Record bundle.

DELTA-0 currently represents the full proof chain as separate artifacts:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

The SDK verifies these pairs. A future Delta Record bundle verifier will verify all layers and cross-object hash relations together.

---

## Verify a Claim pair from files

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

## Verify a Claim pair from memory

```python
from delta_protocol import load_json_file, verify_claim_data

claim = load_json_file("genesis/claim.json")
signature = load_json_file("genesis/executor_signature.json")

result = verify_claim_data(claim, signature)

if result.ok:
    print("OK")
    print(result.payload_hash)
else:
    print("FAILED")
    print(result.reason)
```

The in-memory API is intended for systems that already hold JSON-compatible dictionaries in RAM:

- AI agents
- backend services
- API middleware
- CI/CD sensors
- security scanners
- audit systems

The SDK does not require callers to write temporary JSON files before verification.

---

## Verifier signatures

`verify_claim_data()` verifies a Claim with its Executor signature only.

Verifier signatures belong to the Attestation layer and are verified with:

```python
from delta_protocol import verify_attestation_data
```

A complete Delta Record bundle verifier will be added later to verify all layers together.

---

## Does the SDK sign records?

No.

The SDK Core verifies existing DELTA objects.

It does not generate private keys, create signatures, or write new proof records.

Signing belongs to CLI Write Mode, application code with access to a private key, or future sensor integrations.

---

## Result object

Most SDK functions return `VerificationResult`.

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

## Public API

```python
canonical_json_bytes(value) -> bytes
sha256_prefixed(data: bytes) -> str
load_json_file(path) -> object
verify_signature(payload, signature_envelope, ...) -> VerificationResult
verify_data(payload, signature_envelope, ...) -> VerificationResult
verify_pair(payload_path, signature_path, ...) -> VerificationResult
verify_claim_data(claim, executor_signature) -> VerificationResult
verify_claim_pair(claim_path, executor_signature_path) -> VerificationResult
verify_attestation_data(attestation, verifier_signature) -> VerificationResult
verify_attestation_pair(attestation_path, verifier_signature_path) -> VerificationResult
verify_checkpoint_data(checkpoint, checkpoint_signature) -> VerificationResult
verify_checkpoint_pair(checkpoint_path, checkpoint_signature_path) -> VerificationResult
```

---

## Tests

From the repository root:

```bash
python -m unittest discover -s ./packages/python/delta_protocol/tests -v
```

The test suite covers:

- canonical JSON ordering
- canonical equality across formatting and key order
- SHA-256 prefixed hashing
- float rejection
- UTF-8 BOM rejection
- valid Claim verification
- valid Attestation verification
- valid Signed Checkpoint verification
- wrong target hash failure
- wrong signature role failure

---

## Security boundary

The SDK verifies cryptographic consistency.

It does not prove absolute truth about the physical world.
