# DELTA Python SDK Example

This example demonstrates the minimal DELTA Python SDK Core.

Install from the repository root:

```bash
python -m pip install -e ./packages/python/delta_protocol
```

Verify the Genesis Claim pair:

```bash
python examples/sdk-python/verify_claim_pair.py genesis/claim.json genesis/executor_signature.json
```

Expected output:

```text
OK
sha256:...
```

The SDK verifies detached signature pairs without private keys.
