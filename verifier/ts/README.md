# DELTA TypeScript Verifier v2.9.4

Status: **experimental independent verifier**  
Scope: **L0/L1 + schema + Ed25519 signed record + `.delta` bundle + signed bundle verification**

## What this verifies

v2.9.4 verifies:

- canonical JSON vectors,
- schema compilation,
- Ed25519 signed records under the narrow v2.9.2 MVP profile,
- public `.delta` bundle container integrity,
- detached signed bundle signatures.

## Signed bundle verification scope

v2.9.4 checks:

- the `.delta` bundle passes v2.9.3 bundle verification,
- the detached signature JSON file is readable,
- the signature binds to the exact bundle file hash,
- public key hash is checked when declared,
- `signature_body_hash` is checked when declared,
- Ed25519 signature shape and cryptographic verification.

## Command

```bash
npm run verify-signed-bundle -- --bundle path/to/sample.delta --signature path/to/sample.delta.sig.json
```

Optional public key override:

```bash
npm run verify-signed-bundle -- --bundle path/to/sample.delta --signature path/to/sample.delta.sig.json --public-key ed25519:<hex>
```

## Security boundary

Signed bundle verification proves only that an Ed25519 key signed data bound to the exact `.delta` bundle hash.

It does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, trust validity, or correctness of contained proofs.
