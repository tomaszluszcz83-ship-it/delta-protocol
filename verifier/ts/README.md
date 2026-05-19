# DELTA TypeScript Verifier

Status: **experimental independent verifier**  
Current milestone: **v2.10.0 public README refresh**  
Primary implementation status: Python remains the **Alpha Reference Implementation**

## 1. What this is

This directory contains the experimental TypeScript verifier for selected DELTA Protocol verification layers.

It exists to prove that DELTA verification can be implemented outside Python and to support future browser, CI/CD, and cross-language verification workflows.

The TypeScript verifier is intentionally incremental. It does not yet verify every DELTA proof profile.

## 2. What TypeScript verifies today

As of v2.10.0, the TypeScript verifier supports:

```text
L0 — Canonical JSON vectors and SHA-256 hashing
L1 — Basic record checks and JSON Schema pre-verification
L2 — Ed25519 signed record MVP profile
L2 — Public .delta bundle verification
L2 — Signed .delta bundle verification
```

More specifically, it verifies:

- DELTA Canonical JSON Profile v1 test vectors,
- SHA-256 over canonical bytes,
- duplicate key rejection,
- float / NaN / Infinity / unsafe integer rejection,
- basic DELTA record required fields,
- basic record hash recomputation,
- repository-local JSON Schema compilation,
- named JSON Schema validation,
- Ed25519 signed record verification for the TypeScript v2.9.2 MVP profile,
- public `.delta` ZIP bundle integrity,
- detached signed `.delta` bundle verification.

## 3. What TypeScript does not verify yet

The TypeScript verifier does **not** currently verify:

- Proof of Replay,
- replay environment assumptions,
- Proof of Intent authority or policy,
- Proof of Audit encrypted evidence correctness,
- Proof of Publication anchoring truth,
- Trust Ledger policy,
- Wallet proof profiles,
- Ethereum EIP-191 / EIP-712,
- Bitcoin BIP-322 cryptographic verification,
- regulatory compliance,
- legal identity,
- signer authority,
- real-world truth of evidence,
- proof-specific validity of all artifacts inside a bundle.

## 4. Security boundary

The TypeScript verifier is not a legal, regulatory, identity, or authority oracle.

A successful TypeScript verification means only that the specific supported cryptographic or structural checks passed.

Important boundaries:

- Schema validation is pre-verification only.
- Bundle verification checks the public container and manifest, not proof-specific truth.
- Signed bundle verification proves that an Ed25519 key signed data bound to the exact `.delta` bundle hash.
- Signed bundle verification does not prove legal identity, signer authority, real-world truth, wallet ownership, regulatory compliance, trust validity, or correctness of contained proofs.
- Python remains the Alpha Reference Implementation for the broader DELTA toolchain.

## 5. Install

From repository root:

```powershell
cd verifier\ts
npm install
```

Node.js 20 or newer is recommended.

## 6. Build

```powershell
npm run build
```

Expected result: no TypeScript compiler errors.

## 7. Verify canonical JSON vectors

```powershell
npm run verify-vectors
```

Expected final output:

```text
DELTA_TS_VERIFY_OK=True
```

This checks the frozen DELTA canonical JSON vectors under:

```text
tests/vectors/canonical-json/vectors.json
```

## 8. Verify JSON Schemas

```powershell
npm run verify-schemas
```

Expected final output:

```text
DELTA_TS_SCHEMA_VERIFY_OK=True
```

This compiles the repository-local schemas under:

```text
schemas/
```

Schema validation is a pre-verification step only.

## 9. Validate a JSON file against a named schema

```powershell
npm run validate-schema -- --schema delta-record --file C:\path\to\delta-record.json
```

Supported schema names include:

```text
delta-common
delta-record
intent-attestation
audit-package
publication-proof
trust-ledger
wallet-proof
schema-registry
```

## 10. Verify a basic record

```powershell
npm run verify-record -- --record C:\path\to\delta-record.json
```

This performs basic record checks only. It does not verify every DELTA proof profile.

## 11. Create and verify a signed record demo

Create a local demo signed record:

```powershell
npm run create-signed-record-demo -- --out ..\..\.delta\ts-signed-record-tests\R-demo\signed-record.json
```

Verify it:

```powershell
npm run verify-signed-record -- --record ..\..\.delta\ts-signed-record-tests\R-demo\signed-record.json
```

Expected output includes:

```text
DELTA_TS_SIGNED_RECORD_VERIFY_OK=True
DELTA_TS_SIGNED_RECORD_SIGNATURE_OK=True
```

Signed record verification is limited to the TypeScript v2.9.2 MVP profile.

## 12. Verify a public .delta bundle

```powershell
npm run verify-bundle -- --bundle C:\path\to\sample.delta
```

Expected output for a valid bundle:

```text
DELTA_TS_BUNDLE_VERIFY_OK=True
DELTA_TS_BUNDLE_MANIFEST_OK=True
```

The bundle verifier checks:

- ZIP readability,
- required `bundle_manifest.json`,
- artifact SHA-256 checks,
- duplicate filename rejection,
- path traversal rejection,
- forbidden sensitive filename fragment rejection,
- unreferenced artifact rejection.

It does not verify proof-specific correctness of all contained artifacts.

## 13. Verify a signed .delta bundle

```powershell
npm run verify-signed-bundle -- --bundle C:\path\to\sample.delta --signature C:\path\to\sample.delta.sig.json
```

Expected output for a valid signed bundle:

```text
DELTA_TS_SIGNED_BUNDLE_VERIFY_OK=True
DELTA_TS_SIGNED_BUNDLE_BUNDLE_INTEGRITY_OK=True
DELTA_TS_SIGNED_BUNDLE_BUNDLE_HASH_BINDING_OK=True
DELTA_TS_SIGNED_BUNDLE_SIGNATURE_BODY_HASH_OK=True
DELTA_TS_SIGNED_BUNDLE_PUBLIC_KEY_HASH_OK=True
DELTA_TS_SIGNED_BUNDLE_SIGNATURE_OK=True
```

Signed bundle verification checks:

- the `.delta` bundle passes public bundle verification,
- exact `.delta` file hash binding,
- `signature_body_hash` self-check,
- Python `delta_bundle_sign.py` compatible public key text hash,
- Ed25519 detached signature verification.

## 14. Typical full local check

From repository root:

```powershell
python src/delta_cli.py verify-all

python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json

cd verifier\ts
npm install
npm run build
npm run verify-vectors
npm run verify-schemas

cd ..\..

git diff --check
```

Expected important outputs:

```text
DELTA CLI RESULT: OK
DELTA_JCS_VERIFY_OK=True
DELTA_TS_VERIFY_OK=True
DELTA_TS_SCHEMA_VERIFY_OK=True
```

Before committing, remove local generated artifacts:

```powershell
Remove-Item verifier\ts\node_modules -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item verifier\ts\dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item verifier\ts\.delta -Recurse -Force -ErrorAction SilentlyContinue
```

Do not commit `node_modules`, `dist`, private keys, generated `.delta` test artifacts, or decrypted/private evidence.

## 15. Public wording

Recommended wording:

```text
DELTA includes an experimental TypeScript verifier for canonical JSON, schema pre-verification, basic record checks, Ed25519 signed records, public .delta bundles, and signed .delta bundles.
The Python implementation remains the Alpha Reference Implementation.
Proof-specific TypeScript verification for replay, intent, audit, publication, trust, and wallet profiles remains future work.
```

Avoid saying:

```text
TypeScript is a complete DELTA verifier.
TypeScript verifies all Python proof profiles.
Schema validation proves cryptographic validity.
Bundle verification proves contained proofs are valid.
Signed bundle verification proves legal identity or signer authority.
```

## 16. Roadmap

Recommended next TypeScript milestones:

```text
v2.10.1 — TypeScript CLI Error Codes / Machine-Readable JSON Output
v2.10.2 — TypeScript Proof of Intent Verification MVP
v2.10.3 — TypeScript Replay Environment Check MVP
```

Continue incremental, testable milestones. Do not add all proof layers at once.
