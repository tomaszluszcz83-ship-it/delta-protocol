# DELTA Protocol — TypeScript Release Readiness (v2.9.5)

Status: Release readiness note  
Type: Documentation-only milestone

## 1. Summary

v2.9.5 marks the first TypeScript verifier readiness checkpoint after five incremental verifier releases:

```text
v2.9.0 — TypeScript Verifier L0/L1
v2.9.1 — TypeScript JSON Schema Validation
v2.9.2 — TypeScript Ed25519 Signed Record Verification
v2.9.3 — TypeScript .delta Bundle Verification
v2.9.4 — TypeScript Signed Bundle Verification
```

The TypeScript verifier now covers enough independent verification layers to be useful for public review, but it must still be described carefully.

## 2. Readiness checklist

| Check | Status |
| --- | --- |
| TypeScript build works | Ready |
| Canonical JSON vector verification works | Ready |
| JSON Schema registry compilation works | Ready |
| Ed25519 signed record MVP verification works | Ready |
| Public `.delta` bundle verification works | Ready |
| Signed `.delta` bundle verification works | Ready |
| Security boundaries documented | Ready |
| Out-of-scope proof layers documented | Ready |
| Full proof-specific verification parity with Python | Not ready |
| Production conformance claim | Not ready |
| Standards-track multi-implementation claim | Not ready |

## 3. What can be claimed

Acceptable claims:

```text
The TypeScript verifier is an experimental independent verifier for selected DELTA verification layers.
It verifies canonical JSON vectors, schema pre-verification, basic record checks, Ed25519 signed records, public .delta bundles, and signed .delta bundles.
It helps demonstrate cross-language feasibility for DELTA verification.
```

## 4. What must not be claimed

Do not claim:

```text
TypeScript is a complete DELTA verifier.
TypeScript verifies all Python proof profiles.
TypeScript verifies Proof of Replay, Intent, Audit, Publication, Trust, or Wallet profiles.
Signed bundle verification proves legal identity or signer authority.
Schema validation proves cryptographic validity.
Bundle verification proves contained proofs are valid.
```

## 5. Release readiness decision

v2.9.5 is approved as a documentation and readiness milestone if the following pass:

```powershell
cd verifier\ts
npm install
npm run build
npm run verify-vectors
npm run verify-schemas

cd ..\..
python src/delta_cli.py verify-all
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
git diff --check
```

## 6. Security boundary

This milestone does not add cryptographic functionality.

It documents the boundary of what already exists.

The TypeScript verifier remains experimental and must not be described as a complete standards-conformant implementation until DELTA conformance levels, frozen cross-language suites, and broader proof-specific parity are complete.
