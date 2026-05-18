# DELTA v1.9.0 — Proof of Audit MVP

## Purpose

Proof of Audit adds encrypted evidence disclosure to DELTA.

A DELTA sensor record can commit to private evidence using hashes. Proof of Audit lets the record owner encrypt the referenced evidence files for an auditor, producing an audit package that is cryptographically bound to the full `delta-record.json` hash.

## Security model

DELTA v1.9.0 uses a separate audit encryption key:

- Sensor key signs the sensor record.
- Intent key signs approval/intent attestations.
- Audit key decrypts private evidence packages.

The audit private key must never be committed, pasted into chat, or stored in CI. The audit public key may be committed or distributed.

## Binding

The audit package target uses:

```text
SHA-256(canonical_json(full delta-record.json))
```

This is intentionally the same full-record binding model used by Proof of Intent replay verification. The package is bound to the complete DELTA sensor record, not only to `record_body_hash`.

## Encryption

The MVP uses hybrid public-key encryption:

```text
X25519 + HKDF-SHA256 + AES-256-GCM
```

Each evidence entry has its own ephemeral X25519 key and AES-GCM nonce. The AES-GCM AAD includes the record hash, package id, entry index, evidence path hint, and evidence commitment hash.

## Files

Typical files:

```text
.delta/audit-public-key.json
.delta/audit-tests/A-001/delta-audit-package.json
.delta/audit-tests/A-001/decrypted/
```

The private audit key should be outside the repository, for example:

```text
C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_AUDIT_PRIVATE_KEY.txt
```

## CLI

Generate audit key pair:

```powershell
python tools/delta_audit.py keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_AUDIT_PRIVATE_KEY.txt `
  --public-out .delta\audit-public-key.json `
  --key-id audit-key-local-v1 `
  --owner local-auditor `
  --role auditor
```

Encrypt evidence for an auditor:

```powershell
python tools/delta_audit.py encrypt-evidence `
  --record .delta\artifacts\intent-policy-test\delta-record.json `
  --auditor-public-key .delta\audit-public-key.json `
  --out-dir .delta\audit-tests\A-001 `
  --package-id A-001 `
  --include private `
  --require-hash-match
```

Verify package binding without decrypting:

```powershell
python tools/delta_audit.py verify-package `
  --record .delta\artifacts\intent-policy-test\delta-record.json `
  --package .delta\audit-tests\A-001\delta-audit-package.json `
  --auditor-public-key .delta\audit-public-key.json
```

Decrypt as auditor:

```powershell
python tools/delta_audit.py decrypt-package `
  --package .delta\audit-tests\A-001\delta-audit-package.json `
  --private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_AUDIT_PRIVATE_KEY.txt `
  --record .delta\artifacts\intent-policy-test\delta-record.json `
  --out-dir .delta\audit-tests\A-001\decrypted
```

## Verification outputs

Expected successful outputs include:

```text
DELTA_AUDIT_KEYGEN_OK=True
DELTA_AUDIT_ENCRYPT_OK=True
DELTA_AUDIT_VERIFY_OK=True
DELTA_AUDIT_RECORD_BINDING_OK=True
DELTA_AUDIT_DECRYPT_OK=True
```

## What Proof of Audit proves

It proves that evidence files were encrypted into a package for a specific auditor public key and that the package is bound to a specific DELTA record hash.

## What Proof of Audit does not prove

It does not prove:

- legal consent,
- real-world auditor identity,
- truth of external systems,
- timestamp anchoring,
- registry governance,
- that decrypted evidence was later interpreted correctly by an auditor.

## v1.9.0 scope

Included:

- audit key generation,
- encrypted evidence package creation,
- package verification,
- auditor-side decryption,
- full record hash binding,
- documentation.

Not included:

- HSM/YubiKey integration,
- threshold audit disclosure,
- OpenTimestamps/public anchoring,
- organization-level auditor registry,
- automatic CI upload of decrypted evidence.

## v1.9.0 audit edge cases

If the target record contains no matching evidence commitments for the selected `--include` mode, `encrypt-evidence` still creates a valid empty audit package with:

```text
DELTA_AUDIT_NO_EVIDENCE_FOUND=True
DELTA_AUDIT_ENTRIES_ENCRYPTED=0
```

This is a warning state, not a crash. It means the record can still be bound to an audit package, but there is no evidence payload to disclose under the selected include policy.

If the record declares evidence commitments but a referenced evidence file is missing, `encrypt-evidence` fails by default with `MISSING_EVIDENCE_FILE`. This protects against accidentally creating a misleading partial package. Use `--allow-missing-evidence` only for controlled negative tests or intentionally partial disclosure workflows.

Evidence paths from records are resolved from the current working directory, the record directory, and optionally `--evidence-root`. For normal sensor artifacts, evidence files written next to `delta-record.json` resolve from the record directory.

`verify-package` checks the package target against the SHA-256 hash of the full canonical `delta-record.json`. If the package is verified against a different record, it reports:

```text
DELTA_AUDIT_RECORD_BINDING_OK=False
DELTA_AUDIT_RECORD_BINDING_REASON=record_hash_mismatch
```

Audit packages are not signed in v1.9.0. They contain encrypted evidence and integrity metadata, including AAD hashes and ciphertext hashes, but package authorship/signature is a future hardening step.

## Repository hygiene

Recommended commit set for v1.9.0:

```text
tools/delta_audit.py
docs/audit/proof-of-audit-v1.9.0.md
.delta/audit-public-key.json
```

Do not commit:

```text
C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_AUDIT_PRIVATE_KEY.txt
.delta/audit-tests/*/delta-audit-package.json
.delta/audit-tests/*/decrypted/
.delta/artifacts/
```

Encrypted audit packages may still contain sensitive ciphertext and metadata. Prefer attaching them to controlled releases or keeping them outside the repository unless an explicit public demo package is intentionally created from non-sensitive sample evidence.
