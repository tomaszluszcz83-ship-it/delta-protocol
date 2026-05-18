# TV-003: Proof of Audit

**Layer:** Proof of Audit  
**Status:** Draft test vector  
**Purpose:** verify encrypted evidence package binding, integrity, and auditor-side disclosure.

## Positive test objective

A valid audit package should verify without decryption and decrypt with the auditor private key.

Expected verification indicators:

```text
DELTA_AUDIT_VERIFY_OK=True
DELTA_AUDIT_RECORD_BINDING_OK=True
DELTA_AUDIT_RECIPIENT_OK=True
DELTA_AUDIT_ENTRY_SHAPES_OK=True
DELTA_AUDIT_ENTRY_HASHES_OK=True
DELTA_AUDIT_AAD_HASHES_OK=True
DELTA_AUDIT_CIPHERTEXT_HASHES_OK=True
```

Expected decryption indicators:

```text
DELTA_AUDIT_DECRYPT_OK=True
DELTA_AUDIT_DECRYPTED_ENTRY_COUNT=<N>
```

## Command pattern: verify package

```powershell
python tools\delta_audit.py verify-package `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --package <PATH_TO_DELTA_AUDIT_PACKAGE_JSON> `
  --auditor-public-key .delta\audit-public-key.json
```

## Command pattern: decrypt package

```powershell
python tools\delta_audit.py decrypt-package `
  --package <PATH_TO_DELTA_AUDIT_PACKAGE_JSON> `
  --auditor-private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_AUDIT_PRIVATE_KEY.txt `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out-dir .delta\audit-tests\A-001\decrypted
```

Private audit keys and decrypted evidence must never be committed.

## Negative test A: tampered ciphertext hash

Modify an entry `ciphertext_hash`.

Expected:

```text
DELTA_AUDIT_VERIFY_OK=False
DELTA_AUDIT_CIPHERTEXT_HASHES_OK=False
```

## Negative test B: tampered AAD / record binding

Modify record hash references inside the package AAD/target area.

Expected one or more of:

```text
DELTA_AUDIT_VERIFY_OK=False
DELTA_AUDIT_RECORD_BINDING_OK=False
DELTA_AUDIT_AAD_HASHES_OK=False
```

## Negative test C: wrong record

Verify an audit package against a different `delta-record.json`.

Expected:

```text
DELTA_AUDIT_VERIFY_OK=False
DELTA_AUDIT_RECORD_BINDING_OK=False
```

## Security boundary

Proof of Audit proves package integrity, recipient binding, evidence hash binding, and optional auditor-side decryption.
It does not prove legal truth, audit authority, evidence truth before hashing, or regulatory compliance by itself.
