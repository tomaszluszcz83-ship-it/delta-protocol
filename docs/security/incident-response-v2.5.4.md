# DELTA v2.5.4 Security Foundation — Incident Response

**Status:** Draft  
**Version:** v2.5.4  
**Purpose:** Define recommended response procedures for key compromise, invalid proofs, verifier bugs, sensitive artifact leaks, and overclaiming incidents.

---

## 1. Scope

This document applies to incidents affecting DELTA proof integrity, private keys, private evidence, audit packages, wallet proofs, trust ledgers, publication proofs, canonicalization, and verifier behavior.

---

## 2. Incident classes

### 2.1 Key compromise

Examples:

- executor private key leaked,
- intent signing key leaked,
- audit private key leaked,
- wallet demo/private key committed,
- publication/trust key compromised.

Required response:

1. Stop using the affected key immediately.
2. Identify all records/proofs signed after suspected compromise time.
3. Publish a security advisory or private notice depending on severity.
4. Generate a replacement key.
5. Update registry documentation where applicable.
6. Publish an invalidation/revocation notice for affected keys or proofs.
7. Re-run affected verification flows with new keys where possible.

DELTA does not yet define a normative revocation record. A future profile SHOULD define `delta_key_revocation_v1` or equivalent.

---

### 2.2 Invalid verifier behavior

Examples:

- verifier accepts tampered record,
- verifier accepts mismatched `record_hash`,
- verifier reports `CRYPTO_SIGNATURE_VERIFIED=True` incorrectly,
- canonicalization bug changes hash output.

Required response:

1. Reproduce with a minimal test vector.
2. Mark affected version(s) as unsafe for the affected proof profile.
3. Patch verifier and add regression test/vector.
4. Publish advisory with affected proof types and versions.
5. Re-verify important records with patched verifier.

---

### 2.3 Sensitive artifact leak

Examples:

- private evidence committed,
- decrypted audit output committed,
- local wallet/private key committed,
- CI token or API secret committed.

Required response:

1. Remove artifact from active branch.
2. Rotate affected secrets/keys immediately.
3. Treat Git history as compromised if pushed publicly.
4. Publish guidance if public users may have copied the material.
5. Add ignore rules and documentation to prevent recurrence.

Deleting a file from a later commit does not remove it from public history.

---

### 2.4 Overclaiming incident

Examples:

- report claims legal compliance,
- report claims wallet ownership/balance without a supported profile,
- Bitcoin external proof is described as locally cryptographically verified.

Required response:

1. Correct public wording immediately.
2. Update README/docs/release notes if necessary.
3. Add explicit warning to relevant proof profile.
4. Add reviewer/test-vector note if the issue can recur.

---

## 3. Revocation and invalidation concept

DELTA should introduce a future proof object such as:

```json
{
  "type": "delta_key_revocation",
  "version": "1.0.0",
  "revoked_public_key_hash": "sha256:...",
  "revoked_at": "2026-...Z",
  "reason": "suspected_compromise",
  "scope": "intent_key|executor_key|audit_key|wallet_key|publication_key",
  "signed_by": "...",
  "signature": "..."
}
```

Until such a normative profile exists, revocation should be documented through release notes, security advisories, registries, and replacement keys.

---

## 4. Advisory template

```text
Title: DELTA Security Advisory: <short title>
Affected versions: <versions>
Affected proof profiles: <profiles>
Severity: Critical/High/Medium/Low
Summary: <what happened>
Impact: <what attackers can do>
Mitigation: <what users should do>
Fixed in: <version/commit>
Verification: <commands/test vectors>
Boundary: <what remains not proven>
```

---

## 5. Required regression after incident

Any security fix SHOULD include at least one of:

- frozen test vector,
- negative test case,
- documentation boundary update,
- verifier output check,
- schema/conformance rule.

---

## 6. Current limitations

As of v2.5.4:

- There is no normative key revocation object.
- There is no public conformance suite yet.
- Canonicalization hardening is planned for v2.6.0.
- JSON Schemas are planned for v2.6.1.
- Conformance levels/tests are planned for v2.6.2.

---

## 7. Summary

Incident response is part of the protocol boundary. DELTA should make compromise and invalidation visible rather than silently pretending all previous proofs remain equally trustworthy.
