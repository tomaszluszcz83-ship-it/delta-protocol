# DELTA Protocol — Key Compromise Playbook (v2.8.1)

Status: Design-only operational playbook

## 1. Purpose

This playbook defines what a DELTA operator should do when a private key may be compromised.

It covers:

- executor keys,
- intent keys,
- audit keys,
- bundle signing keys,
- wallet proof keys where applicable,
- trust ledger keys.

## 2. Immediate actions

If compromise is suspected:

1. Stop using the key.
2. Preserve logs and artifacts.
3. Identify affected artifact hashes.
4. Identify affected signatures.
5. Generate replacement keys if needed.
6. Create a revocation/invalidation event.
7. Publish the event through the agreed trust/publication channel.
8. Notify relying parties.

## 3. What not to do

Do not delete old records.

Do not rewrite old signed artifacts.

Do not silently rotate keys without a revocation trail.

Do not commit private keys while trying to fix the incident.

Do not claim that revocation proves the real-world cause of compromise.

## 4. Key classes

| Key class | Example risk | Response |
| --- | --- | --- |
| Executor signing key | Fake sensor records | Revoke key, stop accepting future records, review historical records. |
| Intent signing key | Unauthorized approvals | Revoke key, invalidate affected intents if needed. |
| Audit private key | Evidence confidentiality risk | Rotate auditor key, re-encrypt future evidence, assess disclosure impact. |
| Bundle signing key | Fake/unauthorized bundles | Revoke key, publish replacement key, ask recipients to verify revocation. |
| Trust ledger key | Malicious delegation events | Revoke delegation key, publish corrective trust event. |

## 5. Bundle signing key compromise

For v2.8.0 signed bundles:

- The old Ed25519 signatures may still verify mathematically.
- Trust policy should reject signatures after the revocation effective time.
- A replacement signing key should be published.
- Old bundle hashes should be reviewed and optionally invalidated.

## 6. Minimum incident record

An incident record SHOULD include:

- incident id,
- detected time,
- affected key hash,
- affected artifact hashes,
- reason code,
- revocation effective time,
- replacement key hash if applicable,
- operator note,
- evidence hash,
- publication proof if available.

## 7. Reason codes

Suggested reason codes:

```text
key_compromise
key_loss
operator_error
artifact_leak
artifact_superseded
signature_misuse
policy_change
trust_delegation_removed
unknown_risk
```

## 8. Security boundary

This playbook does not determine legal liability.

It defines a technical response workflow for preserving audit history while changing trust status.
