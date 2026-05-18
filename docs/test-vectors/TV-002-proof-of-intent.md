# TV-002: Proof of Intent

**Layer:** Proof of Intent  
**Status:** Draft test vector  
**Purpose:** verify that a detached intent attestation is signed and bound to the full `delta-record.json` hash.

## Positive test objective

A valid intent bundle should produce:

```text
DELTA_REPLAY_INTENT_STATUS=INTENT_VERIFIED
DELTA_REPLAY_INTENT_SIGNATURE_OK=True
DELTA_REPLAY_INTENT_RECORD_BINDING_OK=True
DELTA_REPLAY_INTENT_REGISTRY_OK=True
```

The intent target must bind to the full canonical SHA-256 hash of the supplied `delta-record.json`, not merely to an informal label or an unbound ticket id.

## Command pattern

```powershell
python tools\delta_replay.py `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --intent-attestation <PATH_TO_INTENT_ATTESTATION_JSON> `
  --intent-signature <PATH_TO_INTENT_SIGNATURE_JSON> `
  --intent-registry <PATH_TO_INTENT_REGISTRY_JSON> `
  --skip-install
```

Expected:

```text
DELTA_REPLAY_RESULT: OK
DELTA_REPLAY_INTENT_STATUS=INTENT_VERIFIED
DELTA_REPLAY_INTENT_SIGNATURE_OK=True
DELTA_REPLAY_INTENT_RECORD_BINDING_OK=True
DELTA_REPLAY_INTENT_REGISTRY_OK=True
```

## Negative test A: missing signature

Run the same command without `--intent-signature` or with a missing signature path.

Expected:

```text
DELTA_REPLAY_INTENT_STATUS=INTENT_MISSING
DELTA_REPLAY_INTENT_SIGNATURE_OK=False
```

## Negative test B: tampered attestation

Auditor action:

1. Copy the intent attestation file.
2. Modify `ticket_id`, `reason`, or `target.record_hash`.
3. Re-run intent verification with the original signature.

Expected:

```text
DELTA_REPLAY_INTENT_STATUS=INTENT_INVALID
DELTA_REPLAY_INTENT_SIGNATURE_OK=False
```

If `target.record_hash` is changed, expected binding failure:

```text
DELTA_REPLAY_INTENT_RECORD_BINDING_OK=False
```

## Negative test C: registry mismatch

Use a registry that does not contain the intent public key or marks it inactive/revoked.

Expected:

```text
DELTA_REPLAY_INTENT_STATUS=INTENT_INVALID
DELTA_REPLAY_INTENT_REGISTRY_OK=False
```

## Security boundary

Proof of Intent proves that a declared intent object was signed by a key and bound to a specific DELTA record hash.
It does not prove legal approval, ticket truth, identity, MFA completion, governance correctness, or real-world authority.
