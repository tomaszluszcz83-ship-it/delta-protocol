# TV-005: Proof of Trust / Hash-Chain Ledger

**Layer:** Proof of Trust  
**Status:** Draft test vector  
**Purpose:** verify ledger entry hashes, previous-entry links, ledger self-check, and record binding.

## Positive test objective

A valid trust ledger should verify:

```text
DELTA_TRUST_VERIFY_OK=True
DELTA_TRUST_LEDGER_BODY_HASH_OK=True
DELTA_TRUST_LEDGER_SELF_CHECK_OK=True
DELTA_TRUST_ENTRY_HASHES_OK=True
DELTA_TRUST_ENTRY_SELF_CHECKS_OK=True
DELTA_TRUST_CHAIN_LINKS_OK=True
DELTA_TRUST_SEQUENCE_OK=True
DELTA_TRUST_RECORD_BINDING_OK=True
```

## Command pattern: create ledger

```powershell
python tools\delta_trust.py create-ledger `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\trust-tests\T-001\delta-trust-ledger.json `
  --chain-id delta-trust-local-v1 `
  --entry-id T-001-E-001 `
  --actor local-executor `
  --role executor `
  --event-type record_observed `
  --note "Genesis trust entry"
```

## Command pattern: append entry

```powershell
python tools\delta_trust.py append-entry `
  --ledger .delta\trust-tests\T-001\delta-trust-ledger.json `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --entry-id T-001-E-002 `
  --actor local-verifier `
  --role verifier `
  --event-type replay_verified `
  --note "Replay verification completed"
```

## Command pattern: verify ledger

```powershell
python tools\delta_trust.py verify-ledger `
  --ledger .delta\trust-tests\T-001\delta-trust-ledger.json `
  --record <PATH_TO_DELTA_RECORD_JSON>
```

## Negative test: tampered previous entry hash

Modify the second entry:

```json
"previous_entry_hash": "sha256:7777777777777777777777777777777777777777777777777777777777777777"
```

Expected:

```text
DELTA_TRUST_VERIFY_OK=False
DELTA_TRUST_CHAIN_LINKS_OK=False
DELTA_TRUST_REASON_CHAIN_LINKS_OK=previous_entry_hash_mismatch
```

Additional expected failures may include:

```text
DELTA_TRUST_ENTRY_HASHES_OK=False
DELTA_TRUST_ENTRY_SELF_CHECKS_OK=False
DELTA_TRUST_LEDGER_BODY_HASH_OK=False
DELTA_TRUST_LEDGER_SELF_CHECK_OK=False
```

## Security boundary

Proof of Trust proves cryptographic hash-chain consistency and record binding.
It does not prove legal identity, auditor authority, regulator authority, organizational trust, or real-world correctness.
