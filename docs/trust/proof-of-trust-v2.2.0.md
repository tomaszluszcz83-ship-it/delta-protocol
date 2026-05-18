# DELTA v2.2.0 — Proof of Trust / Hash-Chain Ledger

DELTA Proof of Trust v2.2.0 introduces an offline, zero-token hash-chain ledger for DELTA proof events.

The goal is to prove cryptographic continuity:

```text
record hash → trust entry → previous entry hash → trust ledger body hash
```

## What it proves

Proof of Trust v2.2.0 proves that:

- a trust ledger contains entries bound to full DELTA record hashes;
- each entry has a canonical `entry_body_hash` self-check;
- each entry links to the previous entry hash;
- the full ledger has a canonical `ledger_body_hash` self-check;
- tampering with an entry, sequence, record hash, or chain link is detected.

## What it does not prove

Proof of Trust v2.2.0 does **not** prove:

- legal trust;
- real-world identity;
- external-world truth;
- that an actor label is truthful;
- that an auditor/regulator actually approved anything;
- that linked proofs are semantically valid beyond their recorded file hash.

Actor labels are metadata in v2.2.0. Signed trust entries and identity registries are future layers.

## Tool

```text
tools/delta_trust.py
```

Commands:

```text
hash-record
create-ledger
append-entry
verify-ledger
```

## Hash binding

Like Proof of Intent, Proof of Audit, and Proof of Publication, Proof of Trust binds to:

```text
sha256(canonical_json(full_delta_record_json))
```

not merely to `record_body_hash`.

## Ledger shape

A ledger has:

```json
{
  "type": "delta_trust_ledger",
  "version": "1.0.0",
  "protocol": "DELTA-0",
  "ledger_body_hash": "sha256:...",
  "ledger_body": {
    "type": "delta_trust_ledger_body",
    "chain_id": "delta-trust-local-v1",
    "entries": [
      {
        "entry_body_hash": "sha256:...",
        "entry_body": {
          "type": "delta_trust_entry",
          "sequence": 0,
          "previous_entry_hash": "GENESIS",
          "target": {
            "record_hash": "sha256:..."
          }
        }
      }
    ]
  }
}
```

## Roles

Supported metadata roles:

```text
executor
verifier
intent_approver
auditor
publisher
regulator
observer
```

## Event types

Supported event types:

```text
record_observed
replay_verified
intent_verified
audit_verified
publication_verified
manual_reviewed
regulatory_reviewed
```

## Example

Create a ledger:

```powershell
python tools\delta_trust.py create-ledger `
  --record C:\path\to\delta-record.json `
  --out .delta\trust-tests\T-001\delta-trust-ledger.json `
  --chain-id delta-trust-local-v1 `
  --entry-id T-001-E-001 `
  --actor local-executor `
  --role executor `
  --event-type record_observed
```

Append replay verification:

```powershell
python tools\delta_trust.py append-entry `
  --ledger .delta\trust-tests\T-001\delta-trust-ledger.json `
  --record C:\path\to\delta-record.json `
  --entry-id T-001-E-002 `
  --actor local-verifier `
  --role verifier `
  --event-type replay_verified
```

Verify:

```powershell
python tools\delta_trust.py verify-ledger `
  --ledger .delta\trust-tests\T-001\delta-trust-ledger.json `
  --record C:\path\to\delta-record.json
```

Expected:

```text
DELTA_TRUST_VERIFY_OK=True
DELTA_TRUST_ENTRY_HASHES_OK=True
DELTA_TRUST_CHAIN_LINKS_OK=True
DELTA_TRUST_LEDGER_BODY_HASH_OK=True
DELTA_TRUST_RECORD_BINDING_OK=True
```

## Security boundary

Proof of Trust v2.2.0 is a cryptographic continuity layer. It is not an authority system by itself.

Future versions may add:

- signed trust entries;
- identity registries;
- delegation chains;
- threshold trust entries;
- regulator/auditor public key registries;
- trust policy enforcement.
