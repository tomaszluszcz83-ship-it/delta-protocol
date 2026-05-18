# DELTA Test Vectors v2.5.2

**Status:** Draft  
**Release:** v2.5.2 Audit / Test Vectors Pack  
**Purpose:** provide auditor-friendly, repeatable test scenarios for the current DELTA reference implementation.

This directory documents test vectors and expected verifier behavior for DELTA proof layers.
It intentionally does not commit private keys, seed phrases, generated sensitive evidence, encrypted audit packages, decrypted evidence, wallet private keys, or local test artifacts.

## Scope

The current pack covers:

| Test Vector | Layer | Purpose |
|---|---|---|
| TV-001 | Sensor Record / Proof of Change | Verify signed sensor record integrity and replay-related checks. |
| TV-002 | Proof of Intent | Verify detached intent binding to full `delta-record.json` hash. |
| TV-003 | Proof of Audit | Verify encrypted evidence package binding and tamper detection. |
| TV-004 | Proof of Publication | Verify publication proof binding and external evidence hash checks. |
| TV-005 | Proof of Trust | Verify hash-chain ledger entry links and record binding. |
| TV-006 | Proof of Wallet | Verify Ed25519, Ethereum EIP-191, Ethereum EIP-712, and Bitcoin external profiles. |

## Security boundary

DELTA test vectors prove verifier behavior for hashes, signatures, canonical JSON, record binding, replay-related checks, audit package binding, publication proof binding, trust ledger integrity, and wallet challenge binding.

They do **not** prove:

- legal truth,
- real-world truth,
- legal ownership,
- identity,
- wallet balance,
- regulatory compliance,
- signer authority outside the declared cryptographic key,
- that evidence was not fabricated before hashing,
- local cryptographic Bitcoin BIP-322 validation for `bitcoin_bip322_external_v1`.

For Bitcoin external-only proofs, `CRYPTO_SIGNATURE_VERIFIED=False` and `shape_only` / `external_pending` are expected and intentional.

## Recommended audit flow

1. Read `docs/rfc/RFC-01-delta-core-protocol.md`.
2. Read `docs/rfc/RFC-02-proof-of-wallet.md`.
3. Run the core verifier:

```powershell
python src/delta_cli.py verify-all
```

Expected:

```text
DELTA CLI RESULT: OK
```

4. Review each `TV-*.md` file.
5. Re-run the positive and negative tests locally.
6. Confirm that generated artifacts are not committed.
7. Confirm that private keys remain outside the repository.

## Repository hygiene requirements

Before committing changes related to test vectors:

```powershell
python src/delta_cli.py verify-all
git diff --check
git status --short
```

Expected tracked files for this pack:

```text
docs/test-vectors/README.md
docs/test-vectors/TV-001-sensor-record.md
docs/test-vectors/TV-002-proof-of-intent.md
docs/test-vectors/TV-003-proof-of-audit.md
docs/test-vectors/TV-004-proof-of-publication.md
docs/test-vectors/TV-005-proof-of-trust.md
docs/test-vectors/TV-006-proof-of-wallet.md
docs/audit/audit-checklist-v2.5.2.md
```

Do not commit `.delta/*-tests/`, decrypted evidence, generated proof packages, or private key files.
