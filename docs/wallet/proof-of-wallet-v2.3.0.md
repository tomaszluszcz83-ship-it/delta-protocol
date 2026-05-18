# DELTA v2.3.0 — Proof of Crypto Wallet / Address Control

## Purpose

DELTA Proof of Wallet v2.3.0 introduces a controlled wallet/address-control proof envelope.

The MVP adapter is `ed25519_address_control_v1`. It is a demo adapter, not a BTC, ETH, or KAS production wallet implementation.

## Core flow

```text
create-challenge -> create-proof -> verify-proof
```

When `--record` is used during `create-challenge`, the full canonical `delta-record.json` hash is inserted into `challenge_body.target.record_hash`. The wallet signature signs the entire `challenge_body`, so the wallet proof is bound to the specific DELTA record hash.

This keeps Proof of Wallet aligned with the rest of DELTA:

```text
Proof of Intent      -> full delta-record.json hash
Proof of Audit       -> full delta-record.json hash
Proof of Publication -> full delta-record.json hash
Proof of Trust       -> full delta-record.json hash
Proof of Wallet      -> full delta-record.json hash when --record is used
```

## Commands

### Generate demo key

```powershell
python tools\delta_wallet.py keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ED25519_PRIVATE_KEY.txt `
  --public-out .delta\wallet-tests\W-001\wallet-public.json `
  --force
```

### Create record-bound challenge

```powershell
python tools\delta_wallet.py create-challenge `
  --out .delta\wallet-tests\W-001\wallet-challenge-record.json `
  --chain ed25519-demo `
  --address $Address `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --domain local-delta-test `
  --purpose "DELTA v2.3.0 record-bound wallet proof test"
```

### Create record-bound proof

```powershell
python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\W-001\wallet-challenge-record.json `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ED25519_PRIVATE_KEY.txt `
  --out .delta\wallet-tests\W-001\wallet-proof-record.json `
  --holder local-wallet-holder
```

### Verify record-bound proof

```powershell
python tools\delta_wallet.py verify-proof `
  --proof .delta\wallet-tests\W-001\wallet-proof-record.json `
  --challenge .delta\wallet-tests\W-001\wallet-challenge-record.json `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json
```

Expected key signals:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_CHALLENGE_BINDING_OK=True
DELTA_WALLET_ADDRESS_BINDING_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

## Security boundary

Proof of Wallet v2.3.0 does **not** prove:

- legal ownership of an address
- real-world identity
- wallet balance
- MiCA compliance
- chain state
- smart-contract wallet authority
- Bitcoin BIP-322 validity
- Ethereum EIP-191/EIP-712 validity
- Kaspa signmessage support

It proves only that:

- a supplied demo Ed25519 private key signed a specific DELTA wallet challenge
- the corresponding public key/address matches the challenge target
- when `--record` is used, the signed challenge is bound to the full canonical hash of a specific DELTA record

## Roadmap

Future adapters should be implemented separately and tested independently:

- Ethereum EIP-191 / `personal_sign`
- Ethereum EIP-712 typed structured data
- Bitcoin BIP-322
- Kaspa observation-only or future signing adapter once a stable message-signing standard exists
- DID/VC wallet attestations
- MiCA-style user attestations
- proof of balance / proof of balance threshold
- ZK/MPC/hardware wallet attestation
