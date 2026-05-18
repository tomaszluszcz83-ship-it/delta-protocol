# DELTA v2.3.2 — Ethereum EIP-712 Wallet Proof

## Adapter

`ethereum_eip712_typed_data_v1`

This adapter extends DELTA Proof of Crypto Wallet / Address Control with Ethereum EIP-712 typed structured data signing.

It is a controlled follow-up to `ethereum_eip191_personal_sign_v1`. EIP-191 signs a plain human-readable message. EIP-712 signs structured fields, making the challenge easier for wallet software and auditors to inspect.

## What v2.3.2 proves

v2.3.2 proves that an Ethereum address signed a DELTA EIP-712 typed challenge that contains the SHA-256 hash of a specific full `delta-record.json`.

The signed typed-data challenge includes, at minimum:

- challenge id
- protocol
- chain
- standard
- Ethereum address
- domain/context label
- purpose
- full DELTA record hash
- creation timestamp
- nonce

## What v2.3.2 does not prove

It does not prove:

- legal ownership of the wallet
- identity of a person
- wallet balance
- MiCA compliance
- correctness of the underlying change
- external-world truth
- that a production hardware wallet was used

## Security model

- DELTA never asks for seed phrases.
- DELTA does not store production private keys.
- `eth-keygen` and `--eth-private-key` are for local demo tests only.
- Production usage should provide an externally created EIP-712 signature via `--signature`.
- The record hash is inside the signed typed-data challenge body.
- Verification rebuilds the EIP-712 typed data from the challenge fields, so tampering with `record_hash`, `address`, `challenge_id`, `nonce`, or similar fields invalidates the signature.

## Dependency

Ethereum adapters require the optional Python package:

```powershell
python -m pip install eth-account
```

DELTA core remains independent of Ethereum. The dependency is only needed for Ethereum wallet proof commands.

## Example flow

Create a local demo Ethereum key:

```powershell
python tools\delta_wallet.py eth-keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ETH_EIP712_TEST_KEY.txt `
  --public-out .delta\wallet-tests\EIP712-001\eth-wallet-public.json `
  --force
```

Create an EIP-712 typed challenge bound to a DELTA record:

```powershell
python tools\delta_wallet.py create-challenge `
  --chain ethereum `
  --standard ethereum_eip712_typed_data_v1 `
  --address 0xYourTestAddress `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --out .delta\wallet-tests\EIP712-001\wallet-challenge-eip712.json `
  --domain local-delta-test `
  --purpose "DELTA v2.3.2 Ethereum EIP-712 wallet proof test" `
  --eip712-chain-id 1
```

Create a local demo proof:

```powershell
python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\EIP712-001\wallet-challenge-eip712.json `
  --eth-private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ETH_EIP712_TEST_KEY.txt `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --out .delta\wallet-tests\EIP712-001\wallet-proof-eip712.json `
  --holder local-eth-eip712-holder
```

Verify:

```powershell
python tools\delta_wallet.py verify-proof `
  --proof .delta\wallet-tests\EIP712-001\wallet-proof-eip712.json `
  --challenge .delta\wallet-tests\EIP712-001\wallet-challenge-eip712.json `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json
```

Expected key outputs:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_ADDRESS_BINDING_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
DELTA_WALLET_EIP712_TYPED_DATA_HASH=sha256:...
```

## Tamper tests

Required checks before release:

- valid EIP-712 proof verifies successfully
- tampered record hash fails
- tampered signature fails
- `python src/delta_cli.py verify-all` remains OK

