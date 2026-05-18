# DELTA v2.3.1 — Ethereum EIP-191 Wallet Proof

DELTA v2.3.1 adds an Ethereum `personal_sign` adapter for Proof of Crypto Wallet / Address Control.

## Adapter

`ethereum_eip191_personal_sign_v1`

This adapter verifies that an Ethereum address signed a DELTA wallet challenge using EIP-191 / `personal_sign` semantics.

## What DELTA proves

DELTA verifies that:

- the supplied proof uses the `ethereum_eip191_personal_sign_v1` standard,
- the challenge is bound to the SHA-256 hash of the full canonical `delta-record.json`,
- the challenge message was signed through Ethereum EIP-191 / `personal_sign`,
- the recovered Ethereum address matches the declared address,
- tampering with the record hash, challenge, address, proof body, or signature is detected.

## What DELTA does not prove

Proof of Wallet does **not** prove:

- legal ownership of an address,
- identity of a person,
- account balance,
- regulatory compliance,
- MiCA compliance,
- that funds are safe,
- that a specific hardware wallet was used,
- external-world truth.

It proves only that a cryptographic key/address signed a DELTA challenge that is bound to a specific full `delta-record.json` hash.

## Security boundary

DELTA never asks for a seed phrase.
DELTA does not need the user's production wallet private key.
For tests, a local demo Ethereum key may be generated and used; it must never be used for funds and must never be committed.

The optional `eth-account` dependency is used only for Ethereum EIP-191 signing/recovery:

```powershell
python -m pip install eth-account
```

## Example flow

Create a challenge bound to a DELTA record:

```powershell
python tools\delta_wallet.py create-challenge `
  --chain ethereum `
  --standard ethereum_eip191_personal_sign_v1 `
  --address 0xYourEthereumAddress `
  --record C:\path\to\delta-record.json `
  --out .delta\wallet-tests\ETH-001\wallet-challenge-eth.json `
  --domain local-delta-test `
  --purpose "DELTA v2.3.1 Ethereum EIP-191 wallet proof test"
```

Sign the challenge message externally with a wallet that supports `personal_sign`, such as MetaMask, or with a local test key.
The exact signed text is stored in:

```text
challenge_body.message
```

Create a proof from an externally supplied signature:

```powershell
python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\ETH-001\wallet-challenge-eth.json `
  --signature 0xYourPersonalSignSignature `
  --record C:\path\to\delta-record.json `
  --out .delta\wallet-tests\ETH-001\wallet-proof-eth.json `
  --holder local-eth-holder
```

Verify the proof:

```powershell
python tools\delta_wallet.py verify-proof `
  --proof .delta\wallet-tests\ETH-001\wallet-proof-eth.json `
  --challenge .delta\wallet-tests\ETH-001\wallet-challenge-eth.json `
  --record C:\path\to\delta-record.json
```

Expected successful checks include:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_ADDRESS_BINDING_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

## Local demo test flow

For a fully local test, use the demo Ethereum helper commands:

```powershell
python tools\delta_wallet.py eth-keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ETH_TEST_KEY.txt `
  --public-out .delta\wallet-tests\ETH-001\eth-wallet-public.json `
  --force
```

Then create the proof with:

```powershell
python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\ETH-001\wallet-challenge-eth.json `
  --eth-private-key C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ETH_TEST_KEY.txt `
  --record C:\path\to\delta-record.json `
  --out .delta\wallet-tests\ETH-001\wallet-proof-eth.json `
  --holder local-eth-holder
```

The local demo key is not a production wallet and must not be committed.

## Roadmap

Ethereum EIP-191 is the first public-chain wallet adapter.
Future adapters may include:

- Ethereum EIP-712 typed structured data,
- Bitcoin BIP-322,
- Kaspa observation/future signing adapter when a safe message-signing standard exists,
- DID/VC binding,
- ZK balance threshold proofs,
- MPC / threshold wallet attestations,
- hardware wallet attestation.
