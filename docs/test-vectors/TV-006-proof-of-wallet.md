# TV-006: Proof of Wallet / Address Control

**Layer:** Proof of Crypto Wallet / Address Control  
**Status:** Draft test vector  
**Purpose:** verify wallet challenge binding, signature/address binding, record binding, and profile-specific security boundaries.

## Supported profiles in current reference implementation

```text
ed25519_address_control_v1
ethereum_eip191_personal_sign_v1
ethereum_eip712_typed_data_v1
bitcoin_bip322_external_v1
```

## Common positive checks

A valid wallet proof should verify:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_CHALLENGE_BINDING_OK=True
DELTA_WALLET_ADDRESS_BINDING_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

For Ed25519 and Ethereum profiles, cryptographic signature verification is expected:

```text
DELTA_WALLET_SIGNATURE_OK=True
```

For Bitcoin external profile, local cryptographic verification is intentionally not claimed:

```text
DELTA_WALLET_SIGNATURE_SHAPE_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False
DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL=shape_only
DELTA_WALLET_SIGNATURE_VERIFICATION_MODE=external_pending
```

## Ed25519 positive pattern

```powershell
python tools\delta_wallet.py keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ED25519_PRIVATE_KEY.txt `
  --public-out .delta\wallet-tests\W-001\wallet-public.json `
  --force
```

Create challenge and proof with `--record <PATH_TO_DELTA_RECORD_JSON>`, then verify.

Expected:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

## Ethereum EIP-191 positive pattern

```powershell
python tools\delta_wallet.py eth-keygen `
  --private-out C:\Users\PC\Desktop\DELTA-PRIVATE-KEYS\DELTA_WALLET_ETH_TEST_KEY.txt `
  --public-out .delta\wallet-tests\ETH-001\eth-wallet-public.json `
  --force
```

Create challenge:

```powershell
python tools\delta_wallet.py create-challenge `
  --chain ethereum `
  --standard ethereum_eip191_personal_sign_v1 `
  --address <ETH_ADDRESS> `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\wallet-tests\ETH-001\wallet-challenge-eth.json
```

Create proof with `--eth-private-key` or externally supplied `--signature`.

Expected:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_ADDRESS_BINDING_OK=True
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

## Ethereum EIP-712 positive pattern

Create challenge:

```powershell
python tools\delta_wallet.py create-challenge `
  --chain ethereum `
  --standard ethereum_eip712_typed_data_v1 `
  --address <ETH_ADDRESS> `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\wallet-tests\EIP712-001\wallet-challenge-eip712.json `
  --eip712-chain-id 1
```

Expected:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_EIP712_TYPED_DATA_HASH=sha256:...
```

## Bitcoin external positive pattern

Create challenge:

```powershell
python tools\delta_wallet.py create-challenge `
  --chain bitcoin `
  --standard bitcoin_bip322_external_v1 `
  --address <BTC_ADDRESS> `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\wallet-tests\BTC-001\wallet-challenge-btc.json
```

Create proof:

```powershell
python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\BTC-001\wallet-challenge-btc.json `
  --signature <EXTERNAL_BIP322_OR_EXTERNAL_PROOF_OBJECT> `
  --signature-format bip322_simple_base64_or_external `
  --record <PATH_TO_DELTA_RECORD_JSON> `
  --out .delta\wallet-tests\BTC-001\wallet-proof-btc.json
```

Expected:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_BITCOIN_PROOF_SHAPE_OK=True
DELTA_WALLET_BITCOIN_SIGNATURE_FORMAT_OK=True
DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False
DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL=shape_only
DELTA_WALLET_SIGNATURE_VERIFICATION_MODE=external_pending
```

## Negative test A: tampered record hash

Modify `challenge_body.target.record_hash` in the challenge.

Expected:

```text
DELTA_WALLET_VERIFY_OK=False
DELTA_WALLET_RECORD_BINDING_OK=False
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=False
```

For cryptographic profiles, signature verification may also fail:

```text
DELTA_WALLET_SIGNATURE_OK=False
```

## Negative test B: tampered signature

Modify `proof_body.signature.signature`.

Expected:

```text
DELTA_WALLET_VERIFY_OK=False
DELTA_WALLET_SIGNATURE_OK=False
```

For Bitcoin external, empty signature should produce:

```text
DELTA_WALLET_VERIFY_OK=False
DELTA_WALLET_SIGNATURE_SHAPE_OK=False
```

## Negative test C: unsupported Bitcoin signature format

Modify:

```json
"signature_format": "unsupported_format"
```

Expected:

```text
DELTA_WALLET_VERIFY_OK=False
DELTA_WALLET_BITCOIN_SIGNATURE_FORMAT_OK=False
```

## Security boundary

Proof of Wallet proves that a cryptographic key/address signed or supplied a proof object bound to a DELTA challenge and record hash.
It does not prove legal ownership, identity, wallet balance, MiCA compliance, regulatory compliance, UTXO ownership, or external-world truth.

For `bitcoin_bip322_external_v1`, local cryptographic BIP-322 verification is not performed in v2.4.0/v2.5.2 documentation.
`CRYPTO_SIGNATURE_VERIFIED=False` is expected and required for this profile.
