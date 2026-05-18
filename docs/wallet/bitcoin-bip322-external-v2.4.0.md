# DELTA v2.4.0 — Bitcoin BIP-322 External Wallet Proof Skeleton

## Adapter

`bitcoin_bip322_external_v1`

This release adds a Bitcoin-ready wallet proof adapter for DELTA Proof of Crypto Wallet / Address Control.

The adapter is intentionally conservative. It does not locally evaluate Bitcoin Script, Taproot witness data, virtual BIP-322 transactions, PSBTs, or proof-of-funds semantics. It records and verifies the structure, hashes, self-checks, and DELTA record binding for an externally supplied Bitcoin proof artifact.

## What v2.4.0 proves

v2.4.0 proves that:

- a Bitcoin wallet proof object has the expected DELTA shape,
- the proof object is bound to a specific DELTA challenge,
- the challenge contains the SHA-256 hash of the full `delta-record.json`,
- the proof target matches that same full record hash,
- the external Bitcoin proof field is present and has a supported declared format,
- DELTA integrity self-checks pass.

## What v2.4.0 does not prove

v2.4.0 does not prove that:

- DELTA locally verified a BIP-322 signature,
- a Bitcoin address truly signed the message,
- a UTXO exists or is spendable,
- a balance exists,
- the signer has legal ownership,
- the signer has a verified identity,
- any regulatory or external-world claim is true.

The output explicitly separates:

- `DELTA_WALLET_SIGNATURE_SHAPE_OK`
- `DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False`
- `DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL=shape_only`
- `DELTA_WALLET_SIGNATURE_VERIFICATION_MODE=external_pending`

## Flow

1. Create a DELTA Bitcoin challenge bound to a record.
2. Sign or produce a Bitcoin proof externally using a trusted Bitcoin wallet/tool.
3. Create a DELTA wallet proof using the external signature/proof string.
4. Verify DELTA shape, hashes, challenge binding, and record binding.

## Example

```powershell
$RecordPath = "C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json"
$BtcAddress = "tb1qexampleaddress0000000000000000000000000"

python tools\delta_wallet.py create-challenge `
  --chain bitcoin `
  --standard bitcoin_bip322_external_v1 `
  --address $BtcAddress `
  --record $RecordPath `
  --out .delta\wallet-tests\BTC-001\wallet-challenge-btc.json `
  --domain local-delta-test `
  --purpose "DELTA v2.4.0 Bitcoin external wallet proof test"
```

The challenge contains a text message and a target record hash. The user should produce a Bitcoin proof externally. For v2.4.0, DELTA accepts the externally supplied string as a proof artifact and marks local cryptographic verification as pending.

```powershell
$ExternalProof = "MEUCIQDbased64orExternalProofExample000000000000000000000000000000000000000=="

python tools\delta_wallet.py create-proof `
  --challenge .delta\wallet-tests\BTC-001\wallet-challenge-btc.json `
  --signature $ExternalProof `
  --signature-format bip322_simple_base64_or_external `
  --record $RecordPath `
  --out .delta\wallet-tests\BTC-001\wallet-proof-btc.json `
  --holder local-btc-holder

python tools\delta_wallet.py verify-proof `
  --proof .delta\wallet-tests\BTC-001\wallet-proof-btc.json `
  --challenge .delta\wallet-tests\BTC-001\wallet-challenge-btc.json `
  --record $RecordPath
```

Expected verification level:

```text
DELTA_WALLET_VERIFY_OK=True
DELTA_WALLET_SIGNATURE_SHAPE_OK=True
DELTA_WALLET_SIGNATURE_OK=True
DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False
DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL=shape_only
DELTA_WALLET_SIGNATURE_VERIFICATION_MODE=external_pending
DELTA_WALLET_RECORD_BINDING_OK=True
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True
```

## Tamper tests

Required tests for v2.4.0:

- valid external proof object: `DELTA_WALLET_VERIFY_OK=True`,
- changed `record_hash` in challenge: `DELTA_WALLET_VERIFY_OK=False`,
- changed proof body hash: `DELTA_WALLET_VERIFY_OK=False`,
- empty signature/proof field: `DELTA_WALLET_VERIFY_OK=False`,
- unsupported `signature_format`: `DELTA_WALLET_VERIFY_OK=False`.

## Roadmap

Future work:

- v2.4.1: selected local BIP-322 verification support,
- v2.4.2: fuller BIP-322 variants and proof-of-funds handling,
- later: hardware wallet workflows and policy/registry integration.

