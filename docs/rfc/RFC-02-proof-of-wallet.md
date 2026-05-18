# RFC-02: DELTA Proof of Wallet

**Status:** Draft  
**Version:** v2.5.0  
**Scope:** Wallet/address-control proof profiles for DELTA Protocol

## 1. Abstract

DELTA Proof of Wallet defines how a cryptographic address or public key can sign or provide a proof object bound to a specific DELTA record.

The goal is not to prove legal ownership of a wallet. The goal is to prove that a cryptographic address/control mechanism participated in a DELTA proof process.

## 2. Core Claim

A valid wallet proof may support the following claim:

```text
A cryptographic key or address produced a signature/proof object bound to a specific DELTA full record hash.
```

It does not prove:

- legal ownership;
- identity of a person;
- account balance;
- source of funds;
- regulatory compliance;
- that the wallet is controlled by a specific organization;
- that the wallet was uncompromised.

## 3. Required Binding

A wallet proof should bind to:

- challenge id;
- challenge hash;
- wallet standard;
- chain;
- address;
- full `delta-record.json` hash;
- signed challenge body or typed data;
- signature/proof object;
- verification level.

The record hash must be inside the signed payload where the standard supports it.

## 4. Supported Profiles

### 4.1 Ed25519 Demo

```text
standard = ed25519_address_control_v1
```

Reference/demo profile used to test address-control logic without real funds or chain dependencies.

### 4.2 Ethereum EIP-191

```text
standard = ethereum_eip191_personal_sign_v1
chain = ethereum
```

Uses Ethereum `personal_sign` style recovery to recover an address from a signed DELTA challenge.

### 4.3 Ethereum EIP-712

```text
standard = ethereum_eip712_typed_data_v1
chain = ethereum
```

Uses structured typed data so wallets can display meaningful fields.

### 4.4 Bitcoin BIP-322 External

```text
standard = bitcoin_bip322_external_v1
chain = bitcoin
verification_level = shape_only
verification_status = external_pending
crypto_signature_verified = false
```

This profile does not yet perform local cryptographic BIP-322 verification. It binds an external Bitcoin proof object to a DELTA record and verifies structure, hashes, and metadata.

## 5. Verification Outputs

Wallet verification should report:

```text
DELTA_WALLET_VERIFY_OK=True|False
DELTA_WALLET_SIGNATURE_SHAPE_OK=True|False
DELTA_WALLET_SIGNATURE_OK=True|False
DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=True|False
DELTA_WALLET_ADDRESS_BINDING_OK=True|False
DELTA_WALLET_CHALLENGE_BINDING_OK=True|False
DELTA_WALLET_RECORD_BINDING_OK=True|False
DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK=True|False
```

For external-only profiles, `CRYPTO_SIGNATURE_VERIFIED=False` must be reported clearly.

## 6. Security Requirements

Implementations must not:

- request seed phrases;
- commit private keys;
- claim legal ownership;
- claim proof of funds unless using a dedicated proof-of-funds profile;
- report local cryptographic verification where only shape checking occurred;
- silently accept mismatched record hashes.

## 7. Future Profiles

Planned future profiles include:

- full Bitcoin BIP-322 simple verifier;
- broader BIP-322 full/proof-of-funds support;
- hardware wallet workflows;
- DID/VC identity binding;
- threshold/MPC proof workflows;
- MiCA-oriented attestation bundles;
- wallet UI integrations.
