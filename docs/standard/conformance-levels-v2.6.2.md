# DELTA Conformance Levels v2.6.2

**Status:** Draft  
**Version:** v2.6.2  
**Profile:** DELTA Conformance Levels Draft  
**Implementation status:** Alpha Reference Implementation

## 1. Purpose

This document defines draft DELTA Conformance Levels for implementers, auditors, and reviewers.

The goal is to make DELTA adoption incremental. A verifier MAY support a lower conformance level without implementing every proof layer immediately.

This document is intentionally cautious: DELTA is not yet a formal external standards-track specification. These levels are a repository-local conformance draft intended to prepare for future independent implementations and public conformance suites.

## 2. Normative language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

## 3. Conformance principles

A DELTA implementation claiming a conformance level MUST:

1. Declare the supported DELTA conformance level.
2. Declare the supported canonicalization profile.
3. Declare the supported object schemas.
4. Declare the supported proof layers.
5. Pass the relevant frozen vectors and conformance checks for that level.
6. Clearly report unsupported optional profiles rather than silently accepting them.

A DELTA implementation MUST NOT claim legal truth, real-world truth, identity, wallet balance, regulatory compliance, or signer authority by conformance alone.

## 4. Canonicalization baseline

All conformance levels require awareness of the DELTA Canonical JSON Profile v1:

```text
delta_jcs_json_v1
```

A conformant implementation MUST treat canonicalization as part of the trust boundary for hash and signature verification.

Existing historical DELTA records MAY use earlier reference implementation behavior, but new cross-language conformance claims SHOULD use `delta_jcs_json_v1` vectors.

## 5. DELTA-L0: Canonical JSON and hash vectors

### Required capabilities

A DELTA-L0 implementation MUST:

- Parse JSON inputs safely.
- Reject malformed JSON.
- Reject duplicate object keys.
- Reject floating-point numbers under the strict DELTA JCS-compatible subset.
- Reject NaN and Infinity.
- Reject unsafe integers outside the safe cross-language range.
- Produce canonical UTF-8 bytes according to `delta_jcs_json_v1`.
- Produce SHA-256 hashes matching frozen canonical JSON vectors.

### Required test assets

- `tools/delta_canonical_json.py`
- `tests/vectors/canonical-json/vectors.json`
- `docs/standard/canonical-json-profile-v2.6.0.md`

### Acceptance signal

```text
DELTA_JCS_VERIFY_OK=True
```

## 6. DELTA-L1: Schema and signed record verification

### Required capabilities

A DELTA-L1 implementation MUST satisfy DELTA-L0 and additionally:

- Validate relevant DELTA object shape against the repository-local schema registry before proof-specific verification.
- Recompute hashes from canonical payload bytes.
- Verify signed record integrity for supported record types.
- Reject schema-valid but cryptographically invalid records.

### Required test assets

- `schemas/schema-registry.json`
- `schemas/delta-record.schema.json`
- `schemas/delta-common.schema.json`
- Existing signed public proof records in the reference repository.

### Security boundary

Schema validation is a pre-verification step only. It does not replace canonical JSON validation, hash recomputation, signature verification, replay, intent, audit, publication, trust, or wallet checks.

## 7. DELTA-L2: Replay-capable verification

### Required capabilities

A DELTA-L2 implementation MUST satisfy DELTA-L1 and additionally:

- Support replay verification for implemented sensor records.
- Reproduce declared measurement methods where the implementation claims replay support.
- Compare replay output, return code, manifests, and declared result hashes according to the supported method profile.
- Report replay failure explicitly.

### Security boundary

Replay success proves reproducibility of the declared measurement under the declared replay assumptions. It does not prove legal truth, real-world truth, ticket truth, signer authority, or evidence origin truth.

## 8. DELTA-L3: Intent, Audit, Publication, and Trust support

### Required capabilities

A DELTA-L3 implementation MUST satisfy DELTA-L2 and support at least one of the following advanced proof families:

- Proof of Intent
- Proof of Audit
- Proof of Publication
- Proof of Trust

If an implementation claims support for any one of these proof families, it MUST implement its proof-specific binding, integrity, and failure reporting rules.

### Proof-family requirements

#### Proof of Intent

A verifier MUST check:

- Intent attestation shape.
- Intent signature where required.
- Intent registry membership where required.
- Binding to the full `delta-record.json` hash.
- Policy/reporting fields if present.

#### Proof of Audit

A verifier MUST check:

- Audit package shape.
- Record binding.
- AAD hash binding.
- Ciphertext hash binding.
- Recipient public key hash binding.

A verifier MAY decrypt evidence only when it has the appropriate auditor private key.

#### Proof of Publication

A verifier MUST check:

- Publication proof shape.
- Proof body hash.
- Record hash binding.
- External evidence hash binding where provided.

#### Proof of Trust

A verifier MUST check:

- Ledger body hash.
- Entry hashes.
- Previous-entry hash links.
- Sequence consistency.
- Record binding.
- Supported role and event type constraints.

## 9. DELTA-L4: Wallet proof support

### Required capabilities

A DELTA-L4 implementation MUST satisfy DELTA-L1 and support at least one wallet proof profile.

Recognized profiles as of v2.6.2:

```text
ed25519_address_control_v1
ethereum_eip191_personal_sign_v1
ethereum_eip712_typed_data_v1
bitcoin_bip322_external_v1
```

A verifier MUST clearly distinguish signature shape validation from cryptographic signature verification.

For `bitcoin_bip322_external_v1`, a verifier MUST report:

```text
CRYPTO_SIGNATURE_VERIFIED=False
verification_level=shape_only
verification_status=external_pending
```

unless a future local Bitcoin BIP-322 verifier profile explicitly supersedes this behavior.

## 10. DELTA-L5: Full reference conformance suite

### Required capabilities

A DELTA-L5 implementation MUST satisfy all prior levels and pass the repository conformance suite for all mandatory v2.6.x profiles.

DELTA-L5 is aspirational in v2.6.2. The current Python implementation is an Alpha Reference Implementation, not a production-certified verifier.

A future DELTA-L5 conformance suite SHOULD include:

- Canonical JSON vectors.
- Schema validation fixtures.
- Signed record fixtures.
- Replay fixtures.
- Intent positive and negative fixtures.
- Audit package positive and negative fixtures.
- Publication proof positive and negative fixtures.
- Trust ledger positive and negative fixtures.
- Wallet proof positive and negative fixtures.

## 11. Unsupported profiles

An implementation encountering an unsupported profile MUST fail closed unless explicitly configured for report-only behavior.

Unsupported profiles include, but are not limited to:

- Future CBOR profile.
- Future SSZ profile.
- Future Borsh profile.
- Future RLP profile.
- Future Protobuf profile.
- Future ZK-native circuit input profile.

These profiles are not part of v2.6.2 conformance.

## 12. Reporting requirements

A verifier SHOULD emit clear machine-readable status lines, including:

```text
DELTA_CONFORMANCE_LEVEL=...
DELTA_CANONICALIZATION_PROFILE=...
DELTA_SCHEMA_VALIDATION_OK=...
DELTA_HASH_BINDING_OK=...
DELTA_SIGNATURE_OK=...
DELTA_REPLAY_OK=...
DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=...
```

The exact output format will be refined in future conformance suite releases.

## 13. Security boundaries

DELTA conformance does not prove:

- Legal truth.
- Real-world truth.
- Identity by itself.
- Wallet balance by itself.
- Regulatory compliance by itself.
- Signer authority by itself.
- Evidence non-fabrication before hashing.
- Full Bitcoin BIP-322 script-level verification for `bitcoin_bip322_external_v1`.

## 14. Future work

Future work includes:

- Public conformance runner.
- Cross-language verifier fixtures.
- Rust/Go/JS independent implementations.
- Browser verifier conformance subset.
- Optional binary encoding profiles after JCS/JSON conformance stabilizes.
- ZK Provenance research track.
