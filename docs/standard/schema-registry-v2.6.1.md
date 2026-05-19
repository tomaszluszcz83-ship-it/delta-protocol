# DELTA Schema Registry v2.6.1

**Status:** Draft  
**Release:** v2.6.1  
**Canonical JSON profile:** `delta_jcs_json_v1`  
**Scope:** repository-local JSON Schema registry for DELTA object shape validation.

## 1. Purpose

v2.6.1 adds a draft JSON Schema registry for DELTA Protocol objects.

The registry is intended to help reviewers, implementers, and future cross-language verifiers check object shape before deeper cryptographic verification.

Schema validation is only a **pre-verification** step. It does not replace:

- canonical JSON validation,
- SHA-256 hash recomputation,
- signature verification,
- full `delta-record.json` hash binding,
- replay verification,
- intent registry/policy checks,
- audit package hash/AAD/ciphertext checks,
- publication proof checks,
- trust ledger chain checks,
- wallet proof cryptographic verification where supported.

## 2. Files

The v2.6.1 schema registry includes:

```text
schemas/schema-registry.json
schemas/delta-common.schema.json
schemas/delta-record.schema.json
schemas/intent-attestation.schema.json
schemas/audit-package.schema.json
schemas/publication-proof.schema.json
schemas/trust-ledger.schema.json
schemas/wallet-proof.schema.json
```

## 3. Schema identifiers

Each schema uses JSON Schema Draft 2020-12 and includes:

- `$schema`,
- `$id`,
- `title`,
- `description`,
- `schema_version` where applicable.

The current `$id` namespace is:

```text
https://delta-protocol.org/schemas/v2.6.1/
```

This namespace is a protocol identifier, not a guarantee that the schemas are served from a public endpoint yet.

## 4. Versioning

`schema_version` is independent from `protocol_version`.

- `schema_version` identifies the validation schema generation.
- `protocol_version` identifies the DELTA protocol profile or record family.

This separation is intentional. A schema may be updated for clarity or validation coverage without changing historical protocol objects.

## 5. Additional properties policy

The v2.6.1 schemas intentionally keep `additionalProperties: true` for most top-level objects.

Reason: DELTA is still an Alpha Reference Implementation and some object profiles evolved before this schema registry. The v2.6.1 schemas are shape-validation aids, not strict production schemas.

Future schema releases MAY introduce stricter validation profiles after compatibility review and test vector expansion.

## 6. Security boundaries

A malicious object can pass JSON Schema validation and still be cryptographically invalid.

A conforming DELTA verifier MUST NOT accept an object only because it matches a JSON Schema.

For Bitcoin wallet proofs, `bitcoin_bip322_external_v1` remains `shape_only` / `external_pending`. The expected cryptographic verification statement remains:

```text
CRYPTO_SIGNATURE_VERIFIED=False
```

## 7. Relationship to v2.6.0

v2.6.0 introduced `delta_jcs_json_v1` and frozen canonical JSON vectors.

v2.6.1 builds on that by defining object-shape schemas. Schema validation MUST occur before or alongside canonical JSON/hash/signature verification, but it does not replace those checks.

## 8. Future work

Planned follow-up work:

- strict schema profiles,
- conformance levels,
- conformance test suite,
- cross-language schema validation examples,
- Rust/Go/JS verifier compatibility checks.
