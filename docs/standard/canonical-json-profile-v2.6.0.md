# DELTA v2.6.0 — Canonical JSON Profile and Frozen Test Vectors

**Status:** Draft / hardening milestone  
**Profile ID:** `delta_jcs_json_v1`  
**Purpose:** cross-language hash and signature interoperability  

## 1. Why this exists

DELTA records, signatures and proof objects depend on byte-exact hashing. If two implementations serialize the same logical JSON object differently, they will compute different hashes and signatures.

v2.6.0 introduces a conservative canonical JSON profile and frozen test vectors so that future Python, Go, Rust, JavaScript and browser verifiers can agree on the exact same bytes before hashing.

## 2. Relationship to RFC 8785 / JCS

This profile is aligned with the goals of RFC 8785 / JSON Canonicalization Scheme (JCS): deterministic JSON serialization for cryptographic operations.

DELTA v2.6.0 intentionally defines a restricted profile:

- floating-point numbers are rejected;
- `NaN`, `Infinity` and `-Infinity` are rejected;
- duplicate object keys are rejected;
- integers outside the JavaScript safe integer range are rejected;
- JSON object keys are sorted lexicographically;
- insignificant whitespace is removed;
- UTF-8 is used without BOM;
- output bytes are hashed with SHA-256.

Future releases may add dedicated RFC 8785 library cross-checks. Until then, the frozen vectors in `tests/vectors/canonical-json/vectors.json` are the compatibility source of truth for this repository.

## 3. Normative rules for `delta_jcs_json_v1`

A DELTA implementation using this profile:

1. MUST reject malformed JSON.
2. MUST reject duplicate object keys.
3. MUST reject floating-point numbers.
4. MUST reject `NaN`, `Infinity` and `-Infinity`.
5. MUST reject integers outside `[-9007199254740991, 9007199254740991]`.
6. MUST sort object keys lexicographically before serialization.
7. MUST serialize without insignificant whitespace.
8. MUST encode canonical JSON as UTF-8 bytes without BOM.
9. MUST compute `sha256:<hex>` over those exact bytes.
10. MUST pass all frozen vectors before claiming compatibility with `delta_jcs_json_v1`.

## 4. Current reference helper

The reference helper for this milestone is:

```bash
python tools/delta_canonical_json.py verify-vectors --vectors tests/vectors/canonical-json/vectors.json
```

Expected result:

```text
DELTA_JCS_VERIFY_OK=True
DELTA_JCS_PROFILE=delta_jcs_json_v1
```

## 5. Frozen vector categories

The v2.6.0 vector set includes:

- simple object key ordering;
- Unicode and emoji;
- nested objects and arrays;
- empty object and empty array;
- DELTA-like record hash object;
- rejected float;
- rejected NaN;
- rejected Infinity;
- rejected duplicate key;
- rejected unsafe integer.

## 6. Security boundary

Canonical JSON does not prove legal truth, real-world truth, evidence authenticity before hashing, signer authority or regulatory compliance.

It only ensures that supported implementations hash the same logical JSON input into the same canonical bytes and SHA-256 digest.

## 7. Future work

Planned follow-up work:

- v2.6.1 JSON Schemas / Schema Registry;
- v2.6.2 Conformance Levels and conformance tests;
- future RFC 8785/JCS library cross-checks in multiple languages;
- future optional encoding profiles such as CBOR, Borsh, SSZ, RLP and Protobuf after the JSON/JCS profile stabilizes.

Optional binary or ZK-native profiles MUST NOT replace `delta_jcs_json_v1` until they have their own frozen test vectors and conformance tests.
