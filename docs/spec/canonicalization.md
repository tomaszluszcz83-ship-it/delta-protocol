# DELTA-0 Canonicalization Rules

Version: `v0.9.0-draft`  
Protocol family: `DELTA-0`  
Status: Formal draft for review

---

## 1. Purpose

DELTA-0 requires deterministic bytes for hashing and signing.

All JSON payload objects that are hashed or signed MUST be converted into canonical JSON bytes before cryptographic operations.

The required byte representation is:

```text
UTF-8 encoded canonical JSON, without BOM
```

---

## 2. Normative Base

DELTA-0 canonicalization is based on JCS-style deterministic JSON canonicalization as defined by RFC 8785.

Implementations MUST produce a single deterministic byte representation for a given JSON object.

---

## 3. General Rule

For any DELTA JSON object `O`:

```text
canonical_bytes = canonical_json(O).encode("utf-8")
object_hash = sha256(canonical_bytes)
signature = Ed25519.sign(canonical_bytes)
```

The signature input is canonical JSON bytes, not prehashed bytes.

---

## 4. UTF-8

All DELTA JSON files MUST be encoded as UTF-8 without BOM.

Implementations MUST reject or normalize away UTF-8 BOM before hashing only if their compliance profile explicitly permits that behavior. The strict profile rejects BOM.

Recommended strict behavior:

```text
UTF-8 without BOM only.
```

---

## 5. Object Member Ordering

JSON object keys MUST be serialized in deterministic lexicographic order.

No semantic meaning is assigned to original input key order.

---

## 6. Whitespace

Canonical JSON MUST NOT contain insignificant whitespace.

No spaces, tabs, or line breaks are allowed in the canonical byte representation except inside JSON strings.

Pretty-printed JSON files MAY be stored for human readability, but verifiers MUST canonicalize before hashing or signing.

---

## 7. Strings

Strings MUST be valid JSON strings and MUST be encoded in UTF-8.

Implementations SHOULD avoid relying on visually equivalent Unicode forms. Where deployment policies require Unicode normalization, normalization MUST happen before object creation and MUST be documented as an application-level rule.

---

## 8. Numbers

DELTA-0 deliberately restricts numeric usage.

### 8.1 Integers

Integers MAY be used for fields explicitly defined as integers, such as:

```text
seq
checkpoint_seq
entry_count
```

These fields MUST be non-negative integers unless a future specification states otherwise.

### 8.2 Floating-Point Values

Floating-point values are not permitted in DELTA-0 cryptographic structures.

Implementations MUST reject:

```text
float
NaN
Infinity
-Infinity
```

Rationale:

- floating-point serialization differs across languages,
- NaN has multiple representations,
- binary floating-point can produce non-obvious decimal encodings,
- cross-language determinism is more important than numeric convenience.

Applications that need fractional values SHOULD encode them as strings or fixed-scale integers.

Example:

```json
{
  "amount_minor_units": 12345,
  "currency": "USD"
}
```

or:

```json
{
  "amount": "123.45",
  "currency": "USD"
}
```

---

## 9. Booleans and Null

Booleans MAY be used.

`null` SHOULD be avoided in core DELTA structures unless explicitly allowed by a future specification.

Required fields MUST be present and MUST NOT be represented as `null`.

---

## 10. Hash Input

The hash input for DELTA JSON objects is:

```text
canonical_json_bytes(object)
```

Example:

```text
claim_hash = sha256(canonical_json_bytes(claim.json))
```

The hash input for raw evidence is:

```text
raw_evidence_bytes
```

Example:

```text
evidence_hash = sha256(raw_file_bytes)
```

---

## 11. Signature Input

The signature input for DELTA signature envelopes is the canonical JSON bytes of the target payload.

Examples:

```text
executor_signature.signature = Ed25519.sign(canonical_json_bytes(claim.json))
verifier_signature.signature = Ed25519.sign(canonical_json_bytes(attestation.json))
checkpoint_signature.signature = Ed25519.sign(canonical_json_bytes(checkpoint.json))
```

DELTA-0 MUST NOT sign `sha256(canonical_json_bytes(object))` directly.

The hash is stored in `target_hash` as a binding reference.

---

## 12. Determinism Tests

A compliant implementation SHOULD include test vectors proving that the following operations are cross-language stable:

1. canonical Claim hash,
2. canonical Attestation hash,
3. canonical Ledger Entry hash,
4. canonical Checkpoint hash,
5. Ed25519 verification of Python-generated signatures in JavaScript,
6. Ed25519 verification of JavaScript-generated signatures in Python.

---

## 13. Rejected Inputs

A strict DELTA-0 verifier MUST reject:

- malformed JSON,
- JSON arrays as top-level DELTA objects,
- missing required fields,
- duplicate object keys if the parser exposes them,
- non-UTF-8 input,
- UTF-8 BOM under strict profile,
- floating-point numbers,
- NaN,
- Infinity,
- unsupported signature algorithms,
- unsupported hash algorithms,
- self-hashing fields such as `claim_id` when derived from the object hash.

---

## 14. Implementation Note

The reference Python CLI currently uses canonical JSON equivalent to:

```text
json.dumps(
  object,
  sort_keys=True,
  separators=(",", ":"),
  ensure_ascii=False,
  allow_nan=False
).encode("utf-8")
```

This is a practical JCS-style canonicalization profile for the current DELTA-0 structures.

Production SDKs MUST include conformance tests before claiming full JCS/RFC 8785 compatibility.
