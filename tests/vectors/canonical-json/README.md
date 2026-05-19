# DELTA Canonical JSON Test Vectors

This directory contains frozen test vectors for DELTA Canonical JSON Profile v1.

Primary file:

```text
tests/vectors/canonical-json/vectors.json
```

Verify with:

```bash
python tools/delta_canonical_json.py verify-vectors --vectors tests/vectors/canonical-json/vectors.json
```

Expected output includes:

```text
DELTA_JCS_VERIFY_OK=True
DELTA_JCS_PROFILE=delta_jcs_json_v1
```

## Compatibility requirement

Any future DELTA implementation in Python, Go, Rust, JavaScript or another language MUST produce the same canonical output and SHA-256 hash for every valid vector, and MUST reject every invalid vector, before claiming compatibility with `delta_jcs_json_v1`.

## Invalid vectors

Invalid vectors are intentionally included. A compatible implementation MUST reject them.

They cover:

- floating-point values;
- non-finite values;
- duplicate object keys;
- integers outside the safe cross-language range.
