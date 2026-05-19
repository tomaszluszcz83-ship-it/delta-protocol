#!/usr/bin/env python3
"""
DELTA Canonical JSON Profile v1 helper (v2.6.0).

Purpose:
- provide a small reference verifier for DELTA canonical JSON test vectors;
- reject JSON constructs that are unsafe for cross-language hash stability;
- compute SHA-256 over canonical UTF-8 bytes.

This profile is intentionally conservative:
- object keys are sorted lexicographically;
- insignificant whitespace is removed;
- UTF-8 output is used without ASCII escaping;
- floating-point numbers, NaN and Infinity are rejected;
- duplicate object keys are rejected;
- integers outside the JavaScript safe integer range are rejected.

It is designed as a DELTA subset/profile aligned with RFC 8785/JCS goals.
Future releases may replace or cross-check this helper with dedicated RFC 8785/JCS libraries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

PROFILE_ID = "delta_jcs_json_v1"
MAX_SAFE_INTEGER = 9007199254740991
MIN_SAFE_INTEGER = -9007199254740991


class DeltaCanonicalJsonError(ValueError):
    """Raised when input is outside the DELTA Canonical JSON Profile."""


def _reject_float(value: str) -> None:
    raise DeltaCanonicalJsonError(f"floating point numbers are not allowed in {PROFILE_ID}: {value}")


def _reject_constant(value: str) -> None:
    raise DeltaCanonicalJsonError(f"non-finite numeric value is not allowed in {PROFILE_ID}: {value}")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if parsed < MIN_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
        raise DeltaCanonicalJsonError(
            f"integer outside safe cross-language range for {PROFILE_ID}: {value}"
        )
    return parsed


def _object_pairs_no_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DeltaCanonicalJsonError(f"duplicate JSON object key is not allowed: {key!r}")
        obj[key] = value
    return obj


def load_json_text(text: str) -> Any:
    """Load JSON text using DELTA-safe parsing rules."""
    try:
        return json.loads(
            text,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_pairs_no_duplicates,
        )
    except DeltaCanonicalJsonError:
        raise
    except json.JSONDecodeError as exc:
        raise DeltaCanonicalJsonError(f"invalid JSON: {exc}") from exc


def validate_value(value: Any) -> None:
    """Validate an already-loaded Python value against DELTA profile constraints."""
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise DeltaCanonicalJsonError(
                f"integer outside safe cross-language range for {PROFILE_ID}: {value}"
            )
        return
    if isinstance(value, float):
        raise DeltaCanonicalJsonError(f"floating point numbers are not allowed in {PROFILE_ID}: {value}")
    if isinstance(value, list):
        for item in value:
            validate_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DeltaCanonicalJsonError("JSON object keys must be strings")
            validate_value(item)
        return
    raise DeltaCanonicalJsonError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return canonical UTF-8 bytes for a DELTA JSON value."""
    validate_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonicalize_text(text: str) -> str:
    return canonical_json_bytes(load_json_text(text)).decode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def command_canonicalize(args: argparse.Namespace) -> int:
    path = Path(args.input)
    text = path.read_text(encoding="utf-8")
    canonical = canonicalize_text(text)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(canonical + "\n", encoding="utf-8")
    else:
        print(canonical)
    print(f"DELTA_JCS_PROFILE={PROFILE_ID}")
    print(f"DELTA_JCS_CANONICAL_SHA256={sha256_prefixed(canonical.encode('utf-8'))}")
    return 0


def command_hash_file(args: argparse.Namespace) -> int:
    path = Path(args.input)
    text = path.read_text(encoding="utf-8")
    canonical = canonicalize_text(text)
    print(f"DELTA_JCS_PROFILE={PROFILE_ID}")
    print(f"DELTA_JCS_CANONICAL_SHA256={sha256_prefixed(canonical.encode('utf-8'))}")
    return 0


def command_verify_vectors(args: argparse.Namespace) -> int:
    vectors_path = Path(args.vectors)
    data = load_json_text(vectors_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("profile") != PROFILE_ID:
        raise SystemExit(f"vector file must declare profile={PROFILE_ID}")

    valid_vectors = data.get("valid", [])
    invalid_vectors = data.get("invalid", [])
    if not isinstance(valid_vectors, list) or not isinstance(invalid_vectors, list):
        raise SystemExit("vector file must contain valid and invalid lists")

    ok_all = True

    for vector in valid_vectors:
        vector_id = str(vector.get("id", "unknown"))
        raw = str(vector.get("raw"))
        expected_canonical = str(vector.get("canonical"))
        expected_hash = str(vector.get("sha256"))
        try:
            canonical = canonicalize_text(raw)
            actual_hash = sha256_prefixed(canonical.encode("utf-8"))
            vector_ok = canonical == expected_canonical and actual_hash == expected_hash
        except Exception:
            vector_ok = False
            actual_hash = "ERROR"
        ok_all = ok_all and vector_ok
        print(f"DELTA_JCS_VECTOR_{vector_id}_OK={vector_ok}")
        if not vector_ok:
            print(f"DELTA_JCS_VECTOR_{vector_id}_EXPECTED_HASH={expected_hash}")
            print(f"DELTA_JCS_VECTOR_{vector_id}_ACTUAL_HASH={actual_hash}")

    for vector in invalid_vectors:
        vector_id = str(vector.get("id", "unknown"))
        raw = str(vector.get("raw"))
        rejected = False
        reason = ""
        try:
            canonicalize_text(raw)
        except Exception as exc:
            rejected = True
            reason = type(exc).__name__
        vector_ok = rejected
        ok_all = ok_all and vector_ok
        print(f"DELTA_JCS_INVALID_VECTOR_{vector_id}_REJECTED={rejected}")
        if reason:
            print(f"DELTA_JCS_INVALID_VECTOR_{vector_id}_REASON={reason}")

    print(f"DELTA_JCS_PROFILE={PROFILE_ID}")
    print(f"DELTA_JCS_VERIFY_OK={ok_all}")
    return 0 if ok_all else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Canonical JSON Profile v1 helper")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("canonicalize", help="Print or write canonical JSON for an input file")
    c.add_argument("--input", required=True)
    c.add_argument("--output")
    c.set_defaults(func=command_canonicalize)

    h = sub.add_parser("hash-file", help="Compute canonical SHA-256 for an input JSON file")
    h.add_argument("--input", required=True)
    h.set_defaults(func=command_hash_file)

    v = sub.add_parser("verify-vectors", help="Verify frozen DELTA canonical JSON vectors")
    v.add_argument("--vectors", required=True)
    v.set_defaults(func=command_verify_vectors)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DeltaCanonicalJsonError as exc:
        print(f"DELTA_JCS_ERROR={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
