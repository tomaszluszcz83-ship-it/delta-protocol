"""DELTA Protocol SDK Core.

This module implements the minimal DELTA-0 verification core:

- canonical JSON bytes
- SHA-256 prefixed hashes
- Ed25519 detached signature verification
- typed verification helpers for Claim, Attestation, and Signed Checkpoint pairs

The SDK deliberately verifies cryptographic consistency only. It does not prove
absolute truth about the physical world.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROTOCOL_VERSION = "DELTA-0"
HASH_PREFIX = "sha256:"
PUBLIC_KEY_PREFIX = "ed25519:"
SIGNATURE_PREFIX = "ed25519sig:"


class DELTAProtocolError(ValueError):
    """Raised when a DELTA object is malformed or unsupported."""


@dataclass(frozen=True)
class VerificationResult:
    """Result of DELTA detached signature verification."""

    ok: bool
    reason: str
    payload_hash: Optional[str] = None
    target_hash: Optional[str] = None
    role: Optional[str] = None
    target_type: Optional[str] = None
    public_key: Optional[str] = None


def _reject_float_values(value: Any, path: str = "$") -> None:
    """Reject float values recursively.

    DELTA-0 intentionally rejects floats in cryptographic structures to avoid
    cross-language determinism issues involving NaN, Infinity, and numeric
    rendering differences.
    """

    if isinstance(value, float):
        raise DELTAProtocolError(f"Floats are not allowed in DELTA canonical JSON at {path}")

    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise DELTAProtocolError(f"JSON object keys must be strings at {path}")
            _reject_float_values(child, f"{path}.{key}")
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_float_values(child, f"{path}[{index}]")
        return

    if value is None or isinstance(value, (str, int, bool)):
        return

    raise DELTAProtocolError(f"Unsupported JSON value type at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return DELTA canonical JSON bytes.

    Reference behavior:

    json.dumps(
      value,
      sort_keys=True,
      separators=(",", ":"),
      ensure_ascii=False,
      allow_nan=False,
    ).encode("utf-8")

    DELTA-0 rejects floats before serialization.
    """

    _reject_float_values(value)

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise DELTAProtocolError(f"Could not encode canonical JSON: {exc}") from exc

    return encoded.encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    """Return a DELTA-prefixed SHA-256 digest."""

    if not isinstance(data, (bytes, bytearray)):
        raise DELTAProtocolError("sha256_prefixed expects bytes")
    return HASH_PREFIX + hashlib.sha256(bytes(data)).hexdigest()


def load_json_file(path: str | Path) -> Any:
    """Load a UTF-8 JSON file and reject UTF-8 BOM.

    DELTA JSON cryptographic structures are UTF-8 without BOM.
    """

    file_path = Path(path)
    raw = file_path.read_bytes()

    if raw.startswith(b"\xef\xbb\xbf"):
        raise DELTAProtocolError(f"UTF-8 BOM is not allowed: {file_path}")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DELTAProtocolError(f"File is not valid UTF-8: {file_path}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise DELTAProtocolError(f"File is not valid JSON: {file_path}: {exc}") from exc


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DELTAProtocolError(f"{name} must be a JSON object")
    return value


def _require_string(obj: dict[str, Any], field: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise DELTAProtocolError(f"Missing or invalid string field: {field}")
    return value


def _decode_unpadded_base64url(value: str, field: str) -> bytes:
    """Decode URL-safe Base64 with optional missing padding."""

    if not isinstance(value, str) or not value:
        raise DELTAProtocolError(f"Missing or invalid base64url field: {field}")

    padded = value + ("=" * ((4 - len(value) % 4) % 4))

    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise DELTAProtocolError(f"Invalid base64url value in {field}") from exc


def _decode_prefixed_base64url(value: str, prefix: str, field: str) -> bytes:
    if not value.startswith(prefix):
        raise DELTAProtocolError(f"{field} must start with {prefix}")
    return _decode_unpadded_base64url(value[len(prefix):], field)


def _validate_sha256_prefixed(value: str, field: str) -> None:
    if not isinstance(value, str):
        raise DELTAProtocolError(f"{field} must be a string")
    if not value.startswith(HASH_PREFIX):
        raise DELTAProtocolError(f"{field} must start with {HASH_PREFIX}")
    digest = value[len(HASH_PREFIX):]
    if len(digest) != 64:
        raise DELTAProtocolError(f"{field} must contain 64 lowercase hexadecimal characters")
    if digest.lower() != digest:
        raise DELTAProtocolError(f"{field} must use lowercase hexadecimal")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise DELTAProtocolError(f"{field} must contain only hexadecimal characters") from exc


def verify_signature(
    payload: Any,
    signature_envelope: Any,
    *,
    expected_payload_type: Optional[str] = None,
    expected_signature_role: Optional[str] = None,
    expected_target_type: Optional[str] = None,
) -> VerificationResult:
    """Verify a DELTA detached signature envelope.

    The Ed25519 signature is checked over canonical_json_bytes(payload).
    The envelope target_hash must match sha256(canonical_json_bytes(payload)).
    """

    try:
        payload_obj = _require_dict(payload, "payload")
        sig_obj = _require_dict(signature_envelope, "signature_envelope")

        if expected_payload_type is not None:
            payload_type = _require_string(payload_obj, "type")
            if payload_type != expected_payload_type:
                raise DELTAProtocolError(
                    f"payload.type mismatch: expected {expected_payload_type}, got {payload_type}"
                )

        sig_type = _require_string(sig_obj, "type")
        if sig_type != "delta_signature":
            raise DELTAProtocolError(f"signature.type mismatch: expected delta_signature, got {sig_type}")

        protocol_version = _require_string(sig_obj, "protocol_version")
        if protocol_version != PROTOCOL_VERSION:
            raise DELTAProtocolError(
                f"signature.protocol_version mismatch: expected {PROTOCOL_VERSION}, got {protocol_version}"
            )

        role = _require_string(sig_obj, "role")
        if expected_signature_role is not None and role != expected_signature_role:
            raise DELTAProtocolError(
                f"signature.role mismatch: expected {expected_signature_role}, got {role}"
            )

        alg = _require_string(sig_obj, "alg")
        if alg != "Ed25519":
            raise DELTAProtocolError(f"signature.alg mismatch: expected Ed25519, got {alg}")

        target_type = _require_string(sig_obj, "target_type")
        if expected_target_type is not None and target_type != expected_target_type:
            raise DELTAProtocolError(
                f"signature.target_type mismatch: expected {expected_target_type}, got {target_type}"
            )

        target_hash = _require_string(sig_obj, "target_hash")
        _validate_sha256_prefixed(target_hash, "target_hash")

        public_key_text = _require_string(sig_obj, "public_key")
        signature_text = _require_string(sig_obj, "signature")

        payload_bytes = canonical_json_bytes(payload_obj)
        payload_hash = sha256_prefixed(payload_bytes)

        if payload_hash != target_hash:
            raise DELTAProtocolError(
                f"target_hash mismatch: expected {payload_hash}, got {target_hash}"
            )

        public_key_bytes = _decode_prefixed_base64url(
            public_key_text,
            PUBLIC_KEY_PREFIX,
            "public_key",
        )
        signature_bytes = _decode_prefixed_base64url(
            signature_text,
            SIGNATURE_PREFIX,
            "signature",
        )

        if len(public_key_bytes) != 32:
            raise DELTAProtocolError("Ed25519 public key must be 32 bytes")
        if len(signature_bytes) != 64:
            raise DELTAProtocolError("Ed25519 signature must be 64 bytes")

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        try:
            public_key.verify(signature_bytes, payload_bytes)
        except InvalidSignature as exc:
            raise DELTAProtocolError("Ed25519 signature verification failed") from exc

        return VerificationResult(
            ok=True,
            reason="OK",
            payload_hash=payload_hash,
            target_hash=target_hash,
            role=role,
            target_type=target_type,
            public_key=public_key_text,
        )

    except DELTAProtocolError as exc:
        return VerificationResult(
            ok=False,
            reason=str(exc),
        )


def verify_pair(
    payload_path: str | Path,
    signature_path: str | Path,
    *,
    expected_payload_type: Optional[str] = None,
    expected_signature_role: Optional[str] = None,
    expected_target_type: Optional[str] = None,
) -> VerificationResult:
    """Load and verify a payload JSON file plus detached signature JSON file."""

    try:
        payload = load_json_file(payload_path)
        signature = load_json_file(signature_path)
    except DELTAProtocolError as exc:
        return VerificationResult(ok=False, reason=str(exc))
    except OSError as exc:
        return VerificationResult(ok=False, reason=f"Could not read file: {exc}")

    return verify_signature(
        payload,
        signature,
        expected_payload_type=expected_payload_type,
        expected_signature_role=expected_signature_role,
        expected_target_type=expected_target_type,
    )


def verify_claim_pair(
    claim_path: str | Path,
    executor_signature_path: str | Path,
) -> VerificationResult:
    """Verify claim.json + executor_signature.json."""

    return verify_pair(
        claim_path,
        executor_signature_path,
        expected_payload_type="delta_claim",
        expected_signature_role="executor",
        expected_target_type="delta_claim",
    )


def verify_attestation_pair(
    attestation_path: str | Path,
    verifier_signature_path: str | Path,
) -> VerificationResult:
    """Verify attestation.json + verifier_signature.json."""

    return verify_pair(
        attestation_path,
        verifier_signature_path,
        expected_payload_type="delta_attestation",
        expected_signature_role="verifier",
        expected_target_type="delta_attestation",
    )


def verify_checkpoint_pair(
    checkpoint_path: str | Path,
    checkpoint_signature_path: str | Path,
) -> VerificationResult:
    """Verify checkpoint.json + checkpoint_signature.json."""

    return verify_pair(
        checkpoint_path,
        checkpoint_signature_path,
        expected_payload_type="delta_signed_checkpoint",
        expected_signature_role="checkpoint_signer",
        expected_target_type="delta_signed_checkpoint",
    )
