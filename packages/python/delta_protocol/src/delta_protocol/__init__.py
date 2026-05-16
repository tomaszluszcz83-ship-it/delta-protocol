"""DELTA Protocol Python SDK Core.

This package exposes minimal cryptographic verification primitives for DELTA-0.
"""

from .core import (
    DELTAProtocolError,
    VerificationResult,
    canonical_json_bytes,
    load_json_file,
    sha256_prefixed,
    verify_attestation_pair,
    verify_checkpoint_pair,
    verify_claim_pair,
    verify_pair,
    verify_signature,
)

__all__ = [
    "DELTAProtocolError",
    "VerificationResult",
    "canonical_json_bytes",
    "load_json_file",
    "sha256_prefixed",
    "verify_signature",
    "verify_pair",
    "verify_claim_pair",
    "verify_attestation_pair",
    "verify_checkpoint_pair",
]

__version__ = "1.2.0"
