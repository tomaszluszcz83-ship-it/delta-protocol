# DELTA-0 Genesis Generator
# Version: DELTA-0 v0.5.2
#
# This script generates the first local DELTA Genesis Record bundle:
#
# - claim.json
# - executor_signature.json
# - attestation.json
# - verifier_signature.json
# - ledger_entry.json
# - checkpoint.json
# - checkpoint_signature.json
# - genesis_bundle.json
#
# IMPORTANT:
# The folder genesis/private_keys contains private Ed25519 keys.
# Do NOT publish private_keys.
# Public DELTA artifacts are the JSON files outside private_keys.

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("")
    print("ERROR: Missing Python package: cryptography")
    print("")
    print("Install it with:")
    print("python -m pip install cryptography")
    print("")
    sys.exit(1)


PROTOCOL_VERSION = "DELTA-0"
SPEC_VERSION = "DELTA-0 v0.5.2"
LEDGER_ID = "delta-ledger:genesis-local"

GENESIS_PREV_ENTRY_HASH = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC_FILE = PROJECT_ROOT / "spec" / "DELTA-0-v0.5.2-core-structures.md"
SRC_FILE = PROJECT_ROOT / "src" / "genesis_generator.py"
GENESIS_DIR = PROJECT_ROOT / "genesis"
PRIVATE_KEYS_DIR = GENESIS_DIR / "private_keys"


def utc_now() -> str:
    """Return current UTC time in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def b64url_encode(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    """Decode base64url string without required padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jcs_bytes(obj: Any) -> bytes:
    """
    Minimal JCS-compatible canonical JSON for the DELTA-0 restricted data model.

    DELTA-0 Genesis objects use:
    - objects
    - arrays
    - strings
    - integers
    - booleans
    - no floats
    - no NaN / Infinity

    For these objects, Python's json.dumps with:
    - sort_keys=True
    - separators=(",", ":")
    - ensure_ascii=False
    - allow_nan=False

    gives deterministic canonical bytes suitable for DELTA-0 Genesis.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_object(obj: Any) -> str:
    return sha256_bytes(jcs_bytes(obj))


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def raw_private_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def raw_public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_to_delta(public_key: Ed25519PublicKey) -> str:
    return "ed25519:" + b64url_encode(raw_public_key_bytes(public_key))


def private_key_to_delta(private_key: Ed25519PrivateKey) -> str:
    return "ed25519priv:" + b64url_encode(raw_private_key_bytes(private_key))


def public_key_from_delta(value: str) -> Ed25519PublicKey:
    if not value.startswith("ed25519:"):
        raise ValueError("Invalid public key prefix. Expected ed25519:")
    raw = b64url_decode(value[len("ed25519:") :])
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_from_delta(value: str) -> Ed25519PrivateKey:
    if not value.startswith("ed25519priv:"):
        raise ValueError("Invalid private key prefix. Expected ed25519priv:")
    raw = b64url_decode(value[len("ed25519priv:") :])
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_object(private_key: Ed25519PrivateKey, obj: Any) -> str:
    signature = private_key.sign(jcs_bytes(obj))
    return "ed25519sig:" + b64url_encode(signature)


def signature_from_delta(value: str) -> bytes:
    if not value.startswith("ed25519sig:"):
        raise ValueError("Invalid signature prefix. Expected ed25519sig:")
    return b64url_decode(value[len("ed25519sig:") :])


def verify_signature(public_key_value: str, obj: Any, signature_value: str) -> bool:
    public_key = public_key_from_delta(public_key_value)
    signature = signature_from_delta(signature_value)
    public_key.verify(signature, jcs_bytes(obj))
    return True


def load_or_create_private_key(role: str, created_at: str) -> Ed25519PrivateKey:
    """
    Load existing private key if present.
    Otherwise generate a new Ed25519 private key and save it.

    This makes repeated runs reuse the same local keys.
    """
    PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_file = PRIVATE_KEYS_DIR / f"{role}_private_key.json"

    if key_file.exists():
        data = json.loads(key_file.read_text(encoding="utf-8"))
        return private_key_from_delta(data["private_key"])

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    key_data = {
        "type": "delta_private_key",
        "protocol_version": PROTOCOL_VERSION,
        "role": role,
        "alg": "Ed25519",
        "warning": "PRIVATE KEY. DO NOT PUBLISH. DO NOT COMMIT TO PUBLIC REPOSITORIES.",
        "public_key": public_key_to_delta(public_key),
        "private_key": private_key_to_delta(private_key),
        "created_at": created_at,
    }

    write_json(key_file, key_data)
    return private_key


def make_signature_envelope(
    *,
    role: str,
    target_type: str,
    target_hash: str,
    public_key: str,
    signature: str,
    signed_at: str,
) -> Dict[str, Any]:
    return {
        "type": "delta_signature",
        "protocol_version": PROTOCOL_VERSION,
        "role": role,
        "alg": "Ed25519",
        "target_type": target_type,
        "target_hash": target_hash,
        "public_key": public_key,
        "signature": signature,
        "signed_at": signed_at,
    }


def assert_hash_format(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("Hash must be a string.")
    if not value.startswith("sha256:"):
        raise ValueError(f"Hash missing sha256: prefix: {value}")
    digest = value[len("sha256:") :]
    if len(digest) != 64:
        raise ValueError(f"Hash must contain 64 lowercase hex chars: {value}")
    if digest.lower() != digest:
        raise ValueError(f"Hash must be lowercase: {value}")
    int(digest, 16)


def self_check(
    *,
    before_statement: Dict[str, Any],
    after_statement: Dict[str, Any],
    verification_policy: Dict[str, Any],
    evidence_manifest: Dict[str, Any],
    claim: Dict[str, Any],
    claim_hash: str,
    executor_signature: Dict[str, Any],
    executor_sig_hash: str,
    attestation: Dict[str, Any],
    attestation_hash: str,
    verifier_signature: Dict[str, Any],
    verifier_sig_hash: str,
    ledger_entry: Dict[str, Any],
    entry_hash: str,
    checkpoint: Dict[str, Any],
    checkpoint_hash: str,
    checkpoint_signature: Dict[str, Any],
    checkpoint_sig_hash: str,
) -> List[str]:
    checks: List[str] = []

    # Hash format checks
    for name, value in [
        ("claim_hash", claim_hash),
        ("executor_sig_hash", executor_sig_hash),
        ("attestation_hash", attestation_hash),
        ("verifier_sig_hash", verifier_sig_hash),
        ("entry_hash", entry_hash),
        ("checkpoint_hash", checkpoint_hash),
        ("checkpoint_sig_hash", checkpoint_sig_hash),
        ("before_hash", claim["before_hash"]),
        ("after_hash", claim["after_hash"]),
        ("evidence_hash", claim["evidence_hash"]),
        ("verification_policy_hash", attestation["verification_policy_hash"]),
    ]:
        assert_hash_format(value)
        checks.append(f"OK hash format: {name}")

    # Recompute hashes
    assert sha256_object(claim) == claim_hash
    checks.append("OK claim_hash recomputed")

    assert sha256_object(executor_signature) == executor_sig_hash
    checks.append("OK executor_sig_hash recomputed")

    assert sha256_object(attestation) == attestation_hash
    checks.append("OK attestation_hash recomputed")

    assert sha256_object(verifier_signature) == verifier_sig_hash
    checks.append("OK verifier_sig_hash recomputed")

    assert sha256_object(ledger_entry) == entry_hash
    checks.append("OK entry_hash recomputed")

    assert sha256_object(checkpoint) == checkpoint_hash
    checks.append("OK checkpoint_hash recomputed")

    assert sha256_object(checkpoint_signature) == checkpoint_sig_hash
    checks.append("OK checkpoint_sig_hash recomputed")

    # Object relationship checks
    assert claim["before_hash"] == sha256_object(before_statement)
    checks.append("OK claim.before_hash matches before_statement")

    assert claim["after_hash"] == sha256_object(after_statement)
    checks.append("OK claim.after_hash matches after_statement")

    assert claim["evidence_hash"] == sha256_object(evidence_manifest)
    checks.append("OK claim.evidence_hash matches evidence_manifest")

    assert attestation["evidence_hash"] == claim["evidence_hash"]
    checks.append("OK attestation.evidence_hash matches claim.evidence_hash")

    assert attestation["verification_policy_hash"] == sha256_object(verification_policy)
    checks.append("OK attestation.verification_policy_hash matches verification_policy")

    assert executor_signature["target_hash"] == claim_hash
    checks.append("OK executor signature target_hash matches claim_hash")

    assert attestation["target_claim_hash"] == claim_hash
    checks.append("OK attestation.target_claim_hash matches claim_hash")

    assert attestation["target_executor_sig_hash"] == executor_sig_hash
    checks.append("OK attestation.target_executor_sig_hash matches executor_sig_hash")

    assert verifier_signature["target_hash"] == attestation_hash
    checks.append("OK verifier signature target_hash matches attestation_hash")

    assert ledger_entry["prev_entry_hash"] == GENESIS_PREV_ENTRY_HASH
    checks.append("OK genesis prev_entry_hash fixed zero hash")

    assert ledger_entry["claim_hash"] == claim_hash
    checks.append("OK ledger_entry.claim_hash matches claim_hash")

    assert ledger_entry["executor_sig_hash"] == executor_sig_hash
    checks.append("OK ledger_entry.executor_sig_hash matches executor_sig_hash")

    assert ledger_entry["attestation_hash"] == attestation_hash
    checks.append("OK ledger_entry.attestation_hash matches attestation_hash")

    assert ledger_entry["verifier_sig_hash"] == verifier_sig_hash
    checks.append("OK ledger_entry.verifier_sig_hash matches verifier_sig_hash")

    assert checkpoint["head_entry_hash"] == entry_hash
    checks.append("OK checkpoint.head_entry_hash matches entry_hash")

    assert checkpoint["entry_count"] == 1
    checks.append("OK checkpoint.entry_count = 1")

    # Signature verification
    verify_signature(
        executor_signature["public_key"],
        claim,
        executor_signature["signature"],
    )
    checks.append("OK executor signature verifies against claim")

    verify_signature(
        verifier_signature["public_key"],
        attestation,
        verifier_signature["signature"],
    )
    checks.append("OK verifier signature verifies against attestation")

    verify_signature(
        checkpoint_signature["public_key"],
        checkpoint,
        checkpoint_signature["signature"],
    )
    checks.append("OK checkpoint signature verifies against checkpoint")

    # DELTA_VERIFIED status check for Genesis
    assert attestation["result"] == "VERIFIED"
    assert checkpoint["head_entry_hash"] == sha256_object(ledger_entry)
    checks.append("OK DELTA_VERIFIED conditions satisfied for Genesis")

    return checks


def main() -> None:
    if not SPEC_FILE.exists():
        print("")
        print("ERROR: Specification file not found:")
        print(str(SPEC_FILE))
        print("")
        print("Create this file first:")
        print("DELTA-0/spec/DELTA-0-v0.5.2-core-structures.md")
        print("")
        sys.exit(1)

    GENESIS_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)

    now = utc_now()

    executor_private_key = load_or_create_private_key("executor", now)
    verifier_private_key = load_or_create_private_key("verifier", now)

    executor_public_key = public_key_to_delta(executor_private_key.public_key())
    verifier_public_key = public_key_to_delta(verifier_private_key.public_key())

    before_statement = {
        "type": "delta_genesis_before_statement",
        "protocol_version": PROTOCOL_VERSION,
        "statement": (
            "The internet could prove ownership, identity, transactions, "
            "and file hashes, but had no universal proof layer for change."
        ),
        "created_at": now,
    }

    after_statement = {
        "type": "delta_genesis_after_statement",
        "protocol_version": PROTOCOL_VERSION,
        "statement": "The first DELTA Proof of Change record exists.",
        "created_at": now,
    }

    verification_policy = {
        "type": "delta_verification_policy",
        "protocol_version": PROTOCOL_VERSION,
        "policy_id": "delta-genesis-local-verification-policy-v1",
        "description": (
            "Genesis local verification policy. The verifier confirms that the "
            "Genesis Claim, evidence manifest, signatures, ledger entry, and "
            "checkpoint are internally consistent according to DELTA-0 v0.5.2."
        ),
        "rules": [
            "The Delta Claim must be canonicalizable.",
            "The Delta Claim must contain SHA-256 hashes with sha256: prefix.",
            "The Executor signature must verify against the canonical Delta Claim.",
            "The Attestation must reference the Claim hash.",
            "The Attestation must reference the Executor signature envelope hash.",
            "The Attestation result must be VERIFIED.",
            "The Verifier signature must verify against the canonical Attestation.",
            "The Ledger Entry must include claim_hash, executor_sig_hash, attestation_hash, and verifier_sig_hash.",
            "The Genesis Ledger Entry must use the fixed GENESIS_PREV_ENTRY_HASH.",
            "The Signed Checkpoint must reference the Ledger Entry hash as head_entry_hash.",
            "The Checkpoint signature must verify against the canonical Signed Checkpoint.",
        ],
        "created_at": now,
    }

    before_hash = sha256_object(before_statement)
    after_hash = sha256_object(after_statement)
    verification_policy_hash = sha256_object(verification_policy)
    spec_file_hash = sha256_file(SPEC_FILE)
    generator_file_hash = sha256_file(SRC_FILE)

    evidence_manifest = {
        "type": "delta_evidence_manifest",
        "protocol_version": PROTOCOL_VERSION,
        "evidence_id": "delta-genesis-evidence-v1",
        "items": [
            {
                "name": "DELTA-0 v0.5.2 Core Structures specification",
                "path": "spec/DELTA-0-v0.5.2-core-structures.md",
                "hash": spec_file_hash,
            },
            {
                "name": "DELTA-0 Genesis Generator source code",
                "path": "src/genesis_generator.py",
                "hash": generator_file_hash,
            },
            {
                "name": "Genesis before statement",
                "path": "genesis/before_statement.json",
                "hash": before_hash,
            },
            {
                "name": "Genesis after statement",
                "path": "genesis/after_statement.json",
                "hash": after_hash,
            },
            {
                "name": "Genesis local verification policy",
                "path": "genesis/verification_policy.json",
                "hash": verification_policy_hash,
            },
        ],
        "created_at": now,
    }

    evidence_hash = sha256_object(evidence_manifest)

    claim = {
        "type": "delta_claim",
        "protocol_version": PROTOCOL_VERSION,
        "claim_type": "genesis_release",
        "executor_pubkey": executor_public_key,
        "before_hash": before_hash,
        "action": "DELTA-0 protocol genesis release created",
        "after_hash": after_hash,
        "evidence_hash": evidence_hash,
        "created_at": now,
    }

    claim_hash = sha256_object(claim)
    executor_sig = sign_object(executor_private_key, claim)

    executor_signature = make_signature_envelope(
        role="executor",
        target_type="delta_claim",
        target_hash=claim_hash,
        public_key=executor_public_key,
        signature=executor_sig,
        signed_at=now,
    )

    executor_sig_hash = sha256_object(executor_signature)

    attestation = {
        "type": "delta_attestation",
        "protocol_version": PROTOCOL_VERSION,
        "verifier_pubkey": verifier_public_key,
        "target_claim_hash": claim_hash,
        "target_executor_sig_hash": executor_sig_hash,
        "verification_policy_hash": verification_policy_hash,
        "evidence_hash": evidence_hash,
        "publication_mode": "ledger_required",
        "intended_ledger_id": LEDGER_ID,
        "result": "VERIFIED",
        "verified_at": now,
    }

    attestation_hash = sha256_object(attestation)
    verifier_sig = sign_object(verifier_private_key, attestation)

    verifier_signature = make_signature_envelope(
        role="verifier",
        target_type="delta_attestation",
        target_hash=attestation_hash,
        public_key=verifier_public_key,
        signature=verifier_sig,
        signed_at=now,
    )

    verifier_sig_hash = sha256_object(verifier_signature)

    ledger_entry = {
        "type": "delta_ledger_entry",
        "protocol_version": PROTOCOL_VERSION,
        "ledger_id": LEDGER_ID,
        "seq": 1,
        "prev_entry_hash": GENESIS_PREV_ENTRY_HASH,
        "claim_hash": claim_hash,
        "executor_sig_hash": executor_sig_hash,
        "attestation_hash": attestation_hash,
        "verifier_sig_hash": verifier_sig_hash,
        "included_at": now,
    }

    entry_hash = sha256_object(ledger_entry)

    checkpoint = {
        "type": "delta_signed_checkpoint",
        "protocol_version": PROTOCOL_VERSION,
        "ledger_id": LEDGER_ID,
        "checkpoint_seq": 1,
        "entry_count": 1,
        "head_entry_hash": entry_hash,
        "published_at": now,
        "verifier_pubkey": verifier_public_key,
    }

    checkpoint_hash = sha256_object(checkpoint)
    checkpoint_sig = sign_object(verifier_private_key, checkpoint)

    checkpoint_signature = make_signature_envelope(
        role="checkpoint_signer",
        target_type="delta_signed_checkpoint",
        target_hash=checkpoint_hash,
        public_key=verifier_public_key,
        signature=checkpoint_sig,
        signed_at=now,
    )

    checkpoint_sig_hash = sha256_object(checkpoint_signature)

    public_keys = {
        "type": "delta_public_keys",
        "protocol_version": PROTOCOL_VERSION,
        "executor_pubkey": executor_public_key,
        "verifier_pubkey": verifier_public_key,
        "created_at": now,
    }

    ledger = {
        "type": "delta_ledger",
        "protocol_version": PROTOCOL_VERSION,
        "ledger_id": LEDGER_ID,
        "entries": [
            {
                "entry_hash": entry_hash,
                "entry": ledger_entry,
            }
        ],
        "created_at": now,
    }

    chain_proof = {
        "type": "delta_chain_proof",
        "protocol_version": PROTOCOL_VERSION,
        "ledger_id": LEDGER_ID,
        "target_entry_hash": entry_hash,
        "checkpoint_hash": checkpoint_hash,
        "head_entry_hash": checkpoint["head_entry_hash"],
        "entries": [
            ledger_entry,
        ],
        "created_at": now,
    }

    checks = self_check(
        before_statement=before_statement,
        after_statement=after_statement,
        verification_policy=verification_policy,
        evidence_manifest=evidence_manifest,
        claim=claim,
        claim_hash=claim_hash,
        executor_signature=executor_signature,
        executor_sig_hash=executor_sig_hash,
        attestation=attestation,
        attestation_hash=attestation_hash,
        verifier_signature=verifier_signature,
        verifier_sig_hash=verifier_sig_hash,
        ledger_entry=ledger_entry,
        entry_hash=entry_hash,
        checkpoint=checkpoint,
        checkpoint_hash=checkpoint_hash,
        checkpoint_signature=checkpoint_signature,
        checkpoint_sig_hash=checkpoint_sig_hash,
    )

    # Write public artifacts
    write_json(GENESIS_DIR / "before_statement.json", before_statement)
    write_json(GENESIS_DIR / "after_statement.json", after_statement)
    write_json(GENESIS_DIR / "verification_policy.json", verification_policy)
    write_json(GENESIS_DIR / "evidence_manifest.json", evidence_manifest)
    write_json(GENESIS_DIR / "public_keys.json", public_keys)

    write_json(GENESIS_DIR / "claim.json", claim)
    write_json(GENESIS_DIR / "executor_signature.json", executor_signature)
    write_json(GENESIS_DIR / "attestation.json", attestation)
    write_json(GENESIS_DIR / "verifier_signature.json", verifier_signature)
    write_json(GENESIS_DIR / "ledger_entry.json", ledger_entry)
    write_json(GENESIS_DIR / "ledger.json", ledger)
    write_json(GENESIS_DIR / "chain_proof.json", chain_proof)
    write_json(GENESIS_DIR / "checkpoint.json", checkpoint)
    write_json(GENESIS_DIR / "checkpoint_signature.json", checkpoint_signature)

    artifact_files = [
        "before_statement.json",
        "after_statement.json",
        "verification_policy.json",
        "evidence_manifest.json",
        "public_keys.json",
        "claim.json",
        "executor_signature.json",
        "attestation.json",
        "verifier_signature.json",
        "ledger_entry.json",
        "ledger.json",
        "chain_proof.json",
        "checkpoint.json",
        "checkpoint_signature.json",
    ]

    artifact_hashes = []
    for filename in artifact_files:
        path = GENESIS_DIR / filename
        artifact_hashes.append(
            {
                "path": f"genesis/{filename}",
                "file_hash": sha256_file(path),
            }
        )

    genesis_bundle = {
        "type": "delta_genesis_bundle",
        "protocol_version": PROTOCOL_VERSION,
        "spec_version": SPEC_VERSION,
        "status": "DELTA_VERIFIED",
        "ledger_id": LEDGER_ID,
        "generated_at": now,
        "public_keys": {
            "executor_pubkey": executor_public_key,
            "verifier_pubkey": verifier_public_key,
        },
        "hashes": {
            "before_hash": before_hash,
            "after_hash": after_hash,
            "evidence_hash": evidence_hash,
            "verification_policy_hash": verification_policy_hash,
            "claim_hash": claim_hash,
            "executor_sig_hash": executor_sig_hash,
            "attestation_hash": attestation_hash,
            "verifier_sig_hash": verifier_sig_hash,
            "entry_hash": entry_hash,
            "checkpoint_hash": checkpoint_hash,
            "checkpoint_sig_hash": checkpoint_sig_hash,
            "genesis_prev_entry_hash": GENESIS_PREV_ENTRY_HASH,
        },
        "files": artifact_hashes,
        "formal_meaning": (
            "DELTA_VERIFIED means that the Genesis Claim, Executor signature, "
            "Attestation, Verifier signature, Ledger Entry, chain proof, "
            "Signed Checkpoint, and Checkpoint signature are cryptographically "
            "consistent under DELTA-0 v0.5.2."
        ),
        "limitations": [
            "DELTA_VERIFIED does not mean absolute truth about the physical world.",
            "DELTA_VERIFIED does not mean the Verifier cannot be wrong.",
            "DELTA_VERIFIED means the declared change, evidence hash, signatures, ledger entry, and checkpoint are cryptographically bound and tamper-evident.",
        ],
    }

    write_json(GENESIS_DIR / "genesis_bundle.json", genesis_bundle)
    genesis_bundle_hash = sha256_file(GENESIS_DIR / "genesis_bundle.json")

    hashes_text = "\n".join(
        [
            f"protocol_version={PROTOCOL_VERSION}",
            f"spec_version={SPEC_VERSION}",
            f"generated_at={now}",
            "",
            f"spec_file_hash={spec_file_hash}",
            f"generator_file_hash={generator_file_hash}",
            "",
            f"before_hash={before_hash}",
            f"after_hash={after_hash}",
            f"evidence_hash={evidence_hash}",
            f"verification_policy_hash={verification_policy_hash}",
            "",
            f"claim_hash={claim_hash}",
            f"executor_sig_hash={executor_sig_hash}",
            f"attestation_hash={attestation_hash}",
            f"verifier_sig_hash={verifier_sig_hash}",
            f"entry_hash={entry_hash}",
            f"checkpoint_hash={checkpoint_hash}",
            f"checkpoint_sig_hash={checkpoint_sig_hash}",
            f"genesis_bundle_hash={genesis_bundle_hash}",
            "",
            f"GENESIS_PREV_ENTRY_HASH={GENESIS_PREV_ENTRY_HASH}",
            "",
        ]
    )

    write_text(GENESIS_DIR / "hashes.txt", hashes_text)

    self_check_text = "DELTA-0 Genesis Generator Self-Check\n\n"
    self_check_text += "\n".join(checks)
    self_check_text += "\n\nRESULT: OK\n"

    write_text(GENESIS_DIR / "SELF_CHECK_OK.txt", self_check_text)

    print("")
    print("DELTA-0 Genesis Generator")
    print("-------------------------")
    print("Status: OK")
    print("")
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Genesis folder: {GENESIS_DIR}")
    print("")
    print("Generated public files:")
    for filename in artifact_files + ["genesis_bundle.json", "hashes.txt", "SELF_CHECK_OK.txt"]:
        print(f"- genesis/{filename}")
    print("")
    print("Private key files:")
    print("- genesis/private_keys/executor_private_key.json")
    print("- genesis/private_keys/verifier_private_key.json")
    print("")
    print("IMPORTANT: Do NOT publish genesis/private_keys.")
    print("")
    print("Main hashes:")
    print(f"claim_hash:          {claim_hash}")
    print(f"attestation_hash:    {attestation_hash}")
    print(f"entry_hash:          {entry_hash}")
    print(f"checkpoint_hash:     {checkpoint_hash}")
    print(f"genesis_bundle_hash: {genesis_bundle_hash}")
    print("")
    print("RESULT: DELTA GENESIS RECORD GENERATED AND SELF-CHECKED")
    print("")


if __name__ == "__main__":
    main()