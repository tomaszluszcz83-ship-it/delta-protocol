from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROTOCOL_VERSION = "DELTA-0"
EXAMPLE_VERSION = "DELTA-0 v0.6.1"
LEDGER_ID = "delta-ledger:private-payload-proof-example"
ZERO_HASH = "sha256:" + ("0" * 64)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = ROOT / "examples" / "private-payload-proof"
RECORDS_DIR = EXAMPLE_DIR / "records"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def jcs_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_object(obj) -> str:
    return sha256_bytes(jcs_bytes(obj))


def read_json(name: str):
    return json.loads((RECORDS_DIR / name).read_text(encoding="utf-8"))


def read_hashes_txt() -> dict[str, str]:
    result = {}
    for line in (RECORDS_DIR / "hashes.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            key, value = line.split("=", 1)
            result[key] = value
    return result


def require_equal(label: str, actual, expected) -> None:
    if actual != expected:
        raise AssertionError(f"{label} mismatch.\nActual:   {actual}\nExpected: {expected}")


def require_hash(label: str, value: str) -> None:
    if not isinstance(value, str) or not HASH_RE.match(value):
        raise AssertionError(f"{label} is not a valid sha256 hash: {value}")


def parse_public_key(value: str) -> Ed25519PublicKey:
    if not value.startswith("ed25519:"):
        raise AssertionError("Unsupported public key format.")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(value.split(":", 1)[1]))


def parse_signature(value: str) -> bytes:
    if not value.startswith("ed25519sig:"):
        raise AssertionError("Unsupported signature format.")
    return b64url_decode(value.split(":", 1)[1])


def verify_signature_envelope(*, envelope, name: str, role: str, target_type: str, target_hash: str, public_key: str, target_object) -> None:
    require_equal(f"{name}.type", envelope["type"], "delta_signature")
    require_equal(f"{name}.protocol_version", envelope["protocol_version"], PROTOCOL_VERSION)
    require_equal(f"{name}.example_version", envelope["example_version"], EXAMPLE_VERSION)
    require_equal(f"{name}.role", envelope["role"], role)
    require_equal(f"{name}.alg", envelope["alg"], "Ed25519")
    require_equal(f"{name}.public_key", envelope["public_key"], public_key)
    require_equal(f"{name}.target_type", envelope["target_type"], target_type)
    require_equal(f"{name}.target_hash", envelope["target_hash"], target_hash)
    parse_public_key(envelope["public_key"]).verify(parse_signature(envelope["signature"]), jcs_bytes(target_object))


def check_no_private_payload_or_secret_files() -> None:
    forbidden_names = {"private_payload.txt", "payload_private.txt", "secret_payload.txt", "private_document.txt", "nda_private.txt"}
    forbidden_dirs = {"private_keys", "private_payloads", "secrets"}
    forbidden_suffixes = {".pem", ".key", ".secret", ".env"}

    for path in EXAMPLE_DIR.rglob("*"):
        rel = path.relative_to(EXAMPLE_DIR)
        parts = {part.lower() for part in rel.parts}
        name = path.name.lower()

        if path.is_dir():
            if name in forbidden_dirs:
                raise AssertionError(f"Forbidden private directory found: {rel}")
            continue

        if name in forbidden_names:
            raise AssertionError(f"Forbidden private payload file found: {rel}")
        if path.suffix.lower() in forbidden_suffixes:
            raise AssertionError(f"Forbidden secret file found: {rel}")
        if parts & forbidden_dirs:
            raise AssertionError(f"File inside forbidden private directory found: {rel}")


def main() -> int:
    print("DELTA-0 v0.6.1 Private Payload Proof Verifier")
    print("---------------------------------------------")
    print("This verifier checks public proof records without private payload bytes.")
    print("")

    checks = []

    check_no_private_payload_or_secret_files()
    checks.append("OK example contains no private payload files or secret files")

    before_state = read_json("before_state.json")
    after_state = read_json("after_state.json")
    private_payload_manifest = read_json("private_payload_manifest.json")
    verification_policy = read_json("verification_policy.json")
    public_keys = read_json("public_keys.json")
    claim = read_json("claim.json")
    executor_signature = read_json("executor_signature.json")
    attestation = read_json("attestation.json")
    verifier_signature = read_json("verifier_signature.json")
    ledger_entry = read_json("ledger_entry.json")
    ledger = read_json("ledger.json")
    checkpoint = read_json("checkpoint.json")
    checkpoint_signature = read_json("checkpoint_signature.json")
    chain_proof = read_json("chain_proof.json")
    hashes_json = read_json("hashes.json")
    hashes_txt = read_hashes_txt()

    require_equal("private_payload_manifest.type", private_payload_manifest["type"], "delta_private_payload_manifest")
    require_equal("private_payload_manifest.payload_status", private_payload_manifest["payload_status"], "not_public")
    require_equal("private_payload_manifest.privacy_model", private_payload_manifest["privacy_model"], "hash_commitment_only")
    require_hash("private_payload_manifest.payload_hash", private_payload_manifest["payload_hash"])
    checks.append("OK private payload is represented by hash commitment only")

    require_equal("before_state.payload_visibility", before_state["payload_visibility"], "private")
    require_equal("after_state.payload_visibility", after_state["payload_visibility"], "private")
    require_equal("before_state.status", before_state["status"], "draft")
    require_equal("after_state.status", after_state["status"], "signed")
    checks.append("OK before/after states describe a private payload state change")

    before_hash = sha256_object(before_state)
    after_hash = sha256_object(after_state)
    private_payload_manifest_hash = sha256_object(private_payload_manifest)
    verification_policy_hash = sha256_object(verification_policy)
    claim_hash = sha256_object(claim)
    executor_sig_hash = sha256_object(executor_signature)
    attestation_hash = sha256_object(attestation)
    verifier_sig_hash = sha256_object(verifier_signature)
    entry_hash = sha256_object(ledger_entry)
    checkpoint_hash = sha256_object(checkpoint)
    checkpoint_sig_hash = sha256_object(checkpoint_signature)
    private_payload_hash = private_payload_manifest["payload_hash"]

    require_equal("claim.before_hash", claim["before_hash"], before_hash)
    require_equal("claim.after_hash", claim["after_hash"], after_hash)
    require_equal("claim.evidence_hash", claim["evidence_hash"], private_payload_hash)
    require_equal("claim.private_payload_manifest_hash", claim["private_payload_manifest_hash"], private_payload_manifest_hash)
    require_equal("claim.publication_model", claim["publication_model"], "hash_commitment_only")
    checks.append("OK claim binds private payload hash without exposing payload bytes")

    verify_signature_envelope(
        envelope=executor_signature,
        name="executor_signature",
        role="executor",
        target_type="delta_claim",
        target_hash=claim_hash,
        public_key=public_keys["executor_pubkey"],
        target_object=claim,
    )
    checks.append("OK executor signature verifies")

    require_equal("attestation.target_claim_hash", attestation["target_claim_hash"], claim_hash)
    require_equal("attestation.target_executor_sig_hash", attestation["target_executor_sig_hash"], executor_sig_hash)
    require_equal("attestation.verification_policy_hash", attestation["verification_policy_hash"], verification_policy_hash)
    require_equal("attestation.private_payload_manifest_hash", attestation["private_payload_manifest_hash"], private_payload_manifest_hash)
    require_equal("attestation.evidence_hash", attestation["evidence_hash"], private_payload_hash)
    require_equal("attestation.result", attestation["result"], "HASH_COMMITMENT_VERIFIED")
    checks.append("OK attestation verifies hash commitment without payload disclosure")

    verify_signature_envelope(
        envelope=verifier_signature,
        name="verifier_signature",
        role="verifier",
        target_type="delta_attestation",
        target_hash=attestation_hash,
        public_key=public_keys["verifier_pubkey"],
        target_object=attestation,
    )
    checks.append("OK verifier signature verifies")

    require_equal("ledger_entry.ledger_id", ledger_entry["ledger_id"], LEDGER_ID)
    require_equal("ledger_entry.prev_entry_hash", ledger_entry["prev_entry_hash"], ZERO_HASH)
    require_equal("ledger_entry.claim_hash", ledger_entry["claim_hash"], claim_hash)
    require_equal("ledger_entry.executor_sig_hash", ledger_entry["executor_sig_hash"], executor_sig_hash)
    require_equal("ledger_entry.attestation_hash", ledger_entry["attestation_hash"], attestation_hash)
    require_equal("ledger_entry.verifier_sig_hash", ledger_entry["verifier_sig_hash"], verifier_sig_hash)
    require_equal("ledger_entry.private_payload_manifest_hash", ledger_entry["private_payload_manifest_hash"], private_payload_manifest_hash)
    checks.append("OK ledger entry binds claim, signatures, attestation, and private payload manifest")

    require_equal("ledger.entries[0].entry_hash", ledger["entries"][0]["entry_hash"], entry_hash)
    require_equal("ledger.entries[0].entry", ledger["entries"][0]["entry"], ledger_entry)
    checks.append("OK ledger contains private payload proof entry")

    require_equal("checkpoint.ledger_id", checkpoint["ledger_id"], LEDGER_ID)
    require_equal("checkpoint.head_entry_hash", checkpoint["head_entry_hash"], entry_hash)

    verify_signature_envelope(
        envelope=checkpoint_signature,
        name="checkpoint_signature",
        role="checkpoint_signer",
        target_type="delta_signed_checkpoint",
        target_hash=checkpoint_hash,
        public_key=public_keys["verifier_pubkey"],
        target_object=checkpoint,
    )
    checks.append("OK checkpoint signature verifies")

    require_equal("chain_proof.target_entry_hash", chain_proof["target_entry_hash"], entry_hash)
    require_equal("chain_proof.checkpoint_hash", chain_proof["checkpoint_hash"], checkpoint_hash)
    require_equal("chain_proof.head_entry_hash", chain_proof["head_entry_hash"], entry_hash)
    require_equal("chain_proof.entries[0]", chain_proof["entries"][0], ledger_entry)
    checks.append("OK chain proof links private payload entry to checkpoint")

    expected_hashes = {
        "before_hash": before_hash,
        "after_hash": after_hash,
        "private_payload_hash": private_payload_hash,
        "private_payload_manifest_hash": private_payload_manifest_hash,
        "verification_policy_hash": verification_policy_hash,
        "claim_hash": claim_hash,
        "executor_sig_hash": executor_sig_hash,
        "attestation_hash": attestation_hash,
        "verifier_sig_hash": verifier_sig_hash,
        "entry_hash": entry_hash,
        "checkpoint_hash": checkpoint_hash,
        "checkpoint_sig_hash": checkpoint_sig_hash,
        "prev_entry_hash": ZERO_HASH,
    }

    for key, expected_value in expected_hashes.items():
        require_equal(f"hashes.json.{key}", hashes_json.get(key), expected_value)
        require_equal(f"hashes.txt.{key}", hashes_txt.get(key), expected_value)

    checks.append("OK hash summaries match recomputed hashes")

    print("Checks:")
    for check in checks:
        print(check)

    print("")
    print("Main recomputed hashes:")
    for key, value in expected_hashes.items():
        print(f"{key}: {value}")

    print("")
    print("DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("")
        print("DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: FAILED")
        print("")
        print("ERROR:")
        print(exc)
        raise SystemExit(1)
