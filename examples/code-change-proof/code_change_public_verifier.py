from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path.cwd()
EXAMPLE_DIR = ROOT / "examples" / "code-change-proof"
EVIDENCE_DIR = EXAMPLE_DIR / "evidence"
RECORDS_DIR = EXAMPLE_DIR / "records"

PROTOCOL_VERSION = "DELTA-0"
EXAMPLE_VERSION = "DELTA-0 v0.5.3"
LEDGER_ID = "delta-ledger:code-change-proof-example"
ZERO_HASH = "sha256:" + ("0" * 64)


def fail(message: str) -> None:
    print("")
    print("DELTA CODE CHANGE PROOF VERIFIER RESULT: FAILED")
    print("")
    print("ERROR:")
    print(message)
    print("")
    sys.exit(1)


def ok(checks: List[str], message: str) -> None:
    checks.append("OK " + message)


def load_json(path: Path) -> Any:
    if not path.exists():
        fail(f"Missing JSON file: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Cannot parse JSON file {path}: {exc}")


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"Missing text file: {path}")

    return path.read_text(encoding="utf-8")


def jcs_bytes(obj: Any) -> bytes:
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
    if not path.exists():
        fail(f"Missing file for hash calculation: {path}")

    return sha256_bytes(path.read_bytes())


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def assert_hash_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("sha256:"):
        fail(f"{name} must start with sha256:")

    digest = value[len("sha256:"):]

    if len(digest) != 64:
        fail(f"{name} must contain 64 lowercase hex chars.")

    if digest != digest.lower():
        fail(f"{name} must be lowercase.")

    try:
        int(digest, 16)
    except ValueError:
        fail(f"{name} contains non-hex characters.")


def assert_git_commit(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not re.fullmatch(r"[0-9a-f]{40}", value):
        fail(f"{name} must be a 40-character lowercase hex Git commit hash.")


def assert_public_key_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("ed25519:"):
        fail(f"{name} must start with ed25519:")

    raw = b64url_decode(value[len("ed25519:"):])

    if len(raw) != 32:
        fail(f"{name} must decode to 32 Ed25519 public key bytes.")


def assert_signature_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("ed25519sig:"):
        fail(f"{name} must start with ed25519sig:")

    raw = b64url_decode(value[len("ed25519sig:"):])

    if len(raw) != 64:
        fail(f"{name} must decode to 64 Ed25519 signature bytes.")


def public_key_from_delta(value: str) -> Ed25519PublicKey:
    assert_public_key_format("public_key", value)
    raw = b64url_decode(value[len("ed25519:"):])
    return Ed25519PublicKey.from_public_bytes(raw)


def signature_from_delta(value: str) -> bytes:
    assert_signature_format("signature", value)
    return b64url_decode(value[len("ed25519sig:"):])


def require_equal(name: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        fail(f"{name} mismatch.\nActual:   {actual}\nExpected: {expected}")


def require_field(obj: Dict[str, Any], field: str, obj_name: str) -> Any:
    if not isinstance(obj, dict):
        fail(f"{obj_name} must be a JSON object.")

    if field not in obj:
        fail(f"Missing field '{field}' in {obj_name}.")

    return obj[field]


def verify_signature(public_key_value: str, target_object: Any, signature_value: str) -> None:
    try:
        public_key = public_key_from_delta(public_key_value)
        signature = signature_from_delta(signature_value)
        public_key.verify(signature, jcs_bytes(target_object))
    except Exception as exc:
        fail(f"Signature verification failed: {exc}")


def verify_signature_envelope(
    *,
    checks: List[str],
    envelope: Dict[str, Any],
    envelope_name: str,
    expected_role: str,
    expected_target_type: str,
    expected_target_hash: str,
    expected_public_key: str,
    target_object: Dict[str, Any],
) -> str:
    require_equal(f"{envelope_name}.type", require_field(envelope, "type", envelope_name), "delta_signature")
    require_equal(f"{envelope_name}.protocol_version", envelope["protocol_version"], PROTOCOL_VERSION)
    require_equal(f"{envelope_name}.example_version", envelope["example_version"], EXAMPLE_VERSION)
    require_equal(f"{envelope_name}.role", envelope["role"], expected_role)
    require_equal(f"{envelope_name}.alg", envelope["alg"], "Ed25519")
    require_equal(f"{envelope_name}.target_type", envelope["target_type"], expected_target_type)
    require_equal(f"{envelope_name}.target_hash", envelope["target_hash"], expected_target_hash)
    require_equal(f"{envelope_name}.public_key", envelope["public_key"], expected_public_key)

    signature = require_field(envelope, "signature", envelope_name)
    assert_signature_format(f"{envelope_name}.signature", signature)

    verify_signature(expected_public_key, target_object, signature)
    ok(checks, f"{envelope_name} signature verifies")

    envelope_hash = sha256_object(envelope)
    assert_hash_format(f"{envelope_name}_hash", envelope_hash)
    ok(checks, f"{envelope_name}_hash recomputed")

    return envelope_hash


def ensure_no_private_files(checks: List[str]) -> None:
    forbidden = []

    for path in EXAMPLE_DIR.rglob("*"):
        lower = str(path).lower().replace("\\", "/")

        if "private_keys" in lower:
            forbidden.append(path)

        if path.suffix.lower() in [".pem", ".key", ".secret"]:
            forbidden.append(path)

        if path.name.lower() == ".env":
            forbidden.append(path)

    if forbidden:
        fail("Forbidden private/secret files found:\n" + "\n".join(str(p) for p in forbidden))

    ok(checks, "example contains no private keys or secret files")


def parse_hashes_txt(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()

    return result


def main() -> None:
    checks: List[str] = []

    print("")
    print("DELTA-0 v0.5.3 Code Change Proof Verifier")
    print("-----------------------------------------")
    print("This verifier checks the example without private keys.")
    print("")

    ensure_no_private_files(checks)

    evidence_file = EVIDENCE_DIR / "test_results.log"

    before_state = load_json(RECORDS_DIR / "before_state.json")
    after_state = load_json(RECORDS_DIR / "after_state.json")
    verification_policy = load_json(RECORDS_DIR / "verification_policy.json")
    public_keys = load_json(RECORDS_DIR / "public_keys.json")

    claim = load_json(RECORDS_DIR / "claim.json")
    executor_signature = load_json(RECORDS_DIR / "executor_signature.json")
    attestation = load_json(RECORDS_DIR / "attestation.json")
    verifier_signature = load_json(RECORDS_DIR / "verifier_signature.json")
    ledger_entry = load_json(RECORDS_DIR / "ledger_entry.json")
    ledger = load_json(RECORDS_DIR / "ledger.json")
    checkpoint = load_json(RECORDS_DIR / "checkpoint.json")
    checkpoint_signature = load_json(RECORDS_DIR / "checkpoint_signature.json")
    chain_proof = load_json(RECORDS_DIR / "chain_proof.json")
    hashes_json = load_json(RECORDS_DIR / "hashes.json")
    hashes_txt = parse_hashes_txt(read_text(RECORDS_DIR / "hashes.txt"))
    evidence_hash_txt = read_text(RECORDS_DIR / "evidence_hash.txt").strip()

    require_equal("before_state.type", before_state["type"], "code_state")
    require_equal("after_state.type", after_state["type"], "code_state")
    require_equal("before_state.protocol_version", before_state["protocol_version"], PROTOCOL_VERSION)
    require_equal("after_state.protocol_version", after_state["protocol_version"], PROTOCOL_VERSION)
    require_equal("before_state.example_version", before_state["example_version"], EXAMPLE_VERSION)
    require_equal("after_state.example_version", after_state["example_version"], EXAMPLE_VERSION)

    assert_git_commit("before_state.git_commit", before_state["git_commit"])
    assert_git_commit("after_state.git_commit", after_state["git_commit"])

    require_equal("before_state.test_result", before_state["test_result"], "FAIL")
    require_equal("after_state.test_result", after_state["test_result"], "PASS")
    require_equal("before_state.test_name", before_state["test_name"], "test_payment_validation_timeout")
    require_equal("after_state.test_name", after_state["test_name"], "test_payment_validation_timeout")

    ok(checks, "before/after code states are valid Git-based states")

    evidence_text = read_text(evidence_file)

    if "FAIL -> PASS" not in evidence_text:
        fail("Evidence log does not contain FAIL -> PASS.")

    ok(checks, "evidence log contains FAIL -> PASS")

    before_hash = sha256_object(before_state)
    after_hash = sha256_object(after_state)
    evidence_hash = sha256_file(evidence_file)
    verification_policy_hash = sha256_object(verification_policy)

    require_equal("evidence_hash.txt", evidence_hash_txt, evidence_hash)

    assert_hash_format("before_hash", before_hash)
    assert_hash_format("after_hash", after_hash)
    assert_hash_format("evidence_hash", evidence_hash)
    assert_hash_format("verification_policy_hash", verification_policy_hash)

    ok(checks, "state and evidence hashes recomputed")

    executor_pubkey = public_keys["executor_pubkey"]
    verifier_pubkey = public_keys["verifier_pubkey"]

    assert_public_key_format("executor_pubkey", executor_pubkey)
    assert_public_key_format("verifier_pubkey", verifier_pubkey)

    require_equal("claim.type", claim["type"], "delta_claim")
    require_equal("claim.protocol_version", claim["protocol_version"], PROTOCOL_VERSION)
    require_equal("claim.example_version", claim["example_version"], EXAMPLE_VERSION)
    require_equal("claim.claim_type", claim["claim_type"], "code_change")
    require_equal("claim.executor_pubkey", claim["executor_pubkey"], executor_pubkey)
    require_equal("claim.before_hash", claim["before_hash"], before_hash)
    require_equal("claim.after_hash", claim["after_hash"], after_hash)
    require_equal("claim.evidence_hash", claim["evidence_hash"], evidence_hash)
    require_equal("claim.before_git_commit", claim["before_git_commit"], before_state["git_commit"])
    require_equal("claim.after_git_commit", claim["after_git_commit"], after_state["git_commit"])

    claim_hash = sha256_object(claim)
    ok(checks, "claim_hash recomputed")

    executor_sig_hash = verify_signature_envelope(
        checks=checks,
        envelope=executor_signature,
        envelope_name="executor_signature",
        expected_role="executor",
        expected_target_type="delta_claim",
        expected_target_hash=claim_hash,
        expected_public_key=executor_pubkey,
        target_object=claim,
    )

    require_equal("attestation.type", attestation["type"], "delta_attestation")
    require_equal("attestation.protocol_version", attestation["protocol_version"], PROTOCOL_VERSION)
    require_equal("attestation.example_version", attestation["example_version"], EXAMPLE_VERSION)
    require_equal("attestation.attestation_type", attestation["attestation_type"], "code_change_verification")
    require_equal("attestation.verifier_pubkey", attestation["verifier_pubkey"], verifier_pubkey)
    require_equal("attestation.verifier_name", attestation["verifier_name"], "Local CI Server Verification Key")
    require_equal("attestation.target_claim_hash", attestation["target_claim_hash"], claim_hash)
    require_equal("attestation.target_executor_sig_hash", attestation["target_executor_sig_hash"], executor_sig_hash)
    require_equal("attestation.verification_policy_hash", attestation["verification_policy_hash"], verification_policy_hash)
    require_equal("attestation.evidence_hash", attestation["evidence_hash"], evidence_hash)
    require_equal("attestation.publication_mode", attestation["publication_mode"], "ledger_required")
    require_equal("attestation.intended_ledger_id", attestation["intended_ledger_id"], LEDGER_ID)
    require_equal("attestation.result", attestation["result"], "VERIFIED")

    attestation_hash = sha256_object(attestation)
    ok(checks, "attestation_hash recomputed")

    verifier_sig_hash = verify_signature_envelope(
        checks=checks,
        envelope=verifier_signature,
        envelope_name="verifier_signature",
        expected_role="verifier",
        expected_target_type="delta_attestation",
        expected_target_hash=attestation_hash,
        expected_public_key=verifier_pubkey,
        target_object=attestation,
    )

    require_equal("ledger_entry.type", ledger_entry["type"], "delta_ledger_entry")
    require_equal("ledger_entry.protocol_version", ledger_entry["protocol_version"], PROTOCOL_VERSION)
    require_equal("ledger_entry.example_version", ledger_entry["example_version"], EXAMPLE_VERSION)
    require_equal("ledger_entry.ledger_id", ledger_entry["ledger_id"], LEDGER_ID)
    require_equal("ledger_entry.seq", ledger_entry["seq"], 1)
    require_equal("ledger_entry.prev_entry_hash", ledger_entry["prev_entry_hash"], ZERO_HASH)
    require_equal("ledger_entry.claim_hash", ledger_entry["claim_hash"], claim_hash)
    require_equal("ledger_entry.executor_sig_hash", ledger_entry["executor_sig_hash"], executor_sig_hash)
    require_equal("ledger_entry.attestation_hash", ledger_entry["attestation_hash"], attestation_hash)
    require_equal("ledger_entry.verifier_sig_hash", ledger_entry["verifier_sig_hash"], verifier_sig_hash)

    entry_hash = sha256_object(ledger_entry)
    ok(checks, "entry_hash recomputed")

    require_equal("ledger.type", ledger["type"], "delta_ledger")
    require_equal("ledger.protocol_version", ledger["protocol_version"], PROTOCOL_VERSION)
    require_equal("ledger.example_version", ledger["example_version"], EXAMPLE_VERSION)
    require_equal("ledger.ledger_id", ledger["ledger_id"], LEDGER_ID)
    require_equal("ledger.entries[0].entry_hash", ledger["entries"][0]["entry_hash"], entry_hash)
    require_equal("ledger.entries[0].entry", ledger["entries"][0]["entry"], ledger_entry)

    ok(checks, "ledger contains code-change entry")

    require_equal("checkpoint.type", checkpoint["type"], "delta_signed_checkpoint")
    require_equal("checkpoint.protocol_version", checkpoint["protocol_version"], PROTOCOL_VERSION)
    require_equal("checkpoint.example_version", checkpoint["example_version"], EXAMPLE_VERSION)
    require_equal("checkpoint.ledger_id", checkpoint["ledger_id"], LEDGER_ID)
    require_equal("checkpoint.entry_count", checkpoint["entry_count"], 1)
    require_equal("checkpoint.head_entry_hash", checkpoint["head_entry_hash"], entry_hash)
    require_equal("checkpoint.verifier_pubkey", checkpoint["verifier_pubkey"], verifier_pubkey)

    checkpoint_hash = sha256_object(checkpoint)
    ok(checks, "checkpoint_hash recomputed")

    checkpoint_sig_hash = verify_signature_envelope(
        checks=checks,
        envelope=checkpoint_signature,
        envelope_name="checkpoint_signature",
        expected_role="checkpoint_signer",
        expected_target_type="delta_signed_checkpoint",
        expected_target_hash=checkpoint_hash,
        expected_public_key=verifier_pubkey,
        target_object=checkpoint,
    )

    require_equal("chain_proof.type", chain_proof["type"], "delta_chain_proof")
    require_equal("chain_proof.protocol_version", chain_proof["protocol_version"], PROTOCOL_VERSION)
    require_equal("chain_proof.example_version", chain_proof["example_version"], EXAMPLE_VERSION)
    require_equal("chain_proof.ledger_id", chain_proof["ledger_id"], LEDGER_ID)
    require_equal("chain_proof.target_entry_hash", chain_proof["target_entry_hash"], entry_hash)
    require_equal("chain_proof.checkpoint_hash", chain_proof["checkpoint_hash"], checkpoint_hash)
    require_equal("chain_proof.head_entry_hash", chain_proof["head_entry_hash"], entry_hash)
    require_equal("chain_proof.entries[0]", chain_proof["entries"][0], ledger_entry)

    ok(checks, "chain proof links ledger entry to checkpoint")

    expected_hashes = {
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
        "prev_entry_hash": ZERO_HASH,
    }

    for key, expected_value in expected_hashes.items():
        require_equal(f"hashes.json.{key}", hashes_json.get(key), expected_value)
        require_equal(f"hashes.txt {key}", hashes_txt.get(key), expected_value)

    ok(checks, "hash summaries match recomputed hashes")

    print("Checks:")
    for check in checks:
        print(check)

    print("")
    print("Main recomputed hashes:")
    for key, value in expected_hashes.items():
        print(f"{key}: {value}")

    print("")
    print("DELTA CODE CHANGE PROOF VERIFIER RESULT: OK")
    print("")


if __name__ == "__main__":
    main()
