# DELTA-0 Genesis Public Verifier
# Version: DELTA-0 v0.5.2
#
# Verifies the public DELTA Genesis package WITHOUT private keys.
#
# Supported layouts:
#
# 1. Development layout:
#    DELTA-0/
#      src/genesis_public_verifier.py
#      release/DELTA-0-genesis-public/
#
# 2. Public repository layout:
#    DELTA-0-PUBLIC/
#      src/genesis_public_verifier.py
#      genesis/
#      spec/
#      release/
#
# 3. Extracted public package layout:
#    DELTA-0-genesis-public/
#      src/genesis_public_verifier.py
#      genesis/
#      spec/
#
# The verifier intentionally ignores SELF_CHECK_OK.txt as proof.

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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
PUBLIC_PACKAGE_NAME = "DELTA-0-genesis-public"

GENESIS_PREV_ENTRY_HASH = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

SCRIPT_PATH = Path(__file__).resolve()
PROJECT_ROOT = SCRIPT_PATH.parents[1]


def fail(message: str) -> None:
    print("")
    print("DELTA PUBLIC VERIFIER RESULT: FAILED")
    print("")
    print("ERROR:")
    print(message)
    print("")
    sys.exit(1)


def detect_public_release_root() -> Path:
    """
    Detection priority:

    1. Development layout:
       DELTA-0/release/DELTA-0-genesis-public/

    2. Public repository layout:
       DELTA-0-PUBLIC/

    3. Extracted public package layout:
       DELTA-0-genesis-public/
    """

    dev_release_root = PROJECT_ROOT / "release" / PUBLIC_PACKAGE_NAME

    if (
        (dev_release_root / "genesis").exists()
        and (dev_release_root / "spec").exists()
        and (dev_release_root / "src").exists()
    ):
        return dev_release_root

    direct_root = PROJECT_ROOT

    if (
        (direct_root / "genesis").exists()
        and (direct_root / "spec").exists()
        and (direct_root / "src").exists()
    ):
        return direct_root

    fail(
        "Cannot find public release folder.\n\n"
        "Expected one of these layouts:\n\n"
        "1. Development layout:\n"
        "   DELTA-0/release/DELTA-0-genesis-public/\n\n"
        "2. Public repository layout:\n"
        "   DELTA-0-PUBLIC/genesis/\n"
        "   DELTA-0-PUBLIC/spec/\n"
        "   DELTA-0-PUBLIC/src/\n\n"
        "3. Extracted public package layout:\n"
        "   DELTA-0-genesis-public/genesis/\n"
        "   DELTA-0-genesis-public/spec/\n"
        "   DELTA-0-genesis-public/src/"
    )


PUBLIC_RELEASE_ROOT = detect_public_release_root()
PUBLIC_GENESIS_DIR = PUBLIC_RELEASE_ROOT / "genesis"
PUBLIC_SPEC_DIR = PUBLIC_RELEASE_ROOT / "spec"
PUBLIC_SRC_DIR = PUBLIC_RELEASE_ROOT / "src"


def ok(checks: List[str], message: str) -> None:
    checks.append("OK " + message)


def load_json(path: Path) -> Any:
    if not path.exists():
        fail(f"Missing required JSON file: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Cannot parse JSON file {path}: {exc}")


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"Missing required text file: {path}")

    return path.read_text(encoding="utf-8")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


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
        fail(f"Missing file for SHA-256 calculation: {path}")

    return sha256_bytes(path.read_bytes())


def assert_hash_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("sha256:"):
        fail(f"{name} missing sha256: prefix: {value}")

    digest = value[len("sha256:") :]

    if len(digest) != 64:
        fail(f"{name} must contain 64 lowercase hex chars: {value}")

    if digest.lower() != digest:
        fail(f"{name} must be lowercase: {value}")

    try:
        int(digest, 16)
    except ValueError:
        fail(f"{name} contains non-hex characters: {value}")


def assert_public_key_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("ed25519:"):
        fail(f"{name} missing ed25519: prefix.")

    raw = b64url_decode(value[len("ed25519:") :])

    if len(raw) != 32:
        fail(f"{name} must decode to 32 raw Ed25519 public key bytes.")


def assert_signature_format(name: str, value: str) -> None:
    if not isinstance(value, str):
        fail(f"{name} must be a string.")

    if not value.startswith("ed25519sig:"):
        fail(f"{name} missing ed25519sig: prefix.")

    raw = b64url_decode(value[len("ed25519sig:") :])

    if len(raw) != 64:
        fail(f"{name} must decode to 64 raw Ed25519 signature bytes.")


def public_key_from_delta(value: str) -> Ed25519PublicKey:
    assert_public_key_format("public_key", value)
    raw = b64url_decode(value[len("ed25519:") :])
    return Ed25519PublicKey.from_public_bytes(raw)


def signature_from_delta(value: str) -> bytes:
    assert_signature_format("signature", value)
    return b64url_decode(value[len("ed25519sig:") :])


def verify_signature(public_key_value: str, obj: Any, signature_value: str) -> None:
    try:
        public_key = public_key_from_delta(public_key_value)
        signature = signature_from_delta(signature_value)
        public_key.verify(signature, jcs_bytes(obj))
    except Exception as exc:
        fail(f"Signature verification failed: {exc}")


def require_equal(name: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        fail(f"{name} mismatch.\nActual:   {actual}\nExpected: {expected}")


def require_field(obj: Dict[str, Any], field: str, obj_name: str) -> Any:
    if not isinstance(obj, dict):
        fail(f"{obj_name} must be a JSON object.")

    if field not in obj:
        fail(f"Missing field '{field}' in {obj_name}.")

    return obj[field]


def ensure_no_private_keys(public_root: Path, checks: List[str]) -> None:
    forbidden_hits: List[Path] = []

    for path in public_root.rglob("*"):
        lower = str(path).lower().replace("\\", "/")

        if "private_keys" in lower:
            forbidden_hits.append(path)

        if path.suffix.lower() in [".pem", ".key", ".secret"]:
            forbidden_hits.append(path)

        if path.name.lower() == ".env":
            forbidden_hits.append(path)

    if forbidden_hits:
        formatted = "\n".join(str(p) for p in forbidden_hits)
        fail(f"Public release contains forbidden private/secret files:\n{formatted}")

    ok(checks, "public release contains no private keys or secret files")


def parse_hashes_txt(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()

    return result


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
    require_equal(
        f"{envelope_name}.type",
        require_field(envelope, "type", envelope_name),
        "delta_signature",
    )
    require_equal(
        f"{envelope_name}.protocol_version",
        require_field(envelope, "protocol_version", envelope_name),
        PROTOCOL_VERSION,
    )
    require_equal(
        f"{envelope_name}.role",
        require_field(envelope, "role", envelope_name),
        expected_role,
    )
    require_equal(
        f"{envelope_name}.alg",
        require_field(envelope, "alg", envelope_name),
        "Ed25519",
    )
    require_equal(
        f"{envelope_name}.target_type",
        require_field(envelope, "target_type", envelope_name),
        expected_target_type,
    )
    require_equal(
        f"{envelope_name}.target_hash",
        require_field(envelope, "target_hash", envelope_name),
        expected_target_hash,
    )
    require_equal(
        f"{envelope_name}.public_key",
        require_field(envelope, "public_key", envelope_name),
        expected_public_key,
    )

    signature = require_field(envelope, "signature", envelope_name)
    assert_signature_format(f"{envelope_name}.signature", signature)

    verify_signature(expected_public_key, target_object, signature)

    ok(checks, f"{envelope_name} signature verifies")

    envelope_hash = sha256_object(envelope)
    assert_hash_format(f"{envelope_name}_hash", envelope_hash)

    ok(checks, f"{envelope_name}_hash recomputed")

    return envelope_hash


def verify_chain_proof(
    *,
    checks: List[str],
    chain_proof: Dict[str, Any],
    target_entry_hash: str,
    checkpoint_hash: str,
    head_entry_hash: str,
) -> None:
    require_equal(
        "chain_proof.type",
        require_field(chain_proof, "type", "chain_proof"),
        "delta_chain_proof",
    )
    require_equal(
        "chain_proof.protocol_version",
        require_field(chain_proof, "protocol_version", "chain_proof"),
        PROTOCOL_VERSION,
    )
    require_equal(
        "chain_proof.ledger_id",
        require_field(chain_proof, "ledger_id", "chain_proof"),
        LEDGER_ID,
    )
    require_equal(
        "chain_proof.target_entry_hash",
        require_field(chain_proof, "target_entry_hash", "chain_proof"),
        target_entry_hash,
    )
    require_equal(
        "chain_proof.checkpoint_hash",
        require_field(chain_proof, "checkpoint_hash", "chain_proof"),
        checkpoint_hash,
    )
    require_equal(
        "chain_proof.head_entry_hash",
        require_field(chain_proof, "head_entry_hash", "chain_proof"),
        head_entry_hash,
    )

    entries = require_field(chain_proof, "entries", "chain_proof")

    if not isinstance(entries, list) or not entries:
        fail("chain_proof.entries must be a non-empty list.")

    current_hash = sha256_object(entries[0])

    require_equal(
        "chain_proof first entry hash",
        current_hash,
        target_entry_hash,
    )

    for index in range(1, len(entries)):
        next_entry = entries[index]

        if not isinstance(next_entry, dict):
            fail(f"chain_proof.entries[{index}] must be an object.")

        prev_hash = require_field(
            next_entry,
            "prev_entry_hash",
            f"chain_proof.entries[{index}]",
        )

        require_equal(
            f"chain_proof.entries[{index}].prev_entry_hash",
            prev_hash,
            current_hash,
        )

        current_hash = sha256_object(next_entry)

    require_equal(
        "chain_proof final entry hash",
        current_hash,
        head_entry_hash,
    )

    ok(checks, "chain proof links ledger entry to checkpoint")


def verify_evidence_manifest(
    *,
    checks: List[str],
    evidence_manifest: Dict[str, Any],
    before_statement: Dict[str, Any],
    after_statement: Dict[str, Any],
    verification_policy: Dict[str, Any],
) -> str:
    require_equal(
        "evidence_manifest.type",
        require_field(evidence_manifest, "type", "evidence_manifest"),
        "delta_evidence_manifest",
    )

    require_equal(
        "evidence_manifest.protocol_version",
        require_field(evidence_manifest, "protocol_version", "evidence_manifest"),
        PROTOCOL_VERSION,
    )

    items = require_field(evidence_manifest, "items", "evidence_manifest")

    if not isinstance(items, list) or not items:
        fail("evidence_manifest.items must be a non-empty list.")

    expected_hashes_by_path = {
        "spec/DELTA-0-v0.5.2-core-structures.md": sha256_file(
            PUBLIC_SPEC_DIR / "DELTA-0-v0.5.2-core-structures.md"
        ),
        "src/genesis_generator.py": sha256_file(PUBLIC_SRC_DIR / "genesis_generator.py"),
        "genesis/before_statement.json": sha256_object(before_statement),
        "genesis/after_statement.json": sha256_object(after_statement),
        "genesis/verification_policy.json": sha256_object(verification_policy),
    }

    seen_paths = set()

    for item in items:
        if not isinstance(item, dict):
            fail("Each evidence_manifest item must be an object.")

        path = require_field(item, "path", "evidence_manifest item")
        item_hash = require_field(item, "hash", "evidence_manifest item")

        assert_hash_format(f"evidence_manifest item hash for {path}", item_hash)

        if path not in expected_hashes_by_path:
            fail(
                "Unexpected path in evidence_manifest. "
                "Generated bundle or ZIP hashes must not be inside evidence_manifest. "
                f"Unexpected path: {path}"
            )

        require_equal(
            f"evidence_manifest hash for {path}",
            item_hash,
            expected_hashes_by_path[path],
        )

        seen_paths.add(path)

    missing = set(expected_hashes_by_path.keys()) - seen_paths

    if missing:
        fail("Missing required evidence_manifest paths:\n" + "\n".join(sorted(missing)))

    evidence_hash = sha256_object(evidence_manifest)
    assert_hash_format("evidence_hash", evidence_hash)

    ok(checks, "evidence_manifest contains only pre-claim evidence items")
    ok(checks, "evidence_hash recomputed")

    return evidence_hash


def main() -> None:
    checks: List[str] = []

    print("")
    print("DELTA-0 Genesis Public Verifier")
    print("-------------------------------")
    print("This verifier uses only public release artifacts.")
    print("It does not use private keys.")
    print("It ignores SELF_CHECK_OK.txt as proof.")
    print("")
    print("Detected public release folder:")
    print(str(PUBLIC_RELEASE_ROOT))
    print("")

    ensure_no_private_keys(PUBLIC_RELEASE_ROOT, checks)

    spec_file = PUBLIC_SPEC_DIR / "DELTA-0-v0.5.2-core-structures.md"
    generator_file = PUBLIC_SRC_DIR / "genesis_generator.py"

    if not spec_file.exists():
        fail(f"Missing public spec file: {spec_file}")

    if not generator_file.exists():
        fail(f"Missing public generator file: {generator_file}")

    ok(checks, "public spec file exists")
    ok(checks, "public generator file exists")

    before_statement = load_json(PUBLIC_GENESIS_DIR / "before_statement.json")
    after_statement = load_json(PUBLIC_GENESIS_DIR / "after_statement.json")
    verification_policy = load_json(PUBLIC_GENESIS_DIR / "verification_policy.json")
    evidence_manifest = load_json(PUBLIC_GENESIS_DIR / "evidence_manifest.json")
    public_keys = load_json(PUBLIC_GENESIS_DIR / "public_keys.json")

    claim = load_json(PUBLIC_GENESIS_DIR / "claim.json")
    executor_signature = load_json(PUBLIC_GENESIS_DIR / "executor_signature.json")
    attestation = load_json(PUBLIC_GENESIS_DIR / "attestation.json")
    verifier_signature = load_json(PUBLIC_GENESIS_DIR / "verifier_signature.json")
    ledger_entry = load_json(PUBLIC_GENESIS_DIR / "ledger_entry.json")
    ledger = load_json(PUBLIC_GENESIS_DIR / "ledger.json")
    chain_proof = load_json(PUBLIC_GENESIS_DIR / "chain_proof.json")
    checkpoint = load_json(PUBLIC_GENESIS_DIR / "checkpoint.json")
    checkpoint_signature = load_json(PUBLIC_GENESIS_DIR / "checkpoint_signature.json")
    genesis_bundle = load_json(PUBLIC_GENESIS_DIR / "genesis_bundle.json")
    hashes_txt = read_text(PUBLIC_GENESIS_DIR / "hashes.txt")

    if (PUBLIC_GENESIS_DIR / "SELF_CHECK_OK.txt").exists():
        ok(checks, "SELF_CHECK_OK.txt exists but is ignored as proof")

    require_equal(
        "public_keys.type",
        require_field(public_keys, "type", "public_keys"),
        "delta_public_keys",
    )
    require_equal(
        "public_keys.protocol_version",
        require_field(public_keys, "protocol_version", "public_keys"),
        PROTOCOL_VERSION,
    )

    executor_pubkey = require_field(public_keys, "executor_pubkey", "public_keys")
    verifier_pubkey = require_field(public_keys, "verifier_pubkey", "public_keys")

    assert_public_key_format("executor_pubkey", executor_pubkey)
    assert_public_key_format("verifier_pubkey", verifier_pubkey)

    ok(checks, "public keys have valid format")

    before_hash = sha256_object(before_statement)
    after_hash = sha256_object(after_statement)
    verification_policy_hash = sha256_object(verification_policy)

    evidence_hash = verify_evidence_manifest(
        checks=checks,
        evidence_manifest=evidence_manifest,
        before_statement=before_statement,
        after_statement=after_statement,
        verification_policy=verification_policy,
    )

    require_equal("claim.type", require_field(claim, "type", "claim"), "delta_claim")
    require_equal(
        "claim.protocol_version",
        require_field(claim, "protocol_version", "claim"),
        PROTOCOL_VERSION,
    )
    require_equal("claim.executor_pubkey", claim["executor_pubkey"], executor_pubkey)
    require_equal("claim.before_hash", claim["before_hash"], before_hash)
    require_equal("claim.after_hash", claim["after_hash"], after_hash)
    require_equal("claim.evidence_hash", claim["evidence_hash"], evidence_hash)

    claim_hash = sha256_object(claim)
    assert_hash_format("claim_hash", claim_hash)
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

    require_equal(
        "attestation.type",
        require_field(attestation, "type", "attestation"),
        "delta_attestation",
    )
    require_equal(
        "attestation.protocol_version",
        attestation["protocol_version"],
        PROTOCOL_VERSION,
    )
    require_equal("attestation.verifier_pubkey", attestation["verifier_pubkey"], verifier_pubkey)
    require_equal("attestation.target_claim_hash", attestation["target_claim_hash"], claim_hash)
    require_equal(
        "attestation.target_executor_sig_hash",
        attestation["target_executor_sig_hash"],
        executor_sig_hash,
    )
    require_equal(
        "attestation.verification_policy_hash",
        attestation["verification_policy_hash"],
        verification_policy_hash,
    )
    require_equal("attestation.evidence_hash", attestation["evidence_hash"], evidence_hash)
    require_equal("attestation.publication_mode", attestation["publication_mode"], "ledger_required")
    require_equal("attestation.intended_ledger_id", attestation["intended_ledger_id"], LEDGER_ID)
    require_equal("attestation.result", attestation["result"], "VERIFIED")

    attestation_hash = sha256_object(attestation)
    assert_hash_format("attestation_hash", attestation_hash)
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

    require_equal(
        "ledger_entry.type",
        require_field(ledger_entry, "type", "ledger_entry"),
        "delta_ledger_entry",
    )
    require_equal("ledger_entry.protocol_version", ledger_entry["protocol_version"], PROTOCOL_VERSION)
    require_equal("ledger_entry.ledger_id", ledger_entry["ledger_id"], LEDGER_ID)
    require_equal("ledger_entry.seq", ledger_entry["seq"], 1)
    require_equal("ledger_entry.prev_entry_hash", ledger_entry["prev_entry_hash"], GENESIS_PREV_ENTRY_HASH)
    require_equal("ledger_entry.claim_hash", ledger_entry["claim_hash"], claim_hash)
    require_equal("ledger_entry.executor_sig_hash", ledger_entry["executor_sig_hash"], executor_sig_hash)
    require_equal("ledger_entry.attestation_hash", ledger_entry["attestation_hash"], attestation_hash)
    require_equal("ledger_entry.verifier_sig_hash", ledger_entry["verifier_sig_hash"], verifier_sig_hash)

    entry_hash = sha256_object(ledger_entry)
    assert_hash_format("entry_hash", entry_hash)
    ok(checks, "entry_hash recomputed")
    ok(checks, "ledger_entry binds object hashes and signature envelope hashes")

    require_equal("ledger.type", require_field(ledger, "type", "ledger"), "delta_ledger")
    require_equal("ledger.protocol_version", ledger["protocol_version"], PROTOCOL_VERSION)
    require_equal("ledger.ledger_id", ledger["ledger_id"], LEDGER_ID)

    ledger_entries = require_field(ledger, "entries", "ledger")

    if not isinstance(ledger_entries, list) or len(ledger_entries) != 1:
        fail("Genesis ledger must contain exactly one entry.")

    require_equal("ledger.entries[0].entry_hash", ledger_entries[0].get("entry_hash"), entry_hash)
    require_equal("ledger.entries[0].entry", ledger_entries[0].get("entry"), ledger_entry)

    ok(checks, "ledger contains genesis entry")

    require_equal(
        "checkpoint.type",
        require_field(checkpoint, "type", "checkpoint"),
        "delta_signed_checkpoint",
    )
    require_equal("checkpoint.protocol_version", checkpoint["protocol_version"], PROTOCOL_VERSION)
    require_equal("checkpoint.ledger_id", checkpoint["ledger_id"], LEDGER_ID)
    require_equal("checkpoint.checkpoint_seq", checkpoint["checkpoint_seq"], 1)
    require_equal("checkpoint.entry_count", checkpoint["entry_count"], 1)
    require_equal("checkpoint.head_entry_hash", checkpoint["head_entry_hash"], entry_hash)
    require_equal("checkpoint.verifier_pubkey", checkpoint["verifier_pubkey"], verifier_pubkey)

    checkpoint_hash = sha256_object(checkpoint)
    assert_hash_format("checkpoint_hash", checkpoint_hash)
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

    verify_chain_proof(
        checks=checks,
        chain_proof=chain_proof,
        target_entry_hash=entry_hash,
        checkpoint_hash=checkpoint_hash,
        head_entry_hash=checkpoint["head_entry_hash"],
    )

    require_equal(
        "genesis_bundle.type",
        require_field(genesis_bundle, "type", "genesis_bundle"),
        "delta_genesis_bundle",
    )
    require_equal("genesis_bundle.protocol_version", genesis_bundle["protocol_version"], PROTOCOL_VERSION)
    require_equal("genesis_bundle.spec_version", genesis_bundle["spec_version"], SPEC_VERSION)
    require_equal("genesis_bundle.status", genesis_bundle["status"], "DELTA_VERIFIED")
    require_equal("genesis_bundle.ledger_id", genesis_bundle["ledger_id"], LEDGER_ID)

    bundle_public_keys = require_field(genesis_bundle, "public_keys", "genesis_bundle")
    require_equal("genesis_bundle.public_keys.executor_pubkey", bundle_public_keys.get("executor_pubkey"), executor_pubkey)
    require_equal("genesis_bundle.public_keys.verifier_pubkey", bundle_public_keys.get("verifier_pubkey"), verifier_pubkey)

    bundle_hashes = require_field(genesis_bundle, "hashes", "genesis_bundle")

    expected_bundle_hashes = {
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
    }

    for key, expected_value in expected_bundle_hashes.items():
        require_equal(f"genesis_bundle.hashes.{key}", bundle_hashes.get(key), expected_value)

    ok(checks, "genesis_bundle hash summary matches recomputed hashes")

    bundle_files = require_field(genesis_bundle, "files", "genesis_bundle")

    if not isinstance(bundle_files, list):
        fail("genesis_bundle.files must be a list.")

    for item in bundle_files:
        if not isinstance(item, dict):
            fail("Each genesis_bundle.files item must be an object.")

        rel_path = item.get("path")
        expected_file_hash = item.get("file_hash")

        if not isinstance(rel_path, str) or not isinstance(expected_file_hash, str):
            fail("Each genesis_bundle.files item must contain path and file_hash.")

        assert_hash_format(f"genesis_bundle file hash for {rel_path}", expected_file_hash)

        actual_file_hash = sha256_file(PUBLIC_RELEASE_ROOT / rel_path)

        require_equal(
            f"genesis_bundle file_hash for {rel_path}",
            actual_file_hash,
            expected_file_hash,
        )

    ok(checks, "genesis_bundle distribution file hashes match release files")

    hashes_txt_map = parse_hashes_txt(hashes_txt)

    expected_hashes_txt = {
        "protocol_version": PROTOCOL_VERSION,
        "spec_version": SPEC_VERSION,
        "spec_file_hash": sha256_file(spec_file),
        "generator_file_hash": sha256_file(generator_file),
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
        "genesis_bundle_hash": sha256_file(PUBLIC_GENESIS_DIR / "genesis_bundle.json"),
        "GENESIS_PREV_ENTRY_HASH": GENESIS_PREV_ENTRY_HASH,
    }

    for key, expected_value in expected_hashes_txt.items():
        if key not in hashes_txt_map:
            fail(f"hashes.txt missing key: {key}")

        require_equal(f"hashes.txt {key}", hashes_txt_map[key], expected_value)

    ok(checks, "hashes.txt matches recomputed hashes")

    if attestation["result"] != "VERIFIED":
        fail("Attestation result is not VERIFIED.")

    if checkpoint["head_entry_hash"] != entry_hash:
        fail("Checkpoint does not point to Genesis ledger entry hash.")

    ok(checks, "DELTA_VERIFIED conditions satisfied")

    print("Checks:")

    for check in checks:
        print(check)

    print("")
    print("Main recomputed hashes:")
    print(f"claim_hash:          {claim_hash}")
    print(f"executor_sig_hash:   {executor_sig_hash}")
    print(f"attestation_hash:    {attestation_hash}")
    print(f"verifier_sig_hash:   {verifier_sig_hash}")
    print(f"entry_hash:          {entry_hash}")
    print(f"checkpoint_hash:     {checkpoint_hash}")
    print(f"checkpoint_sig_hash: {checkpoint_sig_hash}")
    print(f"genesis_bundle_hash: {sha256_file(PUBLIC_GENESIS_DIR / 'genesis_bundle.json')}")
    print("")
    print("DELTA PUBLIC VERIFIER RESULT: OK")
    print("")


if __name__ == "__main__":
    main()
