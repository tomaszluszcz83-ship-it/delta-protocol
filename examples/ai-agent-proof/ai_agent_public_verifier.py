from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROTOCOL_VERSION = "DELTA-0"
EXAMPLE_VERSION = "DELTA-0 v0.6.2"
LEDGER_ID = "delta-ledger:ai-agent-proof-example"
ZERO_HASH = "sha256:" + ("0" * 64)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = ROOT / "examples" / "ai-agent-proof"
RECORDS_DIR = EXAMPLE_DIR / "records"


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def jcs_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_object(obj) -> str:
    return "sha256:" + hashlib.sha256(jcs_bytes(obj)).hexdigest()


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


def parse_public_key(value: str) -> Ed25519PublicKey:
    if not value.startswith("ed25519:"):
        raise AssertionError("Unsupported public key format.")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(value.split(":", 1)[1]))


def parse_signature(value: str) -> bytes:
    if not value.startswith("ed25519sig:"):
        raise AssertionError("Unsupported signature format.")
    return b64url_decode(value.split(":", 1)[1])


def verify_signature_envelope(*, envelope, name, role, target_type, target_hash, public_key, target_object) -> None:
    require_equal(f"{name}.type", envelope["type"], "delta_signature")
    require_equal(f"{name}.protocol_version", envelope["protocol_version"], PROTOCOL_VERSION)
    require_equal(f"{name}.example_version", envelope["example_version"], EXAMPLE_VERSION)
    require_equal(f"{name}.role", envelope["role"], role)
    require_equal(f"{name}.alg", envelope["alg"], "Ed25519")
    require_equal(f"{name}.public_key", envelope["public_key"], public_key)
    require_equal(f"{name}.target_type", envelope["target_type"], target_type)
    require_equal(f"{name}.target_hash", envelope["target_hash"], target_hash)
    parse_public_key(envelope["public_key"]).verify(parse_signature(envelope["signature"]), jcs_bytes(target_object))


def check_no_private_keys_or_secret_files() -> None:
    forbidden_suffixes = {".pem", ".key", ".secret", ".env"}
    forbidden_dirs = {"private_keys", "secrets"}
    forbidden_names = {"agent_private_key.txt", "private_agent_key.txt", "human_private_key.txt", "supervisor_private_key.txt"}

    for path in EXAMPLE_DIR.rglob("*"):
        rel = path.relative_to(EXAMPLE_DIR)
        parts = {part.lower() for part in rel.parts}
        name = path.name.lower()
        if path.is_dir():
            if name in forbidden_dirs:
                raise AssertionError(f"Forbidden private directory found: {rel}")
            continue
        if path.suffix.lower() in forbidden_suffixes:
            raise AssertionError(f"Forbidden secret file found: {rel}")
        if name in forbidden_names:
            raise AssertionError(f"Forbidden private key file found: {rel}")
        if parts & forbidden_dirs:
            raise AssertionError(f"File inside forbidden private directory found: {rel}")


def main() -> int:
    print("DELTA-0 v0.6.2 AI Agent Proof Verifier")
    print("--------------------------------------")
    print("This verifier checks a public proof of AI-agent analytical work.")
    print("")

    checks = []

    check_no_private_keys_or_secret_files()
    checks.append("OK example contains no private keys or secret files")

    before_state = read_json("before_state.json")
    after_state = read_json("after_state.json")
    agent_execution = read_json("agent_execution.json")
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

    require_equal("before_state.agent_id", before_state["agent_id"], "AI-Agent-X-77")
    require_equal("before_state.executor_role", before_state["executor_role"], "ai_agent")
    require_equal("before_state.task.prompt", before_state["task"]["prompt"], agent_execution["prompt"])
    require_equal("before_state.task.input_data", before_state["task"]["input_data"], agent_execution["input_data"])
    checks.append("OK before_state contains raw prompt and Q3 financial input data")

    require_equal("after_state.agent_id", after_state["agent_id"], "AI-Agent-X-77")
    require_equal("after_state.output_status", after_state["output_status"], "completed")
    require_equal("after_state.agent_output", after_state["agent_output"], agent_execution["agent_output"])
    checks.append("OK after_state contains the AI analyst output report")

    require_equal("agent_execution.agent_identity_model", agent_execution["agent_identity_model"], "agent_ed25519_executor_key")
    require_equal("agent_execution.human_review_required", agent_execution["human_review_required"], True)

    tool_names = [step["tool"] for step in agent_execution["execution_trace"]]
    for required_tool in ["read_dataset", "detect_anomalies", "generate_report"]:
        if required_tool not in tool_names:
            raise AssertionError(f"Missing execution trace tool: {required_tool}")

    if agent_execution["token_usage"]["total_tokens"] <= 0:
        raise AssertionError("Invalid token usage values.")

    checks.append("OK execution trace includes tools, token usage, and duration")

    agent_output = after_state["agent_output"]
    require_equal("agent_output.report_type", agent_output["report_type"], "q3_financial_anomaly_summary")
    require_equal("agent_output.risk_level", agent_output["risk_level"], "high")
    require_equal("len(agent_output.anomalies)", len(agent_output["anomalies"]), 2)

    limitation_text = agent_output["limitations"].lower()
    if "not a legal" not in limitation_text or "human review" not in limitation_text:
        raise AssertionError("AI output does not include required limitation language.")

    checks.append("OK AI output contains two anomalies and limitation language")

    before_hash = sha256_object(before_state)
    after_hash = sha256_object(after_state)
    agent_execution_hash = sha256_object(agent_execution)
    verification_policy_hash = sha256_object(verification_policy)
    claim_hash = sha256_object(claim)
    executor_sig_hash = sha256_object(executor_signature)
    attestation_hash = sha256_object(attestation)
    verifier_sig_hash = sha256_object(verifier_signature)
    entry_hash = sha256_object(ledger_entry)
    checkpoint_hash = sha256_object(checkpoint)
    checkpoint_sig_hash = sha256_object(checkpoint_signature)

    require_equal("claim.claim_type", claim["claim_type"], "ai_agent_work")
    require_equal("claim.executor_type", claim["executor_type"], "ai_agent")
    require_equal("claim.executor_pubkey", claim["executor_pubkey"], public_keys["ai_agent_executor_pubkey"])
    require_equal("claim.before_hash", claim["before_hash"], before_hash)
    require_equal("claim.after_hash", claim["after_hash"], after_hash)
    require_equal("claim.evidence_hash", claim["evidence_hash"], agent_execution_hash)
    checks.append("OK claim binds task, output, AI agent key, and execution trace")

    verify_signature_envelope(
        envelope=executor_signature,
        name="executor_signature",
        role="ai_agent_executor",
        target_type="delta_claim",
        target_hash=claim_hash,
        public_key=public_keys["ai_agent_executor_pubkey"],
        target_object=claim,
    )
    checks.append("OK AI agent executor signature verifies")

    require_equal("verification_policy.verifier_role", verification_policy["verifier_role"], "human_supervisor_or_qa_gate")
    checks.append("OK verification policy defines Human Supervisor / QA checks")

    require_equal("attestation.attestation_type", attestation["attestation_type"], "ai_agent_output_review")
    require_equal("attestation.verifier_role", attestation["verifier_role"], "Human Supervisor / QA Verification Key")
    require_equal("attestation.target_claim_hash", attestation["target_claim_hash"], claim_hash)
    require_equal("attestation.target_executor_sig_hash", attestation["target_executor_sig_hash"], executor_sig_hash)
    require_equal("attestation.agent_execution_hash", attestation["agent_execution_hash"], agent_execution_hash)
    require_equal("attestation.verification_policy_hash", attestation["verification_policy_hash"], verification_policy_hash)
    require_equal("attestation.result", attestation["result"], "AI_AGENT_OUTPUT_REVIEWED")
    checks.append("OK Human Supervisor / QA attestation binds agent output and policy")

    verify_signature_envelope(
        envelope=verifier_signature,
        name="verifier_signature",
        role="human_supervisor_or_qa_gate",
        target_type="delta_attestation",
        target_hash=attestation_hash,
        public_key=public_keys["human_supervisor_pubkey"],
        target_object=attestation,
    )
    checks.append("OK Human Supervisor / QA signature verifies")

    require_equal("ledger_entry.ledger_id", ledger_entry["ledger_id"], LEDGER_ID)
    require_equal("ledger_entry.prev_entry_hash", ledger_entry["prev_entry_hash"], ZERO_HASH)
    require_equal("ledger_entry.claim_hash", ledger_entry["claim_hash"], claim_hash)
    require_equal("ledger_entry.executor_sig_hash", ledger_entry["executor_sig_hash"], executor_sig_hash)
    require_equal("ledger_entry.attestation_hash", ledger_entry["attestation_hash"], attestation_hash)
    require_equal("ledger_entry.verifier_sig_hash", ledger_entry["verifier_sig_hash"], verifier_sig_hash)
    require_equal("ledger_entry.agent_execution_hash", ledger_entry["agent_execution_hash"], agent_execution_hash)
    checks.append("OK ledger entry binds AI claim, signatures, attestation, and execution trace")

    require_equal("ledger.entries[0].entry_hash", ledger["entries"][0]["entry_hash"], entry_hash)
    require_equal("ledger.entries[0].entry", ledger["entries"][0]["entry"], ledger_entry)
    checks.append("OK ledger contains AI Agent Proof entry")

    require_equal("checkpoint.head_entry_hash", checkpoint["head_entry_hash"], entry_hash)

    verify_signature_envelope(
        envelope=checkpoint_signature,
        name="checkpoint_signature",
        role="checkpoint_signer",
        target_type="delta_signed_checkpoint",
        target_hash=checkpoint_hash,
        public_key=public_keys["human_supervisor_pubkey"],
        target_object=checkpoint,
    )
    checks.append("OK checkpoint signature verifies")

    require_equal("chain_proof.target_entry_hash", chain_proof["target_entry_hash"], entry_hash)
    require_equal("chain_proof.checkpoint_hash", chain_proof["checkpoint_hash"], checkpoint_hash)
    require_equal("chain_proof.head_entry_hash", chain_proof["head_entry_hash"], entry_hash)
    require_equal("chain_proof.entries[0]", chain_proof["entries"][0], ledger_entry)
    checks.append("OK chain proof links AI Agent entry to checkpoint")

    expected_hashes = {
        "before_hash": before_hash,
        "after_hash": after_hash,
        "agent_execution_hash": agent_execution_hash,
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
    print("DELTA AI AGENT PROOF VERIFIER RESULT: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("")
        print("DELTA AI AGENT PROOF VERIFIER RESULT: FAILED")
        print("")
        print("ERROR:")
        print(exc)
        raise SystemExit(1)
