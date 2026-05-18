#!/usr/bin/env python3
"""DELTA replay verifier.

v1.8.1 goal:
- replay an existing signed DELTA Sensor Record from a fresh clone
- re-run the declared measurement method
- compare replay result against the signed record
- optionally verify a detached Proof of Intent attestation/signature/registry bundle

Security boundary:
- this verifies replay consistency for a signed sensor record
- it can verify that a separate intent key signed an attestation bound to the record hash
- it does not create a new signed replay proof yet
- it does not prove legal consent, ticket truth, real-world identity, registry governance, anchoring, or external-world truth
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence


SIGNATURE_PREFIX = "ed25519sig:"
PUBLIC_KEY_PREFIX = "ed25519:"
SHA256_PREFIX = "sha256:"
DELTA_PROTOCOL = "DELTA-0"
INTENT_ATTESTATION_TYPE = "delta_intent_attestation"
INTENT_SIGNATURE_TYPE = "delta_intent_signature"
INTENT_STATUS_NOT_REQUIRED = "INTENT_NOT_REQUIRED"
INTENT_STATUS_MISSING = "INTENT_MISSING"
INTENT_STATUS_INVALID = "INTENT_INVALID"
INTENT_STATUS_VERIFIED = "INTENT_VERIFIED"


def b64url_decode_unpadded(value: str, field: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"invalid base64url in {field}") from exc


def b64_decode_strict(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 in {field}") from exc


def sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def parse_iso_z(value: str | None) -> _dt.datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"expected ISO timestamp string, got {type(value).__name__}")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = _dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def run_text(cmd: Sequence[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + result.stdout
            + "\n\nSTDERR:\n"
            + result.stderr
        )
    return result


def run_bytes(cmd: Sequence[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + result.stdout.decode("utf-8", errors="replace")
            + "\n\nSTDERR:\n"
            + result.stderr.decode("utf-8", errors="replace")
        )
    return result


def verify_record_signature(record: dict[str, Any]) -> tuple[bool, str]:
    body = record.get("record_body")
    sig = record.get("record_signature") or {}

    if body is None:
        return False, "missing record_body"

    expected_hash = record.get("record_body_hash")
    actual_hash = sha256_prefixed(canonical_json_bytes(body))
    if expected_hash != actual_hash:
        return False, f"record_body_hash mismatch: expected {expected_hash}, got {actual_hash}"

    signed_hash = sig.get("signed_hash")
    if signed_hash != expected_hash:
        return False, f"signed_hash mismatch: expected {expected_hash}, got {signed_hash}"

    public_key_text = sig.get("executor_public_key") or sig.get("public_key")
    signature_text = sig.get("signature")

    if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
        return False, "missing or invalid executor/public key prefix"

    if not isinstance(signature_text, str) or not signature_text.startswith(SIGNATURE_PREFIX):
        return False, "missing or invalid signature prefix"

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = b64url_decode_unpadded(public_key_text[len(PUBLIC_KEY_PREFIX):], "public_key")
        signature_bytes = b64url_decode_unpadded(signature_text[len(SIGNATURE_PREFIX):], "signature")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, canonical_json_bytes(body))
    except Exception as exc:
        return False, f"signature verification failed: {exc}"

    return True, "ok"


def parse_public_key(public_key_value: str):
    if not isinstance(public_key_value, str) or not public_key_value.startswith(PUBLIC_KEY_PREFIX):
        raise ValueError("missing_or_invalid_intent_public_key_prefix")
    raw = b64_decode_strict(public_key_value[len(PUBLIC_KEY_PREFIX):], "intent_public_key")
    if len(raw) != 32:
        raise ValueError(f"invalid_intent_public_key_length:{len(raw)}")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(raw), raw


def parse_signature(signature_value: str) -> bytes:
    if not isinstance(signature_value, str) or not signature_value.startswith(SIGNATURE_PREFIX):
        raise ValueError("missing_or_invalid_intent_signature_prefix")
    raw = b64_decode_strict(signature_value[len(SIGNATURE_PREFIX):], "intent_signature")
    if len(raw) != 64:
        raise ValueError(f"invalid_intent_signature_length:{len(raw)}")
    return raw


def public_key_hash(public_key_value: str) -> str:
    _public_key, raw = parse_public_key(public_key_value)
    return sha256_prefixed(raw)


def load_registry(path: Path) -> dict[str, Any]:
    registry = read_json(path)
    if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
        raise ValueError("registry_must_be_object_with_keys_list")
    return registry


def find_registry_key(registry: dict[str, Any], public_key_value: str, created_at: str | None) -> tuple[bool, dict[str, Any] | None, str]:
    pk_hash = public_key_hash(public_key_value)
    matches = [entry for entry in registry.get("keys", []) if entry.get("public_key") == public_key_value or entry.get("public_key_hash") == pk_hash]
    if not matches:
        return False, None, "intent_public_key_not_found_in_registry"

    created_dt = parse_iso_z(created_at) if created_at else None
    for entry in matches:
        if entry.get("public_key") != public_key_value:
            continue
        if entry.get("public_key_hash") and entry.get("public_key_hash") != pk_hash:
            continue
        if created_dt is not None:
            active_from = parse_iso_z(entry.get("active_from")) if entry.get("active_from") else None
            revoked_at = parse_iso_z(entry.get("revoked_at")) if entry.get("revoked_at") else None
            if active_from and created_dt < active_from:
                continue
            if revoked_at and created_dt >= revoked_at:
                continue
        return True, entry, "registry_key_active_at_intent_created_at"

    return False, None, "registry_key_found_but_not_active_for_intent_created_at"



def validate_intent_required_fields(attestation: dict[str, Any], signature_doc: dict[str, Any]) -> tuple[bool, str]:
    missing: list[str] = []

    for field in ("type", "version", "protocol", "target", "approval", "policy", "created_at"):
        if field not in attestation:
            missing.append(f"attestation.{field}")

    target = attestation.get("target") if isinstance(attestation.get("target"), dict) else {}
    for field in ("record_hash", "record_type", "sensor_method"):
        if field not in target:
            missing.append(f"attestation.target.{field}")

    approval = attestation.get("approval") if isinstance(attestation.get("approval"), dict) else {}
    for field in ("ticket_id", "approver", "role", "reason"):
        if field not in approval:
            missing.append(f"attestation.approval.{field}")

    for field in ("type", "alg", "target_hash", "public_key", "public_key_hash", "signature"):
        if field not in signature_doc:
            missing.append(f"signature.{field}")

    if missing:
        return False, "missing_required_fields:" + ",".join(missing)
    return True, "required_fields_ok"

def intent_policy_ok(attestation: dict[str, Any], *, now: _dt.datetime | None = None) -> tuple[bool, str]:
    policy = attestation.get("policy", {})
    if not isinstance(policy, dict):
        return False, "policy_not_object"
    now_dt = now or _dt.datetime.now(_dt.timezone.utc)
    valid_from = parse_iso_z(policy.get("valid_from")) if policy.get("valid_from") else None
    valid_until = parse_iso_z(policy.get("valid_until")) if policy.get("valid_until") else None
    if valid_from and now_dt < valid_from:
        return False, "intent_not_yet_valid"
    if valid_until and now_dt > valid_until:
        return False, "intent_expired"
    return True, "intent_policy_time_ok"


def record_intent_policy_ok(record: dict[str, Any], attestation: dict[str, Any]) -> tuple[bool, str]:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    candidates = [record, body]

    intent_required = None
    deadline_value = None
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if "intent_required" in candidate:
            intent_required = candidate.get("intent_required")
        if "intent_deadline" in candidate:
            deadline_value = candidate.get("intent_deadline")

    if intent_required is None and deadline_value is None:
        return True, "record_has_no_intent_policy_fields_v1_8_detached_mode"
    if intent_required is not True:
        return False, "record_intent_required_is_not_true"
    if deadline_value:
        created_dt = parse_iso_z(attestation.get("created_at"))
        deadline_dt = parse_iso_z(deadline_value)
        if created_dt and deadline_dt and created_dt > deadline_dt:
            return False, "intent_created_after_record_intent_deadline"
    return True, "record_intent_policy_ok"


def record_declares_intent_required(record: dict[str, Any]) -> bool:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    return record.get("intent_required") is True or body.get("intent_required") is True


def verify_intent_bundle(
    *,
    record: dict[str, Any],
    attestation_path: Path | None,
    signature_path: Path | None,
    registry_path: Path | None,
) -> dict[str, Any]:
    supplied = [bool(attestation_path), bool(signature_path), bool(registry_path)]
    required_by_record = record_declares_intent_required(record)

    result: dict[str, Any] = {
        "status": INTENT_STATUS_NOT_REQUIRED,
        "ok": True,
        "checks": {},
        "reasons": {},
        "attestation_path": str(attestation_path) if attestation_path else "",
        "signature_path": str(signature_path) if signature_path else "",
        "registry_path": str(registry_path) if registry_path else "",
        "record_hash": canonical_sha256(record),
        "attestation_hash": "",
        "registry_key_id": "",
    }

    if not any(supplied) and not required_by_record:
        result["reasons"]["status"] = "intent_not_requested_and_record_does_not_require_intent"
        return result

    if not all(supplied):
        result["status"] = INTENT_STATUS_MISSING
        result["ok"] = False
        missing = []
        if not attestation_path:
            missing.append("intent_attestation")
        if not signature_path:
            missing.append("intent_signature")
        if not registry_path:
            missing.append("intent_registry")
        result["reasons"]["status"] = "missing_" + "_".join(missing)
        return result

    assert attestation_path is not None
    assert signature_path is not None
    assert registry_path is not None

    missing_paths = []
    if not attestation_path.exists():
        missing_paths.append("intent_attestation_file")
    if not signature_path.exists():
        missing_paths.append("intent_signature_file")
    if not registry_path.exists():
        missing_paths.append("intent_registry_file")
    if missing_paths:
        result["status"] = INTENT_STATUS_MISSING
        result["ok"] = False
        result["reasons"]["status"] = "missing_" + "_".join(missing_paths)
        return result

    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}
    registry_entry: dict[str, Any] | None = None

    try:
        attestation = read_json(attestation_path)
        signature_doc = read_json(signature_path)
        registry = load_registry(registry_path)
        checks["shape_ok"] = isinstance(attestation, dict) and isinstance(signature_doc, dict) and isinstance(registry, dict)
        reasons["shape"] = "json_shape_ok" if checks["shape_ok"] else "attestation_signature_registry_must_be_json_objects"
    except Exception as exc:
        result["status"] = INTENT_STATUS_INVALID
        result["ok"] = False
        result["checks"] = {"shape_ok": False}
        result["reasons"] = {"shape": f"intent_json_load_error:{type(exc).__name__}"}
        return result

    if not checks.get("shape_ok"):
        attestation = attestation if isinstance(attestation, dict) else {}
        signature_doc = signature_doc if isinstance(signature_doc, dict) else {}

    checks["attestation_type_ok"] = attestation.get("type") == INTENT_ATTESTATION_TYPE and attestation.get("protocol") == DELTA_PROTOCOL
    reasons["attestation_type"] = "attestation_type_ok" if checks["attestation_type_ok"] else "attestation_type_or_protocol_invalid"

    checks["signature_type_ok"] = signature_doc.get("type") == INTENT_SIGNATURE_TYPE and signature_doc.get("alg") == "Ed25519" and signature_doc.get("protocol") == DELTA_PROTOCOL
    reasons["signature_type"] = "signature_type_ok" if checks["signature_type_ok"] else "signature_type_alg_or_protocol_invalid"

    checks["required_fields_ok"], reasons["required_fields"] = validate_intent_required_fields(attestation, signature_doc)

    expected_target_hash = canonical_sha256(attestation)
    result["attestation_hash"] = expected_target_hash
    checks["target_hash_ok"] = signature_doc.get("target_hash") == expected_target_hash
    reasons["target_hash"] = "signature_target_hash_matches_attestation" if checks["target_hash_ok"] else "signature_target_hash_mismatch"

    public_key_value = signature_doc.get("public_key")
    signature_value = signature_doc.get("signature")

    try:
        public_key, _public_key_raw = parse_public_key(public_key_value)
        signature_raw = parse_signature(signature_value)
        public_key.verify(signature_raw, canonical_json_bytes(attestation))
        checks["signature_ok"] = True
        reasons["signature"] = "ed25519_signature_valid"
    except Exception as exc:
        checks["signature_ok"] = False
        reasons["signature"] = f"ed25519_signature_invalid:{type(exc).__name__}"

    try:
        expected_public_key_hash = public_key_hash(public_key_value)
        checks["public_key_hash_ok"] = signature_doc.get("public_key_hash") == expected_public_key_hash
        reasons["public_key_hash"] = "public_key_hash_ok" if checks["public_key_hash_ok"] else "public_key_hash_mismatch"
    except Exception as exc:
        checks["public_key_hash_ok"] = False
        reasons["public_key_hash"] = f"public_key_hash_error:{type(exc).__name__}"

    target = attestation.get("target", {}) if isinstance(attestation.get("target"), dict) else {}
    record_hash = canonical_sha256(record)
    result["record_hash"] = record_hash
    checks["record_binding_ok"] = target.get("record_hash") == record_hash and target.get("record_type") == "delta_sensor_record"
    reasons["record_binding"] = "intent_target_record_hash_matches_record" if checks["record_binding_ok"] else "intent_target_record_hash_mismatch"

    try:
        checks["intent_policy_ok"], reasons["intent_policy"] = intent_policy_ok(attestation)
    except Exception as exc:
        checks["intent_policy_ok"] = False
        reasons["intent_policy"] = f"intent_policy_error:{type(exc).__name__}"

    try:
        checks["record_intent_policy_ok"], reasons["record_intent_policy"] = record_intent_policy_ok(record, attestation)
    except Exception as exc:
        checks["record_intent_policy_ok"] = False
        reasons["record_intent_policy"] = f"record_intent_policy_error:{type(exc).__name__}"

    try:
        registry_ok, registry_entry, registry_reason = find_registry_key(registry, public_key_value, attestation.get("created_at"))
        checks["registry_ok"] = registry_ok
        reasons["registry"] = registry_reason
        if registry_entry:
            result["registry_key_id"] = str(registry_entry.get("id") or "")
    except Exception as exc:
        checks["registry_ok"] = False
        reasons["registry"] = f"registry_error:{type(exc).__name__}"

    all_ok = all([
        checks.get("shape_ok"),
        checks.get("attestation_type_ok"),
        checks.get("signature_type_ok"),
        checks.get("required_fields_ok"),
        checks.get("target_hash_ok"),
        checks.get("signature_ok"),
        checks.get("public_key_hash_ok"),
        checks.get("record_binding_ok"),
        checks.get("intent_policy_ok"),
        checks.get("record_intent_policy_ok"),
        checks.get("registry_ok"),
    ])

    result["status"] = INTENT_STATUS_VERIFIED if all_ok else INTENT_STATUS_INVALID
    result["ok"] = bool(all_ok)
    result["checks"] = checks
    result["reasons"] = reasons
    return result


def infer_method_path(method: dict[str, Any], clone_dir: Path) -> Path:
    explicit = method.get("method_definition_path")
    if explicit:
        return clone_dir / explicit

    method_id = method.get("method_id")
    candidates = [
        clone_dir / ".delta" / "methods" / f"{method_id}.json",
        clone_dir / ".delta" / "methods" / "delta-cli-verify-all-v1.json",
        clone_dir / ".delta" / "methods" / "python-unittest-v1.json",
        clone_dir / ".delta" / "methods" / "local-file-audit-v1.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            try:
                data = read_json(candidate)
                if data.get("method_id") == method_id:
                    return candidate
            except Exception:
                pass

    raise FileNotFoundError(f"cannot infer method definition path for method_id={method_id}")


def extract_file_audit_manifest_hash(stdout_text: str) -> str | None:
    match = re.search(r"DELTA_FILE_AUDIT_MANIFEST_HASH=(sha256:[0-9a-fA-F]+)", stdout_text)
    return match.group(1) if match else None


def find_original_file_audit_manifest_hash(record_path: Path, record: dict[str, Any]) -> str | None:
    evidence_root = record_path.parent

    for manifest_path in evidence_root.rglob("file-audit-manifest.json"):
        try:
            manifest = read_json(manifest_path)
            if isinstance(manifest.get("manifest_hash"), str):
                return manifest["manifest_hash"]
        except Exception:
            pass

    body = record.get("record_body") or {}
    for section_name in ("private_evidence_commitments", "evidence_commitments"):
        commitments = body.get(section_name) or []
        if not isinstance(commitments, list):
            continue
        for item in commitments:
            if not isinstance(item, dict):
                continue
            label = " ".join(str(item.get(k, "")) for k in ("name", "path", "type"))
            if "file-audit-manifest" in label or "file_audit_manifest" in label:
                value = item.get("hash") or item.get("sha256")
                if isinstance(value, str) and value.startswith("sha256:"):
                    return value

    return None


def collect_output_commitments(record: dict[str, Any]) -> dict[str, str]:
    body = record.get("record_body") or {}
    out: dict[str, str] = {}

    for section_name in ("private_evidence_commitments", "evidence_commitments"):
        commitments = body.get(section_name) or []
        if not isinstance(commitments, list):
            continue
        for item in commitments:
            if not isinstance(item, dict):
                continue
            label = " ".join(str(item.get(k, "")) for k in ("name", "path", "type")).lower()
            value = item.get("hash") or item.get("sha256")
            if not isinstance(value, str) or not value.startswith("sha256:"):
                continue
            if "stdout" in label or "output" in label:
                out.setdefault("stdout", value)
            if "stderr" in label or "error" in label:
                out.setdefault("stderr", value)

    return out


def write_report(path: Path, result: dict[str, Any]) -> None:
    lines: list[str] = []
    lines.append("# DELTA Replay Verification Report")
    lines.append("")
    lines.append(f"Status: {'PASS' if result['ok'] else 'FAIL'}")
    lines.append("")
    lines.append("## Record")
    lines.append("")
    lines.append(f"- Record path: `{result['record_path']}`")
    lines.append(f"- Method id: `{result['method_id']}`")
    lines.append(f"- Commit after: `{result['commit_after']}`")
    lines.append(f"- Fresh clone: `{result['clone_dir']}`")
    lines.append("")

    intent = result.get("intent") or {}
    lines.append("## Proof of Intent")
    lines.append("")
    lines.append(f"- Status: `{intent.get('status', INTENT_STATUS_NOT_REQUIRED)}`")
    lines.append(f"- Record hash: `{intent.get('record_hash', '')}`")
    if intent.get("attestation_hash"):
        lines.append(f"- Attestation hash: `{intent.get('attestation_hash')}`")
    if intent.get("registry_key_id"):
        lines.append(f"- Registry key id: `{intent.get('registry_key_id')}`")
    lines.append("")
    if intent.get("checks"):
        lines.append("| Intent check | Result | Detail |")
        lines.append("| --- | --- | --- |")
        intent_reasons = intent.get("reasons") or {}
        for key, value in sorted((intent.get("checks") or {}).items()):
            reason_key = key[:-3] if key.endswith("_ok") else key
            lines.append(f"| `{key}` | `{bool(value)}` | `{intent_reasons.get(reason_key, '')}` |")
        lines.append("")

    lines.append("## Checks")
    lines.append("")
    lines.append("| Check | Result | Detail |")
    lines.append("| --- | --- | --- |")
    for check in result["checks"]:
        lines.append(f"| {check['name']} | `{check['ok']}` | `{check['detail']}` |")
    lines.append("")
    lines.append("## Command")
    lines.append("")
    lines.append("```text")
    lines.append(" ".join(result["command"]))
    lines.append("```")
    lines.append("")
    lines.append("## Measurement output")
    lines.append("")
    lines.append("### Return code")
    lines.append("")
    lines.append("```text")
    lines.append(str(result["return_code"]))
    lines.append("```")
    lines.append("")
    lines.append("### STDOUT tail")
    lines.append("")
    lines.append("```text")
    lines.append(result["stdout_tail"])
    lines.append("```")
    lines.append("")
    lines.append("### STDERR tail")
    lines.append("")
    lines.append("```text")
    lines.append(result["stderr_tail"])
    lines.append("```")
    lines.append("")
    lines.append("## Security boundary")
    lines.append("")
    lines.append("This replay verification does not create a new signed replay proof.")
    lines.append("")
    lines.append("It checks whether the signed sensor record can be replayed from a fresh clone and whether the declared measurement result matches.")
    lines.append("")
    lines.append("When intent inputs are supplied, it also checks whether a detached Proof of Intent attestation is signed by a registered intent key and bound to this exact record hash.")
    lines.append("")
    lines.append("Proof of Intent does not prove legal consent, ticket truth, MFA truth, real-world identity, registry governance, anchoring, or external-world truth.")
    lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a signed DELTA Sensor Record from a fresh clone.")
    parser.add_argument("--record", required=True, help="Path to delta-record.json")
    parser.add_argument("--work-dir", default="", help="Optional directory for replay work. Default: temp dir.")
    parser.add_argument("--keep-workdir", action="store_true", help="Do not delete temporary replay directory.")
    parser.add_argument("--skip-install", action="store_true", help="Skip installing local Python SDK package.")
    parser.add_argument("--strict-output-hashes", action="store_true", help="Fail on stdout/stderr hash mismatch when commitments exist.")
    parser.add_argument("--report-out", default="", help="Optional markdown report output path.")
    parser.add_argument("--json-out", default="", help="Optional JSON report output path.")
    parser.add_argument("--intent-attestation", default="", help="Optional detached Proof of Intent attestation JSON path.")
    parser.add_argument("--intent-signature", default="", help="Optional detached Proof of Intent signature JSON path.")
    parser.add_argument("--intent-registry", default="", help="Optional Proof of Intent public key registry JSON path.")
    args = parser.parse_args()

    record_path = Path(args.record).resolve()
    record = read_json(record_path)

    body = record["record_body"]
    change = body["change"]
    method = body["measurement_method"]

    method_id = method.get("method_id")
    command = method.get("command")
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise SystemExit("record measurement_method.command must be an array of strings")

    signature_ok, signature_detail = verify_record_signature(record)

    intent_result = verify_intent_bundle(
        record=record,
        attestation_path=Path(args.intent_attestation).resolve() if args.intent_attestation else None,
        signature_path=Path(args.intent_signature).resolve() if args.intent_signature else None,
        registry_path=Path(args.intent_registry).resolve() if args.intent_registry else None,
    )

    repo_url = (
        (body.get("replay_instructions") or {}).get("repository_url")
        or (body.get("source") or {}).get("repository_url")
    )

    if not repo_url or repo_url == "<REPOSITORY_URL>":
        repo_url = run_text(["git", "remote", "get-url", "origin"], check=True).stdout.strip()

    commit_after = change["commit_after"]
    expected_after_state_hash = change.get("after_state_hash")
    expected_measurement_ok = bool(body["measurement_result"].get("ok"))
    expected_method_hash = method.get("method_definition_hash")

    replay_root = Path(args.work_dir).resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix="delta-replay-"))
    clone_dir = replay_root / "repo"

    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add_check("record_signature", signature_ok, signature_detail)

    try:
        if clone_dir.exists():
            shutil.rmtree(clone_dir)

        run_text(["git", "clone", repo_url, str(clone_dir)], check=True)
        run_text(["git", "checkout", commit_after], cwd=clone_dir, check=True)

        if not args.skip_install and (clone_dir / "packages" / "python" / "delta_protocol").exists():
            run_text(["python", "-m", "pip", "install", "-e", "./packages/python/delta_protocol"], cwd=clone_dir, check=True)

        tree = run_bytes(["git", "ls-tree", "-r", "-z", "--full-tree", commit_after], cwd=clone_dir, check=True)
        actual_after_state_hash = sha256_prefixed(tree.stdout)
        add_check(
            "after_state_hash",
            actual_after_state_hash == expected_after_state_hash,
            f"expected={expected_after_state_hash} actual={actual_after_state_hash}",
        )

        method_path = infer_method_path(method, clone_dir)
        method_json = read_json(method_path)
        actual_method_hash = sha256_prefixed(canonical_json_bytes(method_json))
        add_check(
            "method_definition_hash",
            actual_method_hash == expected_method_hash,
            f"expected={expected_method_hash} actual={actual_method_hash}",
        )

        measurement = run_text(command, cwd=clone_dir, check=False)
        success_condition = method.get("success_condition") or {}
        expected_return_code = success_condition.get("return_code", 0)
        stdout_contains = success_condition.get("stdout_contains")

        actual_measurement_ok = measurement.returncode == expected_return_code
        if isinstance(stdout_contains, str) and stdout_contains:
            actual_measurement_ok = actual_measurement_ok and stdout_contains in measurement.stdout

        add_check(
            "measurement_result_ok",
            actual_measurement_ok == expected_measurement_ok,
            f"expected={expected_measurement_ok} actual={actual_measurement_ok}",
        )

        if method_id == "local-file-audit-v1":
            original_manifest_hash = find_original_file_audit_manifest_hash(record_path, record)
            replay_manifest_hash = extract_file_audit_manifest_hash(measurement.stdout)
            add_check(
                "file_audit_manifest_hash",
                bool(original_manifest_hash and replay_manifest_hash and original_manifest_hash == replay_manifest_hash),
                f"expected={original_manifest_hash} actual={replay_manifest_hash}",
            )

        output_commitments = collect_output_commitments(record)
        stdout_hash = sha256_prefixed(measurement.stdout.encode("utf-8"))
        stderr_hash = sha256_prefixed(measurement.stderr.encode("utf-8"))

        if "stdout" in output_commitments:
            output_ok = stdout_hash == output_commitments["stdout"]
            add_check("stdout_hash", output_ok or not args.strict_output_hashes, f"expected={output_commitments['stdout']} actual={stdout_hash} strict={args.strict_output_hashes}")

        if "stderr" in output_commitments:
            output_ok = stderr_hash == output_commitments["stderr"]
            add_check("stderr_hash", output_ok or not args.strict_output_hashes, f"expected={output_commitments['stderr']} actual={stderr_hash} strict={args.strict_output_hashes}")

        hard_checks = [c for c in checks if c["name"] not in ("stdout_hash", "stderr_hash")]
        ok = all(c["ok"] for c in hard_checks) and all(c["ok"] for c in checks if args.strict_output_hashes)

        result = {
            "ok": ok,
            "record_path": str(record_path),
            "method_id": method_id,
            "commit_after": commit_after,
            "clone_dir": str(clone_dir),
            "command": command,
            "return_code": measurement.returncode,
            "checks": checks,
            "intent": intent_result,
            "stdout_tail": measurement.stdout[-4000:],
            "stderr_tail": measurement.stderr[-4000:],
        }

        if args.report_out:
            write_report(Path(args.report_out), result)

        if args.json_out:
            out_path = Path(args.json_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        print("DELTA_REPLAY_RESULT:", "OK" if ok else "FAILED")
        print(f"DELTA_REPLAY_METHOD_ID={method_id}")
        print(f"DELTA_REPLAY_COMMIT_AFTER={commit_after}")
        print(f"DELTA_REPLAY_INTENT_STATUS={intent_result['status']}")
        print(f"DELTA_REPLAY_INTENT_OK={bool(intent_result['ok'])}")
        print(f"DELTA_REPLAY_INTENT_SIGNATURE_OK={bool((intent_result.get('checks') or {}).get('signature_ok'))}")
        print(f"DELTA_REPLAY_INTENT_RECORD_BINDING_OK={bool((intent_result.get('checks') or {}).get('record_binding_ok'))}")
        print(f"DELTA_REPLAY_INTENT_REGISTRY_OK={bool((intent_result.get('checks') or {}).get('registry_ok'))}")
        if intent_result.get("record_hash"):
            print(f"DELTA_REPLAY_INTENT_RECORD_HASH={intent_result['record_hash']}")
        if intent_result.get("attestation_hash"):
            print(f"DELTA_REPLAY_INTENT_ATTESTATION_HASH={intent_result['attestation_hash']}")
        if intent_result.get("registry_key_id"):
            print(f"DELTA_REPLAY_INTENT_REGISTRY_KEY_ID={intent_result['registry_key_id']}")
        for check in checks:
            print(f"DELTA_REPLAY_CHECK_{check['name'].upper()}={check['ok']}")

        return 0 if ok else 1

    finally:
        if not args.keep_workdir and not args.work_dir:
            shutil.rmtree(replay_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
