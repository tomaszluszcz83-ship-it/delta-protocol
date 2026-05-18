#!/usr/bin/env python3
"""
DELTA Protocol - Proof of Intent MVP tool.

Commands:
  keygen   Generate an Ed25519 intent keypair and optional public registry entry.
  approve  Create a detached intent attestation and detached signature for a DELTA record.
  verify   Verify the intent attestation, signature, record binding, and key registry.

Security boundary:
  This tool proves that a private Ed25519 intent key signed a canonical intent
  attestation bound by hash to a specific DELTA record. It does not prove legal
  consent, ticket truth, real-world identity, MFA truth, or absolute source truth.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
except Exception as exc:  # pragma: no cover - user-facing import guard
    print("DELTA_INTENT_ERROR=missing_python_dependency_cryptography", file=sys.stderr)
    print(f"DETAIL={exc}", file=sys.stderr)
    sys.exit(2)

DELTA_PROTOCOL = "DELTA-0"
INTENT_ATTESTATION_TYPE = "delta_intent_attestation"
INTENT_SIGNATURE_TYPE = "delta_intent_signature"
INTENT_ATTESTATION_VERSION = "1.0.0"
ED25519_PUBLIC_PREFIX = "ed25519:"
ED25519_PRIVATE_SEED_PREFIX = "ed25519seed:"
ED25519_SIGNATURE_PREFIX = "ed25519sig:"
SHA256_PREFIX = "sha256:"


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: Optional[str]) -> Optional[_dt.datetime]:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Expected ISO timestamp string, got: {type(value).__name__}")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = _dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return SHA256_PREFIX + hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def raw_sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def write_json(path: Path, obj: Any, *, overwrite: bool = True) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_private_key_file(path: Path, content: str, *, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing private key file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")
    # Best effort on POSIX. On Windows, users should store this outside the repo and/or protect it with DPAPI.
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_prefixed_b64(value: str, prefix: str, expected_len: Optional[int] = None) -> bytes:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError(f"Expected value with prefix {prefix!r}")
    raw = b64d(value[len(prefix):])
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"Expected {expected_len} raw bytes for prefix {prefix!r}, got {len(raw)}")
    return raw


def parse_private_key_file(path: Path) -> Tuple[Ed25519PrivateKey, str]:
    value = read_text(path)
    seed = parse_prefixed_b64(value, ED25519_PRIVATE_SEED_PREFIX, 32)
    return Ed25519PrivateKey.from_private_bytes(seed), value


def public_key_string(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return ED25519_PUBLIC_PREFIX + b64e(raw)


def public_key_hash(public_key_value: str) -> str:
    raw = parse_prefixed_b64(public_key_value, ED25519_PUBLIC_PREFIX, 32)
    return raw_sha256_prefixed(raw)


def public_key_from_string(public_key_value: str) -> Ed25519PublicKey:
    raw = parse_prefixed_b64(public_key_value, ED25519_PUBLIC_PREFIX, 32)
    return Ed25519PublicKey.from_public_bytes(raw)


def signature_from_string(signature_value: str) -> bytes:
    return parse_prefixed_b64(signature_value, ED25519_SIGNATURE_PREFIX, 64)


def extract_sensor_method(record: Dict[str, Any]) -> str:
    candidates = [
        ("measurement", "method_id"),
        ("measurement", "method"),
        ("method", "id"),
        ("sensor", "method_id"),
        ("sensor", "method"),
    ]
    for first, second in candidates:
        value = record.get(first)
        if isinstance(value, dict) and value.get(second):
            return str(value[second])
    for key in ("measurement_method", "method_id", "sensor_method"):
        if record.get(key):
            return str(record[key])
    return "unknown"


def extract_commit_after(record: Dict[str, Any]) -> Optional[str]:
    candidates = [
        ("git", "commit_after"),
        ("git", "after"),
        ("commit", "after"),
        ("repository", "commit_after"),
    ]
    for first, second in candidates:
        value = record.get(first)
        if isinstance(value, dict) and value.get(second):
            return str(value[second])
    for key in ("commit_after", "after_commit", "commit_sha", "commit"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def make_registry_entry(key_id: str, public_key_value: str, owner: str, role: str, active_from: str) -> Dict[str, Any]:
    return {
        "id": key_id,
        "public_key": public_key_value,
        "public_key_hash": public_key_hash(public_key_value),
        "owner": owner,
        "role": role,
        "active_from": active_from,
        "revoked_at": None,
    }


def load_registry(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None:
        return None
    if not path.exists():
        raise FileNotFoundError(f"Registry file not found: {path}")
    registry = read_json(path)
    if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
        raise ValueError("Registry must be a JSON object containing a 'keys' list")
    return registry


def find_registry_key(registry: Optional[Dict[str, Any]], public_key_value: str, created_at: Optional[str]) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    if registry is None:
        return True, None, "registry_not_provided"

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


def intent_policy_ok(attestation: Dict[str, Any], *, now: Optional[_dt.datetime] = None) -> Tuple[bool, str]:
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


def record_intent_policy_ok(record: Dict[str, Any], attestation: Dict[str, Any]) -> Tuple[bool, str]:
    """Forward-compatible check for future sensor fields intent_required/intent_deadline.

    Existing v1.4-v1.7 sensor records usually do not include these fields. Absence is treated
    as compatible for v1.8.0 detached MVP verification.
    """
    intent_required = record.get("intent_required")
    deadline_value = record.get("intent_deadline")
    if intent_required is None and deadline_value is None:
        return True, "record_has_no_intent_policy_fields_v1_8_0_detached_mode"
    if intent_required is not True:
        return False, "record_intent_required_is_not_true"
    if deadline_value:
        created_dt = parse_iso_z(attestation.get("created_at"))
        deadline_dt = parse_iso_z(deadline_value)
        if created_dt and deadline_dt and created_dt > deadline_dt:
            return False, "intent_created_after_record_intent_deadline"
    return True, "record_intent_policy_ok"


def cmd_keygen(args: argparse.Namespace) -> int:
    created_at = args.active_from or utc_now_iso()
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public = private_key.public_key()
    private_value = ED25519_PRIVATE_SEED_PREFIX + b64e(seed)
    public_value = public_key_string(public)
    entry = make_registry_entry(args.key_id, public_value, args.owner, args.role, created_at)

    write_private_key_file(Path(args.private_out), private_value, overwrite=args.force)
    public_doc = {
        "type": "delta_intent_public_key",
        "version": "1.0.0",
        "protocol": DELTA_PROTOCOL,
        "key": entry,
        "created_at": created_at,
    }
    write_json(Path(args.public_out), public_doc, overwrite=True)

    if args.registry_out:
        registry_path = Path(args.registry_out)
        if registry_path.exists():
            registry = read_json(registry_path)
            if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
                raise ValueError("Existing registry must be a JSON object containing a 'keys' list")
            registry = copy.deepcopy(registry)
            registry["keys"] = [k for k in registry["keys"] if k.get("id") != args.key_id]
            registry["keys"].append(entry)
            registry.setdefault("type", "delta_intent_key_registry")
            registry.setdefault("version", "1.0.0")
            registry.setdefault("protocol", DELTA_PROTOCOL)
            registry["updated_at"] = utc_now_iso()
        else:
            registry = {
                "type": "delta_intent_key_registry",
                "version": "1.0.0",
                "protocol": DELTA_PROTOCOL,
                "created_at": created_at,
                "updated_at": created_at,
                "keys": [entry],
            }
        write_json(registry_path, registry, overwrite=True)

    print("DELTA_INTENT_KEYGEN_OK=True")
    print(f"DELTA_INTENT_PRIVATE_KEY_WRITTEN={Path(args.private_out)}")
    print(f"DELTA_INTENT_PUBLIC_KEY_WRITTEN={Path(args.public_out)}")
    if args.registry_out:
        print(f"DELTA_INTENT_REGISTRY_WRITTEN={Path(args.registry_out)}")
    print(f"DELTA_INTENT_PUBLIC_KEY_HASH={entry['public_key_hash']}")
    print("DELTA_INTENT_PRIVATE_KEY_WARNING=do_not_commit_do_not_paste_to_chat")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    record_path = Path(args.record)
    record = read_json(record_path)
    if not isinstance(record, dict):
        raise ValueError("DELTA record must be a JSON object")

    private_key, _private_value = parse_private_key_file(Path(args.private_key))
    public_value = public_key_string(private_key.public_key())
    pk_hash = public_key_hash(public_value)
    created_at = args.created_at or utc_now_iso()
    valid_from = args.valid_from
    valid_until = args.valid_until
    time_window = None
    if valid_from and valid_until:
        time_window = f"{valid_from}/{valid_until}"

    attestation = {
        "type": INTENT_ATTESTATION_TYPE,
        "version": INTENT_ATTESTATION_VERSION,
        "protocol": DELTA_PROTOCOL,
        "target": {
            "record_hash": canonical_sha256(record),
            "record_type": "delta_sensor_record",
            "sensor_method": args.sensor_method or extract_sensor_method(record),
            "commit_after": args.commit_after or extract_commit_after(record),
        },
        "approval": {
            "ticket_id": args.ticket,
            "approver": args.approver,
            "role": args.role,
            "reason": args.reason,
        },
        "policy": {
            "requires_mfa": bool(args.requires_mfa),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "time_window": time_window,
        },
        "created_at": created_at,
    }

    target_hash = canonical_sha256(attestation)
    signature_raw = private_key.sign(canonical_json_bytes(attestation))
    signature_doc = {
        "type": INTENT_SIGNATURE_TYPE,
        "version": "1.0.0",
        "protocol": DELTA_PROTOCOL,
        "alg": "Ed25519",
        "target_hash": target_hash,
        "public_key": public_value,
        "public_key_hash": pk_hash,
        "signature": ED25519_SIGNATURE_PREFIX + b64e(signature_raw),
        "key_hint": pk_hash.replace(SHA256_PREFIX, "")[:16],
        "created_at": created_at,
    }

    out_dir = Path(args.out_dir)
    write_json(out_dir / "delta-record.intent.json", attestation, overwrite=True)
    write_json(out_dir / "delta-record.intent.sig.json", signature_doc, overwrite=True)

    print("DELTA_INTENT_APPROVE_OK=True")
    print(f"DELTA_INTENT_ATTESTATION_WRITTEN={out_dir / 'delta-record.intent.json'}")
    print(f"DELTA_INTENT_SIGNATURE_WRITTEN={out_dir / 'delta-record.intent.sig.json'}")
    print(f"DELTA_INTENT_TARGET_RECORD_HASH={attestation['target']['record_hash']}")
    print(f"DELTA_INTENT_TARGET_HASH={target_hash}")
    print(f"DELTA_INTENT_PUBLIC_KEY_HASH={pk_hash}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    attestation = read_json(Path(args.attestation))
    signature_doc = read_json(Path(args.signature))
    record = read_json(Path(args.record))
    registry = load_registry(Path(args.registry)) if args.registry else None

    checks: Dict[str, Any] = {}
    reasons: Dict[str, str] = {}

    checks["shape_ok"] = isinstance(attestation, dict) and isinstance(signature_doc, dict) and isinstance(record, dict)
    if not checks["shape_ok"]:
        reasons["shape"] = "attestation_signature_and_record_must_be_json_objects"
    else:
        reasons["shape"] = "json_shape_ok"

    checks["attestation_type_ok"] = attestation.get("type") == INTENT_ATTESTATION_TYPE and attestation.get("protocol") == DELTA_PROTOCOL
    checks["signature_type_ok"] = signature_doc.get("type") == INTENT_SIGNATURE_TYPE and signature_doc.get("alg") == "Ed25519" and signature_doc.get("protocol") == DELTA_PROTOCOL

    expected_target_hash = canonical_sha256(attestation)
    checks["target_hash_ok"] = signature_doc.get("target_hash") == expected_target_hash
    reasons["target_hash"] = "signature_target_hash_matches_attestation" if checks["target_hash_ok"] else "signature_target_hash_mismatch"

    public_key_value = signature_doc.get("public_key")
    signature_value = signature_doc.get("signature")
    try:
        public_key = public_key_from_string(public_key_value)
        signature_raw = signature_from_string(signature_value)
        public_key.verify(signature_raw, canonical_json_bytes(attestation))
        checks["signature_ok"] = True
        reasons["signature"] = "ed25519_signature_valid"
    except (InvalidSignature, Exception) as exc:
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
    except Exception as exc:
        checks["registry_ok"] = False
        registry_entry = None
        reasons["registry"] = f"registry_error:{type(exc).__name__}"

    all_ok = all([
        checks.get("shape_ok"),
        checks.get("attestation_type_ok"),
        checks.get("signature_type_ok"),
        checks.get("target_hash_ok"),
        checks.get("signature_ok"),
        checks.get("public_key_hash_ok"),
        checks.get("record_binding_ok"),
        checks.get("intent_policy_ok"),
        checks.get("record_intent_policy_ok"),
        checks.get("registry_ok"),
    ])

    print(f"DELTA_INTENT_VERIFY_OK={str(bool(all_ok))}")
    print(f"DELTA_INTENT_SIGNATURE_OK={str(bool(checks.get('signature_ok')))}")
    print(f"DELTA_INTENT_TARGET_HASH_OK={str(bool(checks.get('target_hash_ok')))}")
    print(f"DELTA_INTENT_RECORD_BINDING_OK={str(bool(checks.get('record_binding_ok')))}")
    print(f"DELTA_INTENT_PUBLIC_KEY_HASH_OK={str(bool(checks.get('public_key_hash_ok')))}")
    print(f"DELTA_INTENT_POLICY_OK={str(bool(checks.get('intent_policy_ok')))}")
    print(f"DELTA_INTENT_RECORD_POLICY_OK={str(bool(checks.get('record_intent_policy_ok')))}")
    print(f"DELTA_INTENT_REGISTRY_OK={str(bool(checks.get('registry_ok')))}")
    print(f"DELTA_INTENT_RECORD_HASH={record_hash}")
    print(f"DELTA_INTENT_ATTESTATION_HASH={expected_target_hash}")
    if registry_entry:
        print(f"DELTA_INTENT_REGISTRY_KEY_ID={registry_entry.get('id')}")
    for key in sorted(reasons):
        print(f"DELTA_INTENT_REASON_{key.upper()}={reasons[key]}")

    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Intent MVP CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate an Ed25519 intent keypair and registry entry")
    keygen.add_argument("--private-out", required=True)
    keygen.add_argument("--public-out", required=True)
    keygen.add_argument("--registry-out")
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--owner", required=True)
    keygen.add_argument("--role", required=True)
    keygen.add_argument("--active-from")
    keygen.add_argument("--force", action="store_true", help="Allow overwriting an existing private key file")
    keygen.set_defaults(func=cmd_keygen)

    approve = sub.add_parser("approve", help="Create a detached intent attestation and signature for a record")
    approve.add_argument("--record", required=True)
    approve.add_argument("--ticket", required=True)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--role", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--private-key", required=True)
    approve.add_argument("--out-dir", required=True)
    approve.add_argument("--requires-mfa", action="store_true")
    approve.add_argument("--valid-from")
    approve.add_argument("--valid-until")
    approve.add_argument("--created-at")
    approve.add_argument("--sensor-method")
    approve.add_argument("--commit-after")
    approve.set_defaults(func=cmd_approve)

    verify = sub.add_parser("verify", help="Verify detached intent against a DELTA record")
    verify.add_argument("--attestation", required=True)
    verify.add_argument("--signature", required=True)
    verify.add_argument("--record", required=True)
    verify.add_argument("--registry")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print("DELTA_INTENT_ERROR=True", file=sys.stderr)
        print(f"DELTA_INTENT_ERROR_TYPE={type(exc).__name__}", file=sys.stderr)
        print(f"DELTA_INTENT_ERROR_DETAIL={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
