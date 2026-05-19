#!/usr/bin/env python3
"""DELTA v2.7.1 intent create helper.

Creates a machine-generated Proof of Intent attestation draft bound to a full
DELTA delta-record.json hash. This tool is an adoption/UX helper: it does not
replace the existing Proof of Intent verifier or key registry.

Security boundary:
- Creates an attestation object and self-check hashes.
- Does not prove legal approval, real-world identity, signer authority, or
  regulatory compliance.
- Does not sign by default; detached signing/registry verification remains a
  separate DELTA proof step.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import secrets
import sys
from pathlib import Path
from typing import Any

PROFILE = "delta_intent_create_v2_7_1"
OBJECT_TYPE = "delta_intent_attestation"
SCHEMA_VERSION = "delta_intent_attestation_draft_v1"
MAX_SAFE_INTEGER = 9007199254740991


class DeltaIntentCreateError(Exception):
    pass


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_json_strict(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise DeltaIntentCreateError(f"duplicate JSON key: {key}")
            obj[key] = value
        return obj

    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_constant=lambda x: (_ for _ in ()).throw(DeltaIntentCreateError(f"invalid JSON constant: {x}")),
        )
    except DeltaIntentCreateError:
        raise
    except Exception as exc:
        raise DeltaIntentCreateError(f"invalid JSON: {type(exc).__name__}: {exc}") from exc


def validate_canonical_subset(value: Any, path: str = "$.") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise DeltaIntentCreateError(f"unsafe integer at {path}: {value}")
        return
    if isinstance(value, float):
        raise DeltaIntentCreateError(f"floating point value rejected at {path}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            validate_canonical_subset(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DeltaIntentCreateError(f"non-string key at {path}")
            validate_canonical_subset(item, f"{path}{key}.")
        return
    raise DeltaIntentCreateError(f"unsupported JSON type at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    validate_canonical_subset(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def hash_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def safe_id(prefix: str) -> str:
    return prefix + "-" + secrets.token_hex(8)


def validate_hash_shape(value: str) -> bool:
    return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value or ""))


def build_attestation(args: argparse.Namespace) -> dict[str, Any]:
    record_path = Path(args.record)
    if not record_path.exists():
        raise DeltaIntentCreateError(f"record file not found: {record_path}")

    # Parse as JSON for early user feedback, but bind to the full file bytes.
    read_json_strict(record_path)
    record_hash = hash_file(record_path)

    created_at = args.created_at or utc_now()
    intent_id = args.intent_id or safe_id("I")

    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "intent_id": intent_id,
        "created_at": created_at,
        "created_by": args.created_by,
        "role": args.role,
        "decision": args.decision,
        "issue": args.issue,
        "purpose": args.purpose,
        "reason": args.reason or "",
        "target": {
            "record_hash": record_hash,
            "record_binding": "full_delta_record_json_sha256",
        },
        "policy": {
            "policy_id": args.policy_id,
            "deadline": args.deadline or None,
            "enforcement": args.enforcement,
        },
        "source": {
            "source_type": args.source_type,
            "source_ref": args.source_ref or args.issue,
        },
        "security_boundary": {
            "not_legal_approval": True,
            "not_identity_proof": True,
            "not_regulatory_compliance": True,
            "requires_detached_signature_for_proof_of_intent": True,
        },
    }

    body_hash = canonical_hash(body)
    envelope = {
        "object_type": OBJECT_TYPE,
        "profile": PROFILE,
        "attestation_body": body,
        "attestation_body_hash": body_hash,
        "signature": None,
        "signature_status": "unsigned_draft",
        "integrity": {
            "canonical_json_profile": "delta_jcs_json_v1",
            "self_check_hash": body_hash,
        },
    }
    envelope["envelope_hash"] = canonical_hash({
        "object_type": envelope["object_type"],
        "profile": envelope["profile"],
        "attestation_body_hash": envelope["attestation_body_hash"],
        "signature_status": envelope["signature_status"],
    })
    return envelope


def create_command(args: argparse.Namespace) -> int:
    try:
        attestation = build_attestation(args)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        body = attestation["attestation_body"]
        print("DELTA_INTENT_CREATE_OK=True")
        print(f"DELTA_INTENT_ATTESTATION={out}")
        print(f"DELTA_INTENT_ID={body['intent_id']}")
        print(f"DELTA_INTENT_PROFILE={PROFILE}")
        print(f"DELTA_INTENT_RECORD_HASH={body['target']['record_hash']}")
        print(f"DELTA_INTENT_BODY_HASH={attestation['attestation_body_hash']}")
        print("DELTA_INTENT_SIGNATURE_CREATED=False")
        print("DELTA_INTENT_SIGNATURE_STATUS=unsigned_draft")
        print("DELTA_INTENT_SECURITY_BOUNDARY=technical_intent_attestation_not_legal_approval")
        return 0
    except Exception as exc:
        print("DELTA_INTENT_CREATE_OK=False")
        print(f"DELTA_INTENT_REASON={type(exc).__name__}:{exc}")
        return 1


def verify_command(args: argparse.Namespace) -> int:
    try:
        path = Path(args.attestation)
        data = read_json_strict(path)
        if not isinstance(data, dict):
            raise DeltaIntentCreateError("attestation must be a JSON object")
        body = data.get("attestation_body")
        if not isinstance(body, dict):
            raise DeltaIntentCreateError("missing attestation_body")

        expected_body_hash = canonical_hash(body)
        stored_body_hash = data.get("attestation_body_hash")
        body_hash_ok = stored_body_hash == expected_body_hash

        integrity = data.get("integrity") if isinstance(data.get("integrity"), dict) else {}
        self_check_ok = integrity.get("self_check_hash") == expected_body_hash
        record_hash = body.get("target", {}).get("record_hash") if isinstance(body.get("target"), dict) else ""
        record_hash_shape_ok = validate_hash_shape(record_hash)

        record_binding_ok = True
        if args.record:
            record_path = Path(args.record)
            if not record_path.exists():
                raise DeltaIntentCreateError(f"record file not found: {record_path}")
            read_json_strict(record_path)
            record_binding_ok = hash_file(record_path) == record_hash

        signature_status = data.get("signature_status")
        unsigned_draft_ok = signature_status == "unsigned_draft" and data.get("signature") is None

        ok = body_hash_ok and self_check_ok and record_hash_shape_ok and record_binding_ok and unsigned_draft_ok

        print(f"DELTA_INTENT_VERIFY_OK={ok}")
        print(f"DELTA_INTENT_BODY_HASH_OK={body_hash_ok}")
        print(f"DELTA_INTENT_SELF_CHECK_OK={self_check_ok}")
        print(f"DELTA_INTENT_RECORD_HASH_SHAPE_OK={record_hash_shape_ok}")
        print(f"DELTA_INTENT_RECORD_BINDING_OK={record_binding_ok}")
        print(f"DELTA_INTENT_UNSIGNED_DRAFT_OK={unsigned_draft_ok}")
        print(f"DELTA_INTENT_PROFILE={data.get('profile')}")
        print(f"DELTA_INTENT_RECORD_HASH={record_hash}")
        print(f"DELTA_INTENT_BODY_HASH={expected_body_hash}")
        if not body_hash_ok:
            print("DELTA_INTENT_REASON_BODY_HASH_OK=attestation_body_hash_mismatch")
        if not self_check_ok:
            print("DELTA_INTENT_REASON_SELF_CHECK_OK=self_check_hash_mismatch")
        if not record_binding_ok:
            print("DELTA_INTENT_REASON_RECORD_BINDING_OK=record_hash_mismatch")
        if not unsigned_draft_ok:
            print("DELTA_INTENT_REASON_UNSIGNED_DRAFT_OK=unexpected_signature_state")
        return 0 if ok else 1
    except Exception as exc:
        print("DELTA_INTENT_VERIFY_OK=False")
        print(f"DELTA_INTENT_REASON={type(exc).__name__}:{exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA v2.7.1 intent create helper")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create unsigned Proof of Intent attestation draft")
    create.add_argument("--record", required=True, help="Path to full delta-record.json")
    create.add_argument("--issue", required=True, help="Issue/ticket/change identifier, e.g. SEC-992")
    create.add_argument("--purpose", required=True, help="Human-readable purpose of the change")
    create.add_argument("--created-by", default="local-operator", help="Non-authoritative creator label")
    create.add_argument("--role", default="operator", help="Non-authoritative role label")
    create.add_argument("--decision", default="approved", choices=["approved", "rejected", "requested", "acknowledged"])
    create.add_argument("--reason", default="", help="Optional reason/context")
    create.add_argument("--policy-id", default="intent-policy-v1")
    create.add_argument("--deadline", default=None, help="Optional deadline timestamp")
    create.add_argument("--enforcement", default="report_only", choices=["report_only", "required"])
    create.add_argument("--source-type", default="manual", choices=["manual", "github_issue", "jira", "api", "ci"])
    create.add_argument("--source-ref", default=None)
    create.add_argument("--intent-id", default=None)
    create.add_argument("--created-at", default=None)
    create.add_argument("--out", required=True)
    create.set_defaults(func=create_command)

    verify = sub.add_parser("verify", help="Verify unsigned intent attestation draft integrity")
    verify.add_argument("--attestation", required=True)
    verify.add_argument("--record", default=None, help="Optional delta-record.json path for record binding verification")
    verify.set_defaults(func=verify_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
