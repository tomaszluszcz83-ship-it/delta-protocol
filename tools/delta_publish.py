#!/usr/bin/env python3
"""DELTA Proof of Publication / Anchoring tool.

v2.0.1 goal:
- compute the SHA-256 hash of a full canonical delta-record.json
- create a standalone publication proof bound to that record hash
- bind optional external anchor artifacts, including OpenTimestamps pending .ots files
- verify a publication proof offline, including external artifact hash binding when supplied

Security boundary:
- Proof of Publication proves a publication/anchor claim for a record hash object.
- It does not prove the legal truth, ticket truth, audit truth, real-world identity,
  external timestamp authority, or correctness of the underlying change.
- opentimestamps_pending_v1 binds a DELTA record hash to an OTS artifact hash.
  It does not prove final Bitcoin anchoring unless a future online OTS verification
  step confirms the timestamp.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any

PROTOCOL = "DELTA-0"
SHA256_PREFIX = "sha256:"
PROOF_TYPE = "delta_publication_proof"
PROOF_BODY_TYPE = "delta_publication_proof_body"
PROOF_VERSION = "1.0.1"
SUPPORTED_METHODS = {
    "local_timestamp_v1",
    "github_release_asset_v1",
    "opentimestamps_pending_v1",
    "external_anchor_reference_v1",
}


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return SHA256_PREFIX + h.hexdigest()


def load_record(path: Path) -> dict[str, Any]:
    record = read_json(path)
    if not isinstance(record, dict):
        raise SystemExit("record JSON must be an object")
    return record


def record_type(record: dict[str, Any]) -> str:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    value = body.get("type") or record.get("type") or "delta_sensor_record"
    return str(value)


def make_record_target(record: dict[str, Any], record_path: Path) -> dict[str, Any]:
    return {
        "record_hash": canonical_sha256(record),
        "record_type": record_type(record),
        "record_path_hint": str(record_path),
        "hash_algorithm": "sha256(canonical_json(full_delta_record_json))",
    }


def proof_body_hash(body: dict[str, Any]) -> str:
    return canonical_sha256(body)


def external_evidence_type_for_method(method: str, external_file: Path | None) -> str:
    if method == "opentimestamps_pending_v1":
        return "opentimestamps_ots_file"
    if method == "github_release_asset_v1":
        return "github_release_asset"
    if method == "external_anchor_reference_v1":
        return "external_anchor_reference"
    if external_file is not None:
        return "external_evidence_file"
    return ""


def resolve_external_file_hash(external_file: str, external_hash: str) -> tuple[str, Path | None]:
    if not external_file:
        if external_hash and not external_hash.startswith(SHA256_PREFIX):
            raise SystemExit("--external-hash must start with sha256:")
        return external_hash, None

    path = Path(external_file).resolve()
    if not path.exists() or not path.is_file():
        raise SystemExit(f"--external-file not found or not a file: {path}")

    computed_hash = file_sha256(path)
    if external_hash:
        if not external_hash.startswith(SHA256_PREFIX):
            raise SystemExit("--external-hash must start with sha256:")
        if external_hash != computed_hash:
            raise SystemExit("--external-hash does not match --external-file hash")

    return computed_hash, path


def create_publication_body(
    *,
    record: dict[str, Any],
    record_path: Path,
    method: str,
    publisher: str,
    external_uri: str,
    external_hash: str,
    external_file_path: Path | None,
    note: str,
) -> dict[str, Any]:
    if method not in SUPPORTED_METHODS:
        raise SystemExit(f"unsupported publication method: {method}")

    publication: dict[str, Any] = {
        "method": method,
        "created_at": now_utc(),
        "publisher": publisher,
        "status": "created",
        "verification_mode": "offline_shape_hash_and_optional_external_file_binding_v2_0_1",
    }

    evidence_type = external_evidence_type_for_method(method, external_file_path)

    if external_uri:
        publication["external_evidence_uri"] = external_uri

    if external_file_path is not None:
        publication["external_evidence_path_hint"] = str(external_file_path)
        publication["external_evidence_filename"] = external_file_path.name

    if external_hash:
        publication["external_evidence_hash"] = external_hash
        publication["external_evidence_hash_algorithm"] = "sha256(file_bytes)"
        if evidence_type:
            publication["external_evidence_type"] = evidence_type

    if method == "opentimestamps_pending_v1":
        publication["opentimestamps"] = {
            "status": "pending_or_unverified",
            "artifact_bound": bool(external_hash),
            "online_verification_performed": False,
            "note": "v2.0.1 binds the supplied .ots artifact hash offline. It does not confirm final Bitcoin anchoring.",
        }

    if note:
        publication["note"] = note

    body = {
        "type": PROOF_BODY_TYPE,
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "target": make_record_target(record, record_path),
        "publication": publication,
        "security_boundary": {
            "proves_record_hash_publication_claim": True,
            "proves_legal_truth": False,
            "proves_change_truth": False,
            "proves_ticket_truth": False,
            "proves_audit_truth": False,
            "proves_external_world_truth": False,
            "proves_final_opentimestamps_anchoring": False,
            "note": "Proof of Publication binds a publication or anchor artifact claim to a DELTA record hash. External timestamp strength depends on method and independently verifiable evidence.",
        },
    }
    return body


def create_proof(body: dict[str, Any]) -> dict[str, Any]:
    body_hash = proof_body_hash(body)
    proof = {
        "type": PROOF_TYPE,
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "proof_body_hash": body_hash,
        "proof_body": body,
        "proof_integrity": {
            "hash_algorithm": "sha256(canonical_json(proof_body))",
            "self_check_hash": body_hash,
            "signed": False,
            "signature": None,
            "note": "v2.0.1 uses hash integrity. Optional publication signing may be added later.",
        },
    }
    return proof


def verify_publication_proof(
    *,
    proof: dict[str, Any],
    record: dict[str, Any] | None = None,
    external_file: Path | None = None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    checks["proof_shape_ok"] = isinstance(proof, dict) and isinstance(proof.get("proof_body"), dict)
    reasons["proof_shape"] = "proof_shape_ok" if checks["proof_shape_ok"] else "proof_must_be_object_with_proof_body"

    body = proof.get("proof_body") if isinstance(proof.get("proof_body"), dict) else {}
    checks["proof_type_ok"] = proof.get("type") == PROOF_TYPE and proof.get("protocol") == PROTOCOL
    reasons["proof_type"] = "proof_type_ok" if checks["proof_type_ok"] else "proof_type_or_protocol_invalid"

    checks["body_type_ok"] = body.get("type") == PROOF_BODY_TYPE and body.get("protocol") == PROTOCOL
    reasons["body_type"] = "body_type_ok" if checks["body_type_ok"] else "proof_body_type_or_protocol_invalid"

    expected_body_hash = canonical_sha256(body)
    checks["proof_body_hash_ok"] = proof.get("proof_body_hash") == expected_body_hash
    reasons["proof_body_hash"] = "proof_body_hash_matches" if checks["proof_body_hash_ok"] else "proof_body_hash_mismatch"

    integrity = proof.get("proof_integrity") if isinstance(proof.get("proof_integrity"), dict) else {}
    checks["self_check_ok"] = integrity.get("self_check_hash") in (None, expected_body_hash)
    reasons["self_check"] = "self_check_ok" if checks["self_check_ok"] else "proof_integrity_self_check_hash_mismatch"

    target = body.get("target") if isinstance(body.get("target"), dict) else {}
    publication = body.get("publication") if isinstance(body.get("publication"), dict) else {}

    target_record_hash = target.get("record_hash")
    checks["target_hash_shape_ok"] = isinstance(target_record_hash, str) and target_record_hash.startswith(SHA256_PREFIX)
    reasons["target_hash_shape"] = "target_hash_shape_ok" if checks["target_hash_shape_ok"] else "target_record_hash_missing_or_invalid"

    method = publication.get("method")
    checks["publication_method_ok"] = method in SUPPORTED_METHODS
    reasons["publication_method"] = "publication_method_supported" if checks["publication_method_ok"] else f"unsupported_publication_method:{method}"

    created_at = publication.get("created_at")
    try:
        if not isinstance(created_at, str) or not created_at:
            raise ValueError("missing_created_at")
        normalized = created_at[:-1] + "+00:00" if created_at.endswith("Z") else created_at
        parsed = _dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        checks["publication_timestamp_ok"] = True
        reasons["publication_timestamp"] = "publication_timestamp_parse_ok"
    except Exception as exc:
        checks["publication_timestamp_ok"] = False
        reasons["publication_timestamp"] = f"publication_timestamp_invalid:{type(exc).__name__}"

    checks["record_binding_ok"] = True
    reasons["record_binding"] = "record_not_supplied_binding_not_checked"
    record_hash = ""
    if record is not None:
        record_hash = canonical_sha256(record)
        checks["record_binding_ok"] = target_record_hash == record_hash
        reasons["record_binding"] = "target_record_hash_matches_record" if checks["record_binding_ok"] else "target_record_hash_mismatch"

    declared_external_hash = publication.get("external_evidence_hash")
    checks["external_evidence_hash_shape_ok"] = True
    reasons["external_evidence_hash_shape"] = "no_external_evidence_hash_declared"
    if declared_external_hash:
        checks["external_evidence_hash_shape_ok"] = isinstance(declared_external_hash, str) and declared_external_hash.startswith(SHA256_PREFIX)
        reasons["external_evidence_hash_shape"] = "external_evidence_hash_shape_ok" if checks["external_evidence_hash_shape_ok"] else "external_evidence_hash_invalid"

    checks["external_file_hash_ok"] = True
    reasons["external_file_hash"] = "external_file_not_supplied"
    external_file_hash = ""
    if external_file is not None:
        if not external_file.exists() or not external_file.is_file():
            checks["external_file_hash_ok"] = False
            reasons["external_file_hash"] = "external_file_missing"
        elif not declared_external_hash:
            checks["external_file_hash_ok"] = False
            external_file_hash = file_sha256(external_file)
            reasons["external_file_hash"] = "proof_has_no_external_evidence_hash"
        else:
            external_file_hash = file_sha256(external_file)
            checks["external_file_hash_ok"] = external_file_hash == declared_external_hash
            reasons["external_file_hash"] = "external_file_hash_matches_proof" if checks["external_file_hash_ok"] else "external_file_hash_mismatch"

    checks["opentimestamps_pending_shape_ok"] = True
    reasons["opentimestamps_pending_shape"] = "not_opentimestamps_method"
    if method == "opentimestamps_pending_v1":
        ots = publication.get("opentimestamps") if isinstance(publication.get("opentimestamps"), dict) else {}
        checks["opentimestamps_pending_shape_ok"] = (
            isinstance(ots, dict)
            and ots.get("online_verification_performed") is False
            and "external_evidence_hash" in publication
            and publication.get("external_evidence_type") == "opentimestamps_ots_file"
        )
        reasons["opentimestamps_pending_shape"] = "opentimestamps_pending_shape_ok" if checks["opentimestamps_pending_shape_ok"] else "opentimestamps_pending_shape_invalid"

    ok = all(checks.values())
    return {
        "ok": bool(ok),
        "checks": checks,
        "reasons": reasons,
        "record_hash": record_hash or target_record_hash or "",
        "proof_body_hash": expected_body_hash,
        "method": method or "",
        "publication_created_at": created_at or "",
        "external_file_hash": external_file_hash,
        "external_evidence_hash": declared_external_hash or "",
    }


def command_hash_record(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = load_record(record_path)
    record_hash = canonical_sha256(record)
    print(f"DELTA_PUBLICATION_RECORD_HASH={record_hash}")
    print(f"DELTA_PUBLICATION_RECORD_TYPE={record_type(record)}")
    print(f"DELTA_PUBLICATION_RECORD_PATH={record_path}")
    return 0


def command_create_proof(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = load_record(record_path)

    external_hash, external_file_path = resolve_external_file_hash(args.external_file, args.external_hash)

    body = create_publication_body(
        record=record,
        record_path=record_path,
        method=args.method,
        publisher=args.publisher,
        external_uri=args.external_uri,
        external_hash=external_hash,
        external_file_path=external_file_path,
        note=args.note,
    )
    proof = create_proof(body)
    out_path = Path(args.out).resolve()
    write_json(out_path, proof)

    print("DELTA_PUBLICATION_CREATE_OK=True")
    print(f"DELTA_PUBLICATION_PROOF={out_path}")
    print(f"DELTA_PUBLICATION_RECORD_HASH={body['target']['record_hash']}")
    print(f"DELTA_PUBLICATION_PROOF_BODY_HASH={proof['proof_body_hash']}")
    print(f"DELTA_PUBLICATION_METHOD={body['publication']['method']}")
    print(f"DELTA_PUBLICATION_CREATED_AT={body['publication']['created_at']}")
    if external_hash:
        print(f"DELTA_PUBLICATION_EXTERNAL_EVIDENCE_HASH={external_hash}")
    if external_file_path is not None:
        print(f"DELTA_PUBLICATION_EXTERNAL_FILE={external_file_path}")
    return 0


def command_verify_proof(args: argparse.Namespace) -> int:
    proof_path = Path(args.proof).resolve()
    proof = read_json(proof_path)
    if not isinstance(proof, dict):
        raise SystemExit("publication proof JSON must be an object")

    record = None
    if args.record:
        record = load_record(Path(args.record).resolve())

    external_file = Path(args.external_file).resolve() if args.external_file else None
    result = verify_publication_proof(proof=proof, record=record, external_file=external_file)
    checks = result["checks"]
    reasons = result["reasons"]

    print(f"DELTA_PUBLICATION_VERIFY_OK={bool(result['ok'])}")
    print(f"DELTA_PUBLICATION_PROOF_SHAPE_OK={bool(checks.get('proof_shape_ok'))}")
    print(f"DELTA_PUBLICATION_PROOF_BODY_HASH_OK={bool(checks.get('proof_body_hash_ok'))}")
    print(f"DELTA_PUBLICATION_SELF_CHECK_OK={bool(checks.get('self_check_ok'))}")
    print(f"DELTA_PUBLICATION_RECORD_BINDING_OK={bool(checks.get('record_binding_ok'))}")
    print(f"DELTA_PUBLICATION_METHOD_OK={bool(checks.get('publication_method_ok'))}")
    print(f"DELTA_PUBLICATION_TIMESTAMP_OK={bool(checks.get('publication_timestamp_ok'))}")
    print(f"DELTA_PUBLICATION_EXTERNAL_HASH_SHAPE_OK={bool(checks.get('external_evidence_hash_shape_ok'))}")
    print(f"DELTA_PUBLICATION_EXTERNAL_FILE_HASH_OK={bool(checks.get('external_file_hash_ok'))}")
    print(f"DELTA_PUBLICATION_OPENTIMESTAMPS_PENDING_SHAPE_OK={bool(checks.get('opentimestamps_pending_shape_ok'))}")
    print(f"DELTA_PUBLICATION_RECORD_HASH={result.get('record_hash', '')}")
    print(f"DELTA_PUBLICATION_PROOF_BODY_HASH={result.get('proof_body_hash', '')}")
    print(f"DELTA_PUBLICATION_METHOD={result.get('method', '')}")
    print(f"DELTA_PUBLICATION_CREATED_AT={result.get('publication_created_at', '')}")
    if result.get("external_evidence_hash"):
        print(f"DELTA_PUBLICATION_EXTERNAL_EVIDENCE_HASH={result.get('external_evidence_hash', '')}")
    if result.get("external_file_hash"):
        print(f"DELTA_PUBLICATION_EXTERNAL_FILE_HASH={result.get('external_file_hash', '')}")
    if not result["ok"]:
        for key, ok in sorted(checks.items()):
            if not ok:
                reason_key = key[:-3] if key.endswith("_ok") else key
                print(f"DELTA_PUBLICATION_REASON_{key.upper()}={reasons.get(reason_key, '')}")
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Publication / Anchoring tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_record = subparsers.add_parser("hash-record", help="Compute the full canonical delta-record.json hash.")
    hash_record.add_argument("--record", required=True, help="Path to delta-record.json")
    hash_record.set_defaults(func=command_hash_record)

    create = subparsers.add_parser("create-proof", help="Create a publication proof bound to a DELTA record hash.")
    create.add_argument("--record", required=True, help="Path to delta-record.json")
    create.add_argument("--out", required=True, help="Path for delta-publication-proof.json")
    create.add_argument("--method", default="local_timestamp_v1", choices=sorted(SUPPORTED_METHODS), help="Publication/anchor method")
    create.add_argument("--publisher", default="local-publisher", help="Publisher label")
    create.add_argument("--external-uri", default="", help="Optional external evidence URI")
    create.add_argument("--external-hash", default="", help="Optional sha256: hash of external evidence")
    create.add_argument("--external-file", default="", help="Optional external evidence file, e.g. an OpenTimestamps .ots file. The file hash is recorded in the proof.")
    create.add_argument("--note", default="MVP publication proof. External anchoring can be attached later.", help="Optional publication note")
    create.set_defaults(func=command_create_proof)

    verify = subparsers.add_parser("verify-proof", help="Verify a publication proof offline.")
    verify.add_argument("--proof", required=True, help="Path to delta-publication-proof.json")
    verify.add_argument("--record", default="", help="Optional path to delta-record.json for binding check")
    verify.add_argument("--external-file", default="", help="Optional external evidence file to hash-check against the proof.")
    verify.set_defaults(func=command_verify_proof)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
