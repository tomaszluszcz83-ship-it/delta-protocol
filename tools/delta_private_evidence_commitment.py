#!/usr/bin/env python3
"""
DELTA v2.14.0 Private Evidence Commitment Profile.

Purpose:
- Create public commitments to private evidence without publishing raw evidence.
- Create private opening files for later auditor-side disclosure.
- Verify public commitment package self-checks.
- Verify disclosed evidence against a public commitment and a private opening.

Security boundary:
- This is not encryption.
- This is not ZK.
- Public commitments do not prove evidence truth or policy satisfaction.
- Disclosure verification proves that provided evidence/opening matches a public commitment.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROFILE = "delta_private_evidence_commitment_v2_14_0"
COMMITMENT_DOMAIN = b"DELTA_PRIVATE_EVIDENCE_COMMITMENT_V1"


class DeltaPrivateEvidenceCommitmentError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    )


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def commitment_for(evidence_hash: str, salt_b64u: str, label: str, method_id: str) -> str:
    payload = canonical_json(
        {
            "domain": COMMITMENT_DOMAIN.decode("ascii"),
            "evidence_hash": evidence_hash,
            "label": label,
            "method_id": method_id,
            "salt": salt_b64u,
        }
    )
    return sha256_bytes(payload)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DeltaPrivateEvidenceCommitmentError(f"failed to read JSON: {path}: {exc}") from exc

    if not isinstance(value, dict):
        raise DeltaPrivateEvidenceCommitmentError(f"JSON root is not an object: {path}")

    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_sha256(value: str) -> str:
    value = value.strip()
    return value if value.startswith("sha256:") else "sha256:" + value


def validate_sha256(value: str, field: str) -> None:
    if not isinstance(value, str):
        raise DeltaPrivateEvidenceCommitmentError(f"{field} must be a string")
    normalized = normalize_sha256(value)
    hex_part = normalized.split("sha256:", 1)[1]
    if len(hex_part) != 64 or any(c not in "0123456789abcdef" for c in hex_part.lower()):
        raise DeltaPrivateEvidenceCommitmentError(f"{field} is not a valid sha256-prefixed hash")


def package_body_hash(package: dict[str, Any]) -> str:
    body = dict(package)
    body.pop("self_check", None)
    return sha256_bytes(canonical_json(body))


def create_commitment(args: argparse.Namespace) -> int:
    evidence = Path(args.evidence).resolve()
    if not evidence.exists() or not evidence.is_file():
        raise DeltaPrivateEvidenceCommitmentError(f"evidence file does not exist: {evidence}")

    label = args.label
    method_id = "salted_sha256_private_evidence_commitment_v1"
    evidence_hash = sha256_file(evidence)
    salt = b64u(secrets.token_bytes(32))
    commitment = commitment_for(evidence_hash, salt, label, method_id)

    entry = {
        "label": label,
        "method_id": method_id,
        "commitment": commitment,
        "evidence_size_bytes": evidence.stat().st_size,
        "hash_alg": "sha256",
        "salt_disclosure_required": True,
        "security_boundary": {
            "does_not_publish_raw_evidence": True,
            "does_not_prove_evidence_truth": True,
            "does_not_prove_policy_satisfaction": True,
            "not_encryption": True,
            "not_zero_knowledge": True,
        },
    }

    public_package: dict[str, Any] = {
        "type": "delta_private_evidence_commitment_package",
        "profile": PROFILE,
        "created_at": utc_now(),
        "record_hash": normalize_sha256(args.record_hash) if args.record_hash else None,
        "policy_id": args.policy_id,
        "entries": [entry],
        "security_boundary": {
            "public_package_contains_commitments_only": True,
            "private_opening_required_for_disclosure": True,
            "does_not_prove_legal_truth": True,
            "does_not_replace_audit_decryption_or_zk": True,
        },
    }

    public_package["self_check"] = {
        "hash_alg": "sha256",
        "package_body_hash": package_body_hash(public_package),
    }

    opening = {
        "type": "delta_private_evidence_opening",
        "profile": PROFILE,
        "created_at": utc_now(),
        "public_package_hint": str(args.out_public),
        "label": label,
        "method_id": method_id,
        "evidence_hash": evidence_hash,
        "salt": salt,
        "commitment": commitment,
        "security_boundary": {
            "private_opening_must_not_be_committed_publicly": True,
            "reveals_evidence_hash_and_salt": True,
            "not_encryption": True,
            "not_zero_knowledge": True,
        },
    }

    write_json(Path(args.out_public), public_package)
    write_json(Path(args.out_opening), opening)

    print("DELTA_PRIVATE_EVIDENCE_COMMITMENT_CREATE_OK=True")
    print(f"DELTA_PRIVATE_EVIDENCE_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_PUBLIC={args.out_public}")
    print(f"DELTA_PRIVATE_EVIDENCE_OPENING={args.out_opening}")
    print(f"DELTA_PRIVATE_EVIDENCE_LABEL={label}")
    print(f"DELTA_PRIVATE_EVIDENCE_COMMITMENT={commitment}")
    print("DELTA_PRIVATE_EVIDENCE_WARNING=opening_file_is_private_do_not_commit")
    return 0


def verify_public(args: argparse.Namespace) -> int:
    package = load_json(Path(args.public))
    errors: list[str] = []

    if package.get("type") != "delta_private_evidence_commitment_package":
        errors.append("type_invalid")

    if package.get("profile") != PROFILE:
        errors.append(f"profile_invalid:{package.get('profile')}")

    entries = package.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries_missing_or_empty")
    else:
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                errors.append(f"entry_not_object:{idx}")
                continue
            commitment = entry.get("commitment")
            try:
                validate_sha256(commitment, f"entries[{idx}].commitment")
            except Exception as exc:
                errors.append(str(exc))
            if entry.get("method_id") != "salted_sha256_private_evidence_commitment_v1":
                errors.append(f"entry_method_id_invalid:{idx}")

    declared = None
    if isinstance(package.get("self_check"), dict):
        declared = package["self_check"].get("package_body_hash")

    computed = package_body_hash(package)

    if not declared:
        errors.append("self_check_package_body_hash_missing")
    elif declared != computed:
        errors.append(f"self_check_package_body_hash_mismatch:declared={declared}:computed={computed}")

    ok = len(errors) == 0

    print(f"DELTA_PRIVATE_EVIDENCE_PUBLIC_VERIFY_OK={'True' if ok else 'False'}")
    print(f"DELTA_PRIVATE_EVIDENCE_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_DECLARED_PACKAGE_BODY_HASH={declared}")
    print(f"DELTA_PRIVATE_EVIDENCE_COMPUTED_PACKAGE_BODY_HASH={computed}")
    for error in errors:
        print(f"DELTA_PRIVATE_EVIDENCE_ERROR={error}")

    return 0 if ok else 1


def disclose(args: argparse.Namespace) -> int:
    package = load_json(Path(args.public))
    opening = load_json(Path(args.opening))
    evidence = Path(args.evidence).resolve()

    errors: list[str] = []

    if not evidence.exists() or not evidence.is_file():
        errors.append(f"evidence_file_missing:{evidence}")

    if package.get("profile") != PROFILE:
        errors.append(f"public_profile_invalid:{package.get('profile')}")

    if opening.get("profile") != PROFILE:
        errors.append(f"opening_profile_invalid:{opening.get('profile')}")

    entries = package.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("public_entries_missing")
        entry = None
    else:
        label = args.label or opening.get("label")
        matches = [e for e in entries if isinstance(e, dict) and e.get("label") == label]
        entry = matches[0] if matches else None
        if not entry:
            errors.append(f"public_entry_not_found_for_label:{label}")

    evidence_hash = sha256_file(evidence) if evidence.exists() else None
    opening_hash = opening.get("evidence_hash")
    salt = opening.get("salt")
    label = opening.get("label")
    method_id = opening.get("method_id")

    if not isinstance(opening_hash, str):
        errors.append("opening_evidence_hash_missing")
    elif evidence_hash and opening_hash != evidence_hash:
        errors.append(f"opening_evidence_hash_mismatch:opening={opening_hash}:computed={evidence_hash}")

    if not isinstance(salt, str) or not salt:
        errors.append("opening_salt_missing")

    if not isinstance(label, str) or not label:
        errors.append("opening_label_missing")

    if method_id != "salted_sha256_private_evidence_commitment_v1":
        errors.append(f"opening_method_id_invalid:{method_id}")

    computed_commitment = None
    if isinstance(opening_hash, str) and isinstance(salt, str) and isinstance(label, str) and isinstance(method_id, str):
        computed_commitment = commitment_for(opening_hash, salt, label, method_id)

    opening_commitment = opening.get("commitment")
    if computed_commitment and opening_commitment != computed_commitment:
        errors.append(f"opening_commitment_mismatch:opening={opening_commitment}:computed={computed_commitment}")

    if entry:
        public_commitment = entry.get("commitment")
        if computed_commitment and public_commitment != computed_commitment:
            errors.append(f"public_commitment_mismatch:public={public_commitment}:computed={computed_commitment}")

    ok = len(errors) == 0

    print(f"DELTA_PRIVATE_EVIDENCE_DISCLOSE_VERIFY_OK={'True' if ok else 'False'}")
    print(f"DELTA_PRIVATE_EVIDENCE_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_LABEL={label}")
    print(f"DELTA_PRIVATE_EVIDENCE_COMPUTED_EVIDENCE_HASH={evidence_hash}")
    print(f"DELTA_PRIVATE_EVIDENCE_COMPUTED_COMMITMENT={computed_commitment}")
    for error in errors:
        print(f"DELTA_PRIVATE_EVIDENCE_ERROR={error}")

    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Private Evidence Commitment Profile v2.14.0")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a public commitment and private opening")
    create.add_argument("--evidence", required=True)
    create.add_argument("--label", required=True)
    create.add_argument("--out-public", required=True)
    create.add_argument("--out-opening", required=True)
    create.add_argument("--record-hash", default=None)
    create.add_argument("--policy-id", default=None)
    create.set_defaults(func=create_commitment)

    verify = sub.add_parser("verify-public", help="Verify public commitment package self-checks")
    verify.add_argument("--public", required=True)
    verify.set_defaults(func=verify_public)

    disclose_parser = sub.add_parser("disclose", help="Verify disclosed evidence against public commitment and private opening")
    disclose_parser.add_argument("--public", required=True)
    disclose_parser.add_argument("--opening", required=True)
    disclose_parser.add_argument("--evidence", required=True)
    disclose_parser.add_argument("--label", default=None)
    disclose_parser.set_defaults(func=disclose)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)
    except DeltaPrivateEvidenceCommitmentError as exc:
        print("DELTA_PRIVATE_EVIDENCE_RESULT=False")
        print(f"DELTA_PRIVATE_EVIDENCE_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
