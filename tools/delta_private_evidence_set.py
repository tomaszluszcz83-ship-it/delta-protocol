#!/usr/bin/env python3
"""
DELTA v2.15.0 Private Evidence Package / Merkle Evidence Set.

Purpose:
- Create a public Merkle root over multiple private evidence commitments.
- Create a private opening package with salts, evidence hashes, and Merkle proofs.
- Verify public package self-checks and Merkle root.
- Verify disclosed evidence against public package, private opening, and Merkle proof.

Security boundary:
- This is not encryption.
- This is not zero-knowledge.
- This does not prove evidence truth, completeness, policy satisfaction, legal approval, or compliance.
- It proves consistency between disclosed evidence, private opening, public commitment entry, and public Merkle root.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROFILE = "delta_private_evidence_merkle_set_v2_15_0"
COMMITMENT_METHOD_ID = "salted_sha256_private_evidence_commitment_v1"
LEAF_METHOD_ID = "delta_private_evidence_merkle_leaf_v1"
TREE_METHOD_ID = "delta_private_evidence_merkle_tree_v1"

COMMITMENT_DOMAIN = "DELTA_PRIVATE_EVIDENCE_COMMITMENT_V1"
LEAF_DOMAIN = "DELTA_PRIVATE_EVIDENCE_MERKLE_LEAF_V1"
NODE_DOMAIN = "DELTA_PRIVATE_EVIDENCE_MERKLE_NODE_V1"


class DeltaPrivateEvidenceSetError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def normalize_sha256(value: str) -> str:
    value = value.strip()
    return value if value.startswith("sha256:") else "sha256:" + value


def validate_sha256(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise DeltaPrivateEvidenceSetError(f"{field} must be a string")
    value = normalize_sha256(value)
    hex_part = value.split("sha256:", 1)[1]
    if len(hex_part) != 64 or any(c not in "0123456789abcdef" for c in hex_part.lower()):
        raise DeltaPrivateEvidenceSetError(f"{field} is not a valid sha256-prefixed hash")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DeltaPrivateEvidenceSetError(f"failed to read JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DeltaPrivateEvidenceSetError(f"JSON root is not an object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def package_body_hash(package: dict[str, Any]) -> str:
    body = dict(package)
    body.pop("self_check", None)
    return sha256_bytes(canonical_json(body))


def commitment_for(evidence_hash: str, salt_b64u: str, label: str) -> str:
    return sha256_bytes(
        canonical_json(
            {
                "domain": COMMITMENT_DOMAIN,
                "evidence_hash": evidence_hash,
                "label": label,
                "method_id": COMMITMENT_METHOD_ID,
                "salt": salt_b64u,
            }
        )
    )


def leaf_hash_for(index: int, label: str, commitment: str) -> str:
    return sha256_bytes(
        canonical_json(
            {
                "commitment": commitment,
                "domain": LEAF_DOMAIN,
                "index": index,
                "label": label,
                "method_id": LEAF_METHOD_ID,
            }
        )
    )


def node_hash(left: str, right: str) -> str:
    return sha256_bytes(
        canonical_json(
            {
                "domain": NODE_DOMAIN,
                "left": left,
                "method_id": TREE_METHOD_ID,
                "right": right,
            }
        )
    )


def build_merkle_tree(leaves: list[str]) -> tuple[str, list[list[str]]]:
    if not leaves:
        raise DeltaPrivateEvidenceSetError("cannot build Merkle tree with zero leaves")
    levels = [leaves[:]]
    current = leaves[:]
    while len(current) > 1:
        nxt: list[str] = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                nxt.append(node_hash(current[i], current[i + 1]))
            else:
                nxt.append(current[i])
        levels.append(nxt)
        current = nxt
    return current[0], levels


def merkle_proof_for(index: int, levels: list[list[str]]) -> list[dict[str, str]]:
    proof: list[dict[str, str]] = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sibling_idx = idx + 1
            if sibling_idx < len(level):
                proof.append({"position": "right", "sibling_hash": level[sibling_idx]})
        else:
            sibling_idx = idx - 1
            proof.append({"position": "left", "sibling_hash": level[sibling_idx]})
        idx //= 2
    return proof


def verify_proof(leaf_hash: str, proof: list[dict[str, str]], expected_root: str) -> bool:
    current = leaf_hash
    for step in proof:
        if not isinstance(step, dict):
            return False
        position = step.get("position")
        sibling = step.get("sibling_hash")
        if position not in {"left", "right"} or not isinstance(sibling, str):
            return False
        if position == "left":
            current = node_hash(sibling, current)
        else:
            current = node_hash(current, sibling)
    return current == expected_root


def iter_evidence_files(root: Path, pattern: str) -> list[Path]:
    files = [
        p
        for p in root.rglob("*")
        if p.is_file() and fnmatch.fnmatch(p.name, pattern)
    ]
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def create(args: argparse.Namespace) -> int:
    evidence_dir = Path(args.evidence_dir).resolve()
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        raise DeltaPrivateEvidenceSetError(f"evidence directory does not exist: {evidence_dir}")

    evidence_files = iter_evidence_files(evidence_dir, args.pattern)
    if not evidence_files:
        raise DeltaPrivateEvidenceSetError(f"no evidence files found in {evidence_dir} with pattern {args.pattern!r}")

    public_entries: list[dict[str, Any]] = []
    opening_entries: list[dict[str, Any]] = []

    for index, evidence_path in enumerate(evidence_files):
        label = evidence_path.relative_to(evidence_dir).as_posix()
        evidence_hash = sha256_file(evidence_path)
        salt = b64u(secrets.token_bytes(32))
        commitment = commitment_for(evidence_hash, salt, label)
        leaf_hash = leaf_hash_for(index, label, commitment)

        public_entries.append(
            {
                "index": index,
                "label": label,
                "method_id": COMMITMENT_METHOD_ID,
                "leaf_method_id": LEAF_METHOD_ID,
                "commitment": commitment,
                "leaf_hash": leaf_hash,
                "evidence_size_bytes": evidence_path.stat().st_size,
                "salt_disclosure_required": True,
            }
        )

        opening_entries.append(
            {
                "index": index,
                "label": label,
                "evidence_path_hint": str(evidence_path),
                "evidence_hash": evidence_hash,
                "salt": salt,
                "commitment": commitment,
                "leaf_hash": leaf_hash,
            }
        )

    leaves = [entry["leaf_hash"] for entry in public_entries]
    merkle_root, levels = build_merkle_tree(leaves)

    for entry in opening_entries:
        entry["merkle_proof"] = merkle_proof_for(int(entry["index"]), levels)
        entry["merkle_root"] = merkle_root

    public_package: dict[str, Any] = {
        "type": "delta_private_evidence_merkle_set",
        "profile": PROFILE,
        "created_at": utc_now(),
        "record_hash": normalize_sha256(args.record_hash) if args.record_hash else None,
        "policy_id": args.policy_id,
        "evidence_count": len(public_entries),
        "merkle": {
            "hash_alg": "sha256",
            "tree_method_id": TREE_METHOD_ID,
            "leaf_method_id": LEAF_METHOD_ID,
            "node_domain": NODE_DOMAIN,
            "leaf_count": len(public_entries),
            "root": merkle_root,
        },
        "entries": public_entries,
        "security_boundary": {
            "public_package_contains_commitments_only": True,
            "private_opening_required_for_disclosure": True,
            "does_not_reveal_raw_evidence": True,
            "does_not_prove_evidence_truth": True,
            "does_not_prove_policy_satisfaction": True,
            "not_encryption": True,
            "not_zero_knowledge": True,
        },
    }
    public_package["self_check"] = {
        "hash_alg": "sha256",
        "package_body_hash": package_body_hash(public_package),
    }

    opening_package = {
        "type": "delta_private_evidence_merkle_opening",
        "profile": PROFILE,
        "created_at": utc_now(),
        "public_package_hint": str(args.out_public),
        "merkle_root": merkle_root,
        "entries": opening_entries,
        "security_boundary": {
            "private_opening_must_not_be_committed_publicly": True,
            "reveals_evidence_hashes_salts_and_merkle_proofs": True,
            "not_encryption": True,
            "not_zero_knowledge": True,
        },
    }

    write_json(Path(args.out_public), public_package)
    write_json(Path(args.out_opening), opening_package)

    print("DELTA_PRIVATE_EVIDENCE_SET_CREATE_OK=True")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_PUBLIC={args.out_public}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_OPENING={args.out_opening}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COUNT={len(public_entries)}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_MERKLE_ROOT={merkle_root}")
    print("DELTA_PRIVATE_EVIDENCE_SET_WARNING=opening_file_is_private_do_not_commit")
    return 0


def verify_public(args: argparse.Namespace) -> int:
    package = read_json(Path(args.public))
    errors: list[str] = []

    if package.get("type") != "delta_private_evidence_merkle_set":
        errors.append("type_invalid")
    if package.get("profile") != PROFILE:
        errors.append(f"profile_invalid:{package.get('profile')}")

    entries = package.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries_missing_or_empty")
        entries = []

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry_not_object:{idx}")
            continue
        try:
            validate_sha256(entry.get("commitment"), f"entries[{idx}].commitment")
            validate_sha256(entry.get("leaf_hash"), f"entries[{idx}].leaf_hash")
        except DeltaPrivateEvidenceSetError as exc:
            errors.append(str(exc))

        expected_leaf = None
        if isinstance(entry.get("label"), str) and isinstance(entry.get("commitment"), str) and isinstance(entry.get("index"), int):
            expected_leaf = leaf_hash_for(entry["index"], entry["label"], entry["commitment"])
            if expected_leaf != entry.get("leaf_hash"):
                errors.append(f"entry_leaf_hash_mismatch:{idx}:declared={entry.get('leaf_hash')}:computed={expected_leaf}")

    leaves = [entry.get("leaf_hash") for entry in entries if isinstance(entry, dict) and isinstance(entry.get("leaf_hash"), str)]
    computed_root = None
    if leaves:
        computed_root, _ = build_merkle_tree(leaves)

    merkle = package.get("merkle")
    declared_root = merkle.get("root") if isinstance(merkle, dict) else None
    if declared_root != computed_root:
        errors.append(f"merkle_root_mismatch:declared={declared_root}:computed={computed_root}")

    declared_body_hash = package.get("self_check", {}).get("package_body_hash") if isinstance(package.get("self_check"), dict) else None
    computed_body_hash = package_body_hash(package)
    if declared_body_hash != computed_body_hash:
        errors.append(f"self_check_package_body_hash_mismatch:declared={declared_body_hash}:computed={computed_body_hash}")

    ok = len(errors) == 0

    print(f"DELTA_PRIVATE_EVIDENCE_SET_PUBLIC_VERIFY_OK={'True' if ok else 'False'}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_DECLARED_ROOT={declared_root}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COMPUTED_ROOT={computed_root}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_DECLARED_PACKAGE_BODY_HASH={declared_body_hash}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COMPUTED_PACKAGE_BODY_HASH={computed_body_hash}")
    for error in errors:
        print(f"DELTA_PRIVATE_EVIDENCE_SET_ERROR={error}")
    return 0 if ok else 1


def disclose(args: argparse.Namespace) -> int:
    public = read_json(Path(args.public))
    opening = read_json(Path(args.opening))
    evidence = Path(args.evidence).resolve()

    errors: list[str] = []

    if public.get("profile") != PROFILE:
        errors.append(f"public_profile_invalid:{public.get('profile')}")
    if opening.get("profile") != PROFILE:
        errors.append(f"opening_profile_invalid:{opening.get('profile')}")
    if not evidence.exists() or not evidence.is_file():
        errors.append(f"evidence_file_missing:{evidence}")

    label = args.label
    if not label:
        errors.append("label_required")

    public_entries = public.get("entries")
    opening_entries = opening.get("entries")

    if not isinstance(public_entries, list):
        errors.append("public_entries_missing")
        public_entries = []
    if not isinstance(opening_entries, list):
        errors.append("opening_entries_missing")
        opening_entries = []

    public_entry = next((e for e in public_entries if isinstance(e, dict) and e.get("label") == label), None)
    opening_entry = next((e for e in opening_entries if isinstance(e, dict) and e.get("label") == label), None)

    if not public_entry:
        errors.append(f"public_entry_not_found:{label}")
    if not opening_entry:
        errors.append(f"opening_entry_not_found:{label}")

    evidence_hash = sha256_file(evidence) if evidence.exists() else None
    salt = opening_entry.get("salt") if opening_entry else None

    computed_commitment = None
    computed_leaf_hash = None
    if evidence_hash and isinstance(salt, str) and isinstance(label, str):
        computed_commitment = commitment_for(evidence_hash, salt, label)
        index = opening_entry.get("index") if opening_entry else None
        if isinstance(index, int):
            computed_leaf_hash = leaf_hash_for(index, label, computed_commitment)

    if opening_entry:
        if opening_entry.get("evidence_hash") != evidence_hash:
            errors.append(f"opening_evidence_hash_mismatch:opening={opening_entry.get('evidence_hash')}:computed={evidence_hash}")
        if opening_entry.get("commitment") != computed_commitment:
            errors.append(f"opening_commitment_mismatch:opening={opening_entry.get('commitment')}:computed={computed_commitment}")
        if opening_entry.get("leaf_hash") != computed_leaf_hash:
            errors.append(f"opening_leaf_hash_mismatch:opening={opening_entry.get('leaf_hash')}:computed={computed_leaf_hash}")

    if public_entry:
        if public_entry.get("commitment") != computed_commitment:
            errors.append(f"public_commitment_mismatch:public={public_entry.get('commitment')}:computed={computed_commitment}")
        if public_entry.get("leaf_hash") != computed_leaf_hash:
            errors.append(f"public_leaf_hash_mismatch:public={public_entry.get('leaf_hash')}:computed={computed_leaf_hash}")

    merkle = public.get("merkle")
    expected_root = merkle.get("root") if isinstance(merkle, dict) else None
    proof = opening_entry.get("merkle_proof") if opening_entry else None
    if not isinstance(proof, list):
        errors.append("opening_merkle_proof_missing")
        proof = []

    proof_ok = False
    if computed_leaf_hash and isinstance(expected_root, str):
        proof_ok = verify_proof(computed_leaf_hash, proof, expected_root)
        if not proof_ok:
            errors.append(f"merkle_proof_invalid:expected_root={expected_root}:leaf={computed_leaf_hash}")

    ok = len(errors) == 0

    print(f"DELTA_PRIVATE_EVIDENCE_SET_DISCLOSE_VERIFY_OK={'True' if ok else 'False'}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_PROFILE={PROFILE}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_LABEL={label}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COMPUTED_EVIDENCE_HASH={evidence_hash}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COMPUTED_COMMITMENT={computed_commitment}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_COMPUTED_LEAF_HASH={computed_leaf_hash}")
    print(f"DELTA_PRIVATE_EVIDENCE_SET_MERKLE_PROOF_OK={'True' if proof_ok else 'False'}")
    for error in errors:
        print(f"DELTA_PRIVATE_EVIDENCE_SET_ERROR={error}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Private Evidence Merkle Set v2.15.0")
    sub = parser.add_subparsers(dest="command", required=True)

    create_parser = sub.add_parser("create", help="Create public Merkle evidence set and private opening package")
    create_parser.add_argument("--evidence-dir", required=True)
    create_parser.add_argument("--pattern", default="*")
    create_parser.add_argument("--out-public", required=True)
    create_parser.add_argument("--out-opening", required=True)
    create_parser.add_argument("--record-hash", default=None)
    create_parser.add_argument("--policy-id", default=None)
    create_parser.set_defaults(func=create)

    verify_parser = sub.add_parser("verify-public", help="Verify public package self-checks and Merkle root")
    verify_parser.add_argument("--public", required=True)
    verify_parser.set_defaults(func=verify_public)

    disclose_parser = sub.add_parser("disclose", help="Verify disclosed evidence against opening and Merkle root")
    disclose_parser.add_argument("--public", required=True)
    disclose_parser.add_argument("--opening", required=True)
    disclose_parser.add_argument("--evidence", required=True)
    disclose_parser.add_argument("--label", required=True)
    disclose_parser.set_defaults(func=disclose)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)
    except DeltaPrivateEvidenceSetError as exc:
        print("DELTA_PRIVATE_EVIDENCE_SET_RESULT=False")
        print(f"DELTA_PRIVATE_EVIDENCE_SET_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
