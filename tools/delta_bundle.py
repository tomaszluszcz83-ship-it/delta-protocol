#!/usr/bin/env python3
"""
DELTA Protocol v2.7.2 — Portable Bundle Utility.

Security boundary:
- A .delta file is a ZIP container for public verification artifacts.
- It MUST NOT contain private keys, seed phrases, tokens, raw private evidence,
  decrypted evidence, or other sensitive material.
- This tool verifies bundle structure, manifest hashes, file sizes, and
  path-safety before extraction.
- It does not create new cryptographic proofs and does not replace DELTA
  proof-specific verifiers.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


BUNDLE_PROFILE = "delta_bundle_v2_7_2"
BUNDLE_MANIFEST = "bundle_manifest.json"
MAX_BUNDLE_FILE_SIZE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_EXTRACTED_BYTES = 100 * 1024 * 1024

FORBIDDEN_NAME_FRAGMENTS = (
    "private",
    "secret",
    "seed",
    "token",
    "password",
    "passwd",
    "credential",
    "credentials",
    "key.pem",
    "private_key",
    "id_rsa",
    "id_ed25519",
    "wallet-private",
    "executor-private",
    "decrypted",
    "evidence.raw",
)


class DeltaBundleError(Exception):
    """Raised when a DELTA bundle violates structure or safety rules."""


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_uri(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_arcname(path: Path, preferred_name: str | None = None) -> str:
    name = preferred_name or path.name
    name = name.replace("\\", "/").strip("/")

    if not name:
        raise DeltaBundleError("empty archive filename is not allowed")

    if "/" in name:
        raise DeltaBundleError(f"nested archive paths are not allowed: {name}")

    if name in (".", "..") or name.startswith("../") or "/../" in name:
        raise DeltaBundleError(f"path traversal is not allowed: {name}")

    if os.path.isabs(name):
        raise DeltaBundleError(f"absolute archive paths are not allowed: {name}")

    lower = name.lower()
    for fragment in FORBIDDEN_NAME_FRAGMENTS:
        if fragment in lower:
            raise DeltaBundleError(f"forbidden sensitive filename fragment detected: {name}")

    return name


def ensure_existing_file(path_text: str, role: str) -> Path:
    path = Path(path_text)
    if not path.exists():
        raise DeltaBundleError(f"{role} file does not exist: {path}")
    if not path.is_file():
        raise DeltaBundleError(f"{role} path is not a file: {path}")
    return path


def make_artifact_entry(role: str, path: Path, arcname: str) -> Dict[str, Any]:
    data = read_bytes(path)
    if len(data) > MAX_BUNDLE_FILE_SIZE_BYTES:
        raise DeltaBundleError(f"{role} file is too large: {path} size={len(data)}")

    return {
        "role": role,
        "filename": arcname,
        "sha256": sha256_uri(data),
        "size_bytes": len(data),
    }


def write_zip_entry(zf: zipfile.ZipFile, source: Path, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.date_time = datetime.now().timetuple()[:6]
    zf.writestr(info, source.read_bytes())


def create_bundle(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    if output_path.suffix.lower() != ".delta":
        output_path = output_path.with_suffix(output_path.suffix + ".delta") if output_path.suffix else output_path.with_suffix(".delta")

    record_path = ensure_existing_file(args.record, "record")
    intent_path = ensure_existing_file(args.intent, "intent")
    report_path = ensure_existing_file(args.report, "report")

    record_name = normalize_arcname(record_path, args.record_name or "delta-record.json")
    intent_name = normalize_arcname(intent_path, args.intent_name or "intent-attestation-draft.json")
    report_name = normalize_arcname(report_path, args.report_name or "delta-report.html")

    archive_names = [record_name, intent_name, report_name, BUNDLE_MANIFEST]
    if len(set(archive_names)) != len(archive_names):
        raise DeltaBundleError("duplicate archive filenames are not allowed")

    artifacts = [
        make_artifact_entry("record", record_path, record_name),
        make_artifact_entry("intent_draft", intent_path, intent_name),
        make_artifact_entry("visual_report", report_path, report_name),
    ]

    manifest_body = {
        "bundle_profile": BUNDLE_PROFILE,
        "protocol_version": "2.7.2",
        "created_at": now_utc_iso(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "security_policy": {
            "public_artifacts_only": True,
            "private_keys_allowed": False,
            "private_evidence_allowed": False,
            "decrypted_evidence_allowed": False,
            "generated_artifacts_may_be_shared": "only after local review",
        },
        "security_boundary": {
            "does_not_create_new_proofs": True,
            "does_not_replace_proof_specific_verifiers": True,
            "does_not_prove_legal_truth": True,
            "does_not_prove_real_world_truth": True,
            "does_not_prove_identity": True,
            "does_not_prove_wallet_balance": True,
            "does_not_prove_regulatory_compliance": True,
        },
    }

    manifest_bytes = json.dumps(manifest_body, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    manifest = {
        "manifest_profile": BUNDLE_PROFILE + "_manifest",
        "manifest_body": manifest_body,
        "manifest_body_hash": sha256_uri(manifest_bytes),
        "self_check": {
            "hash_alg": "sha256",
            "manifest_body_hash": sha256_uri(manifest_bytes),
        },
    }
    manifest_final = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        write_zip_entry(zf, record_path, record_name)
        write_zip_entry(zf, intent_path, intent_name)
        write_zip_entry(zf, report_path, report_name)
        zf.writestr(BUNDLE_MANIFEST, manifest_final)

    print("DELTA_BUNDLE_CREATE_OK=True")
    print(f"DELTA_BUNDLE_PROFILE={BUNDLE_PROFILE}")
    print(f"DELTA_BUNDLE={output_path}")
    print(f"DELTA_BUNDLE_MANIFEST={BUNDLE_MANIFEST}")
    for artifact in artifacts:
        print(f"DELTA_BUNDLE_ARTIFACT_{artifact['role'].upper()}={artifact['filename']}")
        print(f"DELTA_BUNDLE_ARTIFACT_{artifact['role'].upper()}_SHA256={artifact['sha256']}")
    return 0


def validate_zip_names(names: Iterable[str]) -> List[str]:
    names = list(names)
    if len(set(names)) != len(names):
        raise DeltaBundleError("duplicate filenames in bundle are not allowed")

    if BUNDLE_MANIFEST not in names:
        raise DeltaBundleError(f"missing required {BUNDLE_MANIFEST}")

    for name in names:
        normalize_arcname(Path(name), name)

    return names


def load_manifest(zf: zipfile.ZipFile) -> Dict[str, Any]:
    try:
        manifest = json.loads(zf.read(BUNDLE_MANIFEST).decode("utf-8"))
    except Exception as exc:
        raise DeltaBundleError(f"manifest is not valid JSON: {type(exc).__name__}:{exc}") from exc

    if manifest.get("manifest_profile") != BUNDLE_PROFILE + "_manifest":
        raise DeltaBundleError("manifest_profile mismatch")

    body = manifest.get("manifest_body")
    if not isinstance(body, dict):
        raise DeltaBundleError("manifest_body missing or invalid")

    if body.get("bundle_profile") != BUNDLE_PROFILE:
        raise DeltaBundleError("bundle_profile mismatch")

    expected_body_hash = manifest.get("manifest_body_hash")
    recomputed_body_bytes = json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    recomputed_body_hash = sha256_uri(recomputed_body_bytes)

    if expected_body_hash != recomputed_body_hash:
        raise DeltaBundleError("manifest_body_hash mismatch")

    self_check = manifest.get("self_check") or {}
    if self_check.get("manifest_body_hash") != recomputed_body_hash:
        raise DeltaBundleError("manifest self_check hash mismatch")

    return manifest


def verify_artifacts(zf: zipfile.ZipFile, manifest: Dict[str, Any]) -> None:
    body = manifest["manifest_body"]
    artifacts = body.get("artifacts")

    if not isinstance(artifacts, list) or not artifacts:
        raise DeltaBundleError("manifest artifacts list missing or empty")

    names = set(zf.namelist())
    total_size = 0

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise DeltaBundleError("invalid artifact entry")

        role = artifact.get("role")
        filename = artifact.get("filename")
        expected_hash = artifact.get("sha256")
        expected_size = artifact.get("size_bytes")

        if not role or not filename or not expected_hash:
            raise DeltaBundleError("artifact entry missing role/filename/sha256")

        filename = normalize_arcname(Path(filename), filename)

        if filename not in names:
            raise DeltaBundleError(f"artifact declared in manifest is missing from zip: {filename}")

        data = zf.read(filename)
        actual_hash = sha256_uri(data)
        actual_size = len(data)
        total_size += actual_size

        if actual_hash != expected_hash:
            raise DeltaBundleError(f"artifact hash mismatch: {filename}")

        if expected_size != actual_size:
            raise DeltaBundleError(f"artifact size mismatch: {filename}")

    if total_size > MAX_TOTAL_EXTRACTED_BYTES:
        raise DeltaBundleError("bundle total extracted size exceeds safety limit")


def safe_extract(zf: zipfile.ZipFile, extract_to: Path) -> None:
    root = extract_to.resolve()
    root.mkdir(parents=True, exist_ok=True)

    for info in zf.infolist():
        name = normalize_arcname(Path(info.filename), info.filename)
        target = (root / name).resolve()

        if root not in target.parents and target != root:
            raise DeltaBundleError(f"unsafe extraction path: {name}")

        if info.file_size > MAX_BUNDLE_FILE_SIZE_BYTES:
            raise DeltaBundleError(f"file too large for extraction: {name}")

        target.write_bytes(zf.read(info.filename))


def verify_bundle(args: argparse.Namespace) -> int:
    bundle_path = Path(args.bundle)
    extract_to = Path(args.dir) if args.dir else None

    if not bundle_path.exists():
        raise DeltaBundleError(f"bundle does not exist: {bundle_path}")

    if not zipfile.is_zipfile(bundle_path):
        raise DeltaBundleError("file is not a valid ZIP/.delta container")

    with zipfile.ZipFile(bundle_path, "r") as zf:
        validate_zip_names(zf.namelist())
        manifest = load_manifest(zf)
        verify_artifacts(zf, manifest)

        if extract_to is not None:
            safe_extract(zf, extract_to)

    print("DELTA_BUNDLE_VERIFY_OK=True")
    print(f"DELTA_BUNDLE_PROFILE={BUNDLE_PROFILE}")
    print(f"DELTA_BUNDLE={bundle_path}")
    if extract_to is not None:
        print(f"DELTA_BUNDLE_EXTRACTED_TO={extract_to}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Protocol v2.7.2 — Portable Bundle Utility")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="Create a portable .delta bundle")
    c.add_argument("--output", required=True, help="Output .delta path")
    c.add_argument("--record", required=True, help="Path to delta-record.json")
    c.add_argument("--intent", required=True, help="Path to unsigned intent draft JSON")
    c.add_argument("--report", required=True, help="Path to exported report HTML or Markdown")
    c.add_argument("--record-name", help="Archive filename for the record artifact")
    c.add_argument("--intent-name", help="Archive filename for the intent artifact")
    c.add_argument("--report-name", help="Archive filename for the report artifact")
    c.set_defaults(func=create_bundle)

    v = sub.add_parser("verify", help="Verify a .delta bundle and optionally extract it")
    v.add_argument("--bundle", required=True, help="Path to .delta bundle")
    v.add_argument("--dir", help="Optional extraction directory")
    v.set_defaults(func=verify_bundle)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except DeltaBundleError as exc:
        print("DELTA_BUNDLE_VERIFY_OK=False")
        print("DELTA_BUNDLE_ERROR=" + html.escape(str(exc), quote=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
