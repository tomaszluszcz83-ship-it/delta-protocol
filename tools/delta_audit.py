#!/usr/bin/env python3
"""DELTA Proof of Audit MVP.

v1.9.0 goal:
- encrypt private evidence for an auditor using a separate audit encryption key
- bind the encrypted audit package to a full DELTA delta-record.json hash
- allow optional disclosure/decryption by the auditor

Security boundary:
- this does not prove legal consent, auditor identity, ticket truth, or external-world truth
- this does not publish or anchor records
- this does not replace the signed sensor record, replay verifier, or Proof of Intent
- it proves that evidence files were encrypted into an audit package bound to a specific DELTA record hash
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag


DELTA_PROTOCOL = "DELTA-0"
AUDIT_PUBLIC_KEY_TYPE = "delta_audit_public_key"
AUDIT_PACKAGE_TYPE = "delta_audit_package"
AUDIT_DISCLOSURE_TYPE = "delta_audit_disclosure"
AUDIT_PACKAGE_VERSION = "1.0.0"
AUDIT_PUBLIC_KEY_VERSION = "1.0.0"
AUDIT_DISCLOSURE_VERSION = "1.0.0"

PUBLIC_KEY_PREFIX = "x25519:"
PRIVATE_SEED_PREFIX = "x25519seed:"
SHA256_PREFIX = "sha256:"
AES_ALG = "X25519-HKDF-SHA256-AES-256-GCM"
HKDF_INFO = b"DELTA Proof of Audit v1.9.0 evidence encryption"
NONCE_SIZE = 12


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode_unpadded(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is empty")
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"{field} is not valid base64url") from exc


def sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    return sha256_prefixed(text.encode("utf-8"))


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


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def parse_public_key(public_key_value: str) -> X25519PublicKey:
    if not isinstance(public_key_value, str) or not public_key_value.startswith(PUBLIC_KEY_PREFIX):
        raise ValueError("audit public key must start with x25519:")
    raw = b64url_decode_unpadded(public_key_value[len(PUBLIC_KEY_PREFIX):], "audit_public_key")
    if len(raw) != 32:
        raise ValueError(f"audit public key must decode to 32 bytes, got {len(raw)}")
    return X25519PublicKey.from_public_bytes(raw)


def parse_private_key(private_key_value: str) -> X25519PrivateKey:
    if not isinstance(private_key_value, str) or not private_key_value.startswith(PRIVATE_SEED_PREFIX):
        raise ValueError("audit private key must start with x25519seed:")
    raw = b64url_decode_unpadded(private_key_value[len(PRIVATE_SEED_PREFIX):], "audit_private_key")
    if len(raw) != 32:
        raise ValueError(f"audit private key seed must decode to 32 bytes, got {len(raw)}")
    return X25519PrivateKey.from_private_bytes(raw)


def public_key_text(public_key: X25519PublicKey) -> str:
    raw = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return PUBLIC_KEY_PREFIX + b64url_no_padding(raw)


def private_key_text(private_key: X25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return PRIVATE_SEED_PREFIX + b64url_no_padding(raw)


def derive_key(shared_secret: bytes, *, record_hash: str, entry_index: int) -> bytes:
    salt = hashlib.sha256(f"{record_hash}|{entry_index}".encode("utf-8")).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def safe_name(value: str, fallback: str) -> str:
    candidate = Path(value).name or fallback
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate)
    return candidate or fallback


def collect_evidence_commitments(record: dict[str, Any], *, include: str) -> list[dict[str, Any]]:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    sections: list[str]
    if include == "private":
        sections = ["private_evidence_commitments"]
    elif include == "public":
        sections = ["evidence_commitments"]
    else:
        sections = ["private_evidence_commitments", "evidence_commitments"]

    commitments: list[dict[str, Any]] = []
    for section in sections:
        values = body.get(section) or []
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            evidence_hash = item.get("hash") or item.get("sha256")
            path_hint = item.get("path") or item.get("name") or item.get("type")
            if not isinstance(evidence_hash, str) or not evidence_hash.startswith(SHA256_PREFIX):
                continue
            if not isinstance(path_hint, str) or not path_hint:
                continue
            enriched = dict(item)
            enriched["_section"] = section
            enriched["_path_hint"] = path_hint
            enriched["_evidence_hash"] = evidence_hash
            commitments.append(enriched)
    return commitments


def resolve_evidence_path(path_hint: str, *, record_path: Path, evidence_root: Path | None) -> Path | None:
    hint = Path(path_hint)
    candidates: list[Path] = []
    if hint.is_absolute():
        candidates.append(hint)
    else:
        cwd = Path.cwd()
        roots = []
        if evidence_root is not None:
            roots.append(evidence_root)
        roots.extend([record_path.parent, cwd])
        for root in roots:
            candidates.append(root / hint)
            candidates.append(root / hint.name)
        candidates.append(hint)

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()

    # Last resort: search by basename under the evidence root and record parent.
    basename = hint.name
    for root in [evidence_root, record_path.parent]:
        if root and root.exists():
            for candidate in root.rglob(basename):
                if candidate.is_file():
                    return candidate.resolve()
    return None


def build_aad(*, package_id: str, record_hash: str, entry_index: int, commitment: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "delta_audit_aad",
        "version": "1.0.0",
        "protocol": DELTA_PROTOCOL,
        "package_id": package_id,
        "record_hash": record_hash,
        "entry_index": entry_index,
        "evidence_path_hint": commitment.get("_path_hint"),
        "evidence_hash": commitment.get("_evidence_hash"),
        "evidence_type": commitment.get("type"),
        "commitment_section": commitment.get("_section"),
    }


def write_private_key_file(path: Path, content: str, *, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise SystemExit(f"refusing to overwrite existing private key file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8", newline="\n")


def command_keygen(args: argparse.Namespace) -> int:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_value = public_key_text(public_key)
    private_value = private_key_text(private_key)

    public_doc = {
        "type": AUDIT_PUBLIC_KEY_TYPE,
        "version": AUDIT_PUBLIC_KEY_VERSION,
        "protocol": DELTA_PROTOCOL,
        "alg": "X25519",
        "id": args.key_id,
        "owner": args.owner,
        "role": args.role,
        "public_key": public_value,
        "public_key_hash": hash_text(public_value),
        "created_at": now_utc(),
        "security_boundary": "Public audit encryption key. Safe to commit. Private audit key must never be committed or pasted into chat.",
    }

    write_private_key_file(Path(args.private_out), private_value, overwrite=args.force)
    write_json(Path(args.public_out), public_doc)

    print("DELTA_AUDIT_KEYGEN_OK=True")
    print(f"DELTA_AUDIT_PRIVATE_KEY_WRITTEN={Path(args.private_out)}")
    print(f"DELTA_AUDIT_PUBLIC_KEY_WRITTEN={Path(args.public_out)}")
    print(f"DELTA_AUDIT_PUBLIC_KEY_HASH={public_doc['public_key_hash']}")
    print("DELTA_AUDIT_PRIVATE_KEY_WARNING=do_not_commit_do_not_paste_to_chat")
    return 0


def command_encrypt_evidence(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = read_json(record_path)
    record_hash = canonical_sha256(record)

    auditor_public_key_path = Path(args.auditor_public_key).resolve()
    auditor_public_doc = read_json(auditor_public_key_path)
    if not isinstance(auditor_public_doc, dict):
        raise SystemExit("auditor public key must be a JSON object")
    auditor_public_value = auditor_public_doc.get("public_key")
    auditor_public_key = parse_public_key(auditor_public_value)

    evidence_root = Path(args.evidence_root).resolve() if args.evidence_root else None
    commitments = collect_evidence_commitments(record, include=args.include)
    no_evidence_found = not commitments

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    package_id = args.package_id
    created_at = now_utc()

    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for idx, commitment in enumerate(commitments):
        path_hint = str(commitment["_path_hint"])
        resolved = resolve_evidence_path(path_hint, record_path=record_path, evidence_root=evidence_root)
        if resolved is None:
            skipped.append({"path_hint": path_hint, "reason": "MISSING_EVIDENCE_FILE"})
            if not args.allow_missing_evidence:
                raise SystemExit(f"MISSING_EVIDENCE_FILE: evidence file not found for commitment path: {path_hint}")
            continue

        plaintext = resolved.read_bytes()
        plaintext_hash = sha256_prefixed(plaintext)
        commitment_hash = commitment["_evidence_hash"]
        plaintext_hash_ok = plaintext_hash == commitment_hash
        if not plaintext_hash_ok and args.require_hash_match:
            raise SystemExit(f"EVIDENCE_HASH_MISMATCH: {resolved}: expected={commitment_hash} actual={plaintext_hash}")

        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        shared = ephemeral_private.exchange(auditor_public_key)
        key = derive_key(shared, record_hash=record_hash, entry_index=idx)
        nonce = os.urandom(NONCE_SIZE)
        aad = build_aad(package_id=package_id, record_hash=record_hash, entry_index=idx, commitment=commitment)
        aad_bytes = canonical_json_bytes(aad)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad_bytes)

        entry = {
            "index": idx,
            "type": "encrypted_evidence_entry",
            "evidence": {
                "path_hint": path_hint,
                "resolved_basename": resolved.name,
                "commitment_section": commitment.get("_section"),
                "evidence_type": commitment.get("type"),
                "commitment_hash": commitment_hash,
                "plaintext_hash": plaintext_hash,
                "plaintext_hash_matches_commitment": plaintext_hash_ok,
                "plaintext_size_bytes": len(plaintext),
            },
            "aad": aad,
            "aad_hash": canonical_sha256(aad),
            "encryption": {
                "alg": AES_ALG,
                "ephemeral_public_key": public_key_text(ephemeral_public),
                "nonce": b64url_no_padding(nonce),
                "ciphertext": b64url_no_padding(ciphertext),
                "ciphertext_hash": sha256_prefixed(ciphertext),
            },
        }
        entries.append(entry)

    package = {
        "type": AUDIT_PACKAGE_TYPE,
        "version": AUDIT_PACKAGE_VERSION,
        "protocol": DELTA_PROTOCOL,
        "package_id": package_id,
        "created_at": created_at,
        "target": {
            "record_hash": record_hash,
            "record_type": "delta_sensor_record",
            "record_path_hint": str(record_path),
            "record_body_hash": record.get("record_body_hash"),
        },
        "recipient": {
            "type": "audit_recipient",
            "key_id": auditor_public_doc.get("id") or args.auditor_key_id,
            "owner": auditor_public_doc.get("owner"),
            "role": auditor_public_doc.get("role") or "auditor",
            "public_key": auditor_public_value,
            "public_key_hash": auditor_public_doc.get("public_key_hash") or hash_text(auditor_public_value),
        },
        "publication": {
            "publisher": args.publisher,
            "method": "encrypted_audit_package_v1",
            "note": "Encrypted evidence disclosure package bound to a full DELTA record hash.",
        },
        "evidence_summary": {
            "include": args.include,
            "commitments_found": len(commitments),
            "no_evidence_found": no_evidence_found,
            "entries_encrypted": len(entries),
            "entries_skipped": len(skipped),
            "missing_evidence_allowed": bool(args.allow_missing_evidence),
            "skipped": skipped,
        },
        "entries": entries,
        "security_boundary": {
            "proves": "Evidence files were encrypted for a recipient key into a package bound to the target DELTA record hash.",
            "does_not_prove": [
                "legal consent",
                "real-world auditor identity",
                "ticket truth",
                "external-world truth",
                "anchoring or publication time",
                "package authorship, unless separately signed in a future release",
            ],
        },
    }

    package_path = out_dir / "delta-audit-package.json"
    write_json(package_path, package)

    print("DELTA_AUDIT_ENCRYPT_OK=True")
    print(f"DELTA_AUDIT_PACKAGE={package_path}")
    print(f"DELTA_AUDIT_RECORD_HASH={record_hash}")
    print(f"DELTA_AUDIT_NO_EVIDENCE_FOUND={no_evidence_found}")
    print(f"DELTA_AUDIT_COMMITMENTS_FOUND={len(commitments)}")
    print(f"DELTA_AUDIT_ENTRIES_ENCRYPTED={len(entries)}")
    print(f"DELTA_AUDIT_ENTRIES_SKIPPED={len(skipped)}")
    print(f"DELTA_AUDIT_RECIPIENT_PUBLIC_KEY_HASH={package['recipient']['public_key_hash']}")
    return 0


def command_verify_package(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = read_json(record_path)
    record_hash = canonical_sha256(record)
    package = read_json(Path(args.package))

    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    checks["shape_ok"] = isinstance(package, dict) and package.get("type") == AUDIT_PACKAGE_TYPE and package.get("protocol") == DELTA_PROTOCOL
    reasons["shape"] = "audit_package_shape_ok" if checks["shape_ok"] else "invalid_audit_package_shape"

    target = package.get("target") if isinstance(package.get("target"), dict) else {}
    checks["record_binding_ok"] = target.get("record_hash") == record_hash
    reasons["record_binding"] = "package_target_record_hash_matches_record" if checks["record_binding_ok"] else "package_target_record_hash_mismatch"

    recipient_ok = True
    if args.auditor_public_key:
        public_doc = read_json(Path(args.auditor_public_key))
        recipient = package.get("recipient") if isinstance(package.get("recipient"), dict) else {}
        recipient_ok = recipient.get("public_key") == public_doc.get("public_key")
        if recipient_ok and recipient.get("public_key_hash") and public_doc.get("public_key_hash"):
            recipient_ok = recipient.get("public_key_hash") == public_doc.get("public_key_hash")
    checks["recipient_ok"] = recipient_ok
    reasons["recipient"] = "recipient_key_matches" if recipient_ok else "recipient_key_mismatch"

    commitments = collect_evidence_commitments(record, include="all")
    known_hashes = {c.get("_evidence_hash") for c in commitments}
    entries = package.get("entries") if isinstance(package.get("entries"), list) else []
    evidence_summary = package.get("evidence_summary") if isinstance(package.get("evidence_summary"), dict) else {}
    no_evidence_found = bool(evidence_summary.get("no_evidence_found")) or (len(commitments) == 0 and len(entries) == 0)

    entry_hashes_ok = True
    aad_hashes_ok = True
    ciphertext_hashes_ok = True
    entry_shapes_ok = isinstance(entries, list)
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            entry_shapes_ok = False
            continue
        evidence = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
        commitment_hash = evidence.get("commitment_hash")
        plaintext_hash = evidence.get("plaintext_hash")
        if commitment_hash not in known_hashes or plaintext_hash != commitment_hash:
            entry_hashes_ok = False
        aad = entry.get("aad") if isinstance(entry.get("aad"), dict) else {}
        if entry.get("aad_hash") != canonical_sha256(aad):
            aad_hashes_ok = False
        enc = entry.get("encryption") if isinstance(entry.get("encryption"), dict) else {}
        if enc.get("alg") != AES_ALG or not enc.get("ephemeral_public_key") or not enc.get("nonce") or not enc.get("ciphertext"):
            entry_shapes_ok = False
        if enc.get("ciphertext_hash"):
            try:
                ciphertext_raw = b64url_decode_unpadded(str(enc.get("ciphertext")), "ciphertext")
                if sha256_prefixed(ciphertext_raw) != enc.get("ciphertext_hash"):
                    ciphertext_hashes_ok = False
            except Exception:
                ciphertext_hashes_ok = False

    checks["entry_shapes_ok"] = entry_shapes_ok
    checks["entry_hashes_ok"] = entry_hashes_ok
    checks["aad_hashes_ok"] = aad_hashes_ok
    checks["ciphertext_hashes_ok"] = ciphertext_hashes_ok
    checks["entries_present_or_no_evidence_ok"] = bool(entries) or no_evidence_found

    ok = all(checks.values())
    print(f"DELTA_AUDIT_VERIFY_OK={ok}")
    print(f"DELTA_AUDIT_RECORD_BINDING_OK={checks['record_binding_ok']}")
    print(f"DELTA_AUDIT_RECIPIENT_OK={checks['recipient_ok']}")
    print(f"DELTA_AUDIT_ENTRY_SHAPES_OK={checks['entry_shapes_ok']}")
    print(f"DELTA_AUDIT_ENTRY_HASHES_OK={checks['entry_hashes_ok']}")
    print(f"DELTA_AUDIT_AAD_HASHES_OK={checks['aad_hashes_ok']}")
    print(f"DELTA_AUDIT_CIPHERTEXT_HASHES_OK={checks['ciphertext_hashes_ok']}")
    print(f"DELTA_AUDIT_NO_EVIDENCE_FOUND={no_evidence_found}")
    print(f"DELTA_AUDIT_ENTRY_COUNT={len(entries) if isinstance(entries, list) else 0}")
    print(f"DELTA_AUDIT_RECORD_HASH={record_hash}")
    if not checks['record_binding_ok']:
        print("DELTA_AUDIT_RECORD_BINDING_REASON=record_hash_mismatch")
    return 0 if ok else 1


def command_decrypt_package(args: argparse.Namespace) -> int:
    package = read_json(Path(args.package))
    private_value = Path(args.private_key).read_text(encoding="utf-8").strip()
    private_key = parse_private_key(private_value)

    record = read_json(Path(args.record)) if args.record else None
    record_hash = canonical_sha256(record) if isinstance(record, dict) else package.get("target", {}).get("record_hash")
    if isinstance(record, dict) and package.get("target", {}).get("record_hash") != record_hash:
        raise SystemExit("audit package target.record_hash does not match supplied record")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = package.get("entries") if isinstance(package.get("entries"), list) else []

    disclosure_entries: list[dict[str, Any]] = []
    all_ok = True

    for entry in entries:
        idx = int(entry.get("index"))
        enc = entry.get("encryption") if isinstance(entry.get("encryption"), dict) else {}
        evidence = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
        aad = entry.get("aad") if isinstance(entry.get("aad"), dict) else {}

        ephemeral_public = parse_public_key(enc.get("ephemeral_public_key"))
        shared = private_key.exchange(ephemeral_public)
        key = derive_key(shared, record_hash=record_hash, entry_index=idx)
        nonce = b64url_decode_unpadded(enc.get("nonce"), "nonce")
        ciphertext = b64url_decode_unpadded(enc.get("ciphertext"), "ciphertext")
        if enc.get("ciphertext_hash") and sha256_prefixed(ciphertext) != enc.get("ciphertext_hash"):
            all_ok = False
            disclosure_entries.append({"index": idx, "ok": False, "reason": "ciphertext_hash_mismatch"})
            continue

        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, canonical_json_bytes(aad))
        except InvalidTag:
            all_ok = False
            disclosure_entries.append({"index": idx, "ok": False, "reason": "aes_gcm_invalid_tag"})
            continue

        plaintext_hash = sha256_prefixed(plaintext)
        expected_hash = evidence.get("plaintext_hash")
        hash_ok = plaintext_hash == expected_hash
        all_ok = all_ok and hash_ok

        filename = f"{idx:03d}-" + safe_name(str(evidence.get("resolved_basename") or evidence.get("path_hint") or "evidence.bin"), "evidence.bin")
        out_path = out_dir / filename
        out_path.write_bytes(plaintext)

        disclosure_entries.append({
            "index": idx,
            "ok": hash_ok,
            "path": out_path.as_posix(),
            "plaintext_hash": plaintext_hash,
            "expected_plaintext_hash": expected_hash,
            "commitment_hash": evidence.get("commitment_hash"),
        })
        print(f"DELTA_AUDIT_DECRYPT_ENTRY_{idx}_OK={hash_ok}")
        print(f"DELTA_AUDIT_DECRYPT_ENTRY_{idx}_PATH={out_path}")

    disclosure = {
        "type": AUDIT_DISCLOSURE_TYPE,
        "version": AUDIT_DISCLOSURE_VERSION,
        "protocol": DELTA_PROTOCOL,
        "created_at": now_utc(),
        "package_hash": canonical_sha256(package),
        "record_hash": record_hash,
        "entries": disclosure_entries,
        "ok": all_ok,
    }
    write_json(out_dir / "delta-audit-disclosure.json", disclosure)

    print(f"DELTA_AUDIT_DECRYPT_OK={all_ok}")
    print(f"DELTA_AUDIT_DECRYPTED_ENTRY_COUNT={len(disclosure_entries)}")
    print(f"DELTA_AUDIT_DISCLOSURE={out_dir / 'delta-audit-disclosure.json'}")
    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Audit evidence encryption tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate an auditor X25519 encryption key pair.")
    keygen.add_argument("--private-out", required=True, help="Path for private audit key. Do not commit.")
    keygen.add_argument("--public-out", required=True, help="Path for public audit key JSON. Safe to commit.")
    keygen.add_argument("--key-id", default="audit-key-local-v1", help="Audit key id.")
    keygen.add_argument("--owner", default="local-auditor", help="Audit key owner label.")
    keygen.add_argument("--role", default="auditor", help="Audit key role.")
    keygen.add_argument("--force", action="store_true", help="Overwrite existing private key file.")
    keygen.set_defaults(func=command_keygen)

    enc = subparsers.add_parser("encrypt-evidence", help="Encrypt evidence files referenced by a DELTA record for an auditor.")
    enc.add_argument("--record", required=True, help="Path to delta-record.json")
    enc.add_argument("--auditor-public-key", required=True, help="Path to auditor public key JSON")
    enc.add_argument("--out-dir", required=True, help="Output directory for audit package")
    enc.add_argument("--evidence-root", default="", help="Optional root directory for evidence files")
    enc.add_argument("--include", choices=("private", "public", "all"), default="private", help="Which evidence commitments to encrypt")
    enc.add_argument("--package-id", default="A-001", help="Audit package id")
    enc.add_argument("--auditor-key-id", default="", help="Fallback auditor key id if not present in public key JSON")
    enc.add_argument("--publisher", default="local-publisher", help="Publisher label for audit package metadata")
    enc.add_argument("--require-all", action="store_true", help="Deprecated: missing committed evidence fails by default unless --allow-missing-evidence is used")
    enc.add_argument("--allow-missing-evidence", action="store_true", help="Allow committed evidence files to be skipped when they are missing")
    enc.add_argument("--require-hash-match", action="store_true", help="Fail if evidence plaintext hash does not match record commitment")
    enc.set_defaults(func=command_encrypt_evidence)

    verify = subparsers.add_parser("verify-package", help="Verify an audit package shape and record binding without decrypting evidence.")
    verify.add_argument("--record", required=True, help="Path to delta-record.json")
    verify.add_argument("--package", required=True, help="Path to delta-audit-package.json")
    verify.add_argument("--auditor-public-key", default="", help="Optional auditor public key JSON to check recipient")
    verify.set_defaults(func=command_verify_package)

    dec = subparsers.add_parser("decrypt-package", help="Decrypt an audit package with the auditor private key.")
    dec.add_argument("--package", required=True, help="Path to delta-audit-package.json")
    dec.add_argument("--private-key", required=True, help="Path to private audit key. Do not commit.")
    dec.add_argument("--out-dir", required=True, help="Output directory for decrypted evidence")
    dec.add_argument("--record", default="", help="Optional record path to verify target binding before decrypting")
    dec.set_defaults(func=command_decrypt_package)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
