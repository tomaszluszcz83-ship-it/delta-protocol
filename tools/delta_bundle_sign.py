#!/usr/bin/env python3
"""
DELTA Protocol v2.8.0 — Signed Bundle Utility.

Purpose:
- Create and verify detached Ed25519 signatures for portable .delta bundles.
- The signature is over the exact .delta bundle file hash and signed metadata.
- This does not replace proof-specific DELTA verifiers.

Security boundary:
- A signed bundle proves that a signing key signed the exact bundle bytes.
- It does not prove legal identity, signer authority, wallet balance, regulatory
  compliance, or validity of the contained DELTA proofs.
- Private keys must be stored outside the public repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


SIGNATURE_PROFILE = "delta_signed_bundle_v2_8_0"
PRIVATE_PREFIX = "ed25519priv:"
PUBLIC_PREFIX = "ed25519:"
SIGNATURE_PREFIX = "ed25519sig:"
SHA256_PREFIX = "sha256:"


class DeltaSignedBundleError(Exception):
    """Raised when signed bundle operations fail."""


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64url_encode_unpadded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode_unpadded(text: str, field: str) -> bytes:
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((text + padding).encode("ascii"))
    except Exception as exc:
        raise DeltaSignedBundleError(f"invalid base64url in {field}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return SHA256_PREFIX + h.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def public_key_text(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    return PUBLIC_PREFIX + b64url_encode_unpadded(raw)


def public_key_hash(public_key_text_value: str) -> str:
    return sha256_prefixed(public_key_text_value.encode("utf-8"))


def load_private_key(path: Path) -> Ed25519PrivateKey:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("{"):
        data = json.loads(text)
        value = data.get("private_key") or data.get("ed25519_private_key")
    else:
        value = text

    if not isinstance(value, str) or not value.startswith(PRIVATE_PREFIX):
        raise DeltaSignedBundleError("private key file must contain ed25519priv:<base64url>")

    raw = b64url_decode_unpadded(value[len(PRIVATE_PREFIX):], "private_key")
    if len(raw) != 32:
        raise DeltaSignedBundleError("Ed25519 private key seed must be 32 bytes")

    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(public_key_text_value: str) -> Ed25519PublicKey:
    if not isinstance(public_key_text_value, str) or not public_key_text_value.startswith(PUBLIC_PREFIX):
        raise DeltaSignedBundleError("public key must be ed25519:<base64url>")

    raw = b64url_decode_unpadded(public_key_text_value[len(PUBLIC_PREFIX):], "public_key")
    if len(raw) != 32:
        raise DeltaSignedBundleError("Ed25519 public key must be 32 bytes")

    return Ed25519PublicKey.from_public_bytes(raw)


def command_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.private_out)
    public_path = Path(args.public_out) if args.public_out else None

    if private_path.exists() and not args.force:
        raise DeltaSignedBundleError(f"private key already exists; use --force to overwrite: {private_path}")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes_raw()
    public_text = public_key_text(public_key)
    private_text = PRIVATE_PREFIX + b64url_encode_unpadded(private_raw)

    private_doc = {
        "type": "delta_bundle_signing_private_key",
        "profile": SIGNATURE_PROFILE,
        "created_at": now_utc_iso(),
        "private_key": private_text,
        "public_key": public_text,
        "public_key_hash": public_key_hash(public_text),
        "warning": "do_not_commit_do_not_paste_to_chat_demo_or_local_key_only",
    }

    private_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(private_path, private_doc)

    if public_path is not None:
        public_doc = {
            "type": "delta_bundle_signing_public_key",
            "profile": SIGNATURE_PROFILE,
            "created_at": private_doc["created_at"],
            "public_key": public_text,
            "public_key_hash": public_key_hash(public_text),
        }
        write_json(public_path, public_doc)

    print("DELTA_BUNDLE_KEYGEN_OK=True")
    print(f"DELTA_BUNDLE_PRIVATE_KEY_WRITTEN={private_path}")
    if public_path is not None:
        print(f"DELTA_BUNDLE_PUBLIC_KEY_WRITTEN={public_path}")
    print(f"DELTA_BUNDLE_PUBLIC_KEY_HASH={public_key_hash(public_text)}")
    print("DELTA_BUNDLE_PRIVATE_KEY_WARNING=do_not_commit_do_not_paste_to_chat")
    return 0


def make_signature_body(bundle_path: Path, private_key: Ed25519PrivateKey, args: argparse.Namespace) -> Dict[str, Any]:
    public_text = public_key_text(private_key.public_key())
    bundle_hash = file_sha256(bundle_path)

    return {
        "type": "delta_signed_bundle_signature_body",
        "signature_profile": SIGNATURE_PROFILE,
        "created_at": now_utc_iso(),
        "bundle": {
            "path_hint": str(bundle_path),
            "hash_alg": "sha256",
            "bundle_hash": bundle_hash,
        },
        "signer": {
            "label": args.signer,
            "public_key": public_text,
            "public_key_hash": public_key_hash(public_text),
        },
        "purpose": args.purpose,
        "security_boundary": {
            "does_not_replace_bundle_verify": True,
            "does_not_replace_proof_specific_verifiers": True,
            "does_not_prove_legal_identity": True,
            "does_not_prove_signer_authority": True,
            "does_not_prove_regulatory_compliance": True,
        },
    }


def command_sign(args: argparse.Namespace) -> int:
    bundle_path = Path(args.bundle)
    if not bundle_path.exists() or not bundle_path.is_file():
        raise DeltaSignedBundleError(f"bundle file does not exist: {bundle_path}")

    private_key = load_private_key(Path(args.private_key))
    body = make_signature_body(bundle_path, private_key, args)
    body_bytes = canonical_json_bytes(body)
    body_hash = sha256_prefixed(body_bytes)

    signature_bytes = private_key.sign(body_bytes)
    sig_text = SIGNATURE_PREFIX + b64url_encode_unpadded(signature_bytes)

    doc = {
        "type": "delta_signed_bundle_signature",
        "signature_profile": SIGNATURE_PROFILE,
        "signature_body": body,
        "signature_body_hash": body_hash,
        "signature": {
            "alg": "ed25519",
            "target": "canonical_json(signature_body)",
            "target_hash": body_hash,
            "public_key": body["signer"]["public_key"],
            "public_key_hash": body["signer"]["public_key_hash"],
            "signature": sig_text,
        },
        "self_check": {
            "hash_alg": "sha256",
            "signature_body_hash": body_hash,
        },
    }

    out = Path(args.out)
    write_json(out, doc)

    print("DELTA_BUNDLE_SIGN_OK=True")
    print(f"DELTA_BUNDLE_SIGNATURE={out}")
    print(f"DELTA_BUNDLE_HASH={body['bundle']['bundle_hash']}")
    print(f"DELTA_BUNDLE_SIGNATURE_BODY_HASH={body_hash}")
    print(f"DELTA_BUNDLE_SIGNER_PUBLIC_KEY_HASH={body['signer']['public_key_hash']}")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    bundle_path = Path(args.bundle)
    sig_path = Path(args.signature)

    if not bundle_path.exists() or not bundle_path.is_file():
        raise DeltaSignedBundleError(f"bundle file does not exist: {bundle_path}")
    if not sig_path.exists() or not sig_path.is_file():
        raise DeltaSignedBundleError(f"signature file does not exist: {sig_path}")

    doc = read_json(sig_path)
    checks: Dict[str, bool] = {}
    reasons: Dict[str, str] = {}

    try:
        if not isinstance(doc, dict):
            raise DeltaSignedBundleError("signature JSON must be an object")

        profile_ok = doc.get("signature_profile") == SIGNATURE_PROFILE
        checks["profile_ok"] = profile_ok
        if not profile_ok:
            reasons["profile"] = "signature_profile_mismatch"

        body = doc.get("signature_body")
        if not isinstance(body, dict):
            raise DeltaSignedBundleError("missing signature_body")

        body_bytes = canonical_json_bytes(body)
        actual_body_hash = sha256_prefixed(body_bytes)
        declared_body_hash = doc.get("signature_body_hash")
        checks["body_hash_ok"] = declared_body_hash == actual_body_hash
        if not checks["body_hash_ok"]:
            reasons["body_hash"] = "signature_body_hash_mismatch"

        self_check = doc.get("self_check") or {}
        checks["self_check_ok"] = self_check.get("signature_body_hash") == actual_body_hash
        if not checks["self_check_ok"]:
            reasons["self_check"] = "self_check_signature_body_hash_mismatch"

        actual_bundle_hash = file_sha256(bundle_path)
        declared_bundle_hash = ((body.get("bundle") or {}).get("bundle_hash"))
        checks["bundle_hash_ok"] = declared_bundle_hash == actual_bundle_hash
        if not checks["bundle_hash_ok"]:
            reasons["bundle_hash"] = "bundle_hash_mismatch"

        signer = body.get("signer") or {}
        pub_text = signer.get("public_key")
        declared_pub_hash = signer.get("public_key_hash")
        checks["public_key_hash_ok"] = declared_pub_hash == public_key_hash(str(pub_text))
        if not checks["public_key_hash_ok"]:
            reasons["public_key_hash"] = "public_key_hash_mismatch"

        sig = doc.get("signature") or {}
        checks["signature_target_hash_ok"] = sig.get("target_hash") == actual_body_hash
        if not checks["signature_target_hash_ok"]:
            reasons["signature_target_hash"] = "signature_target_hash_mismatch"

        sig_text = sig.get("signature")
        if not isinstance(sig_text, str) or not sig_text.startswith(SIGNATURE_PREFIX):
            checks["signature_shape_ok"] = False
            reasons["signature_shape"] = "invalid_signature_prefix"
        else:
            checks["signature_shape_ok"] = True

        signature_ok = False
        if checks.get("signature_shape_ok") and isinstance(pub_text, str):
            public_key = load_public_key(pub_text)
            signature_bytes = b64url_decode_unpadded(sig_text[len(SIGNATURE_PREFIX):], "signature")
            try:
                public_key.verify(signature_bytes, body_bytes)
                signature_ok = True
            except InvalidSignature:
                signature_ok = False
                reasons["signature"] = "ed25519_signature_invalid"

        checks["signature_ok"] = signature_ok

    except DeltaSignedBundleError as exc:
        print("DELTA_SIGNED_BUNDLE_VERIFY_OK=False")
        print(f"DELTA_SIGNED_BUNDLE_ERROR={html.escape(str(exc), quote=False)}")
        return 1

    ok = all(checks.values())

    print(f"DELTA_SIGNED_BUNDLE_VERIFY_OK={ok}")
    print(f"DELTA_SIGNED_BUNDLE_PROFILE={SIGNATURE_PROFILE}")
    print(f"DELTA_SIGNED_BUNDLE_BODY_HASH_OK={checks.get('body_hash_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_SELF_CHECK_OK={checks.get('self_check_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_BUNDLE_HASH_OK={checks.get('bundle_hash_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_PUBLIC_KEY_HASH_OK={checks.get('public_key_hash_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_SIGNATURE_TARGET_HASH_OK={checks.get('signature_target_hash_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_SIGNATURE_SHAPE_OK={checks.get('signature_shape_ok', False)}")
    print(f"DELTA_SIGNED_BUNDLE_SIGNATURE_OK={checks.get('signature_ok', False)}")

    bundle_info = (doc.get("signature_body") or {}).get("bundle") or {}
    signer = (doc.get("signature_body") or {}).get("signer") or {}
    print(f"DELTA_SIGNED_BUNDLE_BUNDLE_HASH={bundle_info.get('bundle_hash', '')}")
    print(f"DELTA_SIGNED_BUNDLE_SIGNER_PUBLIC_KEY_HASH={signer.get('public_key_hash', '')}")

    if not ok:
        for key, value in sorted(checks.items()):
            if not value:
                reason_key = key[:-3] if key.endswith("_ok") else key
                print(f"DELTA_SIGNED_BUNDLE_REASON_{key.upper()}={reasons.get(reason_key, '')}")

    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Protocol v2.8.0 — Signed Bundle Utility")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate a local Ed25519 bundle signing key")
    keygen.add_argument("--private-out", required=True, help="Path for private key JSON. Do not commit.")
    keygen.add_argument("--public-out", help="Optional path for public key JSON")
    keygen.add_argument("--force", action="store_true", help="Overwrite existing private key")
    keygen.set_defaults(func=command_keygen)

    sign = sub.add_parser("sign", help="Create a detached signature for a .delta bundle")
    sign.add_argument("--bundle", required=True, help="Path to .delta bundle")
    sign.add_argument("--private-key", required=True, help="Path to Ed25519 private key JSON")
    sign.add_argument("--out", required=True, help="Output signature JSON")
    sign.add_argument("--signer", default="local-bundle-signer", help="Non-authoritative signer label")
    sign.add_argument("--purpose", default="DELTA signed bundle", help="Signing purpose")
    sign.set_defaults(func=command_sign)

    verify = sub.add_parser("verify", help="Verify a detached signed-bundle signature")
    verify.add_argument("--bundle", required=True, help="Path to .delta bundle")
    verify.add_argument("--signature", required=True, help="Path to signature JSON")
    verify.set_defaults(func=command_verify)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except DeltaSignedBundleError as exc:
        print("DELTA_SIGNED_BUNDLE_VERIFY_OK=False")
        print("DELTA_SIGNED_BUNDLE_ERROR=" + html.escape(str(exc), quote=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
