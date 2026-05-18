#!/usr/bin/env python3
"""DELTA Proof of Crypto Wallet / Address Control tool.

v2.3.0 goal:
- create a standalone wallet/address-control challenge
- optionally bind that challenge to a full canonical delta-record.json hash
- create a proof that a key/address signed that exact challenge
- verify the proof offline with clear security boundaries

Security boundary:
- This MVP does not ask for seed phrases and does not store production wallet keys.
- It does not prove legal ownership, real-world identity, wallet balance, MiCA compliance,
  chain state, or smart-contract wallet authority.
- ed25519_address_control_v1 is a DELTA demo adapter used to harden the proof envelope.
  Production adapters such as ETH EIP-191/EIP-712 and BTC BIP-322 are roadmap items.
- When --record is used, the record hash is embedded inside the signed challenge_body,
  so the wallet signature is bound to that specific DELTA record hash.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _dt
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

PROTOCOL = "DELTA-0"
SHA256_PREFIX = "sha256:"
PRIVATE_SEED_PREFIX = "ed25519seed:"
PUBLIC_KEY_PREFIX = "ed25519:"
SIGNATURE_PREFIX = "ed25519sig:"

CHALLENGE_TYPE = "delta_wallet_challenge"
CHALLENGE_BODY_TYPE = "delta_wallet_challenge_body"
PROOF_TYPE = "delta_wallet_proof"
PROOF_BODY_TYPE = "delta_wallet_proof_body"
PROOF_VERSION = "1.0.0"

SUPPORTED_STANDARDS = {
    "ed25519_address_control_v1",
}
SUPPORTED_CHAINS = {
    "ed25519-demo",
}


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> _dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = _dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


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


def write_private_key_file(path: Path, value: str, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise SystemExit(f"private key file already exists: {path}. Use --force to overwrite test keys intentionally.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8", newline="\n")


def public_key_string(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PUBLIC_KEY_PREFIX + b64url_no_padding(raw)


def address_from_public_key_text(public_key_text: str) -> str:
    # In this MVP, the demo address is the Ed25519 raw public key string.
    # This is intentionally NOT an ETH/BTC/KAS address format.
    return public_key_text


def public_key_hash(public_key_text: str) -> str:
    return sha256_prefixed(public_key_text.encode("utf-8"))


def load_private_key(path: Path) -> Ed25519PrivateKey:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text.startswith(PRIVATE_SEED_PREFIX):
        raise SystemExit("wallet private key must start with ed25519seed:")
    seed = b64url_decode_unpadded(text[len(PRIVATE_SEED_PREFIX):], "wallet_private_key")
    if len(seed) != 32:
        raise SystemExit("wallet private key seed must decode to 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_challenge(path: Path) -> dict[str, Any]:
    challenge = read_json(path)
    if not isinstance(challenge, dict):
        raise SystemExit("challenge JSON must be an object")
    return challenge


def load_proof(path: Path) -> dict[str, Any]:
    proof = read_json(path)
    if not isinstance(proof, dict):
        raise SystemExit("wallet proof JSON must be an object")
    return proof


def load_record(path: Path) -> dict[str, Any]:
    record = read_json(path)
    if not isinstance(record, dict):
        raise SystemExit("record JSON must be an object")
    return record


def record_type(record: dict[str, Any]) -> str:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    value = body.get("type") or record.get("type") or "delta_record"
    return str(value)


def make_record_target(record: dict[str, Any], record_path: Path) -> dict[str, Any]:
    return {
        "record_hash": canonical_sha256(record),
        "record_type": record_type(record),
        "record_path_hint": str(record_path),
        "hash_algorithm": "sha256(canonical_json(full_delta_record_json))",
    }


def validate_challenge_self_check(challenge: dict[str, Any]) -> tuple[bool, str, dict[str, Any] | None, str]:
    if challenge.get("type") != CHALLENGE_TYPE or challenge.get("protocol") != PROTOCOL:
        return False, "challenge_type_or_protocol_invalid", None, ""
    body = challenge.get("challenge_body") if isinstance(challenge.get("challenge_body"), dict) else None
    if body is None:
        return False, "challenge_missing_body", None, ""
    body_hash = canonical_sha256(body)
    if challenge.get("challenge_body_hash") != body_hash:
        return False, "challenge_body_hash_mismatch", body, body_hash
    integrity = challenge.get("challenge_integrity") if isinstance(challenge.get("challenge_integrity"), dict) else {}
    if integrity.get("self_check_hash") not in (None, body_hash):
        return False, "challenge_self_check_hash_mismatch", body, body_hash
    return True, "challenge_self_check_ok", body, body_hash


def make_challenge_body(
    *,
    chain: str,
    address: str,
    purpose: str,
    domain: str,
    expires_at: str,
    nonce: str,
    record_target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if chain not in SUPPORTED_CHAINS:
        raise SystemExit(f"unsupported chain for v2.3.0 MVP: {chain}")
    if not address.startswith(PUBLIC_KEY_PREFIX):
        raise SystemExit("ed25519 demo address must start with ed25519:")
    issued_at = now_utc()
    target: dict[str, Any] = {
        "address": address,
        "address_type": "ed25519_public_key_address_demo",
        "public_key_hash": public_key_hash(address),
    }
    if record_target:
        target.update(record_target)

    body = {
        "type": CHALLENGE_BODY_TYPE,
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "wallet_standard": "ed25519_address_control_v1",
        "chain": chain,
        "challenge_id": "W-" + secrets.token_hex(12),
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at or None,
        "domain": domain,
        "purpose": purpose,
        "target": target,
        "statement": (
            "Sign this DELTA challenge to prove control of the listed demo Ed25519 address. "
            "When target.record_hash is present, the signature is also bound to that exact DELTA record hash. "
            "Do not sign this message if the domain, purpose, address, or record hash is unexpected."
        ),
        "security_boundary": {
            "proves_address_control_signature": True,
            "proves_record_hash_binding_when_record_hash_present": bool(record_target),
            "proves_legal_ownership": False,
            "proves_real_world_identity": False,
            "proves_wallet_balance": False,
            "proves_chain_state": False,
            "proves_mica_compliance": False,
            "note": "v2.3.0 uses a demo Ed25519 adapter to harden the proof envelope. ETH/BTC/KAS adapters are separate roadmap items.",
        },
    }
    return body


def create_challenge(body: dict[str, Any]) -> dict[str, Any]:
    body_hash = canonical_sha256(body)
    return {
        "type": CHALLENGE_TYPE,
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "challenge_body_hash": body_hash,
        "challenge_body": body,
        "challenge_integrity": {
            "hash_algorithm": "sha256(canonical_json(challenge_body))",
            "self_check_hash": body_hash,
        },
    }


def create_wallet_proof(
    *,
    challenge: dict[str, Any],
    private_key: Ed25519PrivateKey,
    holder: str,
    record: dict[str, Any] | None = None,
    record_path: Path | None = None,
) -> dict[str, Any]:
    challenge_ok, challenge_reason, challenge_body, challenge_body_hash = validate_challenge_self_check(challenge)
    if not challenge_ok or challenge_body is None:
        raise SystemExit(challenge_reason)

    public_text = public_key_string(private_key.public_key())
    address = address_from_public_key_text(public_text)
    target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
    expected_address = target.get("address")
    if expected_address != address:
        raise SystemExit("private key does not control the challenge target address")

    record_target: dict[str, Any] | None = None
    if record is not None:
        if record_path is None:
            raise SystemExit("record_path is required when record is supplied")
        record_target = make_record_target(record, record_path)
        if target.get("record_hash") != record_target["record_hash"]:
            raise SystemExit(
                "challenge target.record_hash does not match supplied record. "
                "Create the challenge with --record before signing."
            )

    payload = canonical_json_bytes(challenge_body)
    signature_bytes = private_key.sign(payload)

    proof_target = {
        "challenge_hash": challenge_body_hash,
        "challenge_id": challenge_body.get("challenge_id"),
        "address": address,
        "address_type": target.get("address_type"),
        "public_key_hash": public_key_hash(public_text),
    }
    if target.get("record_hash"):
        proof_target["record_hash"] = target.get("record_hash")
        proof_target["record_type"] = target.get("record_type")
        proof_target["record_hash_algorithm"] = target.get("hash_algorithm")
        proof_target["record_path_hint"] = target.get("record_path_hint")

    body = {
        "type": PROOF_BODY_TYPE,
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "wallet_standard": challenge_body.get("wallet_standard"),
        "chain": challenge_body.get("chain"),
        "target": proof_target,
        "attestation": {
            "type": "delta_wallet_address_control_attestation",
            "holder": holder,
            "created_at": now_utc(),
            "claim": "signer_controlled_address_for_challenge",
            "record_binding_signed_by_wallet": bool(target.get("record_hash")),
        },
        "signature": {
            "type": "delta_wallet_signature",
            "alg": "Ed25519",
            "signed_payload": "challenge_body",
            "signed_hash": challenge_body_hash,
            "signed_record_hash": target.get("record_hash") or None,
            "public_key": public_text,
            "address": address,
            "signature": SIGNATURE_PREFIX + b64url_no_padding(signature_bytes),
        },
        "security_boundary": {
            "proves_address_control_signature": True,
            "proves_record_hash_binding_when_record_hash_present": bool(target.get("record_hash")),
            "proves_legal_ownership": False,
            "proves_real_world_identity": False,
            "proves_wallet_balance": False,
            "proves_chain_state": False,
            "proves_mica_compliance": False,
            "note": "This proof verifies control of a demo Ed25519 address for a specific signed challenge. If target.record_hash is present, it is inside the signed challenge_body.",
        },
    }
    body_hash = canonical_sha256(body)
    return {
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
            "note": "The wallet signature is over challenge_body. The proof envelope uses hash self-checks.",
        },
    }


def verify_wallet_proof(
    *,
    proof: dict[str, Any],
    challenge: dict[str, Any] | None = None,
    record: dict[str, Any] | None = None,
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

    standard = body.get("wallet_standard")
    chain = body.get("chain")
    checks["wallet_standard_ok"] = standard in SUPPORTED_STANDARDS
    reasons["wallet_standard"] = "wallet_standard_supported" if checks["wallet_standard_ok"] else f"unsupported_wallet_standard:{standard}"
    checks["chain_ok"] = chain in SUPPORTED_CHAINS
    reasons["chain"] = "chain_supported" if checks["chain_ok"] else f"unsupported_chain:{chain}"

    target = body.get("target") if isinstance(body.get("target"), dict) else {}
    signature = body.get("signature") if isinstance(body.get("signature"), dict) else {}
    target_address = target.get("address")
    public_text = signature.get("public_key")
    signature_address = signature.get("address")

    checks["address_shape_ok"] = isinstance(target_address, str) and target_address.startswith(PUBLIC_KEY_PREFIX)
    reasons["address_shape"] = "address_shape_ok" if checks["address_shape_ok"] else "address_missing_or_invalid"

    checks["public_key_hash_ok"] = isinstance(public_text, str) and public_text.startswith(PUBLIC_KEY_PREFIX) and target.get("public_key_hash") == public_key_hash(public_text)
    reasons["public_key_hash"] = "public_key_hash_matches" if checks["public_key_hash_ok"] else "public_key_hash_mismatch"

    checks["address_binding_ok"] = isinstance(public_text, str) and address_from_public_key_text(public_text) == target_address and signature_address == target_address
    reasons["address_binding"] = "signature_public_key_address_matches_target" if checks["address_binding_ok"] else "signature_public_key_address_mismatch"

    challenge_body = None
    challenge_hash = ""
    challenge_target: dict[str, Any] = {}
    if challenge is not None:
        challenge_ok, challenge_reason, challenge_body, challenge_hash = validate_challenge_self_check(challenge)
        checks["challenge_self_check_ok"] = challenge_ok
        reasons["challenge_self_check"] = challenge_reason
        if challenge_body is not None:
            challenge_target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
        checks["challenge_binding_ok"] = (
            challenge_ok
            and target.get("challenge_hash") == challenge_hash
            and signature.get("signed_hash") == challenge_hash
            and target.get("challenge_id") == challenge_body.get("challenge_id") if isinstance(challenge_body, dict) else False
        )
        reasons["challenge_binding"] = "proof_targets_supplied_challenge" if checks["challenge_binding_ok"] else "challenge_hash_or_id_mismatch"

        expires_at = challenge_body.get("expires_at") if isinstance(challenge_body, dict) else None
        if expires_at:
            try:
                checks["challenge_not_expired_ok"] = parse_time(str(expires_at)) >= _dt.datetime.now(_dt.timezone.utc)
                reasons["challenge_not_expired"] = "challenge_not_expired" if checks["challenge_not_expired_ok"] else "challenge_expired"
            except Exception as exc:
                checks["challenge_not_expired_ok"] = False
                reasons["challenge_not_expired"] = f"challenge_expiry_invalid:{type(exc).__name__}"
        else:
            checks["challenge_not_expired_ok"] = True
            reasons["challenge_not_expired"] = "no_expiry_declared"
    else:
        checks["challenge_self_check_ok"] = True
        reasons["challenge_self_check"] = "challenge_not_supplied"
        checks["challenge_binding_ok"] = True
        reasons["challenge_binding"] = "challenge_not_supplied_binding_not_checked"
        checks["challenge_not_expired_ok"] = True
        reasons["challenge_not_expired"] = "challenge_not_supplied_expiry_not_checked"

    proof_record_hash = target.get("record_hash")
    challenge_record_hash = challenge_target.get("record_hash") if challenge_target else None

    checks["record_hash_shape_ok"] = proof_record_hash in (None, "") or (isinstance(proof_record_hash, str) and proof_record_hash.startswith(SHA256_PREFIX))
    reasons["record_hash_shape"] = "record_hash_shape_ok" if checks["record_hash_shape_ok"] else "proof_target_record_hash_invalid"

    checks["proof_challenge_record_binding_ok"] = True
    reasons["proof_challenge_record_binding"] = "no_record_hash_declared"
    if proof_record_hash or challenge_record_hash:
        checks["proof_challenge_record_binding_ok"] = bool(proof_record_hash) and proof_record_hash == challenge_record_hash and signature.get("signed_record_hash") in (None, proof_record_hash)
        reasons["proof_challenge_record_binding"] = "proof_record_hash_matches_signed_challenge_record_hash" if checks["proof_challenge_record_binding_ok"] else "proof_record_hash_challenge_record_hash_mismatch"

    record_hash = ""
    checks["record_binding_ok"] = True
    reasons["record_binding"] = "record_not_supplied_binding_not_checked"
    if record is not None:
        record_hash = canonical_sha256(record)
        checks["record_binding_ok"] = proof_record_hash == record_hash and challenge_record_hash == record_hash
        reasons["record_binding"] = "proof_and_challenge_record_hash_match_record" if checks["record_binding_ok"] else "record_hash_mismatch"

    checks["record_signed_by_challenge_ok"] = True
    reasons["record_signed_by_challenge"] = "record_not_supplied_or_not_declared"
    if record is not None or proof_record_hash or challenge_record_hash:
        checks["record_signed_by_challenge_ok"] = bool(challenge_record_hash) and bool(proof_record_hash) and proof_record_hash == challenge_record_hash
        reasons["record_signed_by_challenge"] = "record_hash_is_inside_signed_challenge_body" if checks["record_signed_by_challenge_ok"] else "record_hash_not_inside_signed_challenge_body"

    checks["signature_shape_ok"] = (
        signature.get("type") == "delta_wallet_signature"
        and signature.get("alg") == "Ed25519"
        and signature.get("signed_payload") == "challenge_body"
        and isinstance(signature.get("signature"), str)
        and signature.get("signature", "").startswith(SIGNATURE_PREFIX)
    )
    reasons["signature_shape"] = "signature_shape_ok" if checks["signature_shape_ok"] else "signature_shape_invalid"

    checks["signature_ok"] = False
    reasons["signature"] = "signature_not_verified"
    if challenge_body is not None and checks["signature_shape_ok"] and isinstance(public_text, str) and public_text.startswith(PUBLIC_KEY_PREFIX):
        try:
            public_raw = b64url_decode_unpadded(public_text[len(PUBLIC_KEY_PREFIX):], "public_key")
            sig_raw = b64url_decode_unpadded(signature["signature"][len(SIGNATURE_PREFIX):], "signature")
            if len(public_raw) != 32:
                raise ValueError("public_key_not_32_bytes")
            if len(sig_raw) != 64:
                raise ValueError("signature_not_64_bytes")
            pub = Ed25519PublicKey.from_public_bytes(public_raw)
            pub.verify(sig_raw, canonical_json_bytes(challenge_body))
            checks["signature_ok"] = True
            reasons["signature"] = "ed25519_signature_verified"
        except InvalidSignature:
            checks["signature_ok"] = False
            reasons["signature"] = "ed25519_signature_invalid"
        except Exception as exc:
            checks["signature_ok"] = False
            reasons["signature"] = f"signature_verify_error:{type(exc).__name__}"
    elif challenge is None:
        reasons["signature"] = "challenge_not_supplied_signature_not_checked"

    ok = all(checks.values())
    return {
        "ok": bool(ok),
        "checks": checks,
        "reasons": reasons,
        "proof_body_hash": expected_body_hash,
        "challenge_hash": challenge_hash or target.get("challenge_hash", ""),
        "address": target_address or "",
        "wallet_standard": standard or "",
        "chain": chain or "",
        "record_hash": record_hash or proof_record_hash or "",
    }


def command_keygen(args: argparse.Namespace) -> int:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_text = public_key_string(private_key.public_key())
    address = address_from_public_key_text(public_text)
    private_value = PRIVATE_SEED_PREFIX + b64url_no_padding(private_raw)

    private_out = Path(args.private_out).resolve()
    write_private_key_file(private_out, private_value, force=args.force)

    public_doc = {
        "type": "delta_wallet_demo_public_key",
        "version": PROOF_VERSION,
        "protocol": PROTOCOL,
        "wallet_standard": "ed25519_address_control_v1",
        "chain": "ed25519-demo",
        "public_key": public_text,
        "public_key_hash": public_key_hash(public_text),
        "address": address,
        "address_type": "ed25519_public_key_address_demo",
        "security_boundary": {
            "demo_key_only": True,
            "not_a_production_crypto_wallet": True,
            "do_not_commit_private_key": True,
        },
    }
    if args.public_out:
        write_json(Path(args.public_out).resolve(), public_doc)

    print("DELTA_WALLET_KEYGEN_OK=True")
    print(f"DELTA_WALLET_PRIVATE_KEY_WRITTEN={private_out}")
    print("DELTA_WALLET_PRIVATE_KEY_WARNING=do_not_commit_do_not_paste_to_chat_demo_key_only")
    if args.public_out:
        print(f"DELTA_WALLET_PUBLIC_KEY_WRITTEN={Path(args.public_out).resolve()}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_PUBLIC_KEY_HASH={public_key_hash(public_text)}")
    return 0


def command_create_challenge(args: argparse.Namespace) -> int:
    nonce = args.nonce or b64url_no_padding(secrets.token_bytes(32))
    record_target = None
    if args.record:
        record_path = Path(args.record).resolve()
        record_target = make_record_target(load_record(record_path), record_path)
    body = make_challenge_body(
        chain=args.chain,
        address=args.address,
        purpose=args.purpose,
        domain=args.domain,
        expires_at=args.expires_at,
        nonce=nonce,
        record_target=record_target,
    )
    challenge = create_challenge(body)
    out = Path(args.out).resolve()
    write_json(out, challenge)
    print("DELTA_WALLET_CHALLENGE_CREATE_OK=True")
    print(f"DELTA_WALLET_CHALLENGE={out}")
    print(f"DELTA_WALLET_CHALLENGE_ID={body['challenge_id']}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge['challenge_body_hash']}")
    print(f"DELTA_WALLET_ADDRESS={body['target']['address']}")
    print(f"DELTA_WALLET_CHAIN={body['chain']}")
    if body["target"].get("record_hash"):
        print(f"DELTA_WALLET_RECORD_HASH={body['target']['record_hash']}")
        print("DELTA_WALLET_RECORD_BINDING_DECLARED=True")
    else:
        print("DELTA_WALLET_RECORD_BINDING_DECLARED=False")
    return 0


def command_create_proof(args: argparse.Namespace) -> int:
    challenge = load_challenge(Path(args.challenge).resolve())
    private_key = load_private_key(Path(args.private_key).resolve())
    record = None
    record_path = None
    if args.record:
        record_path = Path(args.record).resolve()
        record = load_record(record_path)
    proof = create_wallet_proof(challenge=challenge, private_key=private_key, holder=args.holder, record=record, record_path=record_path)
    out = Path(args.out).resolve()
    write_json(out, proof)
    body = proof["proof_body"]
    print("DELTA_WALLET_PROOF_CREATE_OK=True")
    print(f"DELTA_WALLET_PROOF={out}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={proof['proof_body_hash']}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={body['target']['challenge_hash']}")
    print(f"DELTA_WALLET_ADDRESS={body['target']['address']}")
    print(f"DELTA_WALLET_CHAIN={body['chain']}")
    print(f"DELTA_WALLET_STANDARD={body['wallet_standard']}")
    if body["target"].get("record_hash"):
        print(f"DELTA_WALLET_RECORD_HASH={body['target']['record_hash']}")
        print("DELTA_WALLET_RECORD_BINDING_SIGNED=True")
    else:
        print("DELTA_WALLET_RECORD_BINDING_SIGNED=False")
    return 0


def command_verify_proof(args: argparse.Namespace) -> int:
    proof = load_proof(Path(args.proof).resolve())
    challenge = load_challenge(Path(args.challenge).resolve()) if args.challenge else None
    record = load_record(Path(args.record).resolve()) if args.record else None
    result = verify_wallet_proof(proof=proof, challenge=challenge, record=record)
    checks = result["checks"]
    reasons = result["reasons"]
    print(f"DELTA_WALLET_VERIFY_OK={bool(result['ok'])}")
    print(f"DELTA_WALLET_PROOF_SHAPE_OK={bool(checks.get('proof_shape_ok'))}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH_OK={bool(checks.get('proof_body_hash_ok'))}")
    print(f"DELTA_WALLET_SELF_CHECK_OK={bool(checks.get('self_check_ok'))}")
    print(f"DELTA_WALLET_STANDARD_OK={bool(checks.get('wallet_standard_ok'))}")
    print(f"DELTA_WALLET_CHAIN_OK={bool(checks.get('chain_ok'))}")
    print(f"DELTA_WALLET_ADDRESS_SHAPE_OK={bool(checks.get('address_shape_ok'))}")
    print(f"DELTA_WALLET_PUBLIC_KEY_HASH_OK={bool(checks.get('public_key_hash_ok'))}")
    print(f"DELTA_WALLET_ADDRESS_BINDING_OK={bool(checks.get('address_binding_ok'))}")
    print(f"DELTA_WALLET_CHALLENGE_SELF_CHECK_OK={bool(checks.get('challenge_self_check_ok'))}")
    print(f"DELTA_WALLET_CHALLENGE_BINDING_OK={bool(checks.get('challenge_binding_ok'))}")
    print(f"DELTA_WALLET_CHALLENGE_NOT_EXPIRED_OK={bool(checks.get('challenge_not_expired_ok'))}")
    print(f"DELTA_WALLET_RECORD_HASH_SHAPE_OK={bool(checks.get('record_hash_shape_ok'))}")
    print(f"DELTA_WALLET_PROOF_CHALLENGE_RECORD_BINDING_OK={bool(checks.get('proof_challenge_record_binding_ok'))}")
    print(f"DELTA_WALLET_RECORD_BINDING_OK={bool(checks.get('record_binding_ok'))}")
    print(f"DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK={bool(checks.get('record_signed_by_challenge_ok'))}")
    print(f"DELTA_WALLET_SIGNATURE_SHAPE_OK={bool(checks.get('signature_shape_ok'))}")
    print(f"DELTA_WALLET_SIGNATURE_OK={bool(checks.get('signature_ok'))}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={result.get('challenge_hash', '')}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={result.get('proof_body_hash', '')}")
    print(f"DELTA_WALLET_ADDRESS={result.get('address', '')}")
    print(f"DELTA_WALLET_CHAIN={result.get('chain', '')}")
    print(f"DELTA_WALLET_STANDARD={result.get('wallet_standard', '')}")
    if result.get("record_hash"):
        print(f"DELTA_WALLET_RECORD_HASH={result.get('record_hash', '')}")
    if not result["ok"]:
        for key, ok in sorted(checks.items()):
            if not ok:
                reason_key = key[:-3] if key.endswith("_ok") else key
                print(f"DELTA_WALLET_REASON_{key.upper()}={reasons.get(reason_key, '')}")
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Crypto Wallet / Address Control tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate a demo Ed25519 wallet key pair for local tests only.")
    keygen.add_argument("--private-out", required=True, help="Path for demo private key. Do not commit.")
    keygen.add_argument("--public-out", default="", help="Optional path for demo public key/address JSON.")
    keygen.add_argument("--force", action="store_true", help="Overwrite existing demo private key file.")
    keygen.set_defaults(func=command_keygen)

    challenge = subparsers.add_parser("create-challenge", help="Create a DELTA wallet address-control challenge.")
    challenge.add_argument("--out", required=True, help="Path for challenge JSON.")
    challenge.add_argument("--chain", default="ed25519-demo", choices=sorted(SUPPORTED_CHAINS), help="Chain/adapter id.")
    challenge.add_argument("--address", required=True, help="Target address for this MVP, e.g. ed25519:<base64url_public_key>.")
    challenge.add_argument("--record", default="", help="Optional delta-record.json path. When supplied, target.record_hash is embedded into the signed challenge_body.")
    challenge.add_argument("--domain", default="local-delta-test", help="Domain/context displayed in the challenge.")
    challenge.add_argument("--purpose", default="DELTA wallet address control proof", help="Human-readable challenge purpose.")
    challenge.add_argument("--expires-at", default="", help="Optional UTC ISO-8601 expiry timestamp.")
    challenge.add_argument("--nonce", default="", help="Optional nonce for deterministic tests; normally omitted.")
    challenge.set_defaults(func=command_create_challenge)

    proof = subparsers.add_parser("create-proof", help="Create a DELTA wallet proof by signing a challenge with a demo Ed25519 key.")
    proof.add_argument("--challenge", required=True, help="Path to wallet challenge JSON.")
    proof.add_argument("--private-key", required=True, help="Path to demo private key file. Do not commit.")
    proof.add_argument("--record", default="", help="Optional delta-record.json path. If supplied, it must match challenge_body.target.record_hash.")
    proof.add_argument("--out", required=True, help="Path for wallet proof JSON.")
    proof.add_argument("--holder", default="local-wallet-holder", help="Non-authoritative holder label for test/demo proofs.")
    proof.set_defaults(func=command_create_proof)

    verify = subparsers.add_parser("verify-proof", help="Verify a DELTA wallet proof offline.")
    verify.add_argument("--proof", required=True, help="Path to wallet proof JSON.")
    verify.add_argument("--challenge", default="", help="Optional path to challenge JSON for binding and signature verification.")
    verify.add_argument("--record", default="", help="Optional path to delta-record.json for record binding verification.")
    verify.set_defaults(func=command_verify_proof)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
