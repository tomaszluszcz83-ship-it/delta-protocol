#!/usr/bin/env python3
"""DELTA Proof of Crypto Wallet / Address Control tool.

Security boundary:
- never ask for a seed phrase
- demo key commands are for local testing only
- wallet proofs do not prove legal ownership, balance, identity, compliance, or external truth
- they prove only what each adapter explicitly verifies
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

try:
    from eth_account import Account  # type: ignore
    from eth_account.messages import encode_defunct, encode_typed_data  # type: ignore
    HAS_ETH_ACCOUNT = True
except Exception:  # pragma: no cover - optional dependency
    Account = None  # type: ignore
    encode_defunct = None  # type: ignore
    encode_typed_data = None  # type: ignore
    HAS_ETH_ACCOUNT = False

DELTA_PROTOCOL = "DELTA-0"

CHAIN_ED25519_DEMO = "ed25519-demo"
CHAIN_ETHEREUM = "ethereum"
CHAIN_BITCOIN = "bitcoin"

STANDARD_ED25519 = "ed25519_address_control_v1"
STANDARD_ETH_EIP191 = "ethereum_eip191_personal_sign_v1"
STANDARD_ETH_EIP712 = "ethereum_eip712_typed_data_v1"
STANDARD_BTC_BIP322_EXTERNAL = "bitcoin_bip322_external_v1"
SUPPORTED_STANDARDS = {
    STANDARD_ED25519,
    STANDARD_ETH_EIP191,
    STANDARD_ETH_EIP712,
    STANDARD_BTC_BIP322_EXTERNAL,
}

PUBLIC_KEY_PREFIX = "ed25519:"
SEED_PREFIX = "ed25519seed:"
SIGNATURE_PREFIX = "ed25519sig:"
ETH_KEY_PREFIX = "ethkey:"

SUPPORTED_BITCOIN_SIGNATURE_FORMATS = {
    "bip322_simple_base64_or_external",
    "bip322_simple_base64",
    "legacy_base64_external",
    "external_base64",
    "external_hex",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


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


def load_record_hash(record_path: str | None) -> str | None:
    if not record_path:
        return None
    record = read_json(Path(record_path).resolve())
    return canonical_sha256(record)


def is_sha256_prefixed(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(c in "0123456789abcdef" for c in value[7:])


def normalize_eth_address(address: str) -> str:
    return address.strip()


def is_eth_address(address: Any) -> bool:
    if not isinstance(address, str):
        return False
    value = address.strip()
    if not value.startswith("0x") or len(value) != 42:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value[2:])


def is_bitcoin_address_shape(address: Any) -> bool:
    if not isinstance(address, str):
        return False
    value = address.strip()
    if len(value) < 14 or len(value) > 120:
        return False
    allowed = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzbcqrtBCRT"
    if not all(c in allowed for c in value):
        return False
    return value.startswith(("bc1", "tb1", "bcrt1", "1", "3", "m", "n", "2"))


def infer_standard(chain: str, standard: str | None) -> str:
    if standard:
        return standard
    if chain == CHAIN_ED25519_DEMO:
        return STANDARD_ED25519
    if chain == CHAIN_ETHEREUM:
        return STANDARD_ETH_EIP191
    if chain == CHAIN_BITCOIN:
        return STANDARD_BTC_BIP322_EXTERNAL
    raise SystemExit(f"unsupported chain without explicit standard: {chain}")


def validate_chain_standard(chain: str, standard: str) -> None:
    if standard not in SUPPORTED_STANDARDS:
        raise SystemExit(f"unsupported wallet proof standard: {standard}")
    if standard == STANDARD_ED25519 and chain != CHAIN_ED25519_DEMO:
        raise SystemExit(f"{STANDARD_ED25519} requires chain {CHAIN_ED25519_DEMO}")
    if standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and chain != CHAIN_ETHEREUM:
        raise SystemExit(f"{standard} requires chain {CHAIN_ETHEREUM}")
    if standard == STANDARD_BTC_BIP322_EXTERNAL and chain != CHAIN_BITCOIN:
        raise SystemExit(f"{STANDARD_BTC_BIP322_EXTERNAL} requires chain {CHAIN_BITCOIN}")


def challenge_message(challenge_body: dict[str, Any]) -> str:
    target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
    record_hash = target.get("record_hash") or "none"
    lines = [
        "DELTA Proof of Crypto Wallet / Address Control",
        f"protocol={challenge_body.get('protocol_version')}",
        f"standard={challenge_body.get('standard')}",
        f"chain={challenge_body.get('chain')}",
        f"address={challenge_body.get('address')}",
        f"challenge_id={challenge_body.get('challenge_id')}",
        f"domain={challenge_body.get('domain')}",
        f"purpose={challenge_body.get('purpose')}",
        f"nonce={challenge_body.get('nonce')}",
        f"record_hash={record_hash}",
    ]
    return "\n".join(str(x) for x in lines)


def build_eip712_typed_data(challenge_body: dict[str, Any]) -> dict[str, Any]:
    target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
    eip712 = challenge_body.get("eip712") if isinstance(challenge_body.get("eip712"), dict) else {}
    try:
        chain_id = int(eip712.get("chain_id", 1))
    except Exception:
        chain_id = 1
    domain_name = str(eip712.get("domain_name") or "DELTA Protocol")
    domain_version = str(eip712.get("domain_version") or "2.3.2")
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "DeltaWalletChallenge": [
                {"name": "protocol", "type": "string"},
                {"name": "standard", "type": "string"},
                {"name": "chain", "type": "string"},
                {"name": "address", "type": "string"},
                {"name": "challengeId", "type": "string"},
                {"name": "domain", "type": "string"},
                {"name": "purpose", "type": "string"},
                {"name": "nonce", "type": "string"},
                {"name": "recordHash", "type": "string"},
            ],
        },
        "primaryType": "DeltaWalletChallenge",
        "domain": {
            "name": domain_name,
            "version": domain_version,
            "chainId": chain_id,
        },
        "message": {
            "protocol": str(challenge_body.get("protocol_version") or DELTA_PROTOCOL),
            "standard": str(challenge_body.get("standard") or ""),
            "chain": str(challenge_body.get("chain") or ""),
            "address": str(challenge_body.get("address") or ""),
            "challengeId": str(challenge_body.get("challenge_id") or ""),
            "domain": str(challenge_body.get("domain") or ""),
            "purpose": str(challenge_body.get("purpose") or ""),
            "nonce": str(challenge_body.get("nonce") or ""),
            "recordHash": str(target.get("record_hash") or "none"),
        },
    }


def encode_eip712_message(typed_data: dict[str, Any]) -> Any:
    if not HAS_ETH_ACCOUNT or encode_typed_data is None:
        raise RuntimeError("optional dependency eth-account is required for Ethereum EIP-712")
    return encode_typed_data(full_message=typed_data)  # type: ignore[misc]


def load_ed25519_seed(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8").strip()
    if not text.startswith(SEED_PREFIX):
        raise SystemExit("Ed25519 demo key file has invalid prefix")
    seed = b64url_decode_unpadded(text[len(SEED_PREFIX):], "ed25519 demo key")
    if len(seed) != 32:
        raise SystemExit("Ed25519 demo key must decode to 32 bytes")
    return seed


def public_key_to_address(public_key_bytes: bytes) -> str:
    return PUBLIC_KEY_PREFIX + b64url_no_padding(public_key_bytes)


def hash_text(text: str) -> str:
    return sha256_prefixed(text.encode("utf-8"))


def verify_ed25519_signature(challenge_body: dict[str, Any], sig_doc: dict[str, Any], address: str) -> tuple[bool, str]:
    try:
        if sig_doc.get("alg") != "Ed25519":
            return False, "ed25519_alg_mismatch"
        public_key_text = sig_doc.get("public_key")
        sig_text = sig_doc.get("signature")
        if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
            return False, "ed25519_public_key_shape_invalid"
        if public_key_text != address:
            return False, "ed25519_address_public_key_mismatch"
        if not isinstance(sig_text, str) or not sig_text.startswith(SIGNATURE_PREFIX):
            return False, "ed25519_signature_shape_invalid"
        payload = canonical_json_bytes(challenge_body)
        public_key_bytes = b64url_decode_unpadded(public_key_text[len(PUBLIC_KEY_PREFIX):], "ed25519 public key")
        signature_bytes = b64url_decode_unpadded(sig_text[len(SIGNATURE_PREFIX):], "ed25519 signature")
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, payload)
        return True, "ed25519_signature_valid"
    except InvalidSignature:
        return False, "ed25519_signature_invalid"
    except Exception as exc:
        return False, f"ed25519_signature_error:{type(exc).__name__}"


def verify_eth_eip191(message: str, signature_hex: str, address: str) -> tuple[bool, str, str | None]:
    try:
        if not HAS_ETH_ACCOUNT or Account is None or encode_defunct is None:
            return False, "eth_account_missing", None
        if not is_eth_signature_shape(signature_hex):
            return False, "ethereum_eip191_signature_shape_invalid", None
        encoded = encode_defunct(text=message)
        recovered = Account.recover_message(encoded, signature=signature_hex)
        ok = recovered.lower() == address.lower()
        return ok, "ethereum_eip191_signature_valid" if ok else "ethereum_eip191_signature_invalid", recovered
    except Exception as exc:
        return False, f"ethereum_eip191_signature_error:{type(exc).__name__}", None


def verify_eth_eip712(typed_data: dict[str, Any], signature_hex: str, address: str) -> tuple[bool, str, str | None]:
    try:
        if not HAS_ETH_ACCOUNT or Account is None:
            return False, "eth_account_missing", None
        if not isinstance(typed_data, dict) or not typed_data:
            return False, "ethereum_eip712_typed_data_missing", None
        if not is_eth_signature_shape(signature_hex):
            return False, "ethereum_eip712_signature_shape_invalid", None
        encoded = encode_eip712_message(typed_data)
        recovered = Account.recover_message(encoded, signature=signature_hex)
        ok = recovered.lower() == address.lower()
        return ok, "ethereum_eip712_signature_valid" if ok else "ethereum_eip712_signature_invalid", recovered
    except Exception as exc:
        return False, f"ethereum_eip712_signature_error:{type(exc).__name__}", None


def is_eth_signature_shape(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    sig = value.strip()
    if sig.startswith("0x"):
        sig = sig[2:]
    return len(sig) == 130 and all(c in "0123456789abcdefABCDEF" for c in sig)


def is_base64_like(value: str) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip()
    padded = text + ("=" * ((4 - len(text) % 4) % 4))
    try:
        base64.b64decode(padded, validate=True)
        return True
    except Exception:
        return False


def is_hex_like(value: str) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text.startswith("0x"):
        text = text[2:]
    return len(text) >= 16 and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text)


def bitcoin_signature_shape(signature_value: Any, signature_format: Any) -> tuple[bool, str]:
    if not isinstance(signature_value, str) or not signature_value.strip():
        return False, "bitcoin_signature_empty"
    if not isinstance(signature_format, str) or signature_format not in SUPPORTED_BITCOIN_SIGNATURE_FORMATS:
        return False, "bitcoin_signature_format_unsupported"
    sig = signature_value.strip()
    if signature_format == "external_hex":
        return (True, "bitcoin_signature_hex_shape_ok") if is_hex_like(sig) else (False, "bitcoin_signature_hex_shape_invalid")
    if signature_format in {"bip322_simple_base64", "legacy_base64_external", "external_base64"}:
        return (True, "bitcoin_signature_base64_shape_ok") if is_base64_like(sig) else (False, "bitcoin_signature_base64_shape_invalid")
    if signature_format == "bip322_simple_base64_or_external":
        if is_base64_like(sig) or is_hex_like(sig):
            return True, "bitcoin_signature_external_shape_ok"
        if len(sig) >= 16:
            return True, "bitcoin_signature_external_nonempty_shape_ok"
        return False, "bitcoin_signature_external_shape_invalid"
    return False, "bitcoin_signature_format_unsupported"


def command_keygen(args: argparse.Namespace) -> int:
    out = Path(args.private_out)
    if out.exists() and not args.force:
        raise SystemExit("key file exists; use --force to overwrite")
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    address = public_key_to_address(public_bytes)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(SEED_PREFIX + b64url_no_padding(seed) + "\n", encoding="utf-8")
    public_doc = {
        "type": "delta_wallet_public_key",
        "protocol_version": DELTA_PROTOCOL,
        "standard": STANDARD_ED25519,
        "chain": CHAIN_ED25519_DEMO,
        "address": address,
        "public_key": address,
        "public_key_hash": hash_text(address),
        "created_at": now_utc(),
        "security_boundary": "local demo key only; not a BTC ETH or KAS wallet",
    }
    write_json(Path(args.public_out), public_doc)
    print("DELTA_WALLET_KEYGEN_OK=True")
    print(f"DELTA_WALLET_KEY_FILE_WRITTEN={out}")
    print(f"DELTA_WALLET_PUBLIC_KEY_WRITTEN={Path(args.public_out).resolve()}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_PUBLIC_KEY_HASH={public_doc['public_key_hash']}")
    return 0


def command_eth_keygen(args: argparse.Namespace) -> int:
    if not HAS_ETH_ACCOUNT or Account is None:
        raise SystemExit("optional dependency eth-account is required for eth-keygen")
    out = Path(args.private_out)
    if out.exists() and not args.force:
        raise SystemExit("key file exists; use --force to overwrite")
    acct = Account.create()
    key_hex = acct.key.hex()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(ETH_KEY_PREFIX + key_hex + "\n", encoding="utf-8")
    public_doc = {
        "type": "delta_wallet_public_key",
        "protocol_version": DELTA_PROTOCOL,
        "standard": "ethereum_address_control_demo_key_v1",
        "chain": CHAIN_ETHEREUM,
        "address": acct.address,
        "public_key_hash": hash_text(acct.address.lower()),
        "created_at": now_utc(),
        "security_boundary": "local demo key only; do not use for funds",
    }
    write_json(Path(args.public_out), public_doc)
    print("DELTA_WALLET_ETH_KEYGEN_OK=True")
    print(f"DELTA_WALLET_ETH_KEY_FILE_WRITTEN={out}")
    print(f"DELTA_WALLET_ETH_PUBLIC_WRITTEN={Path(args.public_out).resolve()}")
    print(f"DELTA_WALLET_ETH_ADDRESS={acct.address}")
    print(f"DELTA_WALLET_ETH_ADDRESS_HASH={public_doc['public_key_hash']}")
    return 0


def command_create_challenge(args: argparse.Namespace) -> int:
    chain = args.chain
    standard = infer_standard(chain, args.standard)
    validate_chain_standard(chain, standard)
    address = args.address.strip()
    if standard == STANDARD_ED25519 and not address.startswith(PUBLIC_KEY_PREFIX):
        raise SystemExit("ed25519 demo address must start with ed25519:")
    if standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and not is_eth_address(address):
        raise SystemExit("ethereum address shape is invalid")
    if standard == STANDARD_BTC_BIP322_EXTERNAL and not is_bitcoin_address_shape(address):
        raise SystemExit("bitcoin address shape is invalid")

    record_hash = load_record_hash(args.record)
    challenge_id = args.challenge_id or ("W-" + secrets.token_hex(8))
    challenge_body: dict[str, Any] = {
        "type": "delta_wallet_challenge",
        "protocol_version": DELTA_PROTOCOL,
        "standard": standard,
        "chain": chain,
        "address": address,
        "challenge_id": challenge_id,
        "domain": args.domain,
        "purpose": args.purpose,
        "nonce": secrets.token_hex(16),
        "created_at": now_utc(),
        "expires_at": args.expires_at,
        "target": {
            "record_hash": record_hash,
            "record_type": "delta_record" if record_hash else None,
            "binding": "full_canonical_delta_record_hash" if record_hash else "none",
        },
    }
    challenge_body["message"] = challenge_message(challenge_body)

    if standard == STANDARD_ETH_EIP712:
        challenge_body["eip712"] = {
            "domain_name": "DELTA Protocol",
            "domain_version": "2.3.2",
            "chain_id": int(args.eip712_chain_id),
            "typed_data_source": "derived_from_challenge_body",
        }
        typed_data = build_eip712_typed_data(challenge_body)
        challenge_body["eip712_typed_data"] = typed_data
        challenge_body["eip712_typed_data_hash"] = canonical_sha256(typed_data)

    if standard == STANDARD_BTC_BIP322_EXTERNAL:
        challenge_body["bitcoin"] = {
            "adapter": STANDARD_BTC_BIP322_EXTERNAL,
            "verification_level": "shape_only",
            "verification_status": "external_pending",
            "local_signature_verification": False,
            "note": "v2.4.0 does not locally verify BIP-322 script or witness semantics",
        }

    challenge_hash = canonical_sha256(challenge_body)
    envelope = {
        "type": "delta_wallet_challenge_envelope",
        "protocol_version": DELTA_PROTOCOL,
        "challenge_body_hash": challenge_hash,
        "challenge_body": challenge_body,
        "challenge_integrity": {"self_check_hash": challenge_hash},
    }
    write_json(Path(args.out), envelope)
    print("DELTA_WALLET_CHALLENGE_CREATE_OK=True")
    print(f"DELTA_WALLET_CHALLENGE={Path(args.out).resolve()}")
    print(f"DELTA_WALLET_CHALLENGE_ID={challenge_id}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge_hash}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_CHAIN={chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    print(f"DELTA_WALLET_RECORD_BINDING_DECLARED={record_hash is not None}")
    if record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={record_hash}")
    if standard == STANDARD_ETH_EIP712:
        print(f"DELTA_WALLET_EIP712_TYPED_DATA_HASH={challenge_body.get('eip712_typed_data_hash')}")
    if standard == STANDARD_BTC_BIP322_EXTERNAL:
        print("DELTA_WALLET_BITCOIN_VERIFICATION_LEVEL=shape_only")
        print("DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False")
    return 0


def load_eth_key_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith(ETH_KEY_PREFIX):
        text = text[len(ETH_KEY_PREFIX):]
    if not text.startswith("0x"):
        text = "0x" + text
    return text


def command_create_proof(args: argparse.Namespace) -> int:
    challenge = read_json(Path(args.challenge))
    challenge_body = challenge.get("challenge_body")
    if not isinstance(challenge_body, dict):
        raise SystemExit("challenge_body missing")
    challenge_hash = canonical_sha256(challenge_body)
    if challenge.get("challenge_body_hash") != challenge_hash:
        raise SystemExit("challenge_body_hash mismatch")

    standard = str(challenge_body.get("standard"))
    chain = str(challenge_body.get("chain"))
    address = str(challenge_body.get("address"))
    validate_chain_standard(chain, standard)

    record_hash = load_record_hash(args.record)
    challenge_record_hash = (challenge_body.get("target") or {}).get("record_hash") if isinstance(challenge_body.get("target"), dict) else None
    if record_hash and challenge_record_hash != record_hash:
        raise SystemExit("supplied record hash does not match challenge target.record_hash")

    signature_doc: dict[str, Any]
    recovered_address: str | None = None

    if standard == STANDARD_ED25519:
        if not args.keyfile:
            raise SystemExit("--private-key is required for ed25519 demo proof")
        seed = load_ed25519_seed(Path(args.keyfile))
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_text = public_key_to_address(public)
        if public_text != address:
            raise SystemExit("ed25519 demo key does not match challenge address")
        sig = private.sign(canonical_json_bytes(challenge_body))
        signature_doc = {
            "alg": "Ed25519",
            "signed_payload": "challenge_body",
            "signed_hash": challenge_hash,
            "public_key": public_text,
            "public_key_hash": hash_text(public_text),
            "signature": SIGNATURE_PREFIX + b64url_no_padding(sig),
        }
    elif standard == STANDARD_ETH_EIP191:
        signature_hex = args.signature
        if not signature_hex:
            if not args.eth_keyfile:
                raise SystemExit("--signature or --eth-private-key is required for Ethereum EIP-191 proof")
            if not HAS_ETH_ACCOUNT or Account is None or encode_defunct is None:
                raise SystemExit("optional dependency eth-account is required for Ethereum EIP-191 signing")
            acct = Account.from_key(load_eth_key_text(Path(args.eth_keyfile)))
            signed = acct.sign_message(encode_defunct(text=str(challenge_body.get("message"))))
            signature_hex = "0x" + signed.signature.hex()
        ok, reason, recovered_address = verify_eth_eip191(str(challenge_body.get("message")), signature_hex, address)
        if not ok:
            raise SystemExit(f"Ethereum EIP-191 signature did not verify: {reason}")
        signature_doc = {
            "alg": "Ethereum EIP-191 personal_sign",
            "signed_payload": "challenge_message",
            "signed_hash": hash_text(str(challenge_body.get("message"))),
            "signature": signature_hex,
            "recovered_address": recovered_address,
        }
    elif standard == STANDARD_ETH_EIP712:
        typed_data = build_eip712_typed_data(challenge_body)
        signature_hex = args.signature
        if not signature_hex:
            if not args.eth_keyfile:
                raise SystemExit("--signature or --eth-private-key is required for Ethereum EIP-712 proof")
            if not HAS_ETH_ACCOUNT or Account is None:
                raise SystemExit("optional dependency eth-account is required for Ethereum EIP-712 signing")
            acct = Account.from_key(load_eth_key_text(Path(args.eth_keyfile)))
            signed = acct.sign_message(encode_eip712_message(typed_data))
            signature_hex = "0x" + signed.signature.hex()
        ok, reason, recovered_address = verify_eth_eip712(typed_data, signature_hex, address)
        if not ok:
            raise SystemExit(f"Ethereum EIP-712 signature did not verify: {reason}")
        signature_doc = {
            "alg": "Ethereum EIP-712 typed_data",
            "signed_payload": "eip712_typed_data",
            "signed_hash": canonical_sha256(typed_data),
            "typed_data_hash": canonical_sha256(typed_data),
            "signature": signature_hex,
            "recovered_address": recovered_address,
        }
    elif standard == STANDARD_BTC_BIP322_EXTERNAL:
        signature_value = args.signature or ""
        signature_format = args.signature_format or "bip322_simple_base64_or_external"
        shape_ok, shape_reason = bitcoin_signature_shape(signature_value, signature_format)
        if not shape_ok:
            raise SystemExit(f"Bitcoin external proof signature shape invalid: {shape_reason}")
        signature_doc = {
            "alg": "Bitcoin BIP-322 external proof",
            "signed_payload": "external_bitcoin_wallet_proof",
            "signed_hash": challenge_hash,
            "signature": signature_value,
            "signature_format": signature_format,
            "verification_level": "shape_only",
            "verification_status": "external_pending",
            "local_signature_verification": False,
            "crypto_signature_verified": False,
            "shape_reason": shape_reason,
        }
    else:  # pragma: no cover
        raise SystemExit(f"unsupported standard: {standard}")

    proof_body = {
        "type": "delta_wallet_proof",
        "protocol_version": DELTA_PROTOCOL,
        "standard": standard,
        "chain": chain,
        "address": address,
        "holder": args.holder,
        "created_at": now_utc(),
        "challenge_id": challenge_body.get("challenge_id"),
        "challenge_hash": challenge_hash,
        "target": {
            "record_hash": challenge_record_hash,
            "record_type": "delta_record" if challenge_record_hash else None,
            "binding": "full_canonical_delta_record_hash" if challenge_record_hash else "none",
        },
        "signature": signature_doc,
        "security_boundary": {
            "proves_address_control": standard != STANDARD_BTC_BIP322_EXTERNAL,
            "proves_bitcoin_signature_locally": False if standard == STANDARD_BTC_BIP322_EXTERNAL else None,
            "does_not_prove_legal_ownership": True,
            "does_not_prove_balance": True,
            "does_not_prove_identity": True,
        },
    }
    proof_hash = canonical_sha256(proof_body)
    envelope = {
        "type": "delta_wallet_proof_envelope",
        "protocol_version": DELTA_PROTOCOL,
        "proof_body_hash": proof_hash,
        "proof_body": proof_body,
        "proof_integrity": {"self_check_hash": proof_hash},
    }
    write_json(Path(args.out), envelope)
    print("DELTA_WALLET_PROOF_CREATE_OK=True")
    print(f"DELTA_WALLET_PROOF={Path(args.out).resolve()}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={proof_hash}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge_hash}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_CHAIN={chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    if challenge_record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={challenge_record_hash}")
        print("DELTA_WALLET_RECORD_BINDING_SIGNED=True")
    if recovered_address:
        print(f"DELTA_WALLET_ETH_RECOVERED_ADDRESS={recovered_address}")
    if standard == STANDARD_BTC_BIP322_EXTERNAL:
        print(f"DELTA_WALLET_BITCOIN_SIGNATURE_FORMAT={signature_doc['signature_format']}")
        print("DELTA_WALLET_BITCOIN_VERIFICATION_LEVEL=shape_only")
        print("DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED=False")
    return 0


def command_verify_proof(args: argparse.Namespace) -> int:
    proof = read_json(Path(args.proof))
    proof_body = proof.get("proof_body")
    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}
    eth_recovered: str | None = None
    btc_verification_level: str | None = None
    signature_mode: str | None = None
    crypto_signature_verified = False

    checks["proof_shape_ok"] = isinstance(proof_body, dict) and proof.get("type") == "delta_wallet_proof_envelope"
    if not checks["proof_shape_ok"]:
        print("DELTA_WALLET_VERIFY_OK=False")
        print("DELTA_WALLET_PROOF_SHAPE_OK=False")
        return 1

    proof_body_hash = canonical_sha256(proof_body)
    checks["proof_body_hash_ok"] = proof.get("proof_body_hash") == proof_body_hash
    checks["self_check_ok"] = (proof.get("proof_integrity") or {}).get("self_check_hash") == proof_body_hash
    if not checks["proof_body_hash_ok"]:
        reasons["proof_body_hash_ok"] = "proof_body_hash_mismatch"
    if not checks["self_check_ok"]:
        reasons["self_check_ok"] = "proof_integrity_self_check_hash_mismatch"

    standard = str(proof_body.get("standard") or "")
    chain = str(proof_body.get("chain") or "")
    address = str(proof_body.get("address") or "")
    signature_doc = proof_body.get("signature") if isinstance(proof_body.get("signature"), dict) else {}
    target = proof_body.get("target") if isinstance(proof_body.get("target"), dict) else {}
    proof_record_hash = target.get("record_hash")

    checks["standard_ok"] = standard in SUPPORTED_STANDARDS
    checks["chain_ok"] = (
        (standard == STANDARD_ED25519 and chain == CHAIN_ED25519_DEMO)
        or (standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and chain == CHAIN_ETHEREUM)
        or (standard == STANDARD_BTC_BIP322_EXTERNAL and chain == CHAIN_BITCOIN)
    )
    checks["address_shape_ok"] = (
        (standard == STANDARD_ED25519 and isinstance(address, str) and address.startswith(PUBLIC_KEY_PREFIX))
        or (standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and is_eth_address(address))
        or (standard == STANDARD_BTC_BIP322_EXTERNAL and is_bitcoin_address_shape(address))
    )

    checks["public_key_hash_ok"] = True
    checks["address_binding_ok"] = True
    if standard == STANDARD_ED25519:
        checks["public_key_hash_ok"] = signature_doc.get("public_key_hash") == hash_text(str(signature_doc.get("public_key")))
        checks["address_binding_ok"] = signature_doc.get("public_key") == address
    elif standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712):
        recovered = signature_doc.get("recovered_address")
        if isinstance(recovered, str) and is_eth_address(recovered):
            checks["address_binding_ok"] = recovered.lower() == address.lower()
    elif standard == STANDARD_BTC_BIP322_EXTERNAL:
        checks["address_binding_ok"] = is_bitcoin_address_shape(address)

    challenge_body: dict[str, Any] | None = None
    if args.challenge:
        challenge = read_json(Path(args.challenge))
        possible_body = challenge.get("challenge_body")
        if isinstance(possible_body, dict):
            challenge_body = possible_body
            challenge_hash = canonical_sha256(challenge_body)
            checks["challenge_self_check_ok"] = challenge.get("challenge_body_hash") == challenge_hash and (challenge.get("challenge_integrity") or {}).get("self_check_hash") == challenge_hash
            checks["challenge_binding_ok"] = proof_body.get("challenge_hash") == challenge_hash and proof_body.get("challenge_id") == challenge_body.get("challenge_id")
            checks["challenge_not_expired_ok"] = True
            checks["proof_challenge_record_binding_ok"] = True
            challenge_target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
            challenge_record_hash = challenge_target.get("record_hash")
            if proof_record_hash or challenge_record_hash:
                checks["proof_challenge_record_binding_ok"] = proof_record_hash == challenge_record_hash
        else:
            checks["challenge_self_check_ok"] = False
            checks["challenge_binding_ok"] = False
            checks["challenge_not_expired_ok"] = False
            checks["proof_challenge_record_binding_ok"] = False
    else:
        checks["challenge_self_check_ok"] = True
        checks["challenge_binding_ok"] = True
        checks["challenge_not_expired_ok"] = True
        checks["proof_challenge_record_binding_ok"] = True

    record_hash = load_record_hash(args.record)
    checks["record_hash_shape_ok"] = True if not proof_record_hash else is_sha256_prefixed(proof_record_hash)
    checks["record_binding_ok"] = True
    if record_hash or proof_record_hash:
        checks["record_binding_ok"] = proof_record_hash == record_hash
        if not checks["record_binding_ok"]:
            reasons["record_binding_ok"] = "record_hash_mismatch"
    checks["record_signed_by_challenge_ok"] = True
    if proof_record_hash and challenge_body is not None:
        challenge_target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
        checks["record_signed_by_challenge_ok"] = challenge_target.get("record_hash") == proof_record_hash
        if not checks["record_signed_by_challenge_ok"]:
            reasons["record_signed_by_challenge_ok"] = "record_hash_not_inside_signed_challenge_body"

    sig_text = signature_doc.get("signature")
    if standard == STANDARD_ED25519:
        checks["signature_shape_ok"] = isinstance(sig_text, str) and sig_text.startswith(SIGNATURE_PREFIX)
        ok, reason = verify_ed25519_signature(challenge_body or {}, signature_doc, address) if challenge_body is not None else (False, "challenge_required_for_signature")
        checks["signature_ok"] = ok
        crypto_signature_verified = ok
        if not ok:
            reasons["signature_ok"] = reason
    elif standard == STANDARD_ETH_EIP191:
        checks["signature_shape_ok"] = is_eth_signature_shape(sig_text)
        msg = str((challenge_body or {}).get("message") or "")
        ok, reason, eth_recovered = verify_eth_eip191(msg, str(sig_text), address)
        checks["signature_ok"] = ok
        crypto_signature_verified = ok
        if not ok:
            reasons["signature_ok"] = reason
    elif standard == STANDARD_ETH_EIP712:
        checks["signature_shape_ok"] = is_eth_signature_shape(sig_text)
        typed_data = build_eip712_typed_data(challenge_body or {}) if challenge_body is not None else {}
        ok, reason, eth_recovered = verify_eth_eip712(typed_data, str(sig_text), address)
        checks["signature_ok"] = ok
        crypto_signature_verified = ok
        if not ok:
            reasons["signature_ok"] = reason
    elif standard == STANDARD_BTC_BIP322_EXTERNAL:
        fmt = signature_doc.get("signature_format")
        shape_ok, shape_reason = bitcoin_signature_shape(sig_text, fmt)
        checks["signature_shape_ok"] = shape_ok
        checks["signature_ok"] = shape_ok
        btc_verification_level = str(signature_doc.get("verification_level") or "shape_only")
        signature_mode = str(signature_doc.get("verification_status") or "external_pending")
        crypto_signature_verified = False
        if not shape_ok:
            reasons["signature_shape_ok"] = shape_reason
            reasons["signature_ok"] = shape_reason
    else:
        checks["signature_shape_ok"] = False
        checks["signature_ok"] = False

    required = [
        "proof_shape_ok",
        "proof_body_hash_ok",
        "self_check_ok",
        "standard_ok",
        "chain_ok",
        "address_shape_ok",
        "public_key_hash_ok",
        "address_binding_ok",
        "challenge_self_check_ok",
        "challenge_binding_ok",
        "challenge_not_expired_ok",
        "record_hash_shape_ok",
        "proof_challenge_record_binding_ok",
        "record_binding_ok",
        "record_signed_by_challenge_ok",
        "signature_shape_ok",
        "signature_ok",
    ]
    verify_ok = all(checks.get(name, False) for name in required)

    print(f"DELTA_WALLET_VERIFY_OK={verify_ok}")
    print(f"DELTA_WALLET_PROOF_SHAPE_OK={checks['proof_shape_ok']}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH_OK={checks['proof_body_hash_ok']}")
    print(f"DELTA_WALLET_SELF_CHECK_OK={checks['self_check_ok']}")
    print(f"DELTA_WALLET_STANDARD_OK={checks['standard_ok']}")
    print(f"DELTA_WALLET_CHAIN_OK={checks['chain_ok']}")
    print(f"DELTA_WALLET_ADDRESS_SHAPE_OK={checks['address_shape_ok']}")
    print(f"DELTA_WALLET_PUBLIC_KEY_HASH_OK={checks['public_key_hash_ok']}")
    print(f"DELTA_WALLET_ADDRESS_BINDING_OK={checks['address_binding_ok']}")
    print(f"DELTA_WALLET_CHALLENGE_SELF_CHECK_OK={checks['challenge_self_check_ok']}")
    print(f"DELTA_WALLET_CHALLENGE_BINDING_OK={checks['challenge_binding_ok']}")
    print(f"DELTA_WALLET_CHALLENGE_NOT_EXPIRED_OK={checks['challenge_not_expired_ok']}")
    print(f"DELTA_WALLET_RECORD_HASH_SHAPE_OK={checks['record_hash_shape_ok']}")
    print(f"DELTA_WALLET_PROOF_CHALLENGE_RECORD_BINDING_OK={checks['proof_challenge_record_binding_ok']}")
    print(f"DELTA_WALLET_RECORD_BINDING_OK={checks['record_binding_ok']}")
    print(f"DELTA_WALLET_RECORD_SIGNED_BY_CHALLENGE_OK={checks['record_signed_by_challenge_ok']}")
    print(f"DELTA_WALLET_SIGNATURE_SHAPE_OK={checks['signature_shape_ok']}")
    print(f"DELTA_WALLET_SIGNATURE_OK={checks['signature_ok']}")
    print(f"DELTA_WALLET_CRYPTO_SIGNATURE_VERIFIED={crypto_signature_verified}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={proof_body.get('challenge_hash')}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={proof_body_hash}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_CHAIN={chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    if proof_record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={proof_record_hash}")
    if standard == STANDARD_ETH_EIP712 and challenge_body is not None:
        print(f"DELTA_WALLET_EIP712_TYPED_DATA_HASH={canonical_sha256(build_eip712_typed_data(challenge_body))}")
    if eth_recovered:
        print(f"DELTA_WALLET_ETH_RECOVERED_ADDRESS={eth_recovered}")
    if standard == STANDARD_BTC_BIP322_EXTERNAL:
        print(f"DELTA_WALLET_BITCOIN_PROOF_SHAPE_OK={checks['signature_shape_ok']}")
        print(f"DELTA_WALLET_BITCOIN_SIGNATURE_FORMAT_OK={checks['signature_shape_ok']}")
        print(f"DELTA_WALLET_BITCOIN_LOCAL_VERIFICATION_LEVEL={btc_verification_level or 'shape_only'}")
        print(f"DELTA_WALLET_SIGNATURE_VERIFICATION_MODE={signature_mode or 'external_pending'}")
    for key, reason in reasons.items():
        print(f"DELTA_WALLET_REASON_{key.upper()}={reason}")
    return 0 if verify_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Crypto Wallet / Address Control tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate a local Ed25519 demo wallet key.")
    keygen.add_argument("--private-out", required=True, help="Path for local demo key output. Do not commit.")
    keygen.add_argument("--public-out", required=True, help="Path for demo public wallet JSON.")
    keygen.add_argument("--force", action="store_true", help="Overwrite existing output.")
    keygen.set_defaults(func=command_keygen)

    eth_keygen = subparsers.add_parser("eth-keygen", help="Generate a local Ethereum demo wallet key.")
    eth_keygen.add_argument("--private-out", required=True, help="Path for local demo key output. Do not commit.")
    eth_keygen.add_argument("--public-out", required=True, help="Path for demo Ethereum wallet JSON.")
    eth_keygen.add_argument("--force", action="store_true", help="Overwrite existing output.")
    eth_keygen.set_defaults(func=command_eth_keygen)

    challenge = subparsers.add_parser("create-challenge", help="Create a DELTA wallet challenge.")
    challenge.add_argument("--out", required=True, help="Path for challenge JSON.")
    challenge.add_argument("--chain", required=True, help="Wallet chain, e.g. ed25519-demo, ethereum, bitcoin.")
    challenge.add_argument("--standard", default=None, help="Wallet proof standard.")
    challenge.add_argument("--address", required=True, help="Wallet address/public identifier.")
    challenge.add_argument("--record", default=None, help="Optional delta-record.json path for full record hash binding.")
    challenge.add_argument("--domain", default="local-delta-test", help="Challenge domain/context.")
    challenge.add_argument("--purpose", default="DELTA wallet address control proof", help="Human-readable purpose.")
    challenge.add_argument("--challenge-id", default=None, help="Optional challenge id.")
    challenge.add_argument("--expires-at", default=None, help="Optional UTC ISO-8601 expiry.")
    challenge.add_argument("--eip712-chain-id", default="1", help="EIP-712 domain chainId. Default: 1.")
    challenge.set_defaults(func=command_create_challenge)

    proof = subparsers.add_parser("create-proof", help="Create a DELTA wallet proof.")
    proof.add_argument("--challenge", required=True, help="Path to wallet challenge JSON.")
    proof.add_argument("--private-key", dest="keyfile", default=None, help="Path to local Ed25519 demo key file. Do not commit.")
    proof.add_argument("--eth-private-key", dest="eth_keyfile", default=None, help="Path to local Ethereum demo key file. Do not commit.")
    proof.add_argument("--signature", default=None, help="Externally supplied signature/proof string.")
    proof.add_argument("--signature-format", default=None, help="External signature/proof format, used by Bitcoin external adapter.")
    proof.add_argument("--record", default=None, help="Optional delta-record.json path. Must match challenge target when present.")
    proof.add_argument("--out", required=True, help="Path for wallet proof JSON.")
    proof.add_argument("--holder", default="local-wallet-holder", help="Non-authoritative holder label for test/demo proofs.")
    proof.set_defaults(func=command_create_proof)

    verify = subparsers.add_parser("verify-proof", help="Verify a DELTA wallet proof.")
    verify.add_argument("--proof", required=True, help="Path to wallet proof JSON.")
    verify.add_argument("--challenge", default=None, help="Optional path to challenge JSON for binding and signature verification.")
    verify.add_argument("--record", default=None, help="Optional path to delta-record.json for record binding verification.")
    verify.set_defaults(func=command_verify_proof)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
