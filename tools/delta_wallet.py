#!/usr/bin/env python3
"""DELTA Proof of Crypto Wallet / Address Control tool.

v2.3.2 adds an optional Ethereum EIP-712 typed-data adapter while
preserving the v2.3.1 Ethereum EIP-191 adapter and v2.3.0 Ed25519 demo adapter.

Security boundary:
- DELTA never needs seed phrases.
- Demo private keys are local test artifacts and must not be committed.
- Proof of Wallet proves cryptographic control of a key/address for a specific
  signed DELTA challenge; it does not prove legal ownership, identity, balance,
  MiCA compliance, or external-world truth.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

try:  # Optional Ethereum support.
    from eth_account import Account  # type: ignore
    from eth_account.messages import encode_defunct, encode_typed_data  # type: ignore

    HAS_ETH_ACCOUNT = True
except Exception:  # pragma: no cover - optional dependency by design.
    Account = None  # type: ignore
    encode_defunct = None  # type: ignore
    encode_typed_data = None  # type: ignore
    HAS_ETH_ACCOUNT = False

TOOL_VERSION = "v2.3.2-ethereum-eip712"
PROTOCOL_VERSION = "DELTA-0"

CHALLENGE_ENVELOPE_TYPE = "delta_wallet_challenge_envelope"
CHALLENGE_BODY_TYPE = "delta_wallet_challenge"
PROOF_ENVELOPE_TYPE = "delta_wallet_proof_envelope"
PROOF_BODY_TYPE = "delta_wallet_proof"

STANDARD_ED25519 = "ed25519_address_control_v1"
STANDARD_ETH_EIP191 = "ethereum_eip191_personal_sign_v1"
STANDARD_ETH_EIP712 = "ethereum_eip712_typed_data_v1"
SUPPORTED_STANDARDS = {STANDARD_ED25519, STANDARD_ETH_EIP191, STANDARD_ETH_EIP712}

CHAIN_ED25519_DEMO = "ed25519-demo"
CHAIN_ETHEREUM = "ethereum"

PUBLIC_KEY_PREFIX = "ed25519:"
PRIVATE_SEED_PREFIX = "ed25519seed:"
SIGNATURE_PREFIX = "ed25519sig:"
ETH_PRIVATE_PREFIX = "ethereum_private_hex:"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ETH_SIGNATURE_RE = re.compile(r"^(0x)?[0-9a-fA-F]{130}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode_unpadded(value: str, field: str) -> bytes:
    if not value:
        raise ValueError(f"{field} is empty")
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"{field} is not valid base64url") from exc


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def hash_record_file(path: Path) -> tuple[str, str]:
    record = load_json(path.resolve())
    record_hash = canonical_sha256(record)
    record_type = "unknown"
    if isinstance(record, dict):
        body = record.get("record_body")
        if isinstance(body, dict) and isinstance(body.get("type"), str):
            record_type = body["type"]
        elif isinstance(record.get("type"), str):
            record_type = record["type"]
    return record_hash, record_type


def require_standard_chain(standard: str, chain: str) -> None:
    if standard not in SUPPORTED_STANDARDS:
        raise SystemExit(f"unsupported wallet standard: {standard}")
    if standard == STANDARD_ED25519 and chain != CHAIN_ED25519_DEMO:
        raise SystemExit(f"{STANDARD_ED25519} requires chain {CHAIN_ED25519_DEMO}")
    if standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and chain != CHAIN_ETHEREUM:
        raise SystemExit(f"{standard} requires chain {CHAIN_ETHEREUM}")


def infer_standard(chain: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    if chain == CHAIN_ETHEREUM:
        return STANDARD_ETH_EIP191
    return STANDARD_ED25519


def normalize_eth_signature(signature: str) -> str:
    sig = signature.strip()
    if not sig.startswith("0x"):
        sig = "0x" + sig
    return sig


def normalize_eth_address(address: str) -> str:
    return address.strip()


def validate_address_shape(standard: str, address: str) -> bool:
    if standard == STANDARD_ED25519:
        if not isinstance(address, str) or not address.startswith(PUBLIC_KEY_PREFIX):
            return False
        try:
            raw = b64url_decode_unpadded(address[len(PUBLIC_KEY_PREFIX) :], "ed25519 address")
            return len(raw) == 32
        except Exception:
            return False
    if standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712):
        return isinstance(address, str) and ETH_ADDRESS_RE.match(address) is not None
    return False


def build_wallet_message(challenge_body: dict[str, Any]) -> str:
    target = challenge_body.get("target") or {}
    record_hash = target.get("record_hash", "none")
    lines = [
        "DELTA Wallet Address Control Challenge",
        f"protocol={challenge_body.get('protocol_version')}",
        f"challenge_id={challenge_body.get('challenge_id')}",
        f"chain={challenge_body.get('chain')}",
        f"standard={challenge_body.get('standard')}",
        f"address={challenge_body.get('address')}",
        f"domain={challenge_body.get('domain')}",
        f"purpose={challenge_body.get('purpose')}",
        f"record_hash={record_hash}",
        f"created_at={challenge_body.get('created_at')}",
        f"nonce={challenge_body.get('nonce')}",
    ]
    return "\n".join(lines)



def build_eip712_typed_data(challenge_body: dict[str, Any]) -> dict[str, Any]:
    """Build deterministic EIP-712 typed data from the current challenge body.

    Important: this function deliberately rebuilds typed data from the challenge
    fields instead of trusting any caller-supplied typed-data blob. That means a
    tampered record_hash, challenge_id, address, nonce, or purpose changes the
    EIP-712 message and invalidates the signature.
    """
    target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
    record_hash = target.get("record_hash") or "none"
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
            "DELTAWalletChallenge": [
                {"name": "challengeId", "type": "string"},
                {"name": "protocol", "type": "string"},
                {"name": "chain", "type": "string"},
                {"name": "standard", "type": "string"},
                {"name": "address", "type": "address"},
                {"name": "domain", "type": "string"},
                {"name": "purpose", "type": "string"},
                {"name": "recordHash", "type": "string"},
                {"name": "createdAt", "type": "string"},
                {"name": "nonce", "type": "string"},
            ],
        },
        "primaryType": "DELTAWalletChallenge",
        "domain": {
            "name": domain_name,
            "version": domain_version,
            "chainId": chain_id,
        },
        "message": {
            "challengeId": str(challenge_body.get("challenge_id") or ""),
            "protocol": str(challenge_body.get("protocol_version") or ""),
            "chain": str(challenge_body.get("chain") or ""),
            "standard": str(challenge_body.get("standard") or ""),
            "address": str(challenge_body.get("address") or ""),
            "domain": str(challenge_body.get("domain") or ""),
            "purpose": str(challenge_body.get("purpose") or ""),
            "recordHash": str(record_hash),
            "createdAt": str(challenge_body.get("created_at") or ""),
            "nonce": str(challenge_body.get("nonce") or ""),
        },
    }


def encode_eip712_message(typed_data: dict[str, Any]) -> Any:
    if not HAS_ETH_ACCOUNT or encode_typed_data is None:
        raise RuntimeError("eth_account_missing_install_with_python_m_pip_install_eth_account")
    return encode_typed_data(full_message=typed_data)  # type: ignore[misc]


def load_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    text = path.read_text(encoding="utf-8").strip()
    if not text.startswith(PRIVATE_SEED_PREFIX):
        raise SystemExit("demo Ed25519 key must start with ed25519seed:")
    seed = b64url_decode_unpadded(text[len(PRIVATE_SEED_PREFIX) :], "ed25519 private seed")
    if len(seed) != 32:
        raise SystemExit("demo Ed25519 seed must decode to 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def ed25519_public_key_text(public_key: Ed25519PublicKey) -> str:
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PUBLIC_KEY_PREFIX + b64url_no_padding(public_bytes)


def verify_ed25519_challenge_signature(challenge_body: dict[str, Any], proof_body: dict[str, Any]) -> tuple[bool, str]:
    try:
        signature = proof_body.get("signature") or {}
        public_key_text = signature.get("public_key")
        signature_text = signature.get("signature")
        signed_hash = signature.get("signed_hash")
        if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
            return False, "ed25519_public_key_invalid"
        if proof_body.get("address") != public_key_text:
            return False, "ed25519_address_public_key_mismatch"
        if not isinstance(signature_text, str) or not signature_text.startswith(SIGNATURE_PREFIX):
            return False, "ed25519_signature_shape_invalid"
        payload = canonical_json_bytes(challenge_body)
        payload_hash = sha256_prefixed(payload)
        if signed_hash != payload_hash:
            return False, "ed25519_signed_hash_mismatch"
        public_bytes = b64url_decode_unpadded(public_key_text[len(PUBLIC_KEY_PREFIX) :], "ed25519 public key")
        sig_bytes = b64url_decode_unpadded(signature_text[len(SIGNATURE_PREFIX) :], "ed25519 signature")
        if len(public_bytes) != 32:
            return False, "ed25519_public_key_length_invalid"
        if len(sig_bytes) != 64:
            return False, "ed25519_signature_length_invalid"
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(sig_bytes, payload)
        return True, "ed25519_signature_valid"
    except InvalidSignature:
        return False, "ed25519_signature_invalid"
    except Exception as exc:
        return False, f"ed25519_signature_error:{type(exc).__name__}"


def verify_ethereum_personal_sign(message: str, signature_hex: str, address: str) -> tuple[bool, str, str | None]:
    if not HAS_ETH_ACCOUNT:
        return False, "eth_account_missing_install_with_python_m_pip_install_eth_account", None
    if not isinstance(message, str) or not message:
        return False, "ethereum_message_missing", None
    if not isinstance(signature_hex, str):
        return False, "ethereum_signature_missing", None
    signature = normalize_eth_signature(signature_hex)
    if ETH_SIGNATURE_RE.match(signature) is None:
        return False, "ethereum_eip191_signature_shape_invalid", None
    if not isinstance(address, str) or ETH_ADDRESS_RE.match(address) is None:
        return False, "ethereum_address_shape_invalid", None
    try:
        encoded = encode_defunct(text=message)  # type: ignore[misc]
        recovered = Account.recover_message(encoded, signature=signature)  # type: ignore[union-attr]
        ok = recovered.lower() == address.lower()
        return ok, "ethereum_eip191_signature_valid" if ok else "ethereum_eip191_signature_invalid", recovered
    except Exception as exc:
        return False, f"ethereum_eip191_signature_error:{type(exc).__name__}", None



def verify_ethereum_eip712_typed_data(typed_data: dict[str, Any], signature_hex: str, address: str) -> tuple[bool, str, str | None]:
    if not HAS_ETH_ACCOUNT:
        return False, "eth_account_missing_install_with_python_m_pip_install_eth_account", None
    if not isinstance(typed_data, dict) or not typed_data:
        return False, "ethereum_eip712_typed_data_missing", None
    if not isinstance(signature_hex, str):
        return False, "ethereum_signature_missing", None
    signature = normalize_eth_signature(signature_hex)
    if ETH_SIGNATURE_RE.match(signature) is None:
        return False, "ethereum_eip712_signature_shape_invalid", None
    if not isinstance(address, str) or ETH_ADDRESS_RE.match(address) is None:
        return False, "ethereum_address_shape_invalid", None
    try:
        encoded = encode_eip712_message(typed_data)
        recovered = Account.recover_message(encoded, signature=signature)  # type: ignore[union-attr]
        ok = recovered.lower() == address.lower()
        return ok, "ethereum_eip712_signature_valid" if ok else "ethereum_eip712_signature_invalid", recovered
    except Exception as exc:
        return False, f"ethereum_eip712_signature_error:{type(exc).__name__}", None


def read_eth_private_key(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith(ETH_PRIVATE_PREFIX):
        text = text[len(ETH_PRIVATE_PREFIX) :].strip()
    if not text.startswith("0x"):
        text = "0x" + text
    if not re.match(r"^0x[0-9a-fA-F]{64}$", text):
        raise SystemExit("demo Ethereum private key must be 32-byte hex")
    return text


def command_keygen(args: argparse.Namespace) -> int:
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_text = ed25519_public_key_text(private_key.public_key())
    public_key_hash = sha256_prefixed(public_key_text.encode("utf-8"))

    private_path = Path(args.private_out)
    public_path = Path(args.public_out)
    if private_path.exists() and not args.force:
        raise SystemExit("private key path exists; pass --force to overwrite")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(PRIVATE_SEED_PREFIX + b64url_no_padding(seed) + "\n", encoding="utf-8", newline="\n")

    public_doc = {
        "type": "delta_wallet_public_key",
        "protocol_version": PROTOCOL_VERSION,
        "standard": STANDARD_ED25519,
        "chain": CHAIN_ED25519_DEMO,
        "address": public_key_text,
        "public_key": public_key_text,
        "public_key_hash": public_key_hash,
        "created_at": now_utc(),
        "security_boundary": "demo key for local DELTA wallet proof tests only; do not use for funds",
    }
    write_json(public_path, public_doc)

    print("DELTA_WALLET_KEYGEN_OK=True")
    print(f"DELTA_WALLET_PRIVATE_WRITTEN={private_path}")
    print("DELTA_WALLET_PRIVATE_WARNING=do_not_commit_do_not_paste_to_chat_demo_key_only")
    print(f"DELTA_WALLET_PUBLIC_KEY_WRITTEN={public_path}")
    print(f"DELTA_WALLET_ADDRESS={public_key_text}")
    print(f"DELTA_WALLET_PUBLIC_KEY_HASH={public_key_hash}")
    return 0


def command_eth_keygen(args: argparse.Namespace) -> int:
    if not HAS_ETH_ACCOUNT:
        raise SystemExit("eth-account is required for eth-keygen. Install with: python -m pip install eth-account")
    acct = Account.create()  # type: ignore[union-attr]
    private_hex = acct.key.hex()
    if not private_hex.startswith("0x"):
        private_hex = "0x" + private_hex
    address = acct.address

    private_path = Path(args.private_out)
    public_path = Path(args.public_out)
    if private_path.exists() and not args.force:
        raise SystemExit("demo Ethereum key path exists; pass --force to overwrite")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(ETH_PRIVATE_PREFIX + private_hex + "\n", encoding="utf-8", newline="\n")

    public_doc = {
        "type": "delta_wallet_public_key",
        "protocol_version": PROTOCOL_VERSION,
        "standard": STANDARD_ETH_EIP191,
        "chain": CHAIN_ETHEREUM,
        "address": address,
        "created_at": now_utc(),
        "security_boundary": "demo Ethereum key for local DELTA wallet proof tests only; do not use for funds",
    }
    write_json(public_path, public_doc)

    print("DELTA_WALLET_ETH_KEYGEN_OK=True")
    print(f"DELTA_WALLET_ETH_PRIVATE_WRITTEN={private_path}")
    print("DELTA_WALLET_ETH_PRIVATE_WARNING=do_not_commit_do_not_paste_to_chat_demo_key_only_do_not_use_for_funds")
    print(f"DELTA_WALLET_ETH_PUBLIC_WRITTEN={public_path}")
    print(f"DELTA_WALLET_ETH_ADDRESS={address}")
    return 0


def command_create_challenge(args: argparse.Namespace) -> int:
    standard = infer_standard(args.chain, args.standard)
    require_standard_chain(standard, args.chain)
    if not validate_address_shape(standard, args.address):
        raise SystemExit(f"address shape invalid for {standard}")

    target: dict[str, Any] = {"record_hash": None, "record_type": None, "record_path": None}
    record_hash = None
    if args.record:
        record_hash, record_type = hash_record_file(Path(args.record))
        target = {
            "record_type": "delta_record_full_json",
            "record_hash": record_hash,
            "record_path": str(Path(args.record).resolve()),
            "observed_record_body_type": record_type,
            "binding": "wallet challenge signs the full canonical SHA-256 hash of delta-record.json",
        }

    challenge_body: dict[str, Any] = {
        "type": CHALLENGE_BODY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "tool_version": TOOL_VERSION,
        "challenge_id": args.challenge_id or "W-" + secrets.token_hex(8),
        "created_at": now_utc(),
        "expires_at": args.expires_at,
        "domain": args.domain,
        "purpose": args.purpose,
        "chain": args.chain,
        "standard": standard,
        "address": args.address,
        "nonce": secrets.token_hex(16),
        "target": target,
        "security_boundary": {
            "proves_legal_ownership": False,
            "proves_identity": False,
            "proves_balance": False,
            "proves_address_control_for_signed_challenge": True,
        },
    }
    if standard == STANDARD_ETH_EIP712:
        challenge_body["eip712"] = {
            "domain_name": "DELTA Protocol",
            "domain_version": "2.3.2",
            "chain_id": int(args.eip712_chain_id),
            "primary_type": "DELTAWalletChallenge",
            "typed_data_source": "derived_from_challenge_body",
        }
    challenge_body["message"] = build_wallet_message(challenge_body)
    challenge_body["message_hash"] = sha256_prefixed(challenge_body["message"].encode("utf-8"))
    if standard == STANDARD_ETH_EIP712:
        eip712_typed_data = build_eip712_typed_data(challenge_body)
        challenge_body["eip712_typed_data"] = eip712_typed_data
        challenge_body["eip712_typed_data_hash"] = canonical_sha256(eip712_typed_data)

    challenge_body_hash = canonical_sha256(challenge_body)
    envelope = {
        "type": CHALLENGE_ENVELOPE_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "challenge_body_hash": challenge_body_hash,
        "challenge_body": challenge_body,
        "challenge_integrity": {"self_check": challenge_body_hash},
    }
    write_json(Path(args.out), envelope)

    print("DELTA_WALLET_CHALLENGE_CREATE_OK=True")
    print(f"DELTA_WALLET_CHALLENGE={Path(args.out).resolve()}")
    print(f"DELTA_WALLET_CHALLENGE_ID={challenge_body['challenge_id']}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge_body_hash}")
    print(f"DELTA_WALLET_ADDRESS={args.address}")
    print(f"DELTA_WALLET_CHAIN={args.chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    print(f"DELTA_WALLET_RECORD_BINDING_DECLARED={bool(record_hash)}")
    if record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={record_hash}")
    if standard == STANDARD_ETH_EIP712:
        print(f"DELTA_WALLET_EIP712_TYPED_DATA_HASH={challenge_body.get('eip712_typed_data_hash')}")
    return 0


def load_challenge_body(challenge_path: Path) -> tuple[dict[str, Any], dict[str, Any], str, bool]:
    envelope = load_json(challenge_path)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("challenge_body"), dict):
        raise SystemExit("challenge JSON must contain challenge_body")
    body = envelope["challenge_body"]
    computed = canonical_sha256(body)
    declared = envelope.get("challenge_body_hash")
    return envelope, body, computed, declared == computed


def command_create_proof(args: argparse.Namespace) -> int:
    _challenge_envelope, challenge_body, challenge_hash, challenge_self_check_ok = load_challenge_body(Path(args.challenge))
    if not challenge_self_check_ok:
        raise SystemExit("challenge self-check failed; refusing to sign")

    standard = challenge_body.get("standard")
    chain = challenge_body.get("chain")
    address = challenge_body.get("address")
    require_standard_chain(str(standard), str(chain))

    target = challenge_body.get("target") if isinstance(challenge_body.get("target"), dict) else {}
    challenge_record_hash = target.get("record_hash")
    record_hash = None
    if args.record:
        record_hash, _record_type = hash_record_file(Path(args.record))
        if challenge_record_hash and challenge_record_hash != record_hash:
            raise SystemExit("--record does not match challenge_body.target.record_hash")
        if not challenge_record_hash:
            raise SystemExit("--record supplied but challenge does not declare target.record_hash")

    signature_obj: dict[str, Any]
    recovered_address = None
    if standard == STANDARD_ED25519:
        if not args.private_key:
            raise SystemExit("--private-key is required for Ed25519 proof creation")
        private_key = load_ed25519_private_key(Path(args.private_key))
        public_key_text = ed25519_public_key_text(private_key.public_key())
        if public_key_text != address:
            raise SystemExit("Ed25519 private key does not match challenge address")
        payload = canonical_json_bytes(challenge_body)
        signature_raw = private_key.sign(payload)
        signature_obj = {
            "type": "delta_wallet_signature",
            "alg": "Ed25519",
            "standard": STANDARD_ED25519,
            "signed_payload": "challenge_body",
            "signed_hash": sha256_prefixed(payload),
            "public_key": public_key_text,
            "public_key_hash": sha256_prefixed(public_key_text.encode("utf-8")),
            "signature": SIGNATURE_PREFIX + b64url_no_padding(signature_raw),
        }
    elif standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712):
        if args.signature:
            signature_hex = normalize_eth_signature(args.signature)
            source = "external_signature"
        elif args.eth_private_key:
            if not HAS_ETH_ACCOUNT:
                raise SystemExit("eth-account is required for --eth-private-key. Install with: python -m pip install eth-account")
            private_hex = read_eth_private_key(Path(args.eth_private_key))
            acct = Account.from_key(private_hex)  # type: ignore[union-attr]
            if acct.address.lower() != str(address).lower():
                raise SystemExit("Ethereum private key does not match challenge address")
            if standard == STANDARD_ETH_EIP191:
                message = challenge_body.get("message")
                if not isinstance(message, str) or not message:
                    raise SystemExit("Ethereum EIP-191 challenge must contain challenge_body.message")
                signed = acct.sign_message(encode_defunct(text=message))  # type: ignore[misc]
            else:
                typed_data = build_eip712_typed_data(challenge_body)
                signed = acct.sign_message(encode_eip712_message(typed_data))
            signature_hex = signed.signature.hex()
            if not signature_hex.startswith("0x"):
                signature_hex = "0x" + signature_hex
            source = "eth_demo_private_key"
        else:
            raise SystemExit("Ethereum proof creation requires --signature or --eth-private-key")

        if standard == STANDARD_ETH_EIP191:
            message = challenge_body.get("message")
            if not isinstance(message, str) or not message:
                raise SystemExit("Ethereum EIP-191 challenge must contain challenge_body.message")
            ok, reason, recovered_address = verify_ethereum_personal_sign(message, signature_hex, str(address))
            signed_payload = "challenge_message"
            signed_hash = sha256_prefixed(message.encode("utf-8"))
        else:
            typed_data = build_eip712_typed_data(challenge_body)
            ok, reason, recovered_address = verify_ethereum_eip712_typed_data(typed_data, signature_hex, str(address))
            signed_payload = "eip712_typed_data"
            signed_hash = canonical_sha256(typed_data)
        if not ok:
            raise SystemExit(f"Ethereum signature does not verify for challenge address: {reason}")
        signature_obj = {
            "type": "delta_wallet_signature",
            "alg": "Ethereum-ECDSA",
            "standard": standard,
            "signed_payload": signed_payload,
            "signed_hash": signed_hash,
            "signature": normalize_eth_signature(signature_hex),
            "recovered_address": recovered_address,
            "source": source,
        }
    else:
        raise SystemExit(f"unsupported standard in challenge: {standard}")

    proof_body: dict[str, Any] = {
        "type": PROOF_BODY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "tool_version": TOOL_VERSION,
        "created_at": now_utc(),
        "holder": args.holder,
        "chain": chain,
        "standard": standard,
        "address": address,
        "challenge_id": challenge_body.get("challenge_id"),
        "challenge_hash": challenge_hash,
        "challenge_body": challenge_body,
        "target": target,
        "signature": signature_obj,
        "security_boundary": {
            "proves_legal_ownership": False,
            "proves_identity": False,
            "proves_balance": False,
            "proves_address_control_for_signed_challenge": True,
        },
    }
    proof_body_hash = canonical_sha256(proof_body)
    envelope = {
        "type": PROOF_ENVELOPE_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "proof_body_hash": proof_body_hash,
        "proof_body": proof_body,
        "proof_integrity": {"self_check": proof_body_hash},
    }
    write_json(Path(args.out), envelope)

    print("DELTA_WALLET_PROOF_CREATE_OK=True")
    print(f"DELTA_WALLET_PROOF={Path(args.out).resolve()}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={proof_body_hash}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge_hash}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_CHAIN={chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    if challenge_record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={challenge_record_hash}")
        print("DELTA_WALLET_RECORD_BINDING_SIGNED=True")
    if recovered_address:
        print(f"DELTA_WALLET_ETH_RECOVERED_ADDRESS={recovered_address}")
    return 0


def set_check(checks: dict[str, bool], reasons: dict[str, str], key: str, ok: bool, ok_reason: str, fail_reason: str) -> None:
    checks[key] = ok
    reasons[key] = ok_reason if ok else fail_reason


def command_verify_proof(args: argparse.Namespace) -> int:
    proof_envelope = load_json(Path(args.proof))
    if not isinstance(proof_envelope, dict) or not isinstance(proof_envelope.get("proof_body"), dict):
        raise SystemExit("proof JSON must contain proof_body")
    proof_body = proof_envelope["proof_body"]

    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    checks["proof_shape_ok"] = proof_envelope.get("type") == PROOF_ENVELOPE_TYPE and proof_body.get("type") == PROOF_BODY_TYPE
    reasons["proof_shape_ok"] = "proof_shape_ok" if checks["proof_shape_ok"] else "proof_shape_invalid"

    proof_body_hash = canonical_sha256(proof_body)
    set_check(
        checks,
        reasons,
        "proof_body_hash_ok",
        proof_envelope.get("proof_body_hash") == proof_body_hash,
        "proof_body_hash_matches",
        "proof_body_hash_mismatch",
    )
    integrity = proof_envelope.get("proof_integrity") if isinstance(proof_envelope.get("proof_integrity"), dict) else {}
    set_check(
        checks,
        reasons,
        "self_check_ok",
        integrity.get("self_check") == proof_body_hash,
        "proof_integrity_self_check_matches",
        "proof_integrity_self_check_hash_mismatch",
    )

    standard = proof_body.get("standard")
    chain = proof_body.get("chain")
    address = proof_body.get("address")
    checks["standard_ok"] = standard in SUPPORTED_STANDARDS
    reasons["standard_ok"] = "standard_supported" if checks["standard_ok"] else "standard_unsupported"
    checks["chain_ok"] = (standard == STANDARD_ED25519 and chain == CHAIN_ED25519_DEMO) or (
        standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712) and chain == CHAIN_ETHEREUM
    )
    reasons["chain_ok"] = "chain_matches_standard" if checks["chain_ok"] else "chain_standard_mismatch"
    checks["address_shape_ok"] = isinstance(standard, str) and isinstance(address, str) and validate_address_shape(standard, address)
    reasons["address_shape_ok"] = "address_shape_ok" if checks["address_shape_ok"] else "address_shape_invalid"

    signature = proof_body.get("signature") if isinstance(proof_body.get("signature"), dict) else {}
    if standard == STANDARD_ED25519:
        public_key = signature.get("public_key")
        checks["public_key_hash_ok"] = isinstance(public_key, str) and signature.get("public_key_hash") == sha256_prefixed(
            public_key.encode("utf-8")
        )
        reasons["public_key_hash_ok"] = "public_key_hash_matches" if checks["public_key_hash_ok"] else "public_key_hash_mismatch"
        checks["address_binding_ok"] = public_key == address
        reasons["address_binding_ok"] = "public_key_equals_address" if checks["address_binding_ok"] else "public_key_address_mismatch"
    elif standard in (STANDARD_ETH_EIP191, STANDARD_ETH_EIP712):
        recovered = signature.get("recovered_address")
        checks["public_key_hash_ok"] = True
        reasons["public_key_hash_ok"] = "not_applicable_for_ethereum_address_recovery"
        checks["address_binding_ok"] = isinstance(recovered, str) and recovered.lower() == str(address).lower()
        reasons["address_binding_ok"] = "recovered_address_equals_address" if checks["address_binding_ok"] else "recovered_address_mismatch"
    else:
        checks["public_key_hash_ok"] = False
        reasons["public_key_hash_ok"] = "unsupported_standard"
        checks["address_binding_ok"] = False
        reasons["address_binding_ok"] = "unsupported_standard"

    challenge_body = proof_body.get("challenge_body") if isinstance(proof_body.get("challenge_body"), dict) else None
    external_challenge_body = None
    external_challenge_hash = None
    if args.challenge:
        _env, external_challenge_body, external_challenge_hash, external_challenge_self_check = load_challenge_body(Path(args.challenge))
        checks["challenge_self_check_ok"] = external_challenge_self_check
        reasons["challenge_self_check_ok"] = "challenge_body_hash_matches" if external_challenge_self_check else "challenge_body_hash_mismatch"
        if challenge_body is not None:
            checks["challenge_binding_ok"] = proof_body.get("challenge_hash") == external_challenge_hash and challenge_body == external_challenge_body
        else:
            checks["challenge_binding_ok"] = proof_body.get("challenge_hash") == external_challenge_hash
        reasons["challenge_binding_ok"] = "challenge_hash_and_body_match" if checks["challenge_binding_ok"] else "challenge_hash_or_id_mismatch"
        challenge_for_signature = external_challenge_body
        challenge_hash_for_signature = external_challenge_hash
    else:
        if challenge_body is not None:
            challenge_hash = canonical_sha256(challenge_body)
            checks["challenge_self_check_ok"] = True
            reasons["challenge_self_check_ok"] = "embedded_challenge_body_hash_computed"
            checks["challenge_binding_ok"] = proof_body.get("challenge_hash") == challenge_hash
            reasons["challenge_binding_ok"] = "embedded_challenge_hash_matches" if checks["challenge_binding_ok"] else "embedded_challenge_hash_mismatch"
            challenge_for_signature = challenge_body
            challenge_hash_for_signature = challenge_hash
        else:
            checks["challenge_self_check_ok"] = False
            reasons["challenge_self_check_ok"] = "missing_challenge_body"
            checks["challenge_binding_ok"] = False
            reasons["challenge_binding_ok"] = "missing_challenge_body"
            challenge_for_signature = None
            challenge_hash_for_signature = None

    checks["challenge_not_expired_ok"] = True
    reasons["challenge_not_expired_ok"] = "expiration_not_enforced_v2_3_2"

    supplied_record_hash = None
    if args.record:
        supplied_record_hash, _record_type = hash_record_file(Path(args.record))
    proof_target = proof_body.get("target") if isinstance(proof_body.get("target"), dict) else {}
    proof_record_hash = proof_target.get("record_hash")
    challenge_target = challenge_for_signature.get("target") if isinstance(challenge_for_signature, dict) else {}
    challenge_record_hash = challenge_target.get("record_hash") if isinstance(challenge_target, dict) else None

    checks["record_hash_shape_ok"] = proof_record_hash is None or (isinstance(proof_record_hash, str) and SHA256_RE.match(proof_record_hash) is not None)
    reasons["record_hash_shape_ok"] = "record_hash_shape_ok" if checks["record_hash_shape_ok"] else "record_hash_shape_invalid"
    checks["proof_challenge_record_binding_ok"] = proof_record_hash == challenge_record_hash
    reasons["proof_challenge_record_binding_ok"] = (
        "proof_record_hash_matches_challenge_record_hash"
        if checks["proof_challenge_record_binding_ok"]
        else "proof_record_hash_challenge_record_hash_mismatch"
    )
    if supplied_record_hash:
        checks["record_binding_ok"] = proof_record_hash == supplied_record_hash and challenge_record_hash == supplied_record_hash
    else:
        checks["record_binding_ok"] = proof_record_hash == challenge_record_hash
    reasons["record_binding_ok"] = "record_hash_matches" if checks["record_binding_ok"] else "record_hash_mismatch"
    checks["record_signed_by_challenge_ok"] = challenge_record_hash is not None and challenge_record_hash == proof_record_hash
    reasons["record_signed_by_challenge_ok"] = (
        "record_hash_inside_signed_challenge_body"
        if checks["record_signed_by_challenge_ok"]
        else "record_hash_not_inside_signed_challenge_body"
    )

    checks["signature_shape_ok"] = isinstance(signature, dict) and isinstance(signature.get("signature"), str)
    reasons["signature_shape_ok"] = "signature_shape_ok" if checks["signature_shape_ok"] else "signature_shape_invalid"

    if challenge_for_signature is None:
        checks["signature_ok"] = False
        reasons["signature_ok"] = "missing_challenge_for_signature_verification"
        eth_recovered = None
    elif standard == STANDARD_ED25519:
        ok, reason = verify_ed25519_challenge_signature(challenge_for_signature, proof_body)
        checks["signature_ok"] = ok
        reasons["signature_ok"] = reason
        eth_recovered = None
    elif standard == STANDARD_ETH_EIP191:
        message = challenge_for_signature.get("message") if isinstance(challenge_for_signature, dict) else None
        sig_text = signature.get("signature")
        ok, reason, eth_recovered = verify_ethereum_personal_sign(str(message), str(sig_text), str(address))
        checks["signature_ok"] = ok
        reasons["signature_ok"] = reason
        if ok:
            checks["address_binding_ok"] = eth_recovered is not None and eth_recovered.lower() == str(address).lower()
            reasons["address_binding_ok"] = "recovered_address_equals_address"
    elif standard == STANDARD_ETH_EIP712:
        typed_data = build_eip712_typed_data(challenge_for_signature) if isinstance(challenge_for_signature, dict) else {}
        sig_text = signature.get("signature")
        ok, reason, eth_recovered = verify_ethereum_eip712_typed_data(typed_data, str(sig_text), str(address))
        checks["signature_ok"] = ok
        reasons["signature_ok"] = reason
        if ok:
            checks["address_binding_ok"] = eth_recovered is not None and eth_recovered.lower() == str(address).lower()
            reasons["address_binding_ok"] = "recovered_address_equals_address"
    else:
        checks["signature_ok"] = False
        reasons["signature_ok"] = "unsupported_standard"
        eth_recovered = None

    all_required = [
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
    verify_ok = all(checks.get(key) for key in all_required)

    print(f"DELTA_WALLET_VERIFY_OK={verify_ok}")
    for key in all_required:
        label = key.upper()
        print(f"DELTA_WALLET_{label}={checks.get(key)}")
    print(f"DELTA_WALLET_CHALLENGE_HASH={challenge_hash_for_signature}")
    print(f"DELTA_WALLET_PROOF_BODY_HASH={proof_body_hash}")
    print(f"DELTA_WALLET_ADDRESS={address}")
    print(f"DELTA_WALLET_CHAIN={chain}")
    print(f"DELTA_WALLET_STANDARD={standard}")
    if proof_record_hash:
        print(f"DELTA_WALLET_RECORD_HASH={proof_record_hash}")
    if standard == STANDARD_ETH_EIP712 and isinstance(challenge_for_signature, dict):
        print(f"DELTA_WALLET_EIP712_TYPED_DATA_HASH={canonical_sha256(build_eip712_typed_data(challenge_for_signature))}")
    if eth_recovered:
        print(f"DELTA_WALLET_ETH_RECOVERED_ADDRESS={eth_recovered}")
    for key in all_required:
        if not checks.get(key):
            print(f"DELTA_WALLET_REASON_{key.upper()}={reasons.get(key)}")

    return 0 if verify_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Crypto Wallet / Address Control tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate a local Ed25519 demo wallet key pair.")
    keygen.add_argument("--private-out", required=True, help="Path for local demo private key. Do not commit.")
    keygen.add_argument("--public-out", required=True, help="Path for public wallet JSON.")
    keygen.add_argument("--force", action="store_true", help="Overwrite existing local demo key.")
    keygen.set_defaults(func=command_keygen)

    eth_keygen = subparsers.add_parser("eth-keygen", help="Generate a local Ethereum demo key pair for tests.")
    eth_keygen.add_argument("--private-out", required=True, help="Path for local demo Ethereum key. Do not commit.")
    eth_keygen.add_argument("--public-out", required=True, help="Path for public Ethereum wallet JSON.")
    eth_keygen.add_argument("--force", action="store_true", help="Overwrite existing local demo Ethereum key.")
    eth_keygen.set_defaults(func=command_eth_keygen)

    challenge = subparsers.add_parser("create-challenge", help="Create a DELTA wallet challenge.")
    challenge.add_argument("--out", required=True, help="Path for wallet challenge JSON.")
    challenge.add_argument("--chain", required=True, help="Wallet chain, e.g. ed25519-demo or ethereum.")
    challenge.add_argument("--standard", default=None, help="Wallet proof standard. Defaults from chain.")
    challenge.add_argument("--address", required=True, help="Wallet address/public key controlled by signer.")
    challenge.add_argument("--record", default=None, help="Optional delta-record.json path. Hash is placed in signed challenge body.")
    challenge.add_argument("--domain", default="local-delta", help="Domain/context label for the challenge.")
    challenge.add_argument("--purpose", default="DELTA wallet address control", help="Human-readable challenge purpose.")
    challenge.add_argument("--challenge-id", default=None, help="Optional challenge id.")
    challenge.add_argument("--expires-at", default=None, help="Optional UTC ISO-8601 expiration timestamp. Report-only in v2.3.2.")
    challenge.add_argument("--eip712-chain-id", default="1", help="EIP-712 domain chainId for ethereum_eip712_typed_data_v1. Default: 1.")
    challenge.set_defaults(func=command_create_challenge)

    proof = subparsers.add_parser("create-proof", help="Create a DELTA wallet proof for a challenge.")
    proof.add_argument("--challenge", required=True, help="Path to wallet challenge JSON.")
    proof.add_argument("--private-key", default=None, help="Path to local Ed25519 demo private key. Do not commit.")
    proof.add_argument("--eth-private-key", default=None, help="Path to local Ethereum demo key. Do not commit.")
    proof.add_argument("--signature", default=None, help="External Ethereum signature hex, e.g. EIP-191 personal_sign or EIP-712 typed data.")
    proof.add_argument("--record", default=None, help="Optional delta-record.json path. Must match signed challenge target.")
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
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
