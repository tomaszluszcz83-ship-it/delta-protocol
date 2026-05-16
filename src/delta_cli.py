from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


CLI_VERSION = "DELTA CLI v0.7-alpha-attest-fixed"
PROTOCOL_NAME = "DELTA-0"

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerificationTarget:
    name: str
    label: str
    script_path: Path
    success_marker: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def decode_prefixed_b64url(label: str, value: str, prefix: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError(f"Invalid {label}. Expected prefix: {prefix}")

    encoded = value[len(prefix):]
    if not encoded:
        raise ValueError(f"Invalid {label}. Empty base64url value.")

    try:
        return b64url_decode(encoded)
    except Exception as exc:
        raise ValueError(f"Invalid {label}. Could not decode base64url value.") from exc


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def write_text_exclusive(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_json_exclusive(path: Path, obj) -> None:
    write_text_exclusive(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def write_private_key_exclusive_0600(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY

    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd != -1:
            os.close(fd)

    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def validate_key_name(name: str) -> None:
    if not KEY_NAME_RE.match(name):
        raise ValueError(
            "Invalid key name. Use only letters, digits, dot, underscore, and dash. "
            "Maximum length: 80 characters."
        )


def validate_sha256_hash(label: str, value: str) -> None:
    if not SHA256_RE.match(value):
        raise ValueError(
            f"Invalid {label}. Expected format: sha256:<64 lowercase hex characters>."
        )


def validate_action(action: str) -> None:
    if not action or not action.strip():
        raise ValueError("Invalid action. Action must not be empty.")


def validate_attestation_result(result: str) -> None:
    if not result or not result.strip():
        raise ValueError("Invalid result. Result must not be empty.")

    if not re.match(r"^[A-Z0-9_-]{1,64}$", result.strip()):
        raise ValueError(
            "Invalid result. Use 1-64 uppercase letters, digits, underscore, or dash."
        )


def validate_publication_mode(publication_mode: str) -> None:
    if publication_mode != "ledger_required":
        raise ValueError("Invalid publication-mode. v0.7-alpha requires: ledger_required.")


def validate_ledger_id(ledger_id: str) -> None:
    if not ledger_id or not ledger_id.strip():
        raise ValueError("Invalid ledger-id. ledger-id must not be empty.")

    if not re.match(r"^[A-Za-z0-9._:/-]{1,120}$", ledger_id.strip()):
        raise ValueError(
            "Invalid ledger-id. Use 1-120 chars: letters, digits, dot, underscore, colon, slash, or dash."
        )


def default_key_dir() -> Path:
    return Path.home() / ".delta" / "keys"


def public_key_value(private_key: Ed25519PrivateKey) -> str:
    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + b64url(raw_public_key)


def private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        raise FileNotFoundError(f"Private key file does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Private key path is not a file: {path}")

    root = repo_root()
    if is_relative_to(path, root):
        raise RuntimeError(
            "Refusing to load a private key from inside the repository.\n\n"
            "Use a key generated outside the repository, for example:\n"
            "~/.delta/keys/<name>.ed25519.private.pem"
        )

    try:
        pem_bytes = path.read_bytes()
    except Exception as exc:
        raise RuntimeError(f"Could not read private key file: {path}") from exc

    try:
        loaded = serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as exc:
        pem_bytes = b""
        raise RuntimeError("Could not load Ed25519 private key from PEM file.") from exc

    pem_bytes = b""

    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("Private key PEM is not an Ed25519 private key.")

    return loaded


def public_key_from_value(value: str) -> Ed25519PublicKey:
    raw = decode_prefixed_b64url("public_key", value, "ed25519:")

    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 public key length.")

    return Ed25519PublicKey.from_public_bytes(raw)


def read_json_file(path: Path, label: str):
    if not path.exists():
        raise FileNotFoundError(f"Missing {label}: {path}")

    if not path.is_file():
        raise ValueError(f"{label} path is not a file: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Could not read valid JSON from {label}: {path}") from exc


def build_public_key_record(*, key_name: str, role: str, public_key: str) -> dict:
    fingerprint = sha256_bytes(public_key.encode("utf-8"))

    return {
        "type": "delta_public_key",
        "protocol_version": PROTOCOL_NAME,
        "cli_version": CLI_VERSION,
        "alg": "Ed25519",
        "key_role": role,
        "key_name": key_name,
        "public_key": public_key,
        "public_key_fingerprint": fingerprint,
        "created_at": utc_now(),
    }


def build_claim(
    *,
    before_hash: str,
    action: str,
    after_hash: str,
    evidence_hash: str,
    executor_pubkey: str,
    created_at: str,
) -> dict:
    return {
        "type": "delta_claim",
        "protocol_version": PROTOCOL_NAME,
        "created_at": created_at,
        "executor_pubkey": executor_pubkey,
        "before_hash": before_hash,
        "action": action,
        "after_hash": after_hash,
        "evidence_hash": evidence_hash,
    }


def build_executor_signature(
    *,
    public_key: str,
    target_hash: str,
    signature_bytes: bytes,
    signed_at: str,
) -> dict:
    return {
        "type": "delta_signature",
        "protocol_version": PROTOCOL_NAME,
        "role": "executor",
        "alg": "Ed25519",
        "target_type": "delta_claim",
        "target_hash": target_hash,
        "public_key": public_key,
        "signature": "ed25519sig:" + b64url(signature_bytes),
        "signed_at": signed_at,
    }


def build_attestation(
    *,
    verifier_pubkey: str,
    target_claim_hash: str,
    target_executor_sig_hash: str,
    verification_policy_hash: str,
    evidence_hash: str,
    publication_mode: str,
    intended_ledger_id: str,
    result: str,
    verified_at: str,
) -> dict:
    return {
        "type": "delta_attestation",
        "protocol_version": PROTOCOL_NAME,
        "verifier_pubkey": verifier_pubkey,
        "target_claim_hash": target_claim_hash,
        "target_executor_sig_hash": target_executor_sig_hash,
        "verification_policy_hash": verification_policy_hash,
        "evidence_hash": evidence_hash,
        "publication_mode": publication_mode,
        "intended_ledger_id": intended_ledger_id,
        "result": result,
        "verified_at": verified_at,
    }


def build_verifier_signature(
    *,
    public_key: str,
    target_hash: str,
    signature_bytes: bytes,
    signed_at: str,
) -> dict:
    return {
        "type": "delta_signature",
        "protocol_version": PROTOCOL_NAME,
        "role": "verifier",
        "alg": "Ed25519",
        "target_type": "delta_attestation",
        "target_hash": target_hash,
        "public_key": public_key,
        "signature": "ed25519sig:" + b64url(signature_bytes),
        "signed_at": signed_at,
    }


def require_equal(label: str, actual, expected) -> None:
    if actual != expected:
        raise ValueError(f"Invalid {label}. Expected {expected!r}, got {actual!r}.")


def verify_executor_signature_or_raise(claim: dict, executor_signature: dict) -> tuple[str, str]:
    require_equal("claim.type", claim.get("type"), "delta_claim")
    require_equal("claim.protocol_version", claim.get("protocol_version"), PROTOCOL_NAME)

    require_equal("executor_signature.type", executor_signature.get("type"), "delta_signature")
    require_equal("executor_signature.protocol_version", executor_signature.get("protocol_version"), PROTOCOL_NAME)
    require_equal("executor_signature.role", executor_signature.get("role"), "executor")
    require_equal("executor_signature.alg", executor_signature.get("alg"), "Ed25519")
    require_equal("executor_signature.target_type", executor_signature.get("target_type"), "delta_claim")

    claim_public_key = claim.get("executor_pubkey")
    signature_public_key = executor_signature.get("public_key")

    if not isinstance(claim_public_key, str) or not claim_public_key.startswith("ed25519:"):
        raise ValueError("Invalid claim.executor_pubkey.")

    if signature_public_key != claim_public_key:
        raise ValueError("Executor signature public key does not match claim executor_pubkey.")

    claim_bytes = canonical_json_bytes(claim)
    claim_hash = sha256_bytes(claim_bytes)

    if executor_signature.get("target_hash") != claim_hash:
        raise ValueError("Executor signature target_hash does not match claim hash.")

    signature_bytes = decode_prefixed_b64url(
        "executor_signature.signature",
        executor_signature.get("signature"),
        "ed25519sig:",
    )

    try:
        public_key = public_key_from_value(signature_public_key)
        public_key.verify(signature_bytes, claim_bytes)
    except InvalidSignature as exc:
        raise RuntimeError(
            "Executor signature verification failed. Refusing to attest an invalid claim."
        ) from exc

    return claim_hash, sha256_bytes(canonical_json_bytes(executor_signature))


def require_safe_private_key_location(private_path: Path) -> None:
    root = repo_root()

    if not is_relative_to(private_path, root):
        return

    raise RuntimeError(
        "Refusing to write a private key inside the repository.\n\n"
        "Reason:\n"
        "DELTA public verifiers scan the repository/release tree and fail if private or secret files exist, "
        "even when Git ignores them.\n\n"
        "Use the default key directory instead:\n"
        "~/.delta/keys\n\n"
        "Example:\n"
        "python src/delta_cli.py keygen --name demo-executor\n"
    )


def targets() -> dict[str, VerificationTarget]:
    root = repo_root()

    return {
        "genesis": VerificationTarget(
            name="genesis",
            label="Genesis verifier",
            script_path=root / "src" / "genesis_public_verifier.py",
            success_marker="DELTA PUBLIC VERIFIER RESULT: OK",
        ),
        "code-change": VerificationTarget(
            name="code-change",
            label="Code Change Proof verifier",
            script_path=root / "examples" / "code-change-proof" / "code_change_public_verifier.py",
            success_marker="DELTA CODE CHANGE PROOF VERIFIER RESULT: OK",
        ),
        "private-payload": VerificationTarget(
            name="private-payload",
            label="Private Payload Proof verifier",
            script_path=root / "examples" / "private-payload-proof" / "private_payload_public_verifier.py",
            success_marker="DELTA PRIVATE PAYLOAD PROOF VERIFIER RESULT: OK",
        ),
        "ai-agent": VerificationTarget(
            name="ai-agent",
            label="AI Agent Proof verifier",
            script_path=root / "examples" / "ai-agent-proof" / "ai_agent_public_verifier.py",
            success_marker="DELTA AI AGENT PROOF VERIFIER RESULT: OK",
        ),
    }


def run_python_script(target: VerificationTarget, *, verbose: bool = False) -> bool:
    root = repo_root()

    if not target.script_path.exists():
        print(f"{target.label}: FAILED")
        print(f"Missing verifier script: {target.script_path}")
        return False

    completed = subprocess.run(
        [sys.executable, str(target.script_path)],
        cwd=str(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    output = completed.stdout or ""

    if verbose:
        print(output.rstrip())

    ok = completed.returncode == 0 and target.success_marker in output

    if ok:
        print(f"{target.label}: OK")
        return True

    print(f"{target.label}: FAILED")

    if not verbose:
        print("")
        print("Verifier output:")
        print(output.rstrip())

    return False


def print_header(command: str) -> None:
    print(CLI_VERSION)
    print(f"Command: {command}")
    print("")


def command_version(_args: argparse.Namespace) -> int:
    root = repo_root()

    print(CLI_VERSION)
    print(f"Protocol: {PROTOCOL_NAME}")
    print(f"Repository root: {root}")

    return 0


def command_keygen(args: argparse.Namespace) -> int:
    print_header("keygen")

    try:
        validate_key_name(args.name)

        out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else default_key_dir().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        private_path = out_dir / f"{args.name}.ed25519.private.pem"
        public_json_path = out_dir / f"{args.name}.ed25519.public.json"
        public_txt_path = out_dir / f"{args.name}.ed25519.public.txt"

        existing_paths = [path for path in [private_path, public_json_path, public_txt_path] if path.exists()]
        if existing_paths:
            print("DELTA KEYGEN RESULT: FAILED")
            print("")
            print("ERROR: Refusing to overwrite existing key files.")
            print("")
            for path in existing_paths:
                print(f"Existing file: {path}")
            print("")
            print("Use a different --name or move the existing files first.")
            return 1

        require_safe_private_key_location(private_path)

        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key_pem(private_key)
        public_key = public_key_value(private_key)
        public_record = build_public_key_record(
            key_name=args.name,
            role=args.role,
            public_key=public_key,
        )

        write_private_key_exclusive_0600(private_path, private_pem)
        try:
            write_json_exclusive(public_json_path, public_record)
            write_text_exclusive(public_txt_path, public_key + "\n")
        except Exception as exc:
            private_key = None
            private_pem = b""
            raise RuntimeError(
                "Private key was created, but writing public key files failed. "
                f"Private key location: {private_path}"
            ) from exc

        private_key = None
        private_pem = b""

        print("DELTA KEYGEN RESULT: OK")
        print("")
        print(f"Key name: {args.name}")
        print(f"Key role: {args.role}")
        print("Algorithm: Ed25519")
        print(f"Private key written: {private_path}")
        print(f"Public key JSON written: {public_json_path}")
        print(f"Public key text written: {public_txt_path}")
        print("")
        print(f"Public key: {public_key}")
        print(f"Public key fingerprint: {public_record['public_key_fingerprint']}")
        print("")
        print("Security:")
        print("- The private key was not printed to the screen.")
        print("- The private key file was created atomically with exclusive-create semantics.")
        print("- On supported filesystems, the private key file mode is restricted to owner read/write.")
        print("- The default private key location is outside this repository.")
        print("- Private keys are refused inside the repository, even if Git ignores them.")
        print("- Do not commit private keys.")
        print("")
        print("PKI preparation tip:")
        print("To link this DELTA key to your company domain, add a DNS TXT record:")
        print("")
        print(f'TXT example.com "delta-pubkey={public_key}"')
        print("")
        print("Future DELTA PKI can use domain TXT records to discover trusted public keys.")
        return 0

    except FileExistsError as exc:
        print("DELTA KEYGEN RESULT: FAILED")
        print("")
        print("ERROR: Refusing to overwrite existing key files.")
        print(exc)
        return 1
    except Exception as exc:
        print("DELTA KEYGEN RESULT: FAILED")
        print("")
        print("ERROR:")
        print(exc)
        return 1


def command_claim(args: argparse.Namespace) -> int:
    print_header("claim")

    private_key: Optional[Ed25519PrivateKey] = None

    try:
        validate_sha256_hash("before-hash", args.before_hash)
        validate_sha256_hash("after-hash", args.after_hash)
        validate_sha256_hash("evidence-hash", args.evidence_hash)
        validate_action(args.action)

        key_path = Path(args.key).expanduser().resolve()
        out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else Path.cwd().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        claim_path = out_dir / "claim.json"
        signature_path = out_dir / "executor_signature.json"

        existing_paths = [path for path in [claim_path, signature_path] if path.exists()]
        if existing_paths:
            print("DELTA CLAIM RESULT: FAILED")
            print("")
            print("ERROR: Refusing to overwrite existing claim files.")
            print("")
            for path in existing_paths:
                print(f"Existing file: {path}")
            print("")
            print("Use a different --out-dir or move the existing files first.")
            return 1

        private_key = load_ed25519_private_key(key_path)
        executor_pubkey = public_key_value(private_key)

        created_at = utc_now()
        claim = build_claim(
            before_hash=args.before_hash,
            action=args.action.strip(),
            after_hash=args.after_hash,
            evidence_hash=args.evidence_hash,
            executor_pubkey=executor_pubkey,
            created_at=created_at,
        )

        claim_bytes = canonical_json_bytes(claim)
        claim_hash = sha256_bytes(claim_bytes)
        signature_bytes = private_key.sign(claim_bytes)

        try:
            private_key.public_key().verify(signature_bytes, claim_bytes)
        except InvalidSignature as exc:
            raise RuntimeError("Internal signature self-check failed.") from exc

        signature_envelope = build_executor_signature(
            public_key=executor_pubkey,
            target_hash=claim_hash,
            signature_bytes=signature_bytes,
            signed_at=created_at,
        )

        private_key = None
        signature_bytes = bytes(signature_bytes)

        write_json_exclusive(claim_path, claim)
        write_json_exclusive(signature_path, signature_envelope)

        print("DELTA CLAIM RESULT: OK")
        print("")
        print(f"Claim written: {claim_path}")
        print(f"Executor signature written: {signature_path}")
        print("")
        print(f"Claim hash: {claim_hash}")
        print(f"Executor public key: {executor_pubkey}")
        print("")
        print("Security:")
        print("- claim.json does not contain an embedded signature.")
        print("- executor_signature.json is a detached signature envelope.")
        print("- The signature input is canonical JSON bytes of claim.json.")
        print("- Existing claim files are not overwritten.")
        print("- The private key was loaded only for signing and was not printed.")
        return 0

    except FileExistsError as exc:
        print("DELTA CLAIM RESULT: FAILED")
        print("")
        print("ERROR: Refusing to overwrite existing claim files.")
        print(exc)
        return 1
    except Exception as exc:
        print("DELTA CLAIM RESULT: FAILED")
        print("")
        print("ERROR:")
        print(exc)
        return 1
    finally:
        private_key = None


def command_attest(args: argparse.Namespace) -> int:
    print_header("attest")

    private_key: Optional[Ed25519PrivateKey] = None

    try:
        validate_sha256_hash("policy-hash", args.policy_hash)
        validate_attestation_result(args.result)
        validate_publication_mode(args.publication_mode)
        validate_ledger_id(args.ledger_id)

        claim_dir = Path(args.claim_dir).expanduser().resolve()
        out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else Path.cwd().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        claim_path = claim_dir / "claim.json"
        executor_signature_path = claim_dir / "executor_signature.json"

        attestation_path = out_dir / "attestation.json"
        verifier_signature_path = out_dir / "verifier_signature.json"

        existing_paths = [path for path in [attestation_path, verifier_signature_path] if path.exists()]
        if existing_paths:
            print("DELTA ATTEST RESULT: FAILED")
            print("")
            print("ERROR: Refusing to overwrite existing attestation files.")
            print("")
            for path in existing_paths:
                print(f"Existing file: {path}")
            print("")
            print("Use a different --out-dir or move the existing files first.")
            return 1

        claim = read_json_file(claim_path, "claim.json")
        executor_signature = read_json_file(executor_signature_path, "executor_signature.json")

        claim_hash, executor_signature_hash = verify_executor_signature_or_raise(
            claim,
            executor_signature,
        )

        evidence_hash = claim.get("evidence_hash")
        validate_sha256_hash("claim.evidence_hash", evidence_hash)

        key_path = Path(args.key).expanduser().resolve()
        private_key = load_ed25519_private_key(key_path)
        verifier_pubkey = public_key_value(private_key)

        verified_at = utc_now()
        attestation = build_attestation(
            verifier_pubkey=verifier_pubkey,
            target_claim_hash=claim_hash,
            target_executor_sig_hash=executor_signature_hash,
            verification_policy_hash=args.policy_hash,
            evidence_hash=evidence_hash,
            publication_mode=args.publication_mode,
            intended_ledger_id=args.ledger_id.strip(),
            result=args.result.strip(),
            verified_at=verified_at,
        )

        attestation_bytes = canonical_json_bytes(attestation)
        attestation_hash = sha256_bytes(attestation_bytes)
        verifier_signature_bytes = private_key.sign(attestation_bytes)

        try:
            private_key.public_key().verify(verifier_signature_bytes, attestation_bytes)
        except InvalidSignature as exc:
            raise RuntimeError("Internal verifier signature self-check failed.") from exc

        verifier_signature = build_verifier_signature(
            public_key=verifier_pubkey,
            target_hash=attestation_hash,
            signature_bytes=verifier_signature_bytes,
            signed_at=verified_at,
        )

        private_key = None
        verifier_signature_bytes = bytes(verifier_signature_bytes)

        write_json_exclusive(attestation_path, attestation)
        write_json_exclusive(verifier_signature_path, verifier_signature)

        print("DELTA ATTEST RESULT: OK")
        print("")
        print(f"Attestation written: {attestation_path}")
        print(f"Verifier signature written: {verifier_signature_path}")
        print("")
        print(f"Target claim hash: {claim_hash}")
        print(f"Target executor signature hash: {executor_signature_hash}")
        print(f"Evidence hash: {evidence_hash}")
        print(f"Publication mode: {args.publication_mode}")
        print(f"Intended ledger ID: {args.ledger_id.strip()}")
        print(f"Attestation hash: {attestation_hash}")
        print(f"Verifier public key: {verifier_pubkey}")
        print("")
        print("Security:")
        print("- Executor signature was verified before attestation.")
        print("- attestation.json does not contain an embedded signature.")
        print("- verifier_signature.json is a detached signature envelope.")
        print("- The signature input is canonical JSON bytes of attestation.json.")
        print("- Existing attestation files are not overwritten.")
        print("- The verifier private key was loaded only for signing and was not printed.")
        return 0

    except FileExistsError as exc:
        print("DELTA ATTEST RESULT: FAILED")
        print("")
        print("ERROR: Refusing to overwrite existing attestation files.")
        print(exc)
        return 1
    except Exception as exc:
        print("DELTA ATTEST RESULT: FAILED")
        print("")
        print("ERROR:")
        print(exc)
        return 1
    finally:
        private_key = None


def command_verify_genesis(args: argparse.Namespace) -> int:
    print_header("verify-genesis")

    ok = run_python_script(targets()["genesis"], verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if ok else "DELTA CLI RESULT: FAILED")

    return 0 if ok else 1


def command_verify_code_change(args: argparse.Namespace) -> int:
    print_header("verify-code-change")

    ok = run_python_script(targets()["code-change"], verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if ok else "DELTA CLI RESULT: FAILED")

    return 0 if ok else 1


def command_verify_private_payload(args: argparse.Namespace) -> int:
    print_header("verify-private-payload")

    ok = run_python_script(targets()["private-payload"], verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if ok else "DELTA CLI RESULT: FAILED")

    return 0 if ok else 1


def command_verify_ai_agent(args: argparse.Namespace) -> int:
    print_header("verify-ai-agent")

    ok = run_python_script(targets()["ai-agent"], verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if ok else "DELTA CLI RESULT: FAILED")

    return 0 if ok else 1


def command_verify_all(args: argparse.Namespace) -> int:
    print_header("verify-all")

    ordered_targets: List[VerificationTarget] = [
        targets()["genesis"],
        targets()["code-change"],
        targets()["private-payload"],
        targets()["ai-agent"],
    ]

    all_ok = True

    for target in ordered_targets:
        ok = run_python_script(target, verbose=args.verbose)
        all_ok = all_ok and ok

    print("")
    print("DELTA CLI RESULT: OK" if all_ok else "DELTA CLI RESULT: FAILED")

    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="delta_cli.py",
        description="DELTA Protocol command line interface.",
    )

    subparsers = parser.add_subparsers(dest="command")

    version_parser = subparsers.add_parser(
        "version",
        help="Show DELTA CLI version.",
    )
    version_parser.set_defaults(func=command_version)

    keygen_parser = subparsers.add_parser(
        "keygen",
        help="Generate a local DELTA Ed25519 key pair.",
    )
    keygen_parser.add_argument(
        "--name",
        required=True,
        help="Key name. Allowed characters: letters, digits, dot, underscore, dash.",
    )
    keygen_parser.add_argument(
        "--role",
        choices=["executor", "verifier", "checkpoint-signer", "ai-agent", "identity"],
        default="executor",
        help="DELTA role for this key. Default: executor.",
    )
    keygen_parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory. Default: ~/.delta/keys. Private keys are refused inside the repository.",
    )
    keygen_parser.set_defaults(func=command_keygen)

    claim_parser = subparsers.add_parser(
        "claim",
        help="Create a DELTA Claim and detached Executor signature.",
    )
    claim_parser.add_argument(
        "--before-hash",
        required=True,
        help="Before-state hash in format sha256:<64 lowercase hex characters>.",
    )
    claim_parser.add_argument(
        "--action",
        required=True,
        help="Declared action/change description.",
    )
    claim_parser.add_argument(
        "--after-hash",
        required=True,
        help="After-state hash in format sha256:<64 lowercase hex characters>.",
    )
    claim_parser.add_argument(
        "--evidence-hash",
        required=True,
        help="Evidence hash in format sha256:<64 lowercase hex characters>.",
    )
    claim_parser.add_argument(
        "--key",
        required=True,
        help="Path to the Executor Ed25519 private key PEM.",
    )
    claim_parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory for claim.json and executor_signature.json. Default: current directory.",
    )
    claim_parser.set_defaults(func=command_claim)

    attest_parser = subparsers.add_parser(
        "attest",
        help="Create a DELTA Attestation and detached Verifier signature.",
    )
    attest_parser.add_argument(
        "--claim-dir",
        required=True,
        help="Directory containing claim.json and executor_signature.json.",
    )
    attest_parser.add_argument(
        "--policy-hash",
        required=True,
        help="Verification policy hash in format sha256:<64 lowercase hex characters>.",
    )
    attest_parser.add_argument(
        "--result",
        default="VERIFIED",
        help="Attestation result. Default: VERIFIED.",
    )
    attest_parser.add_argument(
        "--publication-mode",
        default="ledger_required",
        help="Publication mode. v0.7-alpha requires: ledger_required.",
    )
    attest_parser.add_argument(
        "--ledger-id",
        default="delta-ledger:local",
        help="Intended ledger identifier. Default: delta-ledger:local.",
    )
    attest_parser.add_argument(
        "--key",
        required=True,
        help="Path to the Verifier Ed25519 private key PEM.",
    )
    attest_parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory for attestation.json and verifier_signature.json. Default: current directory.",
    )
    attest_parser.set_defaults(func=command_attest)

    verify_genesis_parser = subparsers.add_parser(
        "verify-genesis",
        help="Run the DELTA Genesis public verifier.",
    )
    verify_genesis_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_genesis_parser.set_defaults(func=command_verify_genesis)

    verify_code_change_parser = subparsers.add_parser(
        "verify-code-change",
        help="Run the Code Change Proof verifier.",
    )
    verify_code_change_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_code_change_parser.set_defaults(func=command_verify_code_change)

    verify_private_payload_parser = subparsers.add_parser(
        "verify-private-payload",
        help="Run the Private Payload Proof verifier.",
    )
    verify_private_payload_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_private_payload_parser.set_defaults(func=command_verify_private_payload)

    verify_ai_agent_parser = subparsers.add_parser(
        "verify-ai-agent",
        help="Run the AI Agent Proof verifier.",
    )
    verify_ai_agent_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_ai_agent_parser.set_defaults(func=command_verify_ai_agent)

    verify_all_parser = subparsers.add_parser(
        "verify-all",
        help="Run all public DELTA verifiers.",
    )
    verify_all_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_all_parser.set_defaults(func=command_verify_all)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
