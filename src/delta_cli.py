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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


CLI_VERSION = "DELTA CLI v0.7-alpha-keygen"
PROTOCOL_NAME = "DELTA-0"

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


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
            raise RuntimeError(
                "Private key was created, but writing public key files failed. "
                f"Private key location: {private_path}"
            ) from exc

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
