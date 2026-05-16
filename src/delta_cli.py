from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


CLI_VERSION = "DELTA CLI v0.6.2-alpha"
PROTOCOL_NAME = "DELTA-0"


@dataclass(frozen=True)
class VerificationTarget:
    name: str
    label: str
    script_path: Path
    success_marker: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


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