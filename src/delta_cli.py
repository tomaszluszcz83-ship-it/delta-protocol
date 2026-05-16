from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


DELTA_CLI_VERSION = "DELTA CLI v0.6-alpha"
PROTOCOL_VERSION = "DELTA-0"


@dataclass(frozen=True)
class VerificationTask:
    name: str
    script_path: Path
    ok_marker: str


@dataclass(frozen=True)
class VerificationResult:
    name: str
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    reason: str


def repo_root() -> Path:
    """
    Locate repository root from this file location.

    This intentionally does not use Path.cwd(), because the CLI may be
    executed from any terminal working directory.
    """
    return Path(__file__).resolve().parents[1]


def python_executable() -> str:
    return sys.executable


def build_tasks(root: Path) -> dict[str, VerificationTask]:
    return {
        "genesis": VerificationTask(
            name="Genesis verifier",
            script_path=root / "src" / "genesis_public_verifier.py",
            ok_marker="DELTA PUBLIC VERIFIER RESULT: OK",
        ),
        "code-change": VerificationTask(
            name="Code Change Proof verifier",
            script_path=root
            / "examples"
            / "code-change-proof"
            / "code_change_public_verifier.py",
            ok_marker="DELTA CODE CHANGE PROOF VERIFIER RESULT: OK",
        ),
    }


def run_task(task: VerificationTask, root: Path) -> VerificationResult:
    if not task.script_path.exists():
        return VerificationResult(
            name=task.name,
            ok=False,
            returncode=1,
            stdout="",
            stderr="",
            reason=f"Verifier script not found: {task.script_path}",
        )

    completed = subprocess.run(
        [python_executable(), str(task.script_path)],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    if completed.returncode != 0:
        return VerificationResult(
            name=task.name,
            ok=False,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            reason=f"Verifier exited with code {completed.returncode}.",
        )

    if task.ok_marker not in stdout:
        return VerificationResult(
            name=task.name,
            ok=False,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            reason=f"Expected OK marker not found: {task.ok_marker}",
        )

    return VerificationResult(
        name=task.name,
        ok=True,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        reason="OK",
    )


def print_result(result: VerificationResult, verbose: bool = False) -> None:
    status = "OK" if result.ok else "FAILED"
    print(f"{result.name}: {status}")

    if verbose:
        print("")
        print(f"--- {result.name} stdout ---")
        print(result.stdout.rstrip() if result.stdout else "(empty)")

        if result.stderr:
            print("")
            print(f"--- {result.name} stderr ---")
            print(result.stderr.rstrip())

        print("")

    if not result.ok and not verbose:
        print(f"Reason: {result.reason}")

        if result.stderr:
            print("")
            print("stderr:")
            print(result.stderr.rstrip())


def command_version(_: argparse.Namespace) -> int:
    root = repo_root()

    print(DELTA_CLI_VERSION)
    print(f"Protocol: {PROTOCOL_VERSION}")
    print(f"Repository root: {root}")

    return 0


def command_verify_genesis(args: argparse.Namespace) -> int:
    root = repo_root()
    task = build_tasks(root)["genesis"]

    print(DELTA_CLI_VERSION)
    print("Command: verify-genesis")
    print("")

    result = run_task(task, root)
    print_result(result, verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if result.ok else "DELTA CLI RESULT: FAILED")

    return 0 if result.ok else 1


def command_verify_code_change(args: argparse.Namespace) -> int:
    root = repo_root()
    task = build_tasks(root)["code-change"]

    print(DELTA_CLI_VERSION)
    print("Command: verify-code-change")
    print("")

    result = run_task(task, root)
    print_result(result, verbose=args.verbose)

    print("")
    print("DELTA CLI RESULT: OK" if result.ok else "DELTA CLI RESULT: FAILED")

    return 0 if result.ok else 1


def command_verify_all(args: argparse.Namespace) -> int:
    root = repo_root()
    tasks = build_tasks(root)

    print(DELTA_CLI_VERSION)
    print("Command: verify-all")
    print("")

    results: List[VerificationResult] = [
        run_task(tasks["genesis"], root),
        run_task(tasks["code-change"], root),
    ]

    for result in results:
        print_result(result, verbose=args.verbose)

    all_ok = all(result.ok for result in results)

    print("")
    print("DELTA CLI RESULT: OK" if all_ok else "DELTA CLI RESULT: FAILED")

    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="delta",
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
        help="Run the public DELTA-0 Genesis verifier.",
    )
    verify_genesis_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_genesis_parser.set_defaults(func=command_verify_genesis)

    verify_code_change_parser = subparsers.add_parser(
        "verify-code-change",
        help="Run the Code Change Proof example verifier.",
    )
    verify_code_change_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full verifier output.",
    )
    verify_code_change_parser.set_defaults(func=command_verify_code_change)

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