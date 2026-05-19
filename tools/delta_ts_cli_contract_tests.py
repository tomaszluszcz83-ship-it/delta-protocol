#!/usr/bin/env python3
"""
DELTA v2.11.0 TypeScript CLI Contract Tests.

Purpose:
- Validate machine-readable JSON output contract introduced in v2.10.2.
- Validate stable top-level fields and exit-code categories.
- Validate OK, USAGE_ERROR, and VERIFICATION_FAILED behavior for signed-record JSON verification.

Security boundary:
- This script adds no cryptographic functionality.
- It tests CLI/JSON contract behavior only.
- It does not make TypeScript a complete DELTA verifier.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_TOP_LEVEL_FIELDS = {
    "ok",
    "code",
    "code_name",
    "profile",
    "command",
    "result",
    "errors",
    "warnings",
}

EXPECTED_PROFILE = "delta_typescript_cli_json_v2_10_2"

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE_ERROR = 2
EXIT_INTERNAL_ERROR = 3


class ContractError(RuntimeError):
    pass


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def npm_command() -> str:
    return "npm.cmd" if os.name == "nt" else "npm"


def run_cmd(
    args: list[str],
    cwd: Path,
    *,
    expect_exit: int | None = None,
    label: str,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )

    if expect_exit is not None and result.returncode != expect_exit:
        raise ContractError(
            f"{label}: expected exit {expect_exit}, got {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    return result


def extract_json_from_output(output: str) -> dict[str, Any]:
    start = output.find("{")
    end = output.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ContractError(f"JSON object not found in output:\n{output}")

    try:
        value = json.loads(output[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON output: {exc}\nOUTPUT:\n{output}") from exc

    if not isinstance(value, dict):
        raise ContractError("top-level JSON output is not an object")

    return value


def assert_top_level_contract(value: dict[str, Any], *, command: str) -> None:
    missing = EXPECTED_TOP_LEVEL_FIELDS - set(value.keys())
    if missing:
        raise ContractError(f"{command}: missing top-level JSON fields: {sorted(missing)}")

    if value.get("profile") != EXPECTED_PROFILE:
        raise ContractError(
            f"{command}: unexpected profile {value.get('profile')!r}, expected {EXPECTED_PROFILE!r}"
        )

    if value.get("command") != command:
        raise ContractError(
            f"{command}: unexpected command {value.get('command')!r}, expected {command!r}"
        )

    if not isinstance(value.get("errors"), list):
        raise ContractError(f"{command}: errors must be an array")

    if not isinstance(value.get("warnings"), list):
        raise ContractError(f"{command}: warnings must be an array")


def assert_status(
    value: dict[str, Any],
    *,
    command: str,
    ok: bool,
    code: int,
    code_name: str,
) -> None:
    assert_top_level_contract(value, command=command)

    if value.get("ok") is not ok:
        raise ContractError(f"{command}: expected ok={ok}, got {value.get('ok')!r}")

    if value.get("code") != code:
        raise ContractError(f"{command}: expected code={code}, got {value.get('code')!r}")

    if value.get("code_name") != code_name:
        raise ContractError(
            f"{command}: expected code_name={code_name!r}, got {value.get('code_name')!r}"
        )


def load_json_file(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError(f"{path}: expected JSON object")
    return value


def write_json_file(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_contract_tests(repo: Path, keep_artifacts: bool) -> None:
    verifier_dir = repo / "verifier" / "ts"
    test_dir = repo / ".delta" / "ts-cli-contract-tests" / "R-2110"

    if not verifier_dir.exists():
        raise ContractError(f"missing verifier directory: {verifier_dir}")

    npm = npm_command()

    print("DELTA_TS_CLI_CONTRACT_PROFILE=delta_ts_cli_contract_tests_v2_11_0")

    print("DELTA_TS_CLI_CONTRACT_STEP=build")
    run_cmd([npm, "run", "build"], verifier_dir, expect_exit=0, label="npm run build")

    print("DELTA_TS_CLI_CONTRACT_STEP=verify-vectors")
    run_cmd([npm, "run", "verify-vectors"], verifier_dir, expect_exit=0, label="npm run verify-vectors")

    print("DELTA_TS_CLI_CONTRACT_STEP=verify-schemas")
    run_cmd([npm, "run", "verify-schemas"], verifier_dir, expect_exit=0, label="npm run verify-schemas")

    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    signed_record = test_dir / "signed-record.json"
    tampered_record = test_dir / "signed-record.tampered.json"

    print("DELTA_TS_CLI_CONTRACT_STEP=create-signed-record-demo")
    run_cmd(
        [
            npm,
            "run",
            "create-signed-record-demo",
            "--",
            "--out",
            os.path.relpath(signed_record, verifier_dir),
        ],
        verifier_dir,
        expect_exit=0,
        label="create signed record demo",
    )

    print("DELTA_TS_CLI_CONTRACT_STEP=verify-signed-record-json-ok")
    ok_result = run_cmd(
        [
            npm,
            "run",
            "verify-signed-record-json",
            "--",
            "--record",
            os.path.relpath(signed_record, verifier_dir),
        ],
        verifier_dir,
        expect_exit=EXIT_OK,
        label="verify signed record json ok",
    )
    ok_json = extract_json_from_output(ok_result.stdout)
    assert_status(
        ok_json,
        command="verify-signed-record-json",
        ok=True,
        code=EXIT_OK,
        code_name="OK",
    )

    inner_result = ok_json.get("result")
    if not isinstance(inner_result, dict):
        raise ContractError("verify-signed-record-json OK result must be an object")
    if inner_result.get("signatureOk") is not True:
        raise ContractError("verify-signed-record-json OK result.signatureOk must be true")
    if inner_result.get("recordHashMatches") is not True:
        raise ContractError("verify-signed-record-json OK result.recordHashMatches must be true")

    print("DELTA_TS_CLI_CONTRACT_STEP=verify-signed-record-json-usage-error")
    usage_result = run_cmd(
        [npm, "run", "verify-signed-record-json"],
        verifier_dir,
        expect_exit=EXIT_USAGE_ERROR,
        label="verify signed record json usage error",
    )
    usage_json = extract_json_from_output(usage_result.stdout)
    assert_status(
        usage_json,
        command="verify-signed-record-json",
        ok=False,
        code=EXIT_USAGE_ERROR,
        code_name="USAGE_ERROR",
    )

    source_record = load_json_file(signed_record)
    if "after_state" not in source_record or not isinstance(source_record["after_state"], dict):
        raise ContractError("demo signed record does not contain object after_state")

    source_record["after_state"]["contract_test_tamper"] = "v2.11.0"
    write_json_file(tampered_record, source_record)

    print("DELTA_TS_CLI_CONTRACT_STEP=verify-signed-record-json-verification-failed")
    failed_result = run_cmd(
        [
            npm,
            "run",
            "verify-signed-record-json",
            "--",
            "--record",
            os.path.relpath(tampered_record, verifier_dir),
        ],
        verifier_dir,
        expect_exit=EXIT_VERIFICATION_FAILED,
        label="verify signed record json verification failed",
    )
    failed_json = extract_json_from_output(failed_result.stdout)
    assert_status(
        failed_json,
        command="verify-signed-record-json",
        ok=False,
        code=EXIT_VERIFICATION_FAILED,
        code_name="VERIFICATION_FAILED",
    )

    if not failed_json.get("errors"):
        raise ContractError("verification failed JSON result should include errors")

    print("DELTA_TS_CLI_CONTRACT_TOP_LEVEL_FIELDS_OK=True")
    print("DELTA_TS_CLI_CONTRACT_EXIT_CODE_OK_TRUE=0")
    print("DELTA_TS_CLI_CONTRACT_EXIT_CODE_USAGE_ERROR=2")
    print("DELTA_TS_CLI_CONTRACT_EXIT_CODE_VERIFICATION_FAILED=1")
    print("DELTA_TS_CLI_CONTRACT_JSON_PARSE_OK=True")
    print("DELTA_TS_CLI_CONTRACT_VERIFY_OK=True")

    if not keep_artifacts and test_dir.exists():
        shutil.rmtree(test_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="DELTA TypeScript CLI JSON contract tests v2.11.0")
    parser.add_argument(
        "--repo",
        default=None,
        help="Path to DELTA repository root. Defaults to parent of this script directory.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep generated .delta/ts-cli-contract-tests artifacts.",
    )

    args = parser.parse_args()
    repo = Path(args.repo).resolve() if args.repo else repo_root_from_script()

    try:
        run_contract_tests(repo, keep_artifacts=args.keep_artifacts)
        return 0
    except ContractError as exc:
        print(f"DELTA_TS_CLI_CONTRACT_VERIFY_OK=False")
        print(f"DELTA_TS_CLI_CONTRACT_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
