#!/usr/bin/env python3
"""
DELTA v2.13.0 TypeScript Proof of Intent Contract Tests.

Purpose:
- Freeze TypeScript Proof of Intent machine-readable behavior after v2.12.0-v2.12.3.
- Validate record binding, detached signature, registry binding, and policy/deadline JSON contract.
- Validate positive and negative paths.

Security boundary:
- This script adds no cryptographic functionality.
- It tests verifier behavior and JSON/exit-code contract only.
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

EXPECTED_CLI_JSON_PROFILE = "delta_typescript_cli_json_v2_10_2"

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE_ERROR = 2


class ContractError(RuntimeError):
    pass


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def npm_command() -> str:
    return "npm.cmd" if os.name == "nt" else "npm"


def path_for_node(path: Path, cwd: Path) -> str:
    return os.path.relpath(path, cwd)


def run_cmd(
    args: list[str],
    cwd: Path,
    *,
    expect_exit: int | None,
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

    if value.get("profile") != EXPECTED_CLI_JSON_PROFILE:
        raise ContractError(
            f"{command}: unexpected profile {value.get('profile')!r}, expected {EXPECTED_CLI_JSON_PROFILE!r}"
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
) -> dict[str, Any]:
    assert_top_level_contract(value, command=command)

    if value.get("ok") is not ok:
        raise ContractError(f"{command}: expected ok={ok}, got {value.get('ok')!r}")

    if value.get("code") != code:
        raise ContractError(f"{command}: expected code={code}, got {value.get('code')!r}")

    if value.get("code_name") != code_name:
        raise ContractError(
            f"{command}: expected code_name={code_name!r}, got {value.get('code_name')!r}"
        )

    result = value.get("result")
    if not isinstance(result, dict):
        raise ContractError(f"{command}: result must be an object")

    return result


def run_verify_intent_json(
    verifier_dir: Path,
    test_dir: Path,
    *,
    now: str,
    expect_exit: int,
    label: str,
) -> dict[str, Any]:
    npm = npm_command()
    result = run_cmd(
        [
            npm,
            "run",
            "verify-intent-json",
            "--",
            "--record",
            path_for_node(test_dir / "delta-record.json", verifier_dir),
            "--intent",
            path_for_node(test_dir / "intent-attestation.json", verifier_dir),
            "--signature",
            path_for_node(test_dir / "intent-signature.json", verifier_dir),
            "--registry",
            path_for_node(test_dir / "intent-registry.json", verifier_dir),
            "--policy",
            path_for_node(test_dir / "intent-policy.json", verifier_dir),
            "--now",
            now,
        ],
        verifier_dir,
        expect_exit=expect_exit,
        label=label,
    )
    return extract_json_from_output(result.stdout)


def run_contract_tests(repo: Path, keep_artifacts: bool) -> None:
    verifier_dir = repo / "verifier" / "ts"
    test_dir = repo / ".delta" / "ts-intent-contract-tests" / "I-2130"
    npm = npm_command()

    if not verifier_dir.exists():
        raise ContractError(f"missing verifier directory: {verifier_dir}")

    print("DELTA_TS_INTENT_CONTRACT_PROFILE=delta_ts_intent_contract_tests_v2_13_0")

    print("DELTA_TS_INTENT_CONTRACT_STEP=build")
    run_cmd([npm, "run", "build"], verifier_dir, expect_exit=0, label="npm run build")

    print("DELTA_TS_INTENT_CONTRACT_STEP=verify-vectors")
    run_cmd([npm, "run", "verify-vectors"], verifier_dir, expect_exit=0, label="npm run verify-vectors")

    print("DELTA_TS_INTENT_CONTRACT_STEP=verify-schemas")
    run_cmd([npm, "run", "verify-schemas"], verifier_dir, expect_exit=0, label="npm run verify-schemas")

    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    print("DELTA_TS_INTENT_CONTRACT_STEP=create-signed-intent-demo")
    run_cmd(
        [
            npm,
            "run",
            "create-signed-intent-demo",
            "--",
            "--out-dir",
            path_for_node(test_dir, verifier_dir),
        ],
        verifier_dir,
        expect_exit=0,
        label="create signed intent demo",
    )

    print("DELTA_TS_INTENT_CONTRACT_STEP=verify-intent-json-positive")
    ok_json = run_verify_intent_json(
        verifier_dir,
        test_dir,
        now="2026-01-01T00:00:00Z",
        expect_exit=EXIT_OK,
        label="verify intent json positive",
    )
    ok_result = assert_status(
        ok_json,
        command="verify-intent-json",
        ok=True,
        code=EXIT_OK,
        code_name="OK",
    )

    required_true_fields = [
        "recordHashBindingOk",
        "intentHashBindingOk",
        "signatureBodyHashOk",
        "publicKeyHashOk",
        "signatureShapeOk",
        "signatureOk",
    ]

    for field in required_true_fields:
        if ok_result.get(field) is not True:
            raise ContractError(f"positive result expected {field}=true, got {ok_result.get(field)!r}")

    expected_statuses = {
        "signatureVerificationStatus": "VERIFIED",
        "registryVerificationStatus": "VERIFIED",
        "policyVerificationStatus": "SATISFIED",
    }

    for field, expected in expected_statuses.items():
        if ok_result.get(field) != expected:
            raise ContractError(f"positive result expected {field}={expected!r}, got {ok_result.get(field)!r}")

    registry_result = ok_result.get("registryResult")
    if not isinstance(registry_result, dict):
        raise ContractError("positive result.registryResult must be an object")

    if registry_result.get("registryStatusOk") is not True:
        raise ContractError("positive registryResult.registryStatusOk must be true")

    policy_result = ok_result.get("policyResult")
    if not isinstance(policy_result, dict):
        raise ContractError("positive result.policyResult must be an object")

    for field in ["policyIdOk", "deadlineOk", "policyStatusOk"]:
        if policy_result.get(field) is not True:
            raise ContractError(f"positive policyResult expected {field}=true, got {policy_result.get(field)!r}")

    print("DELTA_TS_INTENT_CONTRACT_STEP=verify-intent-json-expired-deadline")
    expired_json = run_verify_intent_json(
        verifier_dir,
        test_dir,
        now="3000-01-01T00:00:00Z",
        expect_exit=EXIT_VERIFICATION_FAILED,
        label="verify intent json expired deadline",
    )
    expired_result = assert_status(
        expired_json,
        command="verify-intent-json",
        ok=False,
        code=EXIT_VERIFICATION_FAILED,
        code_name="VERIFICATION_FAILED",
    )

    if expired_result.get("policyVerificationStatus") != "INVALID":
        raise ContractError(
            f"expired result expected policyVerificationStatus='INVALID', got {expired_result.get('policyVerificationStatus')!r}"
        )

    expired_policy_result = expired_result.get("policyResult")
    if not isinstance(expired_policy_result, dict):
        raise ContractError("expired result.policyResult must be an object")

    if expired_policy_result.get("deadlineOk") is not False:
        raise ContractError("expired policyResult.deadlineOk must be false")

    errors = expired_json.get("errors")
    if not isinstance(errors, list) or not any("intent_policy_deadline_expired" in str(e) for e in errors):
        raise ContractError("expired result must include intent_policy_deadline_expired error")

    print("DELTA_TS_INTENT_CONTRACT_TOP_LEVEL_FIELDS_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_POSITIVE_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_SIGNATURE_VERIFIED_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_REGISTRY_VERIFIED_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_POLICY_SATISFIED_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_EXPIRED_DEADLINE_REJECTED_OK=True")
    print("DELTA_TS_INTENT_CONTRACT_EXIT_CODE_OK_TRUE=0")
    print("DELTA_TS_INTENT_CONTRACT_EXIT_CODE_VERIFICATION_FAILED=1")
    print("DELTA_TS_INTENT_CONTRACT_VERIFY_OK=True")

    if not keep_artifacts and test_dir.exists():
        shutil.rmtree(test_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="DELTA TypeScript Proof of Intent contract tests v2.13.0")
    parser.add_argument(
        "--repo",
        default=None,
        help="Path to DELTA repository root. Defaults to parent of this script directory.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep generated .delta/ts-intent-contract-tests artifacts.",
    )

    args = parser.parse_args()
    repo = Path(args.repo).resolve() if args.repo else repo_root_from_script()

    try:
        run_contract_tests(repo, keep_artifacts=args.keep_artifacts)
        return 0
    except ContractError as exc:
        print("DELTA_TS_INTENT_CONTRACT_VERIFY_OK=False")
        print(f"DELTA_TS_INTENT_CONTRACT_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
