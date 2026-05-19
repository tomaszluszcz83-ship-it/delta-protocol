#!/usr/bin/env python3
"""
DELTA Protocol v2.8.3 — Replay Environment Checker.

MVP scope:
- declare current local environment into environment.json
- check current local environment against environment.json
- support OS, Python version, and Python package versions
- return MATCH / MISMATCH / MANUAL_REVIEW_REQUIRED

Security boundary:
- This tool checks a declared local environment.
- It does not prove the original execution environment.
- It does not verify containers, Nix, Guix, hardware state, network state, or
  remote attestation in v2.8.3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Tuple


PROFILE = "delta_replay_environment_check_v2_8_3"
STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_MANUAL = "MANUAL_REVIEW_REQUIRED"


class DeltaReplayEnvError(Exception):
    """Raised for invalid environment declaration or checker usage."""


@dataclass
class CheckResult:
    status: str
    reasons: List[str]
    current: Dict[str, Any]
    declared: Dict[str, Any]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def normalize_os_name(name: str) -> str:
    value = (name or "").strip().lower()
    if value.startswith("windows"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value.startswith("darwin") or value.startswith("mac") or value.startswith("macos"):
        return "macos"
    return value or "unknown"


def current_os() -> str:
    return normalize_os_name(platform.system())


def current_python_version(mode: str = "major_minor_patch") -> str:
    v = sys.version_info
    if mode == "major_minor":
        return f"{v.major}.{v.minor}"
    return f"{v.major}.{v.minor}.{v.micro}"


def get_package_version(package: str) -> Tuple[str | None, str | None]:
    try:
        return metadata.version(package), None
    except metadata.PackageNotFoundError:
        return None, "package_not_installed"
    except Exception as exc:
        return None, f"package_version_unknown:{type(exc).__name__}"


def build_environment(packages: List[str], python_version_mode: str = "major_minor_patch") -> Dict[str, Any]:
    dependencies: Dict[str, str | None] = {}

    for package in packages:
        package = package.strip()
        if not package:
            continue
        version, _reason = get_package_version(package)
        dependencies[package] = version

    body = {
        "profile": PROFILE,
        "determinism_level": "L1",
        "mode": "declared_environment",
        "os": current_os(),
        "python_version": current_python_version(python_version_mode),
        "python_version_mode": python_version_mode,
        "dependencies": dependencies,
        "unsupported": {
            "container": None,
            "container_digest": None,
            "nix_hash": None,
            "guix_hash": None,
            "hardware_attestation": None,
            "network_state": "not_checked_in_v2_8_3",
        },
        "security_boundary": {
            "does_not_prove_original_environment": True,
            "does_not_check_container_digest": True,
            "does_not_check_nix_or_guix": True,
            "does_not_check_external_network_state": True,
            "manual_review_required_for_unsupported_fields": True,
        },
    }
    body["environment_hash"] = sha256_prefixed(canonical_json_bytes({k: v for k, v in body.items() if k != "environment_hash"}))
    return body


def read_declared(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise DeltaReplayEnvError(f"environment declaration does not exist: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise DeltaReplayEnvError(f"environment declaration is not valid JSON: {type(exc).__name__}:{exc}") from exc

    if not isinstance(data, dict):
        raise DeltaReplayEnvError("environment declaration must be a JSON object")

    return data


def compare_versions_exact(field: str, declared: str | None, current: str | None, reasons: List[str]) -> str:
    if declared in (None, "", "unknown"):
        reasons.append(f"{field}:missing_or_unknown_declaration")
        return STATUS_MANUAL

    if current in (None, "", "unknown"):
        reasons.append(f"{field}:current_value_unknown")
        return STATUS_MANUAL

    if str(declared).strip() != str(current).strip():
        reasons.append(f"{field}:mismatch declared={declared} current={current}")
        return STATUS_MISMATCH

    return STATUS_MATCH


def check_environment(declared: Dict[str, Any]) -> CheckResult:
    reasons: List[str] = []
    status = STATUS_MATCH

    declared_os = declared.get("os")
    declared_python = declared.get("python_version")
    python_mode = declared.get("python_version_mode") or "major_minor_patch"

    current = build_environment(
        packages=list((declared.get("dependencies") or {}).keys()),
        python_version_mode=python_mode,
    )

    os_status = compare_versions_exact("os", normalize_os_name(str(declared_os)) if declared_os is not None else None, current.get("os"), reasons)
    py_status = compare_versions_exact("python_version", str(declared_python) if declared_python is not None else None, current.get("python_version"), reasons)

    for sub_status in (os_status, py_status):
        if sub_status == STATUS_MISMATCH:
            status = STATUS_MISMATCH
        elif sub_status == STATUS_MANUAL and status != STATUS_MISMATCH:
            status = STATUS_MANUAL

    declared_deps = declared.get("dependencies") or {}
    if not isinstance(declared_deps, dict):
        reasons.append("dependencies:not_a_dictionary")
        status = STATUS_MANUAL
    else:
        for package, expected_version in sorted(declared_deps.items()):
            current_version, reason = get_package_version(str(package))
            if reason is not None:
                reasons.append(f"dependency:{package}:{reason}")
                if status != STATUS_MISMATCH:
                    status = STATUS_MANUAL
                continue

            dep_status = compare_versions_exact(f"dependency:{package}", str(expected_version), current_version, reasons)
            if dep_status == STATUS_MISMATCH:
                status = STATUS_MISMATCH
            elif dep_status == STATUS_MANUAL and status != STATUS_MISMATCH:
                status = STATUS_MANUAL

    unsupported = declared.get("unsupported") or {}
    if isinstance(unsupported, dict):
        for key in ("container", "container_digest", "nix_hash", "guix_hash", "hardware_attestation"):
            value = unsupported.get(key)
            if value not in (None, "", "not_checked_in_v2_8_3"):
                reasons.append(f"{key}:declared_but_not_supported_in_v2_8_3")
                if status != STATUS_MISMATCH:
                    status = STATUS_MANUAL

    if not reasons:
        reasons.append("all_supported_declared_fields_match")

    return CheckResult(status=status, reasons=reasons, current=current, declared=declared)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def command_declare(args: argparse.Namespace) -> int:
    packages = args.package or []
    env = build_environment(packages=packages, python_version_mode=args.python_version_mode)
    out = Path(args.out)
    write_json(out, env)

    print("DELTA_REPLAY_ENV_DECLARE_OK=True")
    print(f"DELTA_REPLAY_ENV_PROFILE={PROFILE}")
    print(f"DELTA_REPLAY_ENV_FILE={out}")
    print(f"DELTA_REPLAY_ENV_HASH={env['environment_hash']}")
    print(f"DELTA_REPLAY_ENV_STATUS={STATUS_MANUAL if not packages else STATUS_MATCH}")
    if not packages:
        print("DELTA_REPLAY_ENV_REASON=no_dependencies_declared_manual_review_recommended")
    return 0


def command_check(args: argparse.Namespace) -> int:
    declared_path = Path(args.env)
    try:
        declared = read_declared(declared_path)
        result = check_environment(declared)
    except DeltaReplayEnvError as exc:
        print("DELTA_REPLAY_ENV_CHECK=MANUAL_REVIEW_REQUIRED")
        print("DELTA_REPLAY_ENV_CHECK_OK=False")
        print(f"DELTA_REPLAY_ENV_REASON={exc}")
        return 1

    print(f"DELTA_REPLAY_ENV_CHECK={result.status}")
    print(f"DELTA_REPLAY_ENV_PROFILE={PROFILE}")
    print(f"DELTA_REPLAY_ENV_CHECK_OK={result.status == STATUS_MATCH}")
    print(f"DELTA_REPLAY_ENV_CURRENT_OS={result.current.get('os')}")
    print(f"DELTA_REPLAY_ENV_DECLARED_OS={result.declared.get('os')}")
    print(f"DELTA_REPLAY_ENV_CURRENT_PYTHON={result.current.get('python_version')}")
    print(f"DELTA_REPLAY_ENV_DECLARED_PYTHON={result.declared.get('python_version')}")
    print(f"DELTA_REPLAY_ENV_CURRENT_HASH={result.current.get('environment_hash')}")
    for reason in result.reasons:
        print(f"DELTA_REPLAY_ENV_REASON={reason}")

    return 0 if result.status == STATUS_MATCH else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Protocol v2.8.3 — Replay Environment Checker")
    sub = parser.add_subparsers(dest="command", required=True)

    declare = sub.add_parser("declare", help="Create environment.json from current local environment")
    declare.add_argument("--out", required=True, help="Output environment JSON path")
    declare.add_argument("--package", action="append", help="Python package name to include. Can be repeated.")
    declare.add_argument("--python-version-mode", choices=["major_minor", "major_minor_patch"], default="major_minor_patch")
    declare.set_defaults(func=command_declare)

    check = sub.add_parser("check", help="Check current local environment against declaration")
    check.add_argument("--env", required=True, help="Path to environment JSON")
    check.set_defaults(func=command_check)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
