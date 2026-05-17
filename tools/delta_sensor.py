#!/usr/bin/env python3
"""DELTA GitHub Actions dirty sensor prototype.

This sensor creates a first machine-generated DELTA sensor record.

It intentionally does NOT change the DELTA-0 core model. It produces a
sensor-level envelope artifact that can later inform the Delta Record RFC.

What it does:
- resolves before/after Git refs
- computes byte-stable state hashes from git tree listings
- runs an executable measurement method
- stores measurement logs as private/local artifacts
- hashes evidence logs
- writes delta-record.json
- verifies the record envelope hash using DELTA SDK canonical JSON

Security boundary:
- this is not yet a signed DELTA-0 Claim/Attestation/Ledger/Checkpoint bundle
- this is not a registry, anchoring, or trust graph implementation
- this is a dirty prototype for learning real sensor requirements
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from delta_protocol import canonical_json_bytes, load_json_file, sha256_prefixed


SENSOR_VERSION = "v1.3.0-dirty"
RECORD_TYPE = "delta_sensor_record"
ENVELOPE_TYPE = "delta_sensor_record_envelope"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_command(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def git_text(args: list[str]) -> Optional[str]:
    result = run_command(["git", *args])
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip()


def load_github_event() -> dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}

    path = Path(event_path)
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def resolve_refs() -> dict[str, Optional[str]]:
    event = load_github_event()

    before = None
    after = None

    if "pull_request" in event:
        pull_request = event.get("pull_request") or {}
        base = pull_request.get("base") or {}
        head = pull_request.get("head") or {}
        before = base.get("sha")
        after = head.get("sha")

    if not before:
        before = event.get("before")

    if not after:
        after = event.get("after") or os.environ.get("GITHUB_SHA")

    if before in ("", "0000000000000000000000000000000000000000"):
        before = None

    if not after:
        after = git_text(["rev-parse", "HEAD"])

    if not before:
        before = git_text(["rev-parse", "HEAD^"])

    return {
        "before": before,
        "after": after,
        "current_head": git_text(["rev-parse", "HEAD"]),
    }


def git_tree_state_hash(ref: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not ref:
        return None, "missing ref"

    result = run_command(["git", "ls-tree", "-r", "-z", "--full-tree", ref])

    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        return None, error or f"git ls-tree failed for {ref}"

    return sha256_prefixed(result.stdout), None


def hash_file(path: Path) -> str:
    return sha256_prefixed(path.read_bytes())


def canonical_json_file_hash(path: Path) -> str:
    return sha256_prefixed(canonical_json_bytes(load_json_file(path)))


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def build_replay_script(
    *,
    before_ref: Optional[str],
    after_ref: Optional[str],
    command: list[str],
) -> str:
    command_text = " ".join(command)

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# DELTA dirty sensor replay script.",
        "# This script is generated as executable replay instructions.",
        "# Run it from a clean repository checkout with Python available.",
        "",
        "python -m pip install -e ./packages/python/delta_protocol",
        "",
    ]

    if before_ref:
        lines.extend(
            [
                f"git checkout {before_ref}",
                f"{command_text} | tee delta-replay-before.log || true",
                "",
            ]
        )

    if after_ref:
        lines.extend(
            [
                f"git checkout {after_ref}",
                f"{command_text} | tee delta-replay-after.log",
                "",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a dirty DELTA GitHub Actions sensor record.")
    parser.add_argument(
        "--method",
        default=".delta/methods/delta-cli-verify-all-v1.json",
        help="Path to measurement method definition JSON.",
    )
    parser.add_argument(
        "--out-dir",
        default=".delta/artifacts",
        help="Directory where sensor artifacts will be written.",
    )
    args = parser.parse_args()

    method_path = Path(args.method)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    method_definition = load_json_file(method_path)
    command = method_definition.get("command")

    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise SystemExit("measurement method command must be a list of strings")

    method_definition_hash = canonical_json_file_hash(method_path)

    refs = resolve_refs()
    before_ref = refs["before"]
    after_ref = refs["after"]

    before_state_hash, before_state_error = git_tree_state_hash(before_ref)
    after_state_hash, after_state_error = git_tree_state_hash(after_ref)

    stdout_path = out_dir / "delta-sensor-output.log"
    stderr_path = out_dir / "delta-sensor-error.log"
    replay_path = out_dir / "delta-replay.sh"
    record_path = out_dir / "delta-record.json"
    summary_path = out_dir / "delta-sensor-summary.md"

    measurement_started_at = now_utc()
    measurement = run_command(command)
    measurement_finished_at = now_utc()

    stdout_bytes = measurement.stdout
    stderr_bytes = measurement.stderr

    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(stderr_bytes)

    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")

    success_condition = method_definition.get("success_condition") or {}
    expected_return_code = success_condition.get("return_code", 0)
    stdout_contains = success_condition.get("stdout_contains")

    measurement_ok = measurement.returncode == expected_return_code

    if isinstance(stdout_contains, str) and stdout_contains:
        measurement_ok = measurement_ok and (stdout_contains in stdout_text)

    replay_script = build_replay_script(before_ref=before_ref, after_ref=after_ref, command=command)
    write_text(replay_path, replay_script)

    source = {
        "provider": "github_actions",
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "job": os.environ.get("GITHUB_JOB"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "actor": os.environ.get("GITHUB_ACTOR"),
        "event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "ref": os.environ.get("GITHUB_REF"),
        "sha": os.environ.get("GITHUB_SHA"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }

    record_body = {
        "type": RECORD_TYPE,
        "protocol_version": "DELTA-0",
        "sensor_name": "github_actions_dirty_sensor",
        "sensor_version": SENSOR_VERSION,
        "created_at": now_utc(),
        "source": source,
        "change": {
            "before_ref": before_ref,
            "after_ref": after_ref,
            "current_head": refs["current_head"],
            "before_state_hash": before_state_hash,
            "after_state_hash": after_state_hash,
            "state_hash_method": "sha256(git ls-tree -r -z --full-tree <ref>)",
            "before_state_error": before_state_error,
            "after_state_error": after_state_error,
        },
        "measurement_method": {
            "method_id": method_definition.get("method_id"),
            "method_version": method_definition.get("method_version"),
            "method_definition_path": method_path.as_posix(),
            "method_definition_hash": method_definition_hash,
            "executor": method_definition.get("executor"),
            "command": command,
            "success_condition": success_condition,
        },
        "measurement_result": {
            "ok": measurement_ok,
            "return_code": measurement.returncode,
            "started_at": measurement_started_at,
            "finished_at": measurement_finished_at,
            "stdout_contains_required": stdout_contains,
        },
        "private_evidence_commitments": [
            {
                "type": "stdout_log",
                "path": stdout_path.as_posix(),
                "hash": hash_file(stdout_path),
                "disclosure": "artifact_only",
            },
            {
                "type": "stderr_log",
                "path": stderr_path.as_posix(),
                "hash": hash_file(stderr_path),
                "disclosure": "artifact_only",
            },
            {
                "type": "replay_script",
                "path": replay_path.as_posix(),
                "hash": hash_file(replay_path),
                "disclosure": "artifact_only",
            },
        ],
        "replay_instructions": {
            "executor": "bash",
            "path": replay_path.as_posix(),
            "hash": hash_file(replay_path),
            "code": replay_script,
        },
        "verification_policy": {
            "type": "all",
            "requires": [
                "ci_verified",
                "measurement_method_hash_present",
                "evidence_hashes_present",
                "record_body_hash_self_check",
            ],
        },
        "security_boundary": {
            "signed_delta0_bundle": False,
            "uses_private_key": False,
            "anchored": False,
            "registry_checked": False,
            "note": "Dirty sensor prototype. It creates a hash-committed sensor record, not a final DELTA-0 Claim/Attestation/Ledger/Checkpoint bundle.",
        },
    }

    record_body_hash = sha256_prefixed(canonical_json_bytes(record_body))

    envelope = {
        "type": ENVELOPE_TYPE,
        "protocol_version": "DELTA-0",
        "record_body_hash": record_body_hash,
        "record_body": record_body,
    }

    write_json(record_path, envelope)

    loaded_record = load_json_file(record_path)
    self_check_hash = sha256_prefixed(canonical_json_bytes(loaded_record["record_body"]))
    self_check_ok = self_check_hash == loaded_record["record_body_hash"]

    summary = [
        "# DELTA Sensor",
        "",
        f"- sensor_version: `{SENSOR_VERSION}`",
        f"- measurement_ok: `{measurement_ok}`",
        f"- record_body_hash: `{record_body_hash}`",
        f"- self_check_ok: `{self_check_ok}`",
        f"- before_ref: `{before_ref}`",
        f"- after_ref: `{after_ref}`",
        f"- before_state_hash: `{before_state_hash}`",
        f"- after_state_hash: `{after_state_hash}`",
        f"- method_definition_hash: `{method_definition_hash}`",
        f"- stdout_hash: `{hash_file(stdout_path)}`",
        f"- stderr_hash: `{hash_file(stderr_path)}`",
        "",
        "## Command",
        "",
        "```text",
        " ".join(command),
        "```",
        "",
        "## Security boundary",
        "",
        "This is a dirty sensor prototype. It does not yet create a signed DELTA-0 bundle.",
        "",
    ]

    write_text(summary_path, "\n".join(summary))

    print(f"DELTA_SENSOR_RECORD={record_path.as_posix()}")
    print(f"DELTA_SENSOR_RECORD_BODY_HASH={record_body_hash}")
    print(f"DELTA_SENSOR_MEASUREMENT_OK={measurement_ok}")
    print(f"DELTA_SENSOR_SELF_CHECK_OK={self_check_ok}")

    if not self_check_ok:
        return 2

    return 0 if measurement_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
