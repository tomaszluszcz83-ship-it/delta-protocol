#!/usr/bin/env python3
"""DELTA GitHub Actions dirty sensor prototype with Ed25519 record signing.

This sensor creates a machine-generated DELTA sensor record.

It intentionally does NOT change the DELTA-0 core model. It produces a
sensor-layer envelope artifact that can later inform the Delta Record RFC.

Security boundary:
- this is not yet a full signed DELTA-0 Claim/Attestation/Ledger/Checkpoint bundle
- this is not a registry, anchoring, or trust graph implementation
- this is a dirty prototype for learning real sensor requirements
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from delta_protocol import canonical_json_bytes, load_json_file, sha256_prefixed


SENSOR_VERSION = "v1.3.1-dirty"
RECORD_TYPE = "delta_sensor_record"
ENVELOPE_TYPE = "delta_sensor_record_envelope"
SIGNATURE_TYPE = "delta_sensor_record_signature"
DEFAULT_SCHEMA_PATH = ".delta/schemas/delta-sensor-record-v1.3.0-dirty.schema.json"

PUBLIC_KEY_PREFIX = "ed25519:"
PRIVATE_SEED_PREFIX = "ed25519seed:"
SIGNATURE_PREFIX = "ed25519sig:"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def run_command(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


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

    commit_before = None
    commit_after = None

    if "pull_request" in event:
        pull_request = event.get("pull_request") or {}
        base = pull_request.get("base") or {}
        head = pull_request.get("head") or {}
        commit_before = base.get("sha")
        commit_after = head.get("sha")

    if not commit_before:
        commit_before = event.get("before")

    if not commit_after:
        commit_after = event.get("after") or os.environ.get("GITHUB_SHA")

    if commit_before in ("", "0000000000000000000000000000000000000000"):
        commit_before = None

    if not commit_after:
        commit_after = git_text(["rev-parse", "HEAD"])

    if not commit_before:
        commit_before = git_text(["rev-parse", "HEAD^"])

    return {
        "commit_before": commit_before,
        "commit_after": commit_after,
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


def hash_text(text: str) -> str:
    return sha256_prefixed(text.encode("utf-8"))


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


def resolve_repo_url() -> str:
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    github_server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")

    if github_repository:
        return f"{github_server_url}/{github_repository}.git"

    origin = git_text(["remote", "get-url", "origin"])
    return origin or "<REPOSITORY_URL>"


def build_replay_script(
    *,
    repository_url: str,
    commit_before: Optional[str],
    commit_after: Optional[str],
    command: list[str],
) -> str:
    command_text = " ".join(command)

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# DELTA dirty sensor replay script.",
        "# IMPORTANT: replay is designed for an isolated fresh clone, not the verifier's active worktree.",
        "",
        f'REPO_URL="${{DELTA_REPLAY_REPO_URL:-{repository_url}}}"',
        'WORKDIR="$(mktemp -d)"',
        'trap \'rm -rf "$WORKDIR"\' EXIT',
        "",
        'git clone "$REPO_URL" "$WORKDIR/repo"',
        'cd "$WORKDIR/repo"',
        "python -m pip install -e ./packages/python/delta_protocol",
        "",
    ]

    if commit_before:
        lines.extend(
            [
                f"git checkout {commit_before}",
                f"{command_text} | tee delta-replay-before.log || true",
                "",
            ]
        )

    if commit_after:
        lines.extend(
            [
                f"git checkout {commit_after}",
                f"{command_text} | tee delta-replay-after.log",
                "",
            ]
        )

    return "\n".join(lines) + "\n"


def load_sensor_private_key() -> Ed25519PrivateKey:
    private_text = os.environ.get("DELTA_SENSOR_PRIVATE_KEY", "").strip()

    if not private_text:
        raise SystemExit(
            "DELTA_SENSOR_PRIVATE_KEY is required. "
            "Generate it with: python tools/delta_sensor_keygen.py"
        )

    if not private_text.startswith(PRIVATE_SEED_PREFIX):
        raise SystemExit("DELTA_SENSOR_PRIVATE_KEY must start with ed25519seed:")

    seed = b64url_decode_unpadded(private_text[len(PRIVATE_SEED_PREFIX):], "DELTA_SENSOR_PRIVATE_KEY")

    if len(seed) != 32:
        raise SystemExit("DELTA_SENSOR_PRIVATE_KEY seed must decode to 32 bytes")

    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_record_body(record_body: dict[str, Any]) -> dict[str, Any]:
    private_key = load_sensor_private_key()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    derived_public_key = PUBLIC_KEY_PREFIX + b64url_no_padding(public_key_bytes)
    derived_public_key_hash = hash_text(derived_public_key)

    expected_public_key = (
        os.environ.get("DELTA_EXECUTOR_PUBLIC_KEY")
        or os.environ.get("DELTA_SENSOR_PUBLIC_KEY")
        or ""
    ).strip()

    if expected_public_key and expected_public_key != derived_public_key:
        raise SystemExit(
            "DELTA_EXECUTOR_PUBLIC_KEY does not match the public key derived from DELTA_SENSOR_PRIVATE_KEY"
        )

    payload_bytes = canonical_json_bytes(record_body)
    record_body_hash = sha256_prefixed(payload_bytes)
    signature_bytes = private_key.sign(payload_bytes)

    signature = {
        "type": SIGNATURE_TYPE,
        "alg": "Ed25519",
        "role": "sensor_executor",
        "signed_payload": "record_body",
        "signed_hash": record_body_hash,
        "public_key": derived_public_key,
        "public_key_hash": derived_public_key_hash,
        "executor_public_key": derived_public_key,
        "executor_public_key_hash": derived_public_key_hash,
        "signature": SIGNATURE_PREFIX + b64url_no_padding(signature_bytes),
    }

    return signature


def verify_record_signature(record_body: dict[str, Any], signature: dict[str, Any]) -> tuple[bool, str]:
    try:
        if signature.get("type") != SIGNATURE_TYPE:
            return False, "signature.type mismatch"
        if signature.get("alg") != "Ed25519":
            return False, "signature.alg mismatch"
        if signature.get("role") != "sensor_executor":
            return False, "signature.role mismatch"

        public_key_text = signature.get("public_key")
        public_key_hash = signature.get("public_key_hash")
        executor_public_key = signature.get("executor_public_key")
        executor_public_key_hash = signature.get("executor_public_key_hash")
        signature_text = signature.get("signature")
        signed_hash = signature.get("signed_hash")

        if executor_public_key != public_key_text:
            return False, "executor_public_key must equal public_key"
        if executor_public_key_hash != public_key_hash:
            return False, "executor_public_key_hash must equal public_key_hash"

        if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
            return False, "signature.public_key invalid"
        if public_key_hash != hash_text(public_key_text):
            return False, "signature.public_key_hash mismatch"
        if not isinstance(signature_text, str) or not signature_text.startswith(SIGNATURE_PREFIX):
            return False, "signature.signature invalid"

        payload_bytes = canonical_json_bytes(record_body)
        payload_hash = sha256_prefixed(payload_bytes)

        if signed_hash != payload_hash:
            return False, "signature.signed_hash mismatch"

        public_key_bytes = b64url_decode_unpadded(public_key_text[len(PUBLIC_KEY_PREFIX):], "public_key")
        signature_bytes = b64url_decode_unpadded(signature_text[len(SIGNATURE_PREFIX):], "signature")

        if len(public_key_bytes) != 32:
            return False, "public key must be 32 bytes"
        if len(signature_bytes) != 64:
            return False, "signature must be 64 bytes"

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, payload_bytes)

        return True, "OK"

    except InvalidSignature:
        return False, "Ed25519 signature verification failed"
    except Exception as exc:
        return False, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a signed dirty DELTA GitHub Actions sensor record.")
    parser.add_argument(
        "--method",
        default=".delta/methods/delta-cli-verify-all-v1.json",
        help="Path to measurement method definition JSON.",
    )
    parser.add_argument(
        "--schema",
        default=DEFAULT_SCHEMA_PATH,
        help="Path to sensor record JSON Schema.",
    )
    parser.add_argument(
        "--out-dir",
        default=".delta/artifacts",
        help="Directory where sensor artifacts will be written.",
    )
    args = parser.parse_args()

    method_path = Path(args.method)
    schema_path = Path(args.schema)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    method_definition = load_json_file(method_path)
    command = method_definition.get("command")

    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise SystemExit("measurement method command must be a list of strings")

    method_definition_hash = canonical_json_file_hash(method_path)
    schema_hash = canonical_json_file_hash(schema_path)

    refs = resolve_refs()
    commit_before = refs["commit_before"]
    commit_after = refs["commit_after"]

    before_state_hash, before_state_error = git_tree_state_hash(commit_before)
    after_state_hash, after_state_error = git_tree_state_hash(commit_after)

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

    success_condition = method_definition.get("success_condition") or {}
    expected_return_code = success_condition.get("return_code", 0)
    stdout_contains = success_condition.get("stdout_contains")

    measurement_ok = measurement.returncode == expected_return_code

    if isinstance(stdout_contains, str) and stdout_contains:
        measurement_ok = measurement_ok and (stdout_contains in stdout_text)

    repository_url = resolve_repo_url()
    replay_script = build_replay_script(
        repository_url=repository_url,
        commit_before=commit_before,
        commit_after=commit_after,
        command=command,
    )
    write_text(replay_path, replay_script)

    source = {
        "provider": "github_actions",
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "repository_url": repository_url,
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
        "schema": {
            "schema_id": "delta-sensor-record-v1.3.0-dirty",
            "schema_path": schema_path.as_posix(),
            "schema_hash": schema_hash,
            "namespace": "sensor_layer",
            "note": "This schema is separate from DELTA-0 Claim, Attestation, Ledger Entry, and Signed Checkpoint types.",
        },
        "sensor_name": "github_actions_dirty_sensor",
        "sensor_version": SENSOR_VERSION,
        "created_at": now_utc(),
        "source": source,
        "change": {
            "commit_before": commit_before,
            "commit_after": commit_after,
            "current_head": refs["current_head"],
            "before_state_hash": before_state_hash,
            "after_state_hash": after_state_hash,
            "state_hash_method": "sha256(git ls-tree -r -z --full-tree <commit>)",
            "before_state_error": before_state_error,
            "after_state_error": after_state_error,
        },
        "measurement_method": {
            "method_id": method_definition.get("method_id"),
            "method_version": method_definition.get("method_version"),
            "description": method_definition.get("description"),
            "method_definition_path": method_path.as_posix(),
            "method_definition_hash": method_definition_hash,
            "executor": method_definition.get("executor"),
            "command": command,
            "success_condition": success_condition,
            "replay_notes": method_definition.get("replay_notes"),
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
            "isolation": "fresh_clone_temp_dir",
            "repository_url": repository_url,
            "path": replay_path.as_posix(),
            "hash": hash_file(replay_path),
            "code": replay_script,
        },
        "verification_policy": {
            "type": "all",
            "requires": [
                "ci_verified",
                "measurement_method_hash_present",
                "schema_hash_present",
                "evidence_hashes_present",
                "record_body_hash_self_check",
                "record_signature_present",
                "record_signature_verification_ok",
                "executor_public_key_present",
            ],
        },
        "security_boundary": {
            "signed_delta0_bundle": False,
            "signed_sensor_record": True,
            "uses_private_key": True,
            "anchored": False,
            "registry_checked": False,
            "sensor_schema_separate_from_delta0": True,
            "note": "Dirty sensor prototype. It creates a signed, hash-committed sensor record, not a final DELTA-0 Claim/Attestation/Ledger/Checkpoint bundle.",
        },
    }

    record_body_hash = sha256_prefixed(canonical_json_bytes(record_body))
    record_signature = sign_record_body(record_body)
    signature_verification_ok, signature_verification_reason = verify_record_signature(
        record_body,
        record_signature,
    )

    envelope = {
        "type": ENVELOPE_TYPE,
        "protocol_version": "DELTA-0",
        "record_body_hash": record_body_hash,
        "record_body": record_body,
        "record_signature": record_signature,
        "record_signature_verification": {
            "ok": signature_verification_ok,
            "reason": signature_verification_reason,
        },
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
        f"- signature_present: `{record_signature is not None}`",
        f"- signature_verification_ok: `{signature_verification_ok}`",
        f"- signature_verification_reason: `{signature_verification_reason}`",
        f"- commit_before: `{commit_before}`",
        f"- commit_after: `{commit_after}`",
        f"- before_state_hash: `{before_state_hash}`",
        f"- after_state_hash: `{after_state_hash}`",
        f"- method_id: `{method_definition.get('method_id')}`",
        f"- method_version: `{method_definition.get('method_version')}`",
        f"- method_definition_hash: `{method_definition_hash}`",
        f"- schema_hash: `{schema_hash}`",
        f"- public_key: `{record_signature.get('public_key')}`",
        f"- public_key_hash: `{record_signature.get('public_key_hash')}`",
        f"- executor_public_key: `{record_signature.get('executor_public_key')}`",
        f"- executor_public_key_hash: `{record_signature.get('executor_public_key_hash')}`",
        f"- stdout_hash: `{hash_file(stdout_path)}`",
        f"- stderr_hash: `{hash_file(stderr_path)}`",
        "",
        "## Command",
        "",
        "```text",
        " ".join(command),
        "```",
        "",
        "## Replay isolation",
        "",
        "Replay instructions are designed for a fresh clone in a temporary directory.",
        "",
        "## Security boundary",
        "",
        "This is a signed dirty sensor prototype. It does not yet create a full signed DELTA-0 bundle.",
        "",
    ]

    write_text(summary_path, "\n".join(summary))

    print(f"DELTA_SENSOR_RECORD={record_path.as_posix()}")
    print(f"DELTA_SENSOR_RECORD_BODY_HASH={record_body_hash}")
    print(f"DELTA_SENSOR_MEASUREMENT_OK={measurement_ok}")
    print(f"DELTA_SENSOR_SELF_CHECK_OK={self_check_ok}")
    print("DELTA_SENSOR_SIGNATURE_PRESENT=True")
    print(f"DELTA_SENSOR_SIGNATURE_VERIFICATION_OK={signature_verification_ok}")
    print("DELTA_SENSOR_EXECUTOR_PUBLIC_KEY_PRESENT=True")

    if not self_check_ok:
        return 2

    if not signature_verification_ok:
        return 3

    return 0 if measurement_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
