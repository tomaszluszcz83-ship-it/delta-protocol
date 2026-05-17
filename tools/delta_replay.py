#!/usr/bin/env python3
"""DELTA replay verifier MVP.

v1.7.0 goal:
- replay an existing signed DELTA Sensor Record from a fresh clone
- re-run the declared measurement method
- compare replay result against the signed record

Security boundary:
- this verifies replay consistency for a signed sensor record
- it does not create a new signed replay proof yet
- it does not prove legal trust, registry trust, anchoring, or external-world truth
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence


SIGNATURE_PREFIX = "ed25519sig:"
PUBLIC_KEY_PREFIX = "ed25519:"


def b64url_decode_unpadded(value: str, field: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"invalid base64url in {field}") from exc


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def run_text(cmd: Sequence[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + result.stdout
            + "\n\nSTDERR:\n"
            + result.stderr
        )
    return result


def run_bytes(cmd: Sequence[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + result.stdout.decode("utf-8", errors="replace")
            + "\n\nSTDERR:\n"
            + result.stderr.decode("utf-8", errors="replace")
        )
    return result


def verify_record_signature(record: dict[str, Any]) -> tuple[bool, str]:
    body = record.get("record_body")
    sig = record.get("record_signature") or {}

    if body is None:
        return False, "missing record_body"

    expected_hash = record.get("record_body_hash")
    actual_hash = sha256_prefixed(canonical_json_bytes(body))
    if expected_hash != actual_hash:
        return False, f"record_body_hash mismatch: expected {expected_hash}, got {actual_hash}"

    signed_hash = sig.get("signed_hash")
    if signed_hash != expected_hash:
        return False, f"signed_hash mismatch: expected {expected_hash}, got {signed_hash}"

    public_key_text = sig.get("executor_public_key") or sig.get("public_key")
    signature_text = sig.get("signature")

    if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
        return False, "missing or invalid executor/public key prefix"

    if not isinstance(signature_text, str) or not signature_text.startswith(SIGNATURE_PREFIX):
        return False, "missing or invalid signature prefix"

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = b64url_decode_unpadded(public_key_text[len(PUBLIC_KEY_PREFIX):], "public_key")
        signature_bytes = b64url_decode_unpadded(signature_text[len(SIGNATURE_PREFIX):], "signature")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, canonical_json_bytes(body))
    except Exception as exc:
        return False, f"signature verification failed: {exc}"

    return True, "ok"


def infer_method_path(method: dict[str, Any], clone_dir: Path) -> Path:
    explicit = method.get("method_definition_path")
    if explicit:
        return clone_dir / explicit

    method_id = method.get("method_id")
    candidates = [
        clone_dir / ".delta" / "methods" / f"{method_id}.json",
        clone_dir / ".delta" / "methods" / "delta-cli-verify-all-v1.json",
        clone_dir / ".delta" / "methods" / "python-unittest-v1.json",
        clone_dir / ".delta" / "methods" / "local-file-audit-v1.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            try:
                data = json.load(open(candidate, encoding="utf-8"))
                if data.get("method_id") == method_id:
                    return candidate
            except Exception:
                pass

    raise FileNotFoundError(f"cannot infer method definition path for method_id={method_id}")


def extract_file_audit_manifest_hash(stdout_text: str) -> str | None:
    match = re.search(r"DELTA_FILE_AUDIT_MANIFEST_HASH=(sha256:[0-9a-fA-F]+)", stdout_text)
    return match.group(1) if match else None


def find_original_file_audit_manifest_hash(record_path: Path, record: dict[str, Any]) -> str | None:
    evidence_root = record_path.parent

    for manifest_path in evidence_root.rglob("file-audit-manifest.json"):
        try:
            manifest = json.load(open(manifest_path, encoding="utf-8"))
            if isinstance(manifest.get("manifest_hash"), str):
                return manifest["manifest_hash"]
        except Exception:
            pass

    body = record.get("record_body") or {}
    for section_name in ("private_evidence_commitments", "evidence_commitments"):
        commitments = body.get(section_name) or []
        if not isinstance(commitments, list):
            continue
        for item in commitments:
            if not isinstance(item, dict):
                continue
            label = " ".join(str(item.get(k, "")) for k in ("name", "path", "type"))
            if "file-audit-manifest" in label or "file_audit_manifest" in label:
                value = item.get("hash") or item.get("sha256")
                if isinstance(value, str) and value.startswith("sha256:"):
                    return value

    return None


def collect_output_commitments(record: dict[str, Any]) -> dict[str, str]:
    body = record.get("record_body") or {}
    out: dict[str, str] = {}

    for section_name in ("private_evidence_commitments", "evidence_commitments"):
        commitments = body.get(section_name) or []
        if not isinstance(commitments, list):
            continue
        for item in commitments:
            if not isinstance(item, dict):
                continue
            label = " ".join(str(item.get(k, "")) for k in ("name", "path", "type")).lower()
            value = item.get("hash") or item.get("sha256")
            if not isinstance(value, str) or not value.startswith("sha256:"):
                continue
            if "stdout" in label or "output" in label:
                out.setdefault("stdout", value)
            if "stderr" in label or "error" in label:
                out.setdefault("stderr", value)

    return out


def write_report(path: Path, result: dict[str, Any]) -> None:
    lines: list[str] = []
    lines.append("# DELTA Replay Verification Report")
    lines.append("")
    lines.append(f"Status: {'PASS' if result['ok'] else 'FAIL'}")
    lines.append("")
    lines.append("## Record")
    lines.append("")
    lines.append(f"- Record path: `{result['record_path']}`")
    lines.append(f"- Method id: `{result['method_id']}`")
    lines.append(f"- Commit after: `{result['commit_after']}`")
    lines.append(f"- Fresh clone: `{result['clone_dir']}`")
    lines.append("")
    lines.append("## Checks")
    lines.append("")
    lines.append("| Check | Result | Detail |")
    lines.append("| --- | --- | --- |")
    for check in result["checks"]:
        lines.append(f"| {check['name']} | `{check['ok']}` | `{check['detail']}` |")
    lines.append("")
    lines.append("## Command")
    lines.append("")
    lines.append("```text")
    lines.append(" ".join(result["command"]))
    lines.append("```")
    lines.append("")
    lines.append("## Measurement output")
    lines.append("")
    lines.append("### Return code")
    lines.append("")
    lines.append("```text")
    lines.append(str(result["return_code"]))
    lines.append("```")
    lines.append("")
    lines.append("### STDOUT tail")
    lines.append("")
    lines.append("```text")
    lines.append(result["stdout_tail"])
    lines.append("```")
    lines.append("")
    lines.append("### STDERR tail")
    lines.append("")
    lines.append("```text")
    lines.append(result["stderr_tail"])
    lines.append("```")
    lines.append("")
    lines.append("## Security boundary")
    lines.append("")
    lines.append("This replay verification does not create a new signed replay proof.")
    lines.append("")
    lines.append("It checks whether the signed sensor record can be replayed from a fresh clone and whether the declared measurement result matches.")
    lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a signed DELTA Sensor Record from a fresh clone.")
    parser.add_argument("--record", required=True, help="Path to delta-record.json")
    parser.add_argument("--work-dir", default="", help="Optional directory for replay work. Default: temp dir.")
    parser.add_argument("--keep-workdir", action="store_true", help="Do not delete temporary replay directory.")
    parser.add_argument("--skip-install", action="store_true", help="Skip installing local Python SDK package.")
    parser.add_argument("--strict-output-hashes", action="store_true", help="Fail on stdout/stderr hash mismatch when commitments exist.")
    parser.add_argument("--report-out", default="", help="Optional markdown report output path.")
    parser.add_argument("--json-out", default="", help="Optional JSON report output path.")
    args = parser.parse_args()

    record_path = Path(args.record).resolve()
    record = json.load(open(record_path, encoding="utf-8"))

    body = record["record_body"]
    change = body["change"]
    method = body["measurement_method"]

    method_id = method.get("method_id")
    command = method.get("command")
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise SystemExit("record measurement_method.command must be an array of strings")

    signature_ok, signature_detail = verify_record_signature(record)

    repo_url = (
        (body.get("replay_instructions") or {}).get("repository_url")
        or (body.get("source") or {}).get("repository_url")
    )

    if not repo_url or repo_url == "<REPOSITORY_URL>":
        repo_url = run_text(["git", "remote", "get-url", "origin"], check=True).stdout.strip()

    commit_after = change["commit_after"]
    expected_after_state_hash = change.get("after_state_hash")
    expected_measurement_ok = bool(body["measurement_result"].get("ok"))
    expected_method_hash = method.get("method_definition_hash")

    replay_root = Path(args.work_dir).resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix="delta-replay-"))
    clone_dir = replay_root / "repo"

    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add_check("record_signature", signature_ok, signature_detail)

    try:
        if clone_dir.exists():
            shutil.rmtree(clone_dir)

        run_text(["git", "clone", repo_url, str(clone_dir)], check=True)
        run_text(["git", "checkout", commit_after], cwd=clone_dir, check=True)

        if not args.skip_install and (clone_dir / "packages" / "python" / "delta_protocol").exists():
            run_text(["python", "-m", "pip", "install", "-e", "./packages/python/delta_protocol"], cwd=clone_dir, check=True)

        tree = run_bytes(["git", "ls-tree", "-r", "-z", "--full-tree", commit_after], cwd=clone_dir, check=True)
        actual_after_state_hash = sha256_prefixed(tree.stdout)
        add_check(
            "after_state_hash",
            actual_after_state_hash == expected_after_state_hash,
            f"expected={expected_after_state_hash} actual={actual_after_state_hash}",
        )

        method_path = infer_method_path(method, clone_dir)
        method_json = json.load(open(method_path, encoding="utf-8"))
        actual_method_hash = sha256_prefixed(canonical_json_bytes(method_json))
        add_check(
            "method_definition_hash",
            actual_method_hash == expected_method_hash,
            f"expected={expected_method_hash} actual={actual_method_hash}",
        )

        measurement = run_text(command, cwd=clone_dir, check=False)
        success_condition = method.get("success_condition") or {}
        expected_return_code = success_condition.get("return_code", 0)
        stdout_contains = success_condition.get("stdout_contains")

        actual_measurement_ok = measurement.returncode == expected_return_code
        if isinstance(stdout_contains, str) and stdout_contains:
            actual_measurement_ok = actual_measurement_ok and stdout_contains in measurement.stdout

        add_check(
            "measurement_result_ok",
            actual_measurement_ok == expected_measurement_ok,
            f"expected={expected_measurement_ok} actual={actual_measurement_ok}",
        )

        if method_id == "local-file-audit-v1":
            original_manifest_hash = find_original_file_audit_manifest_hash(record_path, record)
            replay_manifest_hash = extract_file_audit_manifest_hash(measurement.stdout)
            add_check(
                "file_audit_manifest_hash",
                bool(original_manifest_hash and replay_manifest_hash and original_manifest_hash == replay_manifest_hash),
                f"expected={original_manifest_hash} actual={replay_manifest_hash}",
            )

        output_commitments = collect_output_commitments(record)
        stdout_hash = sha256_prefixed(measurement.stdout.encode("utf-8"))
        stderr_hash = sha256_prefixed(measurement.stderr.encode("utf-8"))

        if "stdout" in output_commitments:
            ok = stdout_hash == output_commitments["stdout"]
            add_check("stdout_hash", ok or not args.strict_output_hashes, f"expected={output_commitments['stdout']} actual={stdout_hash} strict={args.strict_output_hashes}")

        if "stderr" in output_commitments:
            ok = stderr_hash == output_commitments["stderr"]
            add_check("stderr_hash", ok or not args.strict_output_hashes, f"expected={output_commitments['stderr']} actual={stderr_hash} strict={args.strict_output_hashes}")

        hard_checks = [c for c in checks if c["name"] not in ("stdout_hash", "stderr_hash")]
        ok = all(c["ok"] for c in hard_checks) and all(c["ok"] for c in checks if args.strict_output_hashes)

        result = {
            "ok": ok,
            "record_path": str(record_path),
            "method_id": method_id,
            "commit_after": commit_after,
            "clone_dir": str(clone_dir),
            "command": command,
            "return_code": measurement.returncode,
            "checks": checks,
            "stdout_tail": measurement.stdout[-4000:],
            "stderr_tail": measurement.stderr[-4000:],
        }

        if args.report_out:
            write_report(Path(args.report_out), result)

        if args.json_out:
            out_path = Path(args.json_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        print("DELTA_REPLAY_RESULT:", "OK" if ok else "FAILED")
        print(f"DELTA_REPLAY_METHOD_ID={method_id}")
        print(f"DELTA_REPLAY_COMMIT_AFTER={commit_after}")
        for check in checks:
            print(f"DELTA_REPLAY_CHECK_{check['name'].upper()}={check['ok']}")

        return 0 if ok else 1

    finally:
        if not args.keep_workdir and not args.work_dir:
            shutil.rmtree(replay_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
