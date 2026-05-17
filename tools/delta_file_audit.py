#!/usr/bin/env python3
"""DELTA local file audit tool.

This tool creates a deterministic, content-only hash manifest for a single file
or a directory tree.

Security boundary:
- hashes prove observed bytes, not legal truth or external state truth
- timestamps and filesystem metadata are intentionally excluded
- symlinks are not followed by default
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
from typing import Any


METHOD_ID = "local-file-audit-v1"
METHOD_VERSION = "1.0.0"

DEFAULT_IGNORE_PATTERNS = [
    ".git",
    ".git/**",
    "__pycache__",
    "__pycache__/**",
    ".pytest_cache",
    ".pytest_cache/**",
    ".mypy_cache",
    ".mypy_cache/**",
    ".delta/artifacts",
    ".delta/artifacts/**",
    ".delta/artifacts-*",
    ".delta/artifacts-*/**",
]


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


def safe_is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def posix_rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def should_ignore(rel_posix: str, patterns: list[str]) -> bool:
    rel_posix = rel_posix.strip("/")
    for pattern in patterns:
        pattern = pattern.strip("/")
        if fnmatch.fnmatch(rel_posix, pattern):
            return True
    return False


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def build_manifest(target: Path, ignore_patterns: list[str], follow_symlinks: bool) -> dict[str, Any]:
    cwd = Path.cwd().resolve()
    target = target.resolve()

    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    if target.is_file():
        rel = target.relative_to(cwd).as_posix() if safe_is_relative_to(target, cwd) else target.as_posix()
        entries.append({
            "path": rel,
            "type": "file",
            "size_bytes": target.stat().st_size,
            "sha256": hash_file(target),
        })
    elif target.is_dir():
        for root, dirnames, filenames in os.walk(target, followlinks=follow_symlinks):
            root_path = Path(root)

            kept_dirnames = []
            for dirname in sorted(dirnames):
                dir_path = root_path / dirname
                resolved_dir_path = dir_path.resolve()
                rel_to_target = posix_rel(resolved_dir_path, target)
                rel_to_cwd = resolved_dir_path.relative_to(cwd).as_posix() if safe_is_relative_to(resolved_dir_path, cwd) else resolved_dir_path.as_posix()

                if should_ignore(rel_to_target, ignore_patterns) or should_ignore(rel_to_cwd, ignore_patterns):
                    skipped.append({"path": rel_to_cwd, "reason": "ignore_pattern"})
                    continue

                if dir_path.is_symlink() and not follow_symlinks:
                    skipped.append({"path": rel_to_cwd, "reason": "symlink_dir_not_followed"})
                    continue

                kept_dirnames.append(dirname)

            dirnames[:] = kept_dirnames

            for filename in sorted(filenames):
                file_path = root_path / filename
                resolved_file_path = file_path.resolve()
                rel_to_target = posix_rel(resolved_file_path, target)
                rel_to_cwd = resolved_file_path.relative_to(cwd).as_posix() if safe_is_relative_to(resolved_file_path, cwd) else resolved_file_path.as_posix()

                if should_ignore(rel_to_target, ignore_patterns) or should_ignore(rel_to_cwd, ignore_patterns):
                    skipped.append({"path": rel_to_cwd, "reason": "ignore_pattern"})
                    continue

                if file_path.is_symlink() and not follow_symlinks:
                    skipped.append({"path": rel_to_cwd, "reason": "symlink_file_not_followed"})
                    continue

                if not file_path.is_file():
                    skipped.append({"path": rel_to_cwd, "reason": "not_regular_file"})
                    continue

                entries.append({
                    "path": rel_to_cwd,
                    "type": "file",
                    "size_bytes": file_path.stat().st_size,
                    "sha256": hash_file(file_path),
                })
    else:
        raise ValueError(f"Target is neither file nor directory: {target}")

    entries.sort(key=lambda item: item["path"])
    skipped.sort(key=lambda item: item["path"])

    target_label = target.relative_to(cwd).as_posix() if safe_is_relative_to(target, cwd) else target.as_posix()

    manifest_body = {
        "type": "delta_file_audit_manifest",
        "method_id": METHOD_ID,
        "method_version": METHOD_VERSION,
        "target": target_label,
        "target_kind": "directory" if target.is_dir() else "file",
        "hash_algorithm": "sha256",
        "metadata_policy": "content_hash_only_no_atime_ctime_mtime",
        "follow_symlinks": follow_symlinks,
        "ignore_patterns": ignore_patterns,
        "entries": entries,
        "skipped": skipped,
    }

    manifest_hash = sha256_prefixed(canonical_json_bytes(manifest_body))

    return {
        "manifest_hash": manifest_hash,
        "manifest_body": manifest_body,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a deterministic DELTA file audit manifest.")
    parser.add_argument("--target", required=True, help="File or directory to audit.")
    parser.add_argument("--manifest-out", default="", help="Optional path to write manifest JSON.")
    parser.add_argument("--ignore", action="append", default=[], help="Additional ignore glob pattern. Can be repeated.")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks. Default is false.")
    args = parser.parse_args()

    ignore_patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_patterns.extend(args.ignore or [])

    try:
        result = build_manifest(Path(args.target), ignore_patterns, args.follow_symlinks)
    except Exception as exc:
        print("DELTA_FILE_AUDIT_RESULT: FAIL")
        print(f"DELTA_FILE_AUDIT_REASON={exc}")
        return 1

    manifest_hash = result["manifest_hash"]
    manifest_body = result["manifest_body"]

    if args.manifest_out:
        out_path = Path(args.manifest_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    print("DELTA_FILE_AUDIT_RESULT: OK")
    print(f"DELTA_FILE_AUDIT_METHOD_ID={METHOD_ID}")
    print(f"DELTA_FILE_AUDIT_METHOD_VERSION={METHOD_VERSION}")
    print(f"DELTA_FILE_AUDIT_TARGET={manifest_body['target']}")
    print(f"DELTA_FILE_AUDIT_TARGET_KIND={manifest_body['target_kind']}")
    print(f"DELTA_FILE_AUDIT_ENTRY_COUNT={len(manifest_body['entries'])}")
    print(f"DELTA_FILE_AUDIT_SKIPPED_COUNT={len(manifest_body['skipped'])}")
    print(f"DELTA_FILE_AUDIT_MANIFEST_HASH={manifest_hash}")
    if args.manifest_out:
        print(f"DELTA_FILE_AUDIT_MANIFEST_PATH={args.manifest_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
