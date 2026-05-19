#!/usr/bin/env python3
"""
DELTA Export Report helper (v2.7.0).

Purpose:
- read an existing DELTA record;
- compute its canonical record hash using the DELTA Canonical JSON Profile when available;
- generate a self-contained Markdown or HTML technical report for reviewers/auditors.

Security boundary:
- this tool does not create new proof functionality;
- this tool does not sign, verify signatures, replay records, decrypt evidence, or validate legal truth;
- it summarizes an existing record and emits a report with explicit boundaries.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import html
import json
import sys
from pathlib import Path
from typing import Any

PROFILE_ID = "delta_jcs_json_v1"
MAX_SAFE_INTEGER = 9007199254740991
MIN_SAFE_INTEGER = -9007199254740991


class DeltaExportError(ValueError):
    """Raised for export/report input errors."""


def _reject_float(value: str) -> None:
    raise DeltaExportError(f"floating point numbers are not allowed in {PROFILE_ID}: {value}")


def _reject_constant(value: str) -> None:
    raise DeltaExportError(f"non-finite numeric value is not allowed in {PROFILE_ID}: {value}")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if parsed < MIN_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
        raise DeltaExportError(f"integer outside safe cross-language range for {PROFILE_ID}: {value}")
    return parsed


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DeltaExportError(f"duplicate JSON object key is not allowed: {key!r}")
        obj[key] = value
    return obj


def load_delta_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_pairs_no_duplicates,
        )
    except json.JSONDecodeError as exc:
        raise DeltaExportError(f"invalid JSON: {exc}") from exc


def validate_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise DeltaExportError(f"integer outside safe cross-language range for {PROFILE_ID}: {value}")
        return
    if isinstance(value, float):
        raise DeltaExportError(f"floating point numbers are not allowed in {PROFILE_ID}: {value}")
    if isinstance(value, list):
        for item in value:
            validate_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DeltaExportError("JSON object keys must be strings")
            validate_value(item)
        return
    raise DeltaExportError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    validate_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_items(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from iter_items(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_items(item)


def find_first(obj: Any, keys: list[str]) -> Any | None:
    keyset = set(keys)
    if isinstance(obj, dict):
        for k in keys:
            if k in obj:
                return obj[k]
        for value in obj.values():
            found = find_first(value, keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_first(item, keys)
            if found is not None:
                return found
    return None


def count_matching_keys(obj: Any, fragments: list[str]) -> int:
    fragments_l = [f.lower() for f in fragments]
    total = 0
    for key, _ in iter_items(obj):
        key_l = str(key).lower()
        if any(fragment in key_l for fragment in fragments_l):
            total += 1
    return total


def detect_layers(record: Any) -> list[tuple[str, str]]:
    layers: list[tuple[str, str]] = []

    signature_count = count_matching_keys(record, ["signature"])
    hash_count = count_matching_keys(record, ["hash"])
    evidence_count = count_matching_keys(record, ["evidence"])
    replay_count = count_matching_keys(record, ["replay"])
    intent_count = count_matching_keys(record, ["intent"])
    audit_count = count_matching_keys(record, ["audit"])
    publication_count = count_matching_keys(record, ["publication", "timestamp", "checkpoint"])
    trust_count = count_matching_keys(record, ["previous_entry_hash", "trust", "ledger"])
    wallet_count = count_matching_keys(record, ["wallet", "address", "eip191", "eip712", "bip322"])

    layers.append(("Canonical record hash", "present"))
    if hash_count:
        layers.append(("Hash commitments", f"detected {hash_count} hash-related field(s)"))
    if signature_count:
        layers.append(("Digital signatures", f"detected {signature_count} signature-related field(s)"))
    if evidence_count:
        layers.append(("Evidence commitments", f"detected {evidence_count} evidence-related field(s)"))
    if replay_count:
        layers.append(("Replay metadata", f"detected {replay_count} replay-related field(s)"))
    if intent_count:
        layers.append(("Proof of Intent metadata", f"detected {intent_count} intent-related field(s)"))
    if audit_count:
        layers.append(("Proof of Audit metadata", f"detected {audit_count} audit-related field(s)"))
    if publication_count:
        layers.append(("Proof of Publication / checkpoint metadata", f"detected {publication_count} publication/checkpoint-related field(s)"))
    if trust_count:
        layers.append(("Proof of Trust / ledger metadata", f"detected {trust_count} trust/ledger-related field(s)"))
    if wallet_count:
        layers.append(("Proof of Wallet metadata", f"detected {wallet_count} wallet/address-related field(s)"))

    layers.append(("Schema validation", "not performed by export tool; see schemas/"))
    layers.append(("Cryptographic verification", "not performed by export tool; run dedicated DELTA verifier commands"))
    return layers


def summarize_record(record: Any) -> dict[str, str]:
    return {
        "record_type": str(find_first(record, ["type", "record_type", "kind"]) or "unknown"),
        "protocol_version": str(find_first(record, ["protocol_version", "delta_version", "version"]) or "unknown"),
        "schema_version": str(find_first(record, ["schema_version"]) or "unknown"),
        "created_at": str(find_first(record, ["created_at", "timestamp", "generated_at"]) or "unknown"),
        "method_id": str(find_first(record, ["method_id", "measurement_method_id"]) or "unknown"),
        "method_version": str(find_first(record, ["method_version", "measurement_method_version"]) or "unknown"),
    }


def markdown_table(rows: list[tuple[str, str]]) -> str:
    out = ["| Field | Value |", "|---|---|"]
    for key, value in rows:
        safe_value = str(value).replace("|", "\\|")
        out.append(f"| {key} | `{safe_value}` |")
    return "\n".join(out)


def render_markdown(record_path: Path, record_hash: str, record: Any, title: str) -> str:
    generated_at = utc_now()
    summary = summarize_record(record)
    layers = detect_layers(record)

    lines = [
        f"# {title}",
        "",
        "**Status:** DELTA technical report generated",
        "",
        "> This report summarizes an existing DELTA record. It is not a legal certificate, not a regulatory attestation, and not a replacement for verifier output.",
        "",
        "## Record",
        "",
        markdown_table([
            ("record_path", str(record_path)),
            ("record_hash", record_hash),
            ("canonical_profile", PROFILE_ID),
            ("generated_at", generated_at),
        ]),
        "",
        "## Record summary",
        "",
        markdown_table(list(summary.items())),
        "",
        "## Detected proof layers",
        "",
    ]

    for name, status in layers:
        lines.append(f"- **{name}:** {status}")

    lines.extend([
        "",
        "## Verification commands",
        "",
        "```powershell",
        "python src/delta_cli.py verify-all",
        "python tools\\delta_canonical_json.py verify-vectors --vectors tests\\vectors\\canonical-json\\vectors.json",
        "```",
        "",
        "Dedicated proof tools MAY be required for Intent, Audit, Publication, Trust, and Wallet verification.",
        "",
        "## What this report supports",
        "",
        "- It records the full canonical hash of the supplied DELTA record.",
        "- It summarizes visible record metadata and detected proof-layer fields.",
        "- It provides reviewer-friendly commands for independent checks.",
        "",
        "## What this report does not prove",
        "",
        "- It does not prove legal truth.",
        "- It does not prove real-world truth.",
        "- It does not prove identity by itself.",
        "- It does not prove wallet balance.",
        "- It does not prove regulatory compliance.",
        "- It does not decrypt private evidence.",
        "- It does not replace replay, signature, audit, publication, trust, or wallet verification.",
        "",
        "## Bitcoin external boundary",
        "",
        "For `bitcoin_bip322_external_v1`, DELTA external mode remains `shape_only` / `external_pending`, and `CRYPTO_SIGNATURE_VERIFIED=False` is expected unless a future local BIP-322 verifier is used.",
        "",
        "---",
        "",
        "Generated by `tools/delta_export.py` v2.7.0.",
    ])

    return "\n".join(lines) + "\n"


def render_html(record_path: Path, record_hash: str, record: Any, title: str) -> str:
    md = render_markdown(record_path, record_hash, record, title)
    # Keep HTML intentionally simple and self-contained. Convert key sections conservatively.
    escaped = html.escape(md)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; line-height: 1.55; max-width: 980px; margin: 40px auto; padding: 0 20px; color: #17202a; }}
    .badge {{ display: inline-block; padding: 8px 12px; border: 1px solid #1f7a3f; border-radius: 999px; background: #edf9f0; color: #145a32; font-weight: 700; }}
    .boundary {{ padding: 14px 16px; border-left: 4px solid #a36b00; background: #fff8e5; margin: 16px 0; }}
    pre {{ white-space: pre-wrap; background: #f6f8fa; padding: 16px; border-radius: 10px; overflow-x: auto; }}
    code {{ background: #f6f8fa; padding: 1px 4px; border-radius: 4px; }}
    h1, h2 {{ line-height: 1.2; }}
  </style>
</head>
<body>
  <p><span class="badge">DELTA REPORT GENERATED</span></p>
  <div class="boundary"><strong>Security boundary:</strong> This is a technical export report. It is not a legal certificate, regulatory attestation, identity proof, wallet-balance proof, or replacement for dedicated verifier output.</div>
  <pre>{escaped}</pre>
</body>
</html>
"""


def command_export(args: argparse.Namespace) -> int:
    record_path = Path(args.record)
    if not record_path.exists():
        raise SystemExit(f"record file not found: {record_path}")

    record = load_delta_json(record_path)
    record_hash = canonical_sha256(record)

    title = args.title or "DELTA Proof Report"
    if args.format == "markdown":
        report = render_markdown(record_path, record_hash, record, title)
    elif args.format == "html":
        report = render_html(record_path, record_hash, record, title)
    else:
        raise SystemExit(f"unsupported format: {args.format}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    print("DELTA_EXPORT_OK=True")
    print(f"DELTA_EXPORT_FORMAT={args.format}")
    print(f"DELTA_EXPORT_OUT={out_path}")
    print(f"DELTA_EXPORT_RECORD_HASH={record_hash}")
    print(f"DELTA_EXPORT_CANONICAL_PROFILE={PROFILE_ID}")
    print("DELTA_EXPORT_SECURITY_BOUNDARY=technical_report_not_legal_certificate")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA export report helper v2.7.0")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="Export a DELTA record summary report")
    export.add_argument("--record", required=True, help="Path to delta-record.json")
    export.add_argument("--format", choices=["markdown", "html"], required=True, help="Report format")
    export.add_argument("--out", required=True, help="Output report path")
    export.add_argument("--title", default="DELTA Proof Report", help="Report title")
    export.set_defaults(func=command_export)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args) or 0)
    except DeltaExportError as exc:
        print("DELTA_EXPORT_OK=False")
        print(f"DELTA_EXPORT_REASON={type(exc).__name__}:{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
