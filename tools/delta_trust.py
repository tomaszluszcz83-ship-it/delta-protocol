#!/usr/bin/env python3
"""DELTA Proof of Trust / hash-chain ledger tool.

v2.2.0 goal:
- create an append-only hash-chain ledger for DELTA records and related proof events
- bind each trust entry to the SHA-256 hash of a full canonical delta-record.json
- verify ledger self-check hashes, entry hashes, and previous-entry links offline

Security boundary:
- Proof of Trust v2.2.0 proves cryptographic continuity of a trust ledger.
- It does not prove legal trust, real-world identity, auditor authority, regulator authority,
  external-world truth, or that an actor label is truthful.
- This MVP is intentionally zero-token and does not require private keys.
- Optional signed trust entries can be added later without changing the hash-chain model.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any

PROTOCOL = "DELTA-0"
SHA256_PREFIX = "sha256:"
TRUST_LEDGER_TYPE = "delta_trust_ledger"
TRUST_LEDGER_BODY_TYPE = "delta_trust_ledger_body"
TRUST_ENTRY_TYPE = "delta_trust_entry"
TRUST_VERSION = "1.0.0"
GENESIS_PREVIOUS_ENTRY_HASH = "GENESIS"

VALID_ROLES = {
    "executor",
    "verifier",
    "intent_approver",
    "auditor",
    "publisher",
    "regulator",
    "observer",
}

VALID_EVENT_TYPES = {
    "record_observed",
    "replay_verified",
    "intent_verified",
    "audit_verified",
    "publication_verified",
    "manual_reviewed",
    "regulatory_reviewed",
}


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_prefixed(canonical_json_bytes(value))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return sha256_prefixed(h.digest() if False else b"")  # unreachable placeholder for type checkers


def file_bytes_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return SHA256_PREFIX + h.hexdigest()


def load_record(path: Path) -> dict[str, Any]:
    record = read_json(path)
    if not isinstance(record, dict):
        raise SystemExit("delta record JSON must be an object")
    return record


def record_type(record: dict[str, Any]) -> str:
    body = record.get("record_body") if isinstance(record.get("record_body"), dict) else {}
    return str(body.get("type") or record.get("type") or "delta_sensor_record")


def record_target(record: dict[str, Any], record_path: Path) -> dict[str, Any]:
    return {
        "record_hash": canonical_sha256(record),
        "record_type": record_type(record),
        "record_path_hint": str(record_path),
        "hash_algorithm": "sha256(canonical_json(full_delta_record_json))",
    }


def normalize_role(role: str) -> str:
    role = role.strip()
    if role not in VALID_ROLES:
        raise SystemExit(f"unsupported trust role: {role}; expected one of {sorted(VALID_ROLES)}")
    return role


def normalize_event_type(event_type: str) -> str:
    event_type = event_type.strip()
    if event_type not in VALID_EVENT_TYPES:
        raise SystemExit(f"unsupported trust event type: {event_type}; expected one of {sorted(VALID_EVENT_TYPES)}")
    return event_type


def make_entry_body(
    *,
    chain_id: str,
    sequence: int,
    entry_id: str,
    previous_entry_hash: str,
    record: dict[str, Any],
    record_path: Path,
    actor: str,
    role: str,
    event_type: str,
    note: str,
    linked_proofs: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "type": TRUST_ENTRY_TYPE,
        "version": TRUST_VERSION,
        "protocol": PROTOCOL,
        "chain_id": chain_id,
        "sequence": sequence,
        "entry_id": entry_id,
        "previous_entry_hash": previous_entry_hash,
        "created_at": now_utc(),
        "actor": {
            "id": actor,
            "role": normalize_role(role),
            "identity_verified_by_delta": False,
            "note": "Actor label is metadata unless combined with a future signed trust entry or external identity registry.",
        },
        "event": {
            "type": normalize_event_type(event_type),
            "note": note,
        },
        "target": record_target(record, record_path),
        "linked_proofs": linked_proofs,
        "security_boundary": {
            "proves_hash_chain_continuity": True,
            "proves_actor_identity": False,
            "proves_legal_trust": False,
            "proves_external_truth": False,
            "signed": False,
            "note": "Proof of Trust v2.2.0 is a hash-chain ledger MVP. It proves continuity and binding, not authority by itself.",
        },
    }


def wrap_entry(entry_body: dict[str, Any]) -> dict[str, Any]:
    entry_hash = canonical_sha256(entry_body)
    return {
        "entry_body_hash": entry_hash,
        "entry_body": entry_body,
        "entry_integrity": {
            "hash_algorithm": "sha256(canonical_json(entry_body))",
            "self_check_hash": entry_hash,
            "signed": False,
            "signature": None,
        },
    }


def make_ledger(chain_id: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    ledger_body = {
        "type": TRUST_LEDGER_BODY_TYPE,
        "version": TRUST_VERSION,
        "protocol": PROTOCOL,
        "chain_id": chain_id,
        "created_at": now_utc(),
        "hash_algorithm": "sha256(canonical_json(entry_body))",
        "link_algorithm": "entry[n].entry_body.previous_entry_hash == entry[n-1].entry_body_hash",
        "entries": entries,
        "security_boundary": {
            "proves_hash_chain_continuity": True,
            "proves_actor_identity": False,
            "proves_legal_trust": False,
            "proves_external_truth": False,
            "note": "This ledger is a cryptographic continuity layer. Trust policy and signed identities are future layers.",
        },
    }
    body_hash = canonical_sha256(ledger_body)
    return {
        "type": TRUST_LEDGER_TYPE,
        "version": TRUST_VERSION,
        "protocol": PROTOCOL,
        "ledger_body_hash": body_hash,
        "ledger_body": ledger_body,
        "ledger_integrity": {
            "hash_algorithm": "sha256(canonical_json(ledger_body))",
            "self_check_hash": body_hash,
            "signed": False,
            "signature": None,
        },
    }


def load_ledger(path: Path) -> dict[str, Any]:
    ledger = read_json(path)
    if not isinstance(ledger, dict):
        raise SystemExit("trust ledger JSON must be an object")
    if not isinstance(ledger.get("ledger_body"), dict):
        raise SystemExit("trust ledger must contain ledger_body object")
    if not isinstance(ledger["ledger_body"].get("entries"), list):
        raise SystemExit("trust ledger ledger_body.entries must be a list")
    return ledger


def linked_proof_from_args(values: list[str]) -> list[dict[str, Any]]:
    proofs: list[dict[str, Any]] = []
    for item in values:
        raw = item.strip()
        if not raw:
            continue
        if "=" in raw:
            proof_type, path_text = raw.split("=", 1)
        else:
            proof_type, path_text = "generic_proof", raw
        path = Path(path_text).resolve()
        proof_entry: dict[str, Any] = {
            "type": proof_type.strip() or "generic_proof",
            "path_hint": str(path),
            "exists_at_creation": path.exists(),
        }
        if path.exists() and path.is_file():
            proof_entry["file_hash"] = file_bytes_sha256(path)
        proofs.append(proof_entry)
    return proofs


def command_hash_record(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = load_record(record_path)
    print(f"DELTA_TRUST_RECORD_HASH={canonical_sha256(record)}")
    print(f"DELTA_TRUST_RECORD_TYPE={record_type(record)}")
    print(f"DELTA_TRUST_RECORD_PATH={record_path}")
    return 0


def command_create_ledger(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = load_record(record_path)
    linked_proofs = linked_proof_from_args(args.linked_proof or [])
    entry_body = make_entry_body(
        chain_id=args.chain_id,
        sequence=0,
        entry_id=args.entry_id,
        previous_entry_hash=GENESIS_PREVIOUS_ENTRY_HASH,
        record=record,
        record_path=record_path,
        actor=args.actor,
        role=args.role,
        event_type=args.event_type,
        note=args.note,
        linked_proofs=linked_proofs,
    )
    entry = wrap_entry(entry_body)
    ledger = make_ledger(args.chain_id, [entry])
    out_path = Path(args.out).resolve()
    write_json(out_path, ledger)
    print("DELTA_TRUST_CREATE_OK=True")
    print(f"DELTA_TRUST_LEDGER={out_path}")
    print(f"DELTA_TRUST_CHAIN_ID={args.chain_id}")
    print(f"DELTA_TRUST_ENTRY_COUNT=1")
    print(f"DELTA_TRUST_LAST_ENTRY_HASH={entry['entry_body_hash']}")
    print(f"DELTA_TRUST_LEDGER_BODY_HASH={ledger['ledger_body_hash']}")
    return 0


def command_append_entry(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger).resolve()
    ledger = load_ledger(ledger_path)
    body = ledger["ledger_body"]
    entries = list(body.get("entries") or [])
    if not entries:
        raise SystemExit("cannot append to empty ledger; use create-ledger first")
    previous_hash = entries[-1].get("entry_body_hash")
    if not isinstance(previous_hash, str) or not previous_hash.startswith(SHA256_PREFIX):
        raise SystemExit("last ledger entry has invalid entry_body_hash")
    chain_id = str(body.get("chain_id") or args.chain_id or "")
    if args.chain_id and args.chain_id != chain_id:
        raise SystemExit("--chain-id does not match existing ledger chain_id")
    record_path = Path(args.record).resolve()
    record = load_record(record_path)
    linked_proofs = linked_proof_from_args(args.linked_proof or [])
    entry_body = make_entry_body(
        chain_id=chain_id,
        sequence=len(entries),
        entry_id=args.entry_id,
        previous_entry_hash=previous_hash,
        record=record,
        record_path=record_path,
        actor=args.actor,
        role=args.role,
        event_type=args.event_type,
        note=args.note,
        linked_proofs=linked_proofs,
    )
    entry = wrap_entry(entry_body)
    entries.append(entry)
    out_path = Path(args.out).resolve() if args.out else ledger_path
    new_ledger = make_ledger(chain_id, entries)
    # Preserve original ledger creation timestamp for continuity.
    if body.get("created_at"):
        new_ledger["ledger_body"]["created_at"] = body.get("created_at")
        new_ledger["ledger_body_hash"] = canonical_sha256(new_ledger["ledger_body"])
        new_ledger["ledger_integrity"]["self_check_hash"] = new_ledger["ledger_body_hash"]
    write_json(out_path, new_ledger)
    print("DELTA_TRUST_APPEND_OK=True")
    print(f"DELTA_TRUST_LEDGER={out_path}")
    print(f"DELTA_TRUST_CHAIN_ID={chain_id}")
    print(f"DELTA_TRUST_ENTRY_COUNT={len(entries)}")
    print(f"DELTA_TRUST_LAST_ENTRY_HASH={entry['entry_body_hash']}")
    print(f"DELTA_TRUST_LEDGER_BODY_HASH={new_ledger['ledger_body_hash']}")
    return 0


def verify_ledger(ledger: dict[str, Any], record: dict[str, Any] | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    checks["ledger_shape_ok"] = isinstance(ledger, dict) and isinstance(ledger.get("ledger_body"), dict)
    reasons["ledger_shape"] = "ledger_shape_ok" if checks["ledger_shape_ok"] else "ledger_must_be_object_with_ledger_body"
    body = ledger.get("ledger_body") if isinstance(ledger.get("ledger_body"), dict) else {}
    entries = body.get("entries") if isinstance(body.get("entries"), list) else []

    checks["ledger_type_ok"] = ledger.get("type") == TRUST_LEDGER_TYPE and ledger.get("protocol") == PROTOCOL
    reasons["ledger_type"] = "ledger_type_ok" if checks["ledger_type_ok"] else "ledger_type_or_protocol_invalid"
    checks["body_type_ok"] = body.get("type") == TRUST_LEDGER_BODY_TYPE and body.get("protocol") == PROTOCOL
    reasons["body_type"] = "body_type_ok" if checks["body_type_ok"] else "ledger_body_type_or_protocol_invalid"
    checks["entry_count_ok"] = len(entries) > 0
    reasons["entry_count"] = "entry_count_ok" if checks["entry_count_ok"] else "ledger_has_no_entries"

    expected_ledger_hash = canonical_sha256(body)
    checks["ledger_body_hash_ok"] = ledger.get("ledger_body_hash") == expected_ledger_hash
    reasons["ledger_body_hash"] = "ledger_body_hash_matches" if checks["ledger_body_hash_ok"] else "ledger_body_hash_mismatch"
    integrity = ledger.get("ledger_integrity") if isinstance(ledger.get("ledger_integrity"), dict) else {}
    checks["ledger_self_check_ok"] = integrity.get("self_check_hash") in (None, expected_ledger_hash)
    reasons["ledger_self_check"] = "ledger_self_check_ok" if checks["ledger_self_check_ok"] else "ledger_self_check_hash_mismatch"

    entry_hashes_ok = True
    entry_self_checks_ok = True
    chain_links_ok = True
    sequence_ok = True
    entry_shapes_ok = True
    roles_ok = True
    event_types_ok = True
    linked_proofs_ok = True
    record_binding_ok = True if record is not None else True
    supplied_record_hash = canonical_sha256(record) if isinstance(record, dict) else ""
    matching_record_entries = 0
    last_hash = ""

    previous_hash = GENESIS_PREVIOUS_ENTRY_HASH
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("entry_body"), dict):
            entry_shapes_ok = False
            entry_hashes_ok = False
            chain_links_ok = False
            continue
        entry_body = entry["entry_body"]
        expected_entry_hash = canonical_sha256(entry_body)
        declared_hash = entry.get("entry_body_hash")
        if declared_hash != expected_entry_hash:
            entry_hashes_ok = False
        entry_integrity = entry.get("entry_integrity") if isinstance(entry.get("entry_integrity"), dict) else {}
        if entry_integrity.get("self_check_hash") not in (None, expected_entry_hash):
            entry_self_checks_ok = False
        if entry_body.get("previous_entry_hash") != previous_hash:
            chain_links_ok = False
        if entry_body.get("sequence") != index:
            sequence_ok = False
        actor = entry_body.get("actor") if isinstance(entry_body.get("actor"), dict) else {}
        event = entry_body.get("event") if isinstance(entry_body.get("event"), dict) else {}
        if actor.get("role") not in VALID_ROLES:
            roles_ok = False
        if event.get("type") not in VALID_EVENT_TYPES:
            event_types_ok = False
        linked_proofs = entry_body.get("linked_proofs")
        if not isinstance(linked_proofs, list):
            linked_proofs_ok = False
        else:
            for proof in linked_proofs:
                if not isinstance(proof, dict):
                    linked_proofs_ok = False
                    continue
                if proof.get("file_hash") and not str(proof.get("file_hash")).startswith(SHA256_PREFIX):
                    linked_proofs_ok = False
        target = entry_body.get("target") if isinstance(entry_body.get("target"), dict) else {}
        target_hash = target.get("record_hash")
        if record is not None and target_hash == supplied_record_hash:
            matching_record_entries += 1
        if record is not None and not (isinstance(target_hash, str) and target_hash.startswith(SHA256_PREFIX)):
            record_binding_ok = False
        previous_hash = expected_entry_hash
        last_hash = expected_entry_hash

    if record is not None and matching_record_entries == 0:
        record_binding_ok = False

    checks["entry_shapes_ok"] = entry_shapes_ok
    reasons["entry_shapes"] = "entry_shapes_ok" if entry_shapes_ok else "entry_shape_invalid"
    checks["entry_hashes_ok"] = entry_hashes_ok
    reasons["entry_hashes"] = "entry_hashes_match" if entry_hashes_ok else "entry_hash_mismatch"
    checks["entry_self_checks_ok"] = entry_self_checks_ok
    reasons["entry_self_checks"] = "entry_self_checks_ok" if entry_self_checks_ok else "entry_self_check_hash_mismatch"
    checks["chain_links_ok"] = chain_links_ok
    reasons["chain_links"] = "chain_links_ok" if chain_links_ok else "previous_entry_hash_mismatch"
    checks["sequence_ok"] = sequence_ok
    reasons["sequence"] = "sequence_ok" if sequence_ok else "entry_sequence_mismatch"
    checks["roles_ok"] = roles_ok
    reasons["roles"] = "roles_ok" if roles_ok else "unsupported_role_in_entry"
    checks["event_types_ok"] = event_types_ok
    reasons["event_types"] = "event_types_ok" if event_types_ok else "unsupported_event_type_in_entry"
    checks["linked_proofs_ok"] = linked_proofs_ok
    reasons["linked_proofs"] = "linked_proofs_ok" if linked_proofs_ok else "linked_proof_invalid"
    checks["record_binding_ok"] = record_binding_ok
    reasons["record_binding"] = "record_binding_ok" if record_binding_ok else "supplied_record_hash_not_found_or_invalid"

    ok = all(checks.values())
    return {
        "ok": bool(ok),
        "checks": checks,
        "reasons": reasons,
        "chain_id": str(body.get("chain_id") or ""),
        "entry_count": len(entries),
        "ledger_body_hash": expected_ledger_hash,
        "last_entry_hash": last_hash,
        "matching_record_entries": matching_record_entries,
        "record_hash": supplied_record_hash,
    }


def command_verify_ledger(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger).resolve()
    ledger = load_ledger(ledger_path)
    record = load_record(Path(args.record).resolve()) if args.record else None
    result = verify_ledger(ledger, record=record)
    checks = result["checks"]
    reasons = result["reasons"]
    print(f"DELTA_TRUST_VERIFY_OK={bool(result['ok'])}")
    print(f"DELTA_TRUST_CHAIN_ID={result['chain_id']}")
    print(f"DELTA_TRUST_ENTRY_COUNT={result['entry_count']}")
    print(f"DELTA_TRUST_LEDGER_BODY_HASH_OK={bool(checks.get('ledger_body_hash_ok'))}")
    print(f"DELTA_TRUST_LEDGER_SELF_CHECK_OK={bool(checks.get('ledger_self_check_ok'))}")
    print(f"DELTA_TRUST_ENTRY_HASHES_OK={bool(checks.get('entry_hashes_ok'))}")
    print(f"DELTA_TRUST_ENTRY_SELF_CHECKS_OK={bool(checks.get('entry_self_checks_ok'))}")
    print(f"DELTA_TRUST_CHAIN_LINKS_OK={bool(checks.get('chain_links_ok'))}")
    print(f"DELTA_TRUST_SEQUENCE_OK={bool(checks.get('sequence_ok'))}")
    print(f"DELTA_TRUST_ROLES_OK={bool(checks.get('roles_ok'))}")
    print(f"DELTA_TRUST_EVENT_TYPES_OK={bool(checks.get('event_types_ok'))}")
    print(f"DELTA_TRUST_LINKED_PROOFS_OK={bool(checks.get('linked_proofs_ok'))}")
    print(f"DELTA_TRUST_RECORD_BINDING_OK={bool(checks.get('record_binding_ok'))}")
    print(f"DELTA_TRUST_LEDGER_BODY_HASH={result['ledger_body_hash']}")
    print(f"DELTA_TRUST_LAST_ENTRY_HASH={result['last_entry_hash']}")
    if result.get("record_hash"):
        print(f"DELTA_TRUST_RECORD_HASH={result['record_hash']}")
        print(f"DELTA_TRUST_MATCHING_RECORD_ENTRIES={result['matching_record_entries']}")
    if not result["ok"]:
        for key, ok in sorted(checks.items()):
            if not ok:
                reason_key = key[:-3] if key.endswith("_ok") else key
                print(f"DELTA_TRUST_REASON_{key.upper()}={reasons.get(reason_key, '')}")
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DELTA Proof of Trust / hash-chain ledger tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_record = subparsers.add_parser("hash-record", help="Compute the full canonical delta-record.json hash for trust ledgers.")
    hash_record.add_argument("--record", required=True, help="Path to delta-record.json")
    hash_record.set_defaults(func=command_hash_record)

    create = subparsers.add_parser("create-ledger", help="Create a new DELTA trust ledger with a genesis entry.")
    create.add_argument("--record", required=True, help="Path to delta-record.json")
    create.add_argument("--out", required=True, help="Output path for delta-trust-ledger.json")
    create.add_argument("--chain-id", default="delta-trust-local-v1", help="Trust chain id")
    create.add_argument("--entry-id", default="T-001-E-001", help="Entry id")
    create.add_argument("--actor", default="local-executor", help="Actor label")
    create.add_argument("--role", default="executor", choices=sorted(VALID_ROLES), help="Actor role")
    create.add_argument("--event-type", default="record_observed", choices=sorted(VALID_EVENT_TYPES), help="Trust event type")
    create.add_argument("--note", default="Genesis trust entry for a DELTA record.", help="Event note")
    create.add_argument("--linked-proof", action="append", default=[], help="Optional linked proof as type=path or path. May be repeated.")
    create.set_defaults(func=command_create_ledger)

    append = subparsers.add_parser("append-entry", help="Append an entry to an existing DELTA trust ledger.")
    append.add_argument("--ledger", required=True, help="Path to existing delta-trust-ledger.json")
    append.add_argument("--record", required=True, help="Path to delta-record.json")
    append.add_argument("--out", default="", help="Output path. Default: overwrite --ledger")
    append.add_argument("--chain-id", default="", help="Optional chain id sanity check")
    append.add_argument("--entry-id", required=True, help="Entry id")
    append.add_argument("--actor", required=True, help="Actor label")
    append.add_argument("--role", required=True, choices=sorted(VALID_ROLES), help="Actor role")
    append.add_argument("--event-type", required=True, choices=sorted(VALID_EVENT_TYPES), help="Trust event type")
    append.add_argument("--note", default="", help="Event note")
    append.add_argument("--linked-proof", action="append", default=[], help="Optional linked proof as type=path or path. May be repeated.")
    append.set_defaults(func=command_append_entry)

    verify = subparsers.add_parser("verify-ledger", help="Verify a DELTA trust ledger offline.")
    verify.add_argument("--ledger", required=True, help="Path to delta-trust-ledger.json")
    verify.add_argument("--record", default="", help="Optional delta-record.json for record binding check")
    verify.set_defaults(func=command_verify_ledger)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
