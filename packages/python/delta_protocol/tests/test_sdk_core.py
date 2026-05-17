from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from delta_protocol import (
    DELTAProtocolError,
    canonical_json_bytes,
    load_json_file,
    sha256_prefixed,
    verify_attestation_data,
    verify_attestation_pair,
    verify_checkpoint_data,
    verify_checkpoint_pair,
    verify_claim_data,
    verify_claim_pair,
)


REPO_ROOT = Path(__file__).resolve().parents[4]


class DeltaSDKCoreTests(unittest.TestCase):
    def test_canonical_json_orders_keys_and_hashes_deterministically(self) -> None:
        payload = {"b": 2, "a": 1}

        self.assertEqual(canonical_json_bytes(payload), b'{"a":1,"b":2}')
        self.assertEqual(
            sha256_prefixed(canonical_json_bytes(payload)),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )

    def test_canonical_equality_across_formatting_and_key_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pretty = Path(temp_dir) / "pretty.json"
            compact = Path(temp_dir) / "compact.json"

            pretty.write_text(
                '{\n'
                '  "z": [3, 2, 1],\n'
                '  "a": {\n'
                '    "b": true,\n'
                '    "a": "same value"\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
                newline="\n",
            )

            compact.write_text(
                '{"a":{"a":"same value","b":true},"z":[3,2,1]}',
                encoding="utf-8",
                newline="\n",
            )

            pretty_obj = load_json_file(pretty)
            compact_obj = load_json_file(compact)

            pretty_hash = sha256_prefixed(canonical_json_bytes(pretty_obj))
            compact_hash = sha256_prefixed(canonical_json_bytes(compact_obj))

            self.assertEqual(pretty_hash, compact_hash)
            self.assertEqual(canonical_json_bytes(pretty_obj), canonical_json_bytes(compact_obj))

    def test_canonical_json_rejects_float_values(self) -> None:
        with self.assertRaises(DELTAProtocolError):
            canonical_json_bytes({"value": 1.5})

    def test_load_json_file_rejects_utf8_bom(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bom.json"
            path.write_bytes(b"\xef\xbb\xbf{\"a\":1}")

            with self.assertRaises(DELTAProtocolError):
                load_json_file(path)

    def test_verify_claim_pair_from_files(self) -> None:
        result = verify_claim_pair(
            REPO_ROOT / "genesis" / "claim.json",
            REPO_ROOT / "genesis" / "executor_signature.json",
        )

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")
        self.assertIsNotNone(result.payload_hash)
        self.assertTrue(result.payload_hash.startswith("sha256:"))

    def test_verify_claim_pair_from_memory(self) -> None:
        claim = load_json_file(REPO_ROOT / "genesis" / "claim.json")
        signature = load_json_file(REPO_ROOT / "genesis" / "executor_signature.json")

        result = verify_claim_data(claim, signature)

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")

    def test_verify_attestation_pair_from_files(self) -> None:
        result = verify_attestation_pair(
            REPO_ROOT / "genesis" / "attestation.json",
            REPO_ROOT / "genesis" / "verifier_signature.json",
        )

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")

    def test_verify_attestation_pair_from_memory(self) -> None:
        attestation = load_json_file(REPO_ROOT / "genesis" / "attestation.json")
        signature = load_json_file(REPO_ROOT / "genesis" / "verifier_signature.json")

        result = verify_attestation_data(attestation, signature)

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")

    def test_verify_checkpoint_pair_from_files(self) -> None:
        result = verify_checkpoint_pair(
            REPO_ROOT / "genesis" / "checkpoint.json",
            REPO_ROOT / "genesis" / "checkpoint_signature.json",
        )

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")

    def test_verify_checkpoint_pair_from_memory(self) -> None:
        checkpoint = load_json_file(REPO_ROOT / "genesis" / "checkpoint.json")
        signature = load_json_file(REPO_ROOT / "genesis" / "checkpoint_signature.json")

        result = verify_checkpoint_data(checkpoint, signature)

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "OK")

    def test_wrong_target_hash_fails(self) -> None:
        claim = load_json_file(REPO_ROOT / "genesis" / "claim.json")
        signature = load_json_file(REPO_ROOT / "genesis" / "executor_signature.json")
        mutated_signature = copy.deepcopy(signature)
        mutated_signature["target_hash"] = "sha256:" + ("0" * 64)

        result = verify_claim_data(claim, mutated_signature)

        self.assertFalse(result.ok)
        self.assertIn("target_hash mismatch", result.reason)

    def test_wrong_role_fails(self) -> None:
        claim = load_json_file(REPO_ROOT / "genesis" / "claim.json")
        signature = load_json_file(REPO_ROOT / "genesis" / "executor_signature.json")
        mutated_signature = copy.deepcopy(signature)
        mutated_signature["role"] = "verifier"

        result = verify_claim_data(claim, mutated_signature)

        self.assertFalse(result.ok)
        self.assertIn("signature.role mismatch", result.reason)


if __name__ == "__main__":
    unittest.main()
