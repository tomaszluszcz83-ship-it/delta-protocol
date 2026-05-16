from __future__ import annotations

import argparse
import sys

from delta_protocol import verify_claim_pair


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a DELTA claim/signature pair.")
    parser.add_argument("claim_json", help="Path to claim.json")
    parser.add_argument("executor_signature_json", help="Path to executor_signature.json")
    args = parser.parse_args()

    result = verify_claim_pair(args.claim_json, args.executor_signature_json)

    if result.ok:
        print("OK")
        print(result.payload_hash)
        return 0

    print("FAILED")
    print(result.reason)
    return 1


if __name__ == "__main__":
    sys.exit(main())
