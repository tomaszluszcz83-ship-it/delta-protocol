#!/usr/bin/env python3
"""Generate an Ed25519 keypair for DELTA sensor signing.

Output format:
- private seed: ed25519seed:<base64url-no-padding>
- public key:   ed25519:<base64url-no-padding>

Store the private seed as a GitHub Actions secret:
DELTA_SENSOR_PRIVATE_KEY

Store the public key as a GitHub repository variable if desired:
DELTA_EXECUTOR_PUBLIC_KEY

Never commit the private seed.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def main() -> int:
    private_key = Ed25519PrivateKey.generate()
    private_seed = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    print("DELTA_SENSOR_PRIVATE_KEY")
    print("ed25519seed:" + b64url_no_padding(private_seed))
    print()
    print("DELTA_EXECUTOR_PUBLIC_KEY")
    print("ed25519:" + b64url_no_padding(public_key))
    print()
    print("WARNING: Store the private key only in GitHub Secrets. Do not commit it.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
