# Security Policy

DELTA Protocol is a technical alpha / reference implementation / RFC draft.

Security reports are welcome. Please do not publish sensitive vulnerabilities publicly before maintainers have had a reasonable opportunity to review and respond.

---

## Supported versions

The latest tagged release is the primary supported version for security review.

Older releases are useful for historical reference but may not receive fixes.

---

## What to report

Please report issues involving:

- signature verification bypass,
- hash-binding bypass,
- replay verification bypass,
- canonical JSON inconsistencies,
- record-hash substitution,
- private key exposure risk,
- audit package decryption/integrity issues,
- wallet proof verification errors,
- false claims of cryptographic verification,
- unsafe documentation that overclaims DELTA security properties.

Especially important:

```text
bitcoin_bip322_external_v1 must not be described as locally cryptographically verified.
CRYPTO_SIGNATURE_VERIFIED=False is intentional for that external-only profile.
```

---

## What not to report as a vulnerability

The following are known security boundaries, not bugs by themselves:

- DELTA does not prove legal truth.
- DELTA does not prove real-world identity.
- DELTA does not prove wallet balance.
- DELTA does not prove regulatory compliance.
- DELTA does not prove evidence was truthful before hashing.
- DELTA does not prove full Bitcoin BIP-322 script-level correctness for `bitcoin_bip322_external_v1`.

These limitations should remain clearly documented.

---

## Reporting process

Preferred options:

1. Use GitHub private vulnerability reporting if enabled for this repository.
2. If private vulnerability reporting is not available, contact the maintainer privately before opening a public issue.
3. For non-sensitive design feedback, use the RFC feedback issue template.

Do not include private keys, seed phrases, production wallet secrets, customer data, or sensitive evidence in public issues.

---

## Private keys and secrets

DELTA development rules:

- Do not commit private keys.
- Do not paste private keys into issues, pull requests, or chat logs.
- Demo keys must be local-only and disposable.
- Generated test artifacts under `.delta/*-tests/` should not be committed unless explicitly intended as public fixtures.
- Public keys may be committed only when intentionally part of a public registry or demo profile.

---

## Security boundaries

DELTA proves cryptographic consistency and binding between records, signatures, hashes, evidence commitments, replay results, publication proofs, trust-chain entries, and wallet challenges.

DELTA does not by itself establish legal authority, regulatory compliance, real-world truth, identity, wallet ownership, or financial balances.

See:

```text
docs/positioning/what-delta-proves.md
docs/rfc/RFC-01-delta-core-protocol.md
docs/rfc/RFC-02-proof-of-wallet.md
```

---

## Response expectations

This is an early project. The maintainer will make a best effort to:

- acknowledge serious reports,
- reproduce the issue,
- classify severity,
- fix or document the boundary,
- update tests and RFC documents where appropriate.

