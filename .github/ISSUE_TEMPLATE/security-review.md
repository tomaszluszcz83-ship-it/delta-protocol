---
name: Security review
about: Request or provide security-focused review for DELTA Protocol
title: "[Security Review]: "
labels: security, review
assignees: ""
---

## Area reviewed

Which area are you reviewing?

- [ ] Core record/hash binding
- [ ] Canonical JSON
- [ ] Signatures
- [ ] Replay
- [ ] Intent
- [ ] Audit
- [ ] Publication
- [ ] Trust ledger
- [ ] Wallet proof
- [ ] Bitcoin BIP-322 external profile
- [ ] Documentation/security boundary
- [ ] Other

## Summary

Describe the issue or review finding.

## Expected security property

What should DELTA prove or reject?

## Observed behavior

What did you observe?

## Reproduction steps

Please include commands or minimal examples where possible.

Do not include private keys, seed phrases, production secrets, customer data, or sensitive evidence.

## Impact

What could an attacker or confused user do?

## Suggested fix

If known, suggest a fix or documentation clarification.

## Notes

Remember: some limitations are intentional security boundaries. For example, `bitcoin_bip322_external_v1` is currently `shape_only` / `external_pending` and must report `CRYPTO_SIGNATURE_VERIFIED=False`.
