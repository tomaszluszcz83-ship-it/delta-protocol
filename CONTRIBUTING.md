# Contributing to DELTA Protocol

Thank you for your interest in DELTA Protocol.

DELTA is an open, zero-token Proof of Change protocol in technical alpha. Contributions are welcome, especially in protocol review, security review, documentation, test vectors, integrations, and careful reference-implementation improvements.

---

## Project principles

Contributions should follow these principles:

1. **Do not overclaim.** DELTA must clearly state what it proves and what it does not prove.
2. **Hash binding first.** Proof objects should bind to the full relevant DELTA record hash.
3. **No private keys in repo.** Never commit private keys, seed phrases, tokens, or generated sensitive artifacts.
4. **Canonical data.** Hashing and signing must use deterministic canonical JSON rules.
5. **Tamper tests matter.** Every proof type should have positive and negative tests.
6. **Reference implementation is not the final standard.** RFC documents should distinguish normative rules from current implementation details.
7. **Bitcoin external profile must stay honest.** `bitcoin_bip322_external_v1` is `shape_only` / `external_pending` until local cryptographic verification is implemented.

---

## How to contribute

Recommended contribution types:

- RFC feedback,
- security-boundary corrections,
- documentation improvements,
- test vectors,
- GitHub Actions / GitLab CI integrations,
- Docker packaging,
- local Bitcoin BIP-322 verification research,
- schema formalization,
- threat model improvements.

---

## Development checklist

Before opening a PR:

```bash
python src/delta_cli.py verify-all
```

Also run syntax checks for changed Python files:

```bash
python -m py_compile tools/delta_wallet.py
python -m py_compile tools/delta_replay.py
python -m py_compile tools/delta_audit.py
python -m py_compile tools/delta_publish.py
python -m py_compile tools/delta_trust.py
```

Only run commands relevant to files you changed.

---

## Documentation checklist

For documentation PRs:

- clearly distinguish cryptographic proof from legal/business claims,
- avoid saying DELTA proves identity, ownership, balance, compliance, or external truth,
- link to RFC-01 and the security boundary document,
- mark draft/RFC status accurately,
- ensure Bitcoin external proof is described as `shape_only` / `external_pending`.

---

## Pull request process

1. Create a topic branch.
2. Make focused changes.
3. Run verification.
4. Open a PR with:
   - summary,
   - changed files,
   - security impact,
   - tests performed,
   - known limitations.
5. Wait for CI and review.

---

## Issue types

Use issue templates where possible:

- RFC feedback,
- security review request,
- bug report,
- feature proposal,
- documentation correction.

Do not post private keys, seed phrases, customer data, or sensitive evidence in issues.

---

## License

By contributing, you agree that your contributions are submitted under the repository license.

See:

```text
LICENSE
```

