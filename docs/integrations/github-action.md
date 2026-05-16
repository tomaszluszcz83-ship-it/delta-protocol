# DELTA GitHub Action Integration

This document describes the DELTA GitHub Actions MVP integration.

The goal is simple:

```text
Make DELTA verification visible in normal developer workflows.
```

This MVP runs the public DELTA verifier in CI:

```text
python src/delta_cli.py verify-all
```

It is intentionally conservative. It does not create Claims, does not sign with private keys, and does not upload private payloads.

---

## What this integration proves

When the workflow passes, it proves that the repository public DELTA proof artifacts verify successfully in a clean GitHub Actions runner.

It checks:

- Genesis proof artifacts
- Code Change Proof example
- Private Payload Proof example
- AI Agent Proof example
- byte-exact Git checkout policy

Expected result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK

DELTA CLI RESULT: OK
```

---

## Minimal workflow

Copy this file into a repository that contains DELTA proof artifacts:

```text
.github/workflows/delta-verify.yml
```

Workflow:

```yaml
name: DELTA Verify

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  delta-verify:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
          cache: pip

      - name: Install DELTA dependencies
        run: python -m pip install cryptography

      - name: Verify DELTA proofs
        run: python src/delta_cli.py verify-all
```

---

## Security model

This workflow is verification-only.

It does not require:

- private keys
- private evidence
- secrets
- tokens
- backend services
- databases

It should only run against public proof artifacts that are safe to store in the repository.

Do not commit private payloads.

Do not commit private keys.

---

## Byte-exact checkout

DELTA public verifiers hash exact bytes.

For this reason, DELTA repositories should include:

```gitattributes
* -text
```

This disables Git CRLF/LF rewriting and prevents platform-specific checkout changes from breaking proof hashes.

---

## Current scope

This is the v1.1.0 MVP integration.

It is not yet the final reusable GitHub Marketplace action.

The current purpose is to make DELTA verification visible in CI and to provide a copy-paste workflow for early adopters.

Future work may add:

- reusable `uses:` action
- Pull Request comments
- generated proof artifacts
- CI evidence capture
- release checkpoint publishing
