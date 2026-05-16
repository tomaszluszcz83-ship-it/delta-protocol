# DELTA GitHub Action Example

This example shows the minimal CI integration for DELTA verification.

The objective is to make DELTA visible where developers already work:

```text
push -> pull request -> CI -> DELTA Verify
```

---

## Minimal workflow

Create:

```text
.github/workflows/delta-verify.yml
```

with:

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

## Expected output

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK

DELTA CLI RESULT: OK
```

---

## What this gives a project

A project gets a visible CI signal:

```text
DELTA Verify: passing
```

That signal means the public DELTA proof artifacts in the repository are still cryptographically consistent.

---

## What this does not do yet

This MVP does not yet:

- generate new Claims automatically
- sign with CI secrets
- create Pull Request comments
- publish checkpoints
- act as a GitHub Marketplace action

Those are later adoption steps.

This first step is intentionally small:

```text
make verification visible
```
