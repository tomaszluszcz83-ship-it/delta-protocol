# DELTA Protocol — Replay Environment Checker (v2.8.3)

Status: MVP executable environment checker  
Tool: `tools/delta_replay_check_env.py`  
Profile: `delta_replay_environment_check_v2_8_3`

## 1. Purpose

v2.8.2 documented replay environment assumptions.

v2.8.3 adds a small executable checker that turns those assumptions into a practical local procedure.

The checker can:

- declare the current local environment,
- check the current environment against a declaration,
- return `MATCH`, `MISMATCH`, or `MANUAL_REVIEW_REQUIRED`.

## 2. MVP scope

v2.8.3 supports:

- operating system family,
- Python version,
- selected Python package versions.

v2.8.3 does not support:

- Docker image digest verification,
- Nix verification,
- Guix verification,
- hardware attestation,
- network state verification,
- proof that the current environment equals the original execution environment.

Unsupported declared fields should lead to manual review.

## 3. Commands

Declare current environment:

```powershell
python tools\delta_replay_check_env.py declare `
  --out .delta\replay-env-tests\E-283\environment.json `
  --package cryptography `
  --python-version-mode major_minor_patch
```

Check current environment:

```powershell
python tools\delta_replay_check_env.py check `
  --env .delta\replay-env-tests\E-283\environment.json
```

Expected result for a matching environment:

```text
DELTA_REPLAY_ENV_CHECK=MATCH
DELTA_REPLAY_ENV_CHECK_OK=True
```

## 4. Status meanings

| Status | Meaning |
| --- | --- |
| `MATCH` | Supported declared fields match the current local environment. |
| `MISMATCH` | At least one supported declared field differs. |
| `MANUAL_REVIEW_REQUIRED` | Declaration is missing, incomplete, unknown, or contains unsupported fields. |

## 5. Security boundary

This tool does not prove legal truth or real-world truth.

It does not prove that the original execution environment was identical.

It does not prove that all future machines will reproduce the replay result.

It checks a local environment declaration only.

A replay may still require manual review even when supported fields match.

## 6. Relationship to v2.8.2

v2.8.2 defined:

- replay passed vs replay verified,
- determinism levels L0-L3,
- manual-review conditions,
- future environment hash direction.

v2.8.3 implements a small L1-style checker for local Python environments.

## 7. Future work

Future versions may add:

- container image digest checks,
- Nix/Guix profile checks,
- canonical environment manifest hashing,
- dependency lockfile hashing,
- signed replay environment attestations,
- conformance tests for replay environment status.
