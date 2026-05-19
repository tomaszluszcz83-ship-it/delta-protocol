# DELTA Protocol — Replay Environment Assumptions (v2.8.2)

Status: Documentation-only boundary milestone  
Scope: Proof of Replay assumptions, environment declaration, determinism levels, replay passed vs replay verified

## 1. Purpose

Proof of Replay is only meaningful when the replay environment is understood.

v2.8.2 documents the assumptions and boundaries around DELTA replay before adding new replay features.

This milestone answers:

- What does `replay passed` mean?
- What does `replay verified` mean?
- What must be declared about the replay environment?
- When is replay deterministic?
- When is replay only best-effort?
- When should a verifier return `manual_review`?
- What should future sensors record to improve replay confidence?

## 2. Core principle

DELTA replay does not prove that all possible environments would produce the same result.

It proves that a declared replay procedure was executed in a declared environment and produced a declared result.

A replay result MUST be interpreted together with:

- record hash,
- measurement method id,
- measurement method version,
- measurement method hash,
- replay instructions,
- tool versions,
- dependency versions,
- operating system,
- runtime version,
- container or environment declaration where available.

## 3. Replay passed vs replay verified

DELTA SHOULD distinguish:

```text
REPLAY_PASSED=True
REPLAY_ENVIRONMENT_VERIFIED=True|False|manual_review
```

`replay passed` means:

- the replay command executed,
- declared inputs were used,
- declared comparison rules were applied,
- output matched the expected result.

`replay verified` is stronger. It means:

- replay passed,
- the replay environment was verified against a declared environment profile,
- pinned dependencies/container/toolchain requirements were satisfied,
- the verifier policy accepted the environment.

A replay can pass while environment verification remains unknown or manual-review.

## 4. Determinism levels

Future DELTA replay profiles SHOULD describe determinism level separately from pass/fail.

### Level 0 — Same code and same data only

Weakest level.

Expected when:

- code and input artifacts are available,
- environment is not pinned,
- dependencies are not fully declared.

Interpretation:

```text
replay_mode=best_effort
environment_confidence=low
```

### Level 1 — Declared runtime and dependencies

Expected when:

- programming language/runtime version is declared,
- major dependency versions are declared,
- lockfiles may be present but are not fully enforced.

Example:

```json
{
  "environment_declaration": {
    "os": "Ubuntu 22.04",
    "python": "3.11.6",
    "dependencies": {
      "numpy": "1.26.0"
    },
    "container": null,
    "nix_hash": null,
    "timestamp": "2025-01-15T10:00:00Z"
  }
}
```

Interpretation:

```text
replay_mode=declared_environment
environment_confidence=medium
```

### Level 2 — Container-pinned replay

Expected when:

- container image is declared,
- immutable image digest is declared,
- dependency lockfiles are included or hashed,
- network policy is declared.

Recommended fields:

```text
container_image
container_image_digest
dependency_lockfile_hash
toolchain_version
network_policy
```

Interpretation:

```text
replay_mode=container_pinned
environment_confidence=high
```

### Level 3 — Hermetic replay

Strongest level in this document.

Expected when:

- Nix/Guix or equivalent hermetic build profile is declared,
- all dependencies are pinned,
- toolchain is pinned,
- network access is disabled or fully controlled,
- replay script and method are hashed.

Recommended fields:

```text
nix_flake_lock_hash
guix_manifest_hash
toolchain_hash
environment_manifest_hash
```

Interpretation:

```text
replay_mode=hermetic
environment_confidence=very_high
```

## 5. Replay modes

### 5.1 Deterministic replay

A replay MAY be considered deterministic when:

- the environment is pinned,
- dependencies are pinned,
- tool versions are pinned,
- inputs are fixed,
- timestamps/randomness/network calls are disabled or controlled,
- output comparison rules are explicit,
- the measurement method is versioned and hashed.

Recommended future environment anchors:

```text
container_image_digest
nix_flake_lock_hash
guix_manifest_hash
dependency_lockfile_hash
toolchain_hash
environment_manifest_hash
```

### 5.2 Best-effort replay

A replay SHOULD be labeled best-effort when:

- environment is not fully pinned,
- dependency resolution is dynamic,
- network access is involved,
- time/randomness can affect results,
- operating system differences may affect output,
- toolchain version is not recorded.

Best-effort replay can still be useful, but it is weaker than deterministic replay.

### 5.3 Manual-review replay

A replay SHOULD return or be documented as `manual_review` when:

- required environment metadata is missing,
- declared environment cannot be verified,
- replay instructions are ambiguous,
- output comparison is fuzzy,
- the measurement method is not versioned,
- external services affect the result,
- deprecation warnings or fallback behavior affect execution,
- a different OS/runtime/library version is used,
- the verifier cannot reproduce the environment,
- artifacts are available but policy cannot decide pass/fail.

## 6. Minimum environment declaration

Future DELTA replay-capable records SHOULD declare:

```json
{
  "replay_environment": {
    "profile": "delta_replay_environment_v2_8_2",
    "determinism_level": "L0|L1|L2|L3",
    "mode": "best_effort|declared_environment|container_pinned|hermetic|manual_review",
    "os": "windows|linux|macos|unknown",
    "runtime": {
      "python": "3.x",
      "node": null,
      "go": null,
      "rust": null
    },
    "dependencies": {},
    "dependency_lockfiles": [],
    "container": {
      "image": null,
      "digest": null
    },
    "nix": {
      "flake_lock_hash": null
    },
    "guix": {
      "manifest_hash": null
    },
    "environment_hash": null,
    "network_policy": "disabled|declared|required|unknown",
    "notes": "Environment metadata is informational in v2.8.2."
  }
}
```

This document does not require existing records to add this object retroactively.

## 7. Future `environment_hash`

A future DELTA implementation MAY define an `environment_hash`.

The hash SHOULD be computed over a canonical environment manifest, not over a vague human description.

Potential inputs:

- OS image digest,
- container image digest,
- lockfile hashes,
- toolchain versions,
- measurement method hash,
- replay script hash,
- selected environment variables,
- declared network policy.

Security warning: `environment_hash` only proves the declared manifest hash, not that the machine truly matched it unless additional attestation is used.

## 8. Replay result vocabulary

Future replay tools SHOULD distinguish:

```text
REPLAY_STATUS=passed
REPLAY_STATUS=failed
REPLAY_STATUS=manual_review
REPLAY_STATUS=not_reproducible
REPLAY_STATUS=environment_missing
REPLAY_STATUS=environment_mismatch
REPLAY_STATUS=method_missing
REPLAY_STATUS=unsupported
REPLAY_ENVIRONMENT_VERIFIED=True|False|manual_review
```

A simple `passed` status MUST NOT be interpreted as universal truth.

## 9. Security boundaries

Proof of Replay does not prove:

- legal truth,
- real-world truth,
- developer intent,
- human identity,
- regulatory compliance,
- that the original machine had the same environment,
- that the declared environment was actually used unless separately attested,
- that all future machines will reproduce the result,
- that hidden external services were unchanged,
- that the measurement method is correct for a business policy,
- that lack of difference means absence of bugs.

Replay proves a technical re-execution under declared conditions.

## 10. Relationship to conformance

DELTA-L2 replay-capable conformance SHOULD eventually require:

- replay instructions,
- method id and version,
- method hash,
- input artifact hashes,
- output comparison rules,
- environment declaration,
- determinism level,
- negative replay test,
- explicit unsupported/manual-review behavior.

## 11. Relationship to future work

This design prepares for:

- replay environment manifests,
- container/Nix/Guix profiles,
- replay conformance tests,
- signed replay environment attestations,
- CI/CD replay hardening,
- `tools/delta_replay_check_env.py`,
- ZK-friendly replay result commitments.
