# DELTA Protocol — Proof of Replay Boundary (v2.8.2)

Status: Documentation-only boundary statement

## 1. Purpose

This document defines the boundary of DELTA Proof of Replay.

It should be read together with:

- `docs/replay/replay-environment-assumptions-v2.8.2.md`
- `docs/standard/conformance-levels-v2.6.2.md`
- `docs/security/security-boundaries-v2.5.4.md`

## 2. What Proof of Replay can prove

A successful replay can prove that:

- a verifier executed declared replay instructions,
- the replay used declared inputs,
- the replay used a declared measurement method,
- after executing the same declared steps on the same declared starting state, the expected ending state was obtained,
- expected evidence/output hashes matched according to declared comparison rules,
- the replay result is linked to a specific DELTA record hash.

With stronger environment metadata, replay can additionally support stronger reproducibility claims.

## 3. What Proof of Replay cannot prove

Proof of Replay does not prove:

- that the original human action was authorized,
- that the original business decision was correct,
- that the original environment was identical,
- that the replay environment was identical unless separately verified,
- that external services were unchanged,
- that the code has no vulnerabilities,
- that all tests were meaningful,
- that lack of difference means lack of bugs,
- that the artifact is legally compliant,
- that a regulator will accept the result,
- that a private ticket or intent statement is true,
- that the same result will occur forever.

## 4. Replay status and trust status are separate

A record can be:

```text
REPLAY_STATUS=passed
TRUST_STATUS=not_trusted
```

Example: replay passes, but the signing key was later revoked.

A record can also be:

```text
REPLAY_STATUS=manual_review
CRYPTO_SIGNATURE_VALID=True
```

Example: the record signature is valid, but the replay environment is not sufficiently declared.

A record can also be:

```text
REPLAY_PASSED=True
REPLAY_ENVIRONMENT_VERIFIED=False
```

Example: output matched, but the verifier could not prove that the environment matched the declaration.

## 5. Recommended verifier behavior

A verifier SHOULD fail closed or return `manual_review` when:

- replay method is missing,
- replay instructions are missing,
- environment is missing for a policy that requires it,
- declared environment cannot be verified,
- dependency lockfiles are missing,
- output comparison rules are missing,
- external network calls are required but not declared,
- sensor uses timestamp, random data, external API, or hardware state without control,
- replay completes with warnings that may affect output,
- method hash mismatch occurs,
- replay output differs from expected result.

## 6. Policy examples

### 6.1 Public open-source project

A project may accept best-effort replay if:

- dependencies are public,
- code is public,
- risk is low,
- output comparison is simple.

### 6.2 Enterprise audit

An enterprise policy SHOULD require:

- pinned container digest or equivalent,
- dependency lockfile hashes,
- toolchain versions,
- signed intent,
- signed bundle,
- revocation checks,
- audit evidence commitments.

### 6.3 Regulated workflow

A regulated workflow SHOULD treat replay as one technical input only.

It should not treat replay as a legal compliance certificate.

## 7. Replay and private evidence

Replay may depend on private evidence.

If private evidence cannot be disclosed, replay may be limited to:

- evidence hash verification,
- auditor-side replay,
- encrypted evidence package checks,
- zero-knowledge or commitment-based future workflows.

This does not weaken the boundary: public replay cannot claim to have executed private inputs it did not receive.

## 8. Future recommended fields

Future replay-capable records SHOULD consider:

```json
{
  "replay": {
    "replay_profile": "delta_replay_vNext",
    "environment_profile": "delta_replay_environment_v2_8_2",
    "replay_mode": "deterministic|best_effort|manual_review",
    "determinism_level": "L0|L1|L2|L3",
    "method_id": "string",
    "method_version": "string",
    "method_hash": "sha256:...",
    "instructions_hash": "sha256:...",
    "environment_hash": "sha256:...",
    "output_comparison": "exact_hash|normalized_text|policy_specific",
    "network_policy": "disabled|declared|required|unknown"
  }
}
```

## 9. Boundary of responsibility

DELTA does not provide the environment by itself.

DELTA can verify declarations, hashes, signatures, and replay outputs.

The user/operator must provide or reference the required environment.

Future profiles may add container, Nix, Guix, or remote attestation integrations, but those are out of scope for v2.8.2.

## 10. Security boundary statement

A DELTA replay result is evidence of technical reproducibility under declared conditions.

It is not a replacement for:

- legal review,
- security audit,
- policy approval,
- identity verification,
- key revocation checks,
- trust ledger checks,
- audit evidence review.
