# DELTA Minimal Public Demo — Tamper Detection Walkthrough

## Purpose

This directory provides a deliberately small public demonstration artifact for DELTA Protocol.

The goal is to let a first-time reviewer observe, in approximately two minutes, the most basic tamper-evidence principle behind Proof of Change:

```text
known artifact hash -> verification OK -> modify artifact -> hash mismatch -> verification FAIL
```

This demonstration is intentionally minimal. It is designed as an onboarding and communication artifact, not as a replacement for the full DELTA verifier stack.

## What this demo proves

This demo proves that a declared SHA-256 digest of a known artifact changes when the artifact is modified, even by a very small edit.

It demonstrates the core intuition that DELTA builds on: once evidence, records, bundles, signatures, commitments, and verification results are bound to cryptographic hashes, later tampering becomes detectable.

## What this demo does not prove

This demo does not prove:

- legal identity,
- signer authority,
- regulatory compliance,
- real-world truth,
- sensor honesty,
- evidence completeness,
- policy correctness,
- legal validity,
- organizational approval,
- full `.delta` bundle validity,
- Ed25519 signature validity,
- canonical JSON correctness,
- full DELTA proof-layer correctness.

This is intentional.

The full DELTA repository contains the deeper reference verifiers, schema documents, canonical JSON vectors, proof-layer documentation, TypeScript verifier profiles, signed bundle verification tools, reviewer checklist, and external review request.

## Files

| File | Purpose |
|---|---|
| `sample-artifact.txt` | Small public demo artifact. |
| `sample-artifact.sha256` | Expected SHA-256 digest for the artifact. |
| `demo-manifest.json` | Machine-readable description of the demo boundary. |
| `verify.ps1` | PowerShell demonstration script for Windows. |
| `tamper-test.sh` | Bash demonstration script for Linux/macOS. |

## Run on Windows PowerShell

From the repository root:

```powershell
cd demo\minimal-demo
powershell -ExecutionPolicy Bypass -File .\verify.ps1
```

Expected result:

```text
[OK] Original artifact hash matches expected value.
[FAIL] Tampered artifact hash mismatch detected.
[OK] Demo succeeded: tampering was detected.
```

The script uses a temporary working copy under `.demo-run/` and does not modify the tracked `sample-artifact.txt`.

## Run on Linux or macOS

From the repository root:

```bash
cd demo/minimal-demo
chmod +x tamper-test.sh
./tamper-test.sh
```

Expected result:

```text
[OK] Original artifact hash matches expected value.
[FAIL] Tampered artifact hash mismatch detected.
[OK] Demo succeeded: tampering was detected.
```

## Optional DELTA baseline verification

When run from inside this repository, the scripts attempt to locate the repository root and may also show the command used for the full DELTA baseline verifier:

```text
python src/delta_cli.py verify-all
```

That baseline verifier belongs to the DELTA reference implementation. This minimal demo is only the public onboarding layer.

## Expected SHA-256

```text
29167171bdf30c5e9cbfa7cf2c7b389b30646e9187535f3ad944e65d96e3cc83
```

## Public communication boundary

When presenting this demo publicly, describe it as:

> a minimal public tamper-detection walkthrough demonstrating the hash-binding intuition behind DELTA.

Do not describe it as:

> a complete signed DELTA bundle verification,
> a legal proof,
> a compliance proof,
> a proof of signer authority,
> or a production audit artifact.

DELTA’s credibility depends on preserving this distinction.
