# DELTA-0 Code Change Proof Example

This example demonstrates how DELTA can prove a code change using Git commit hashes and CI test logs.

## Use case

A developer fixed a failing payment validation test.

## DELTA mapping

Before:

Git commit before the fix:

1111111111111111111111111111111111111111

Action:

Fixed payment gateway timeout validation logic.

After:

Git commit after the fix:

2222222222222222222222222222222222222222

Evidence:

examples/code-change-proof/evidence/test_results.log

The evidence file contains the CI-style test result showing:

FAIL -> PASS

Verifier:

Local CI Server Verification Key

## Why this matters

This example shows how DELTA can work above Git and CI/CD.

Git proves code history.

CI proves test execution.

DELTA binds the declared change, evidence hash, executor, verifier, and ledger record into a tamper-evident Proof of Change.

## Status

This is an adoption example for DELTA-0 v0.5.3.

It does not replace the DELTA-0 Genesis Release Candidate v0.5.2.

The Genesis release remains unchanged.
