# DELTA ZK — Public Inputs vs Private Witness (v2.16.0)

Status: Design document  
Scope: Field classification for future ZK statements

## 1. Purpose

This document classifies which DELTA fields should be public inputs and which should remain private witnesses in the first ZK provenance model.

## 2. Public inputs

Public inputs are values visible to the verifier.

| Field | Source | Why public |
|---|---|---|
| `evidence_merkle_root` | v2.15.0 public package | Main public commitment to a private evidence set |
| `policy_id` or `policy_hash` | Policy artifact | Identifies which policy the private evidence claims to satisfy |
| `record_hash` | DELTA record | Binds proof to a DELTA Proof of Change record |
| `commitment_method_id` | v2.14/v2.15 profile | Prevents ambiguity in commitment computation |
| `leaf_method_id` | v2.15 profile | Prevents ambiguity in Merkle leaf computation |
| `tree_method_id` | v2.15 profile | Prevents ambiguity in Merkle node computation |
| `verification_context_hash` | Optional context | Binds proof to specific verifier assumptions |
| `proof_profile` | ZK profile | Identifies proving statement and version |
| `public_nonce` | Optional | Prevents replay/reuse in interactive or session-bound contexts |

## 3. Private witness

Private witness values are known to the prover but not revealed to the public verifier.

| Field | Source | Why private |
|---|---|---|
| `raw_evidence` | Private evidence file/log/data | Sensitive evidence should not be disclosed |
| `evidence_hash` | Private opening | Can reveal linkage if public |
| `salt` | Private opening | Must remain private to preserve hiding property |
| `label` | Private opening or public package depending profile | May reveal sensitive file/log names |
| `commitment` | Public or private depending granularity | Can be public if selective disclosure is acceptable |
| `leaf_hash` | Public or private depending granularity | Can reveal set membership metadata |
| `merkle_path` | Private opening | May reveal position/structure |
| `policy_relevant_fields` | Parsed private evidence | Sensitive values used by the circuit |
| `private_ticket_id` | Internal system | Should not be revealed publicly |
| `private_server_name` | Internal system | Should not be revealed publicly |
| `private_employee_or_runner_id` | Internal system | Should not be revealed publicly |

## 4. Public metadata leakage risks

Public inputs can leak metadata.

Examples:

```text
evidence_merkle_root alone does not reveal evidence,
but leaf_count may reveal how many evidence items exist.

policy_id may reveal what kind of control was evaluated.

record_hash may link proof to a public incident/change.
```

Mitigation options:

```text
- use policy_hash rather than human-readable policy_id when needed
- avoid publishing leaf_count in ZK-specific public inputs unless necessary
- bind proof to a context hash rather than verbose context fields
- define privacy profiles
```

## 5. Minimal public input profile

The first ZK PoC should use:

```text
proof_profile
evidence_merkle_root
policy_hash
record_hash
commitment_method_id
leaf_method_id
tree_method_id
```

## 6. Minimal private witness profile

The first ZK PoC should use:

```text
raw_evidence_value_or_simplified_field
salt
label_hash
commitment
leaf_hash
merkle_path
policy_threshold_or_expected_value
```

## 7. Rule

A field should be public only if the verifier needs it to validate the statement.

Everything else should be private or hashed into a context value.
