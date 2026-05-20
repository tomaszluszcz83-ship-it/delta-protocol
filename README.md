# DELTA Protocol
## Public demo and reviewer entry point

DELTA Protocol is now entering a public adoption and external-review phase.

New reviewers, developers, auditors, CI/CD maintainers, software supply-chain engineers, security researchers, protocol reviewers, and early integrators should start here:

[![DELTA Minimal Public Demo](https://img.shields.io/github/actions/workflow/status/tomaszluszcz83-ship-it/delta-protocol/delta-minimal-demo.yml?branch=main&label=CI%20tamper%20demo&logo=github)](https://github.com/tomaszluszcz83-ship-it/delta-protocol/actions/workflows/delta-minimal-demo.yml)

### See DELTA in action

- **Run the minimal local demo:** [`demo/minimal-demo/`](demo/minimal-demo/)
- **Watch automated tamper detection in CI:** [`.github/workflows/delta-minimal-demo.yml`](.github/workflows/delta-minimal-demo.yml)
- **Read the quick-start path:** [`docs/quickstart/quickstart-v2.16.2.md`](docs/quickstart/quickstart-v2.16.2.md)
- **Review the protocol methodically:** [`docs/review/REVIEWER_CHECKLIST.md`](docs/review/REVIEWER_CHECKLIST.md)
- **Submit external review feedback:** [`docs/review/EXTERNAL_REVIEW_REQUEST.md`](docs/review/EXTERNAL_REVIEW_REQUEST.md)

### What the public demo proves

The minimal public demo demonstrates one intentionally narrow foundation of Proof of Change:

```text
known artifact hash → verification OK → tamper → hash mismatch → tampering detected
```

This is not presented as full DELTA signed bundle verification.

It does not claim Ed25519 verification, full `.delta` bundle verification, complete record-chain verification, legal identity, signer authority, regulatory compliance, real-world truth, evidence completeness, policy correctness, institutional approval, or business authority.

It demonstrates the foundational principle that cryptographic binding makes later tampering detectable.

**The internet can prove ownership. DELTA proves change.**

**DELTA Web Explorer:** https://tomaszluszcz83-ship-it.github.io/delta-protocol/

DELTA-0 is a zero-token cryptographic **Proof-of-Change** protocol for verifiable digital actions.

It provides a portable record chain:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

DELTA is not a cryptocurrency, token, marketplace, SaaS platform, or user-account system.

It is a cryptographic protocol and reference implementation for creating, verifying, and publishing tamper-evident records of declared digital change.

---

## What DELTA Proves

DELTA proves cryptographic consistency.

A valid DELTA proof can show that:

- a `Claim` was signed by an `Executor` key,
- an `Attestation` was signed by a `Verifier` key,
- a `Ledger Entry` binds the Claim and Attestation hashes,
- a `Signed Checkpoint` commits to a ledger head,
- the presented proof objects have not been modified without detection.

DELTA does **not** prove absolute truth about the physical world.

DELTA does not prove that:

- a human statement is true,
- private evidence was not fabricated before hashing,
- an AI output is factually correct,
- a compromised key was not misused before revocation,
- a legal or compliance conclusion is automatically valid.

This boundary is intentional.

DELTA is a cryptographic accountability layer, not a magic truth machine.

---

## Public Web Explorer

The DELTA Web Explorer verifies public DELTA JSON artifacts directly in the browser:

https://tomaszluszcz83-ship-it.github.io/delta-protocol/

Security model:

- no backend,
- no account system,
- no token,
- no database,
- no JSON upload endpoint,
- browser-side verification.

The Web Explorer verifies detached signature pairs such as:

```text
claim.json + executor_signature.json
attestation.json + verifier_signature.json
checkpoint.json + checkpoint_signature.json
```

It can also check public hash consistency across:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

---

## Fresh Clone Quick Start

Use this path when testing DELTA from a clean machine.

```bash
git clone https://github.com/tomaszluszcz83-ship-it/delta-protocol.git
cd delta-protocol
python -m pip install cryptography
python src/delta_cli.py verify-all
```

Expected result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK
DELTA CLI RESULT: OK
```

No local keys are required for `verify-all`. The command verifies the public examples included in the repository.

---

## CLI Version

```bash
python src/delta_cli.py version
```

Example output:

```text
DELTA CLI v0.7.0-write-mode
Protocol: DELTA-0
Repository root: ...
```

---

## Create a Claim

The minimal write flow begins with a local Executor key and a Claim.

### Bash / macOS / Linux / Git Bash

```bash
python src/delta_cli.py keygen --name demo-executor
python src/delta_cli.py claim \
  --before-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  --action "demo change" \
  --after-hash sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  --evidence-hash sha256:3333333333333333333333333333333333333333333333333333333333333333 \
  --key ~/.delta/keys/demo-executor.ed25519.private.pem \
  --out-dir ./demo-claim
```

### Windows PowerShell

```powershell
python src/delta_cli.py keygen --name demo-executor
$keyPath = "$env:USERPROFILE\.delta\keys\demo-executor.ed25519.private.pem"
python src/delta_cli.py claim `
  --before-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 `
  --action "demo change" `
  --after-hash sha256:2222222222222222222222222222222222222222222222222222222222222222 `
  --evidence-hash sha256:3333333333333333333333333333333333333333333333333333333333333333 `
  --key $keyPath `
  --out-dir .\demo-claim
```

This produces:

```text
demo-claim/
claim.json
executor_signature.json
```

The private key is not printed to the screen.

By default, keys are written outside the repository under:

```text
~/.delta/keys/
```

On Windows:

```text
%USERPROFILE%\.delta\keys\
```

Do not commit private keys.

---

## Full Write Mode

DELTA CLI v0.7.0 supports the full local proof-generation flow:

```text
keygen -> claim -> attest -> ledger -> checkpoint
```

The flow produces the complete DELTA-0 proof chain:

```text
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

The core object model is:

```text
Claim -> Attestation -> Ledger Entry -> Signed Checkpoint
```

### 1. Key Generation

```bash
python src/delta_cli.py keygen --name demo-executor
python src/delta_cli.py keygen --name demo-verifier --role verifier
python src/delta_cli.py keygen --name demo-checkpoint-signer --role checkpoint-signer
```

### 2. Claim

A Claim is created by an Executor and signed through a detached Executor signature envelope.

```text
claim.json
executor_signature.json
```

### 3. Attestation

An Attestation is created by a Verifier after verifying the Executor signature.

```text
attestation.json
verifier_signature.json
```

### 4. Ledger Entry

A Ledger Entry binds the hashes of the Claim, Executor signature, Attestation, and Verifier signature.

```text
ledger_entry.json
```

A Ledger Entry is hash-chain data only. It is not signed in DELTA-0.

The first entry uses:

```text
GENESIS_PREV_ENTRY_HASH = sha256:0000000000000000000000000000000000000000000000000000000000000000
```

The canonical timestamp field for ledger inclusion is:

```text
included_at
```

### 5. Signed Checkpoint

A Signed Checkpoint commits to a ledger head.

```text
checkpoint.json
checkpoint_signature.json
```

The canonical timestamp field for checkpoint publication is:

```text
published_at
```

---

## Developer Adoption Examples

DELTA includes three public adoption examples covering code, business privacy, and AI accountability.

| Example | Path | What it demonstrates |
|---|---|---|
| Code Change Proof | `examples/code-change-proof/` | Git & CI/CD proof of a code change |
| Private Payload Proof | `examples/private-payload-proof/` | Blind Auditing / NDA proof without exposing private bytes |
| AI Agent Proof | `examples/ai-agent-proof/` | Machine Accountability & AI Executions |

Run all public verifiers through the DELTA CLI:

```bash
python src/delta_cli.py verify-all
```

Expected result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK
DELTA CLI RESULT: OK
```

---

## Formal Specification

The DELTA-0 formal specification is in:

- [DELTA-0 Yellow Paper](docs/spec/DELTA-0-yellow-paper.md)
- [Threat Model](docs/spec/threat-model.md)
- [Canonicalization Rules](docs/spec/canonicalization.md)
- [Cryptographic Structures](docs/spec/cryptographic-structures.md)

The specification freezes the DELTA-0 terminology and core structures:

```text
Claim
Executor
Attestation
Verifier
Ledger Entry
Signed Checkpoint
Checkpoint Signer
Detached Signature
Evidence Hash
Canonical JSON
Proof without exposure
Identity by proof, not exposure
```

Legacy or experimental fields are not part of DELTA-0:

```text
claim_id
recorded_at
checkpointed_at
embedded signatures inside payload objects
```

---

## Cryptographic Model

DELTA-0 uses:

```text
SHA-256
Ed25519
Canonical JSON bytes
Detached signature envelopes
```

Payload objects are signed as:

```text
signature = Ed25519.sign(canonical_json_bytes(payload))
```

The signature input is the canonical JSON bytes of the payload, not a prehashed digest.

A detached signature envelope stores:

```text
target_hash = sha256(canonical_json_bytes(payload))
```

The target hash binds the signature envelope to the payload and prevents substitution attacks.

---

## Canonical JSON

All DELTA JSON objects are hashed and signed using deterministic canonical JSON bytes.

Reference Python behavior:

```text
json.dumps(
  object,
  sort_keys=True,
  separators=(",", ":"),
  ensure_ascii=False,
  allow_nan=False
).encode("utf-8")
```

DELTA-0 intentionally rejects floating-point values in cryptographic structures. This avoids cross-language determinism failures involving float rendering, `NaN`, `Infinity`, and platform-specific numeric behavior.

JSON files must be encoded as UTF-8 without BOM.

---

## Proof Without Exposure

DELTA supports private evidence through hash commitments.

A party can publish:

```text
evidence_hash
claim.json
executor_signature.json
attestation.json
verifier_signature.json
ledger_entry.json
checkpoint.json
checkpoint_signature.json
```

without publishing the private evidence bytes.

Later, the private evidence can be disclosed to an authorized party. If the recomputed hash matches the public `evidence_hash`, the evidence is cryptographically bound to the original proof.

This is a privacy-preserving hash-commitment model.

It is not a general-purpose zero-knowledge proof system.

---

## Identity by Proof, Not Exposure

DELTA-0 does not require publishing private identity documents.

A public key can be associated with an organization or system through external proof channels such as:

- DNS TXT records,
- certificates,
- signed statements,
- registries,
- legal agreements,
- procurement or compliance records.

The CLI key generation command prints a DNS TXT preparation hint:

```text
delta-pubkey=
```

This prepares the protocol for future PKI layers without requiring user accounts or centralized identity.

---

## Repository Map

```text
src/
  delta_cli.py                  # DELTA CLI verifier and Write Mode
examples/
  code-change-proof/            # Git & CI/CD proof example
  private-payload-proof/        # Blind auditing / NDA example
  ai-agent-proof/               # Machine accountability example
docs/
  index.html                    # DELTA Web Explorer for GitHub Pages
  app.js
  style.css
  spec/
    DELTA-0-yellow-paper.md
    threat-model.md
    canonicalization.md
    cryptographic-structures.md
```

---

## Release Milestones

```text
v0.5.2-genesis-rc
v0.5.3-code-change-proof
v0.5.4-evidence-line-endings
v0.6-alpha-cli
v0.6.1-private-payload-proof
v0.6.2-adoption-readme
v0.6.2-ai-agent-proof
v0.7-alpha-keygen
v0.7-alpha-claim
v0.7-alpha-attest
v0.7.0-write-mode-complete
v0.8.0-web-explorer-mvp
v0.9.0-yellow-paper
```

---

## v1.0-RC Fresh Clone Test

Before tagging a v1.0 release candidate, run:

```bash
cd <workspace>
git clone https://github.com/tomaszluszcz83-ship-it/delta-protocol.git
cd delta-protocol
python -m pip install cryptography
python src/delta_cli.py verify-all
```

Expected result:

```text
Genesis verifier: OK
Code Change Proof verifier: OK
Private Payload Proof verifier: OK
AI Agent Proof verifier: OK
DELTA CLI RESULT: OK
```

This test ensures the repository is portable and does not rely on hidden local state.

---

## Status

DELTA-0 currently includes:

- a cryptographic core,
- public verification examples,
- CLI verification,
- CLI Write Mode,
- browser-only Web Explorer,
- formal Yellow Paper and specification draft.

Current direction:

```text
v1.0 Release Candidate Polish & Audit
No new cryptographic features
```

---

## License

License information is defined by the repository license file if present.
