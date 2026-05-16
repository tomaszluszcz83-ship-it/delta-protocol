# DELTA-0 AI Agent Proof Example

Proof of autonomous AI-agent work.

This example demonstrates how DELTA can prove that an AI agent performed a declared analytical task, produced an output, signed the Claim as Executor, and had the output reviewed by a Human Supervisor or QA Verification Key.

## Use case

An AI Data Analyst agent receives a task:

```text
Before: Q3 financial dataset and prompt
Action: AI agent anomaly analysis
After: AI-generated anomaly report
Evidence: agent execution trace hash
Executor: AI Agent X-77 Verification Key
Verifier: Human Supervisor / QA Verification Key
Result: reviewed AI Agent Proof
```

## Architecture

This example follows four rules:

1. The AI agent is the Executor.
2. `before_state.json` contains the raw prompt and input data.
3. `after_state.json` contains the AI agent output.
4. The Verifier represents a Human Supervisor or QA gate.

The private keys are generated in memory and are not written to disk.

## What this proves

The public verifier proves that:

- an AI-agent task was declared,
- the prompt and input data were wrapped into the before state,
- the AI output was wrapped into the after state,
- the AI agent key signed the Delta Claim,
- the execution trace was hashed and bound as evidence,
- the Human Supervisor / QA key signed the Attestation,
- the Ledger Entry binds the Claim, signatures, Attestation, and execution trace,
- the Signed Checkpoint commits to the Ledger Entry,
- the proof chain is tamper-evident.

## What this does not prove

This example does not prove:

- that the AI output is objectively true,
- that the AI had no hallucination risk,
- that the Human Supervisor cannot be wrong,
- legal or financial validity,
- real-world truth outside the signed records.

DELTA proves the cryptographic accountability chain.

It does not turn AI output into absolute truth.

## Run the verifier

From the repository root:

```bash
python examples/ai-agent-proof/ai_agent_public_verifier.py
```

Expected result:

```text
DELTA AI AGENT PROOF VERIFIER RESULT: OK
```

## Principle

Machine accountability by proof, not trust.
