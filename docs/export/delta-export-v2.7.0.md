# DELTA v2.7.0 — Export Report

**Status:** Draft implementation profile  
**Scope:** UX / adoption helper  
**Tool:** `tools/delta_export.py`

## 1. Purpose

`delta_export.py` generates a self-contained Markdown or HTML technical report from an existing DELTA record.

The goal is to make DELTA proofs easier to share with reviewers, customers, auditors, maintainers, and managers without adding new cryptographic proof functionality.

## 2. Security Boundary

The export report is not a legal certificate and is not a regulatory attestation.

The export tool does **not**:

- sign new records;
- verify signatures;
- perform replay;
- decrypt audit evidence;
- verify wallet signatures;
- verify Bitcoin BIP-322 cryptographically;
- prove legal truth;
- prove real-world truth;
- prove identity;
- prove wallet balance;
- prove regulatory compliance.

The report summarizes visible metadata and computes the canonical hash of the supplied record using the DELTA Canonical JSON Profile v1 (`delta_jcs_json_v1`).

Dedicated verifier commands are still required for cryptographic verification.

## 3. Supported Formats

v2.7.0 supports:

- `markdown`
- `html`

The HTML output is self-contained and intentionally simple. It is a readable technical report, not a browser-based cryptographic verifier.

## 4. Example: Markdown Export

```powershell
python tools\delta_export.py export `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --format markdown `
  --out .delta\exports\delta-report.md
```

Expected output:

```text
DELTA_EXPORT_OK=True
DELTA_EXPORT_FORMAT=markdown
DELTA_EXPORT_OUT=.delta\exports\delta-report.md
DELTA_EXPORT_RECORD_HASH=sha256:...
DELTA_EXPORT_CANONICAL_PROFILE=delta_jcs_json_v1
DELTA_EXPORT_SECURITY_BOUNDARY=technical_report_not_legal_certificate
```

## 5. Example: HTML Export

```powershell
python tools\delta_export.py export `
  --record C:\Users\PC\Desktop\DELTA-V1-6-RECORDS\F-001\delta-sensor-record-file-audit\delta-record.json `
  --format html `
  --out .delta\exports\delta-report.html
```

## 6. Report Contents

The report includes:

- report generation status;
- record path;
- full canonical record hash;
- canonical JSON profile;
- basic record metadata;
- detected proof-layer field categories;
- verification command hints;
- what the report supports;
- what the report does not prove;
- Bitcoin external proof boundary.

## 7. Bitcoin External Boundary

For `bitcoin_bip322_external_v1`, DELTA external mode remains:

```text
shape_only / external_pending
CRYPTO_SIGNATURE_VERIFIED=False
```

The export report MUST NOT imply local cryptographic Bitcoin BIP-322 verification.

## 8. Future Work

Future DELTA export milestones may add:

- bundled proof packages;
- embedded verification summaries;
- detached signature checks;
- static browser verification;
- client/auditor certificate templates;
- ZK provenance report sections.

Those features are out of scope for v2.7.0.
