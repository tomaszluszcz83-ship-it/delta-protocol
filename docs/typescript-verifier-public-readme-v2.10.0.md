# DELTA Protocol — TypeScript Verifier Public README Refresh (v2.10.0)

Status: Documentation / public-readiness milestone  
Implementation path: `verifier/ts/README.md`

## 1. Purpose

v2.10.0 refreshes the public README for the TypeScript verifier.

After v2.9.0–v2.9.5, the TypeScript verifier has enough capability to be presented publicly, but it must be described precisely and without overclaiming.

This milestone makes `verifier/ts/README.md` suitable for external reviewers.

## 2. Scope

This release updates documentation only.

It does not add new cryptographic functionality and does not change verifier behavior.

## 3. What the refreshed README explains

The refreshed README explains:

- what the TypeScript verifier is,
- what it verifies today,
- what it does not verify,
- the security boundary,
- install and build commands,
- canonical JSON vector verification,
- JSON Schema verification,
- basic record verification,
- signed record demo verification,
- public `.delta` bundle verification,
- signed `.delta` bundle verification,
- full local check commands,
- safe public wording,
- claims to avoid,
- recommended next TypeScript milestones.

## 4. Public positioning

The README positions TypeScript as:

```text
experimental independent verifier
```

It keeps Python as:

```text
Alpha Reference Implementation
```

This distinction is important because TypeScript does not yet verify all proof-specific DELTA layers.

## 5. Security boundary

The README explicitly states that TypeScript does not prove:

- legal identity,
- signer authority,
- real-world truth,
- wallet ownership,
- regulatory compliance,
- trust validity,
- proof-specific validity of all contained bundle artifacts.

## 6. Why this matters

A verifier can be technically correct and still be misrepresented.

v2.10.0 reduces that risk by giving public users a clear entry point and exact boundaries.

## 7. Expected validation

Expected validation commands:

```powershell
cd verifier\ts
npm install
npm run build
npm run verify-vectors
npm run verify-schemas

cd ..\..
python src/delta_cli.py verify-all
python tools\delta_canonical_json.py verify-vectors --vectors tests\vectors\canonical-json\vectors.json
git diff --check
```
