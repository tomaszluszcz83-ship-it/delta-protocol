# DELTA Web Explorer v0.8.0 MVP

Static browser-only verifier for DELTA Protocol JSON artifacts.

## Purpose

DELTA Web Explorer gives non-technical users a visual way to verify public DELTA artifacts:

- `claim.json` + `executor_signature.json`
- `attestation.json` + `verifier_signature.json`
- `ledger_entry.json`
- `checkpoint.json`

The page runs in the browser and does not upload user JSON to a backend.

## Files

```text
docs/
  index.html
  app.js
  style.css
  README.md
```

## GitHub Pages

Use repository settings:

```text
Settings → Pages → Build and deployment → Source: Deploy from a branch
Branch: main
Folder: /docs
```

## Security model

- No backend
- No account
- No token
- No database
- No upload endpoint
- No analytics
- No forms
- No cookies
- No `fetch`
- No `XMLHttpRequest`
- No `navigator.sendBeacon`

The MVP imports pinned browser modules from CDN:

- `@noble/ed25519`
- `@noble/hashes`
- `fast-json-stable-stringify`

For production hardening, vendor these dependencies under `docs/vendor/` and pin exact checksums.

## Verification model

The explorer canonicalizes JSON, hashes canonical bytes with SHA-256, and verifies Ed25519 signatures over canonical JSON bytes.

For a payload/signature pair, it checks:

- `protocol_version`
- `type`
- `role`
- `target_type`
- `target_hash`
- `public_key`
- Ed25519 signature validity

For bundle consistency, it checks:

- attestation target hashes match claim artifacts
- ledger hashes match claim and attestation artifacts
- optional checkpoint head hash matches ledger entry hash

## Notes

This is v0.8.0 MVP. It is intentionally minimal and technical.
