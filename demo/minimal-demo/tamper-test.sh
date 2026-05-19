#!/usr/bin/env bash
set -euo pipefail

# DELTA Minimal Public Demo — Tamper Detection Walkthrough
#
# Security boundary:
# This is an educational onboarding demo. It is not a signed DELTA bundle verifier
# and it is not a substitute for full DELTA proof verification.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACT="$SCRIPT_DIR/sample-artifact.txt"
EXPECTED_HASH_FILE="$SCRIPT_DIR/sample-artifact.sha256"
RUN_DIR="$SCRIPT_DIR/.demo-run"
WORKING_ARTIFACT="$RUN_DIR/sample-artifact.txt"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print toupper($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print toupper($1)}'
  else
    echo "[FAIL] Neither sha256sum nor shasum is available." >&2
    exit 1
  fi
}

expected_hash() {
  awk '{print toupper($1)}' "$EXPECTED_HASH_FILE"
}

echo "=== DELTA Protocol Minimal Public Demo ==="
echo "Profile: hash-based tamper-detection walkthrough"
echo "Boundary: educational demo, not a signed DELTA bundle verifier"
echo

if [[ ! -f "$ARTIFACT" ]]; then
  echo "[FAIL] Missing sample artifact: $ARTIFACT"
  exit 1
fi

if [[ ! -f "$EXPECTED_HASH_FILE" ]]; then
  echo "[FAIL] Missing expected hash file: $EXPECTED_HASH_FILE"
  exit 1
fi

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
cp "$ARTIFACT" "$WORKING_ARTIFACT"

EXPECTED="$(expected_hash)"

echo "[1] Verifying original artifact"
ORIGINAL="$(sha256_file "$WORKING_ARTIFACT")"
echo "  Expected: $EXPECTED"
echo "  Observed: $ORIGINAL"

if [[ "$ORIGINAL" == "$EXPECTED" ]]; then
  echo "  [OK] Original artifact hash matches expected value."
else
  echo "  [FAIL] Original artifact hash mismatch."
  exit 1
fi

echo
echo "[2] Tampering with temporary working copy"
printf " " >> "$WORKING_ARTIFACT"
TAMPERED="$(sha256_file "$WORKING_ARTIFACT")"
echo "  Original expected hash: $EXPECTED"
echo "  Tampered observed hash: $TAMPERED"

echo
echo "[3] Verifying tampered artifact"
if [[ "$TAMPERED" != "$EXPECTED" ]]; then
  echo "  [FAIL] Tampered artifact hash mismatch detected."
  echo "  [OK] Demo succeeded: tampering was detected."
else
  echo "  [FAIL] Unexpected: tampered artifact still matches expected hash."
  exit 1
fi

echo
echo "[4] Optional full DELTA baseline command"
if [[ -f "$REPO_ROOT/src/delta_cli.py" ]]; then
  echo "  Repository root detected: $REPO_ROOT"
  echo "  Full reference verification command:"
  echo "  python src/delta_cli.py verify-all"
else
  echo "  Full DELTA repository root was not detected from this location."
fi

echo
echo "=== Demo complete ==="
echo "DELTA public message: cryptographic binding makes later tampering detectable."
