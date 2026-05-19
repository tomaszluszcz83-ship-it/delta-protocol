# DELTA Minimal Public Demo — Tamper Detection Walkthrough
# This script demonstrates the most basic public-facing tamper-evidence principle:
# 1. Verify that a known artifact matches its expected SHA-256 digest.
# 2. Copy the artifact to a temporary working area.
# 3. Tamper with the temporary copy.
# 4. Verify that the tampered copy no longer matches the expected digest.
#
# Security boundary:
# This is an educational onboarding demo. It is not a signed DELTA bundle verifier
# and it is not a substitute for full DELTA proof verification.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$ArtifactPath = Join-Path $ScriptDir "sample-artifact.txt"
$ExpectedHashPath = Join-Path $ScriptDir "sample-artifact.sha256"
$RunDir = Join-Path $ScriptDir ".demo-run"
$WorkingArtifact = Join-Path $RunDir "sample-artifact.txt"

function Write-Step($Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Cyan
}

function Get-ExpectedHash {
    $line = Get-Content -Path $ExpectedHashPath -TotalCount 1
    return ($line -split "\s+")[0].Trim().ToUpperInvariant()
}

function Get-Sha256($Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

Write-Host "=== DELTA Protocol Minimal Public Demo ===" -ForegroundColor Cyan
Write-Host "Profile: hash-based tamper-detection walkthrough" -ForegroundColor Gray
Write-Host "Boundary: educational demo, not a signed DELTA bundle verifier" -ForegroundColor Gray

if (-not (Test-Path $ArtifactPath)) {
    Write-Host "[FAIL] Missing sample artifact: $ArtifactPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ExpectedHashPath)) {
    Write-Host "[FAIL] Missing expected hash file: $ExpectedHashPath" -ForegroundColor Red
    exit 1
}

if (Test-Path $RunDir) {
    Remove-Item -Recurse -Force $RunDir
}
New-Item -ItemType Directory -Force $RunDir | Out-Null
Copy-Item -Path $ArtifactPath -Destination $WorkingArtifact -Force

$ExpectedHash = Get-ExpectedHash

Write-Step "[1] Verifying original artifact"
$OriginalHash = Get-Sha256 $WorkingArtifact

Write-Host "  Expected: $ExpectedHash" -ForegroundColor Gray
Write-Host "  Observed: $OriginalHash" -ForegroundColor Gray

if ($OriginalHash -eq $ExpectedHash) {
    Write-Host "  [OK] Original artifact hash matches expected value." -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Original artifact hash mismatch." -ForegroundColor Red
    exit 1
}

Write-Step "[2] Tampering with temporary working copy"
Add-Content -Path $WorkingArtifact -Value " " -NoNewline
$TamperedHash = Get-Sha256 $WorkingArtifact

Write-Host "  Original expected hash: $ExpectedHash" -ForegroundColor Gray
Write-Host "  Tampered observed hash: $TamperedHash" -ForegroundColor Gray

Write-Step "[3] Verifying tampered artifact"
if ($TamperedHash -ne $ExpectedHash) {
    Write-Host "  [FAIL] Tampered artifact hash mismatch detected." -ForegroundColor Red
    Write-Host "  [OK] Demo succeeded: tampering was detected." -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Unexpected: tampered artifact still matches expected hash." -ForegroundColor Red
    exit 1
}

Write-Step "[4] Optional full DELTA baseline command"
$DeltaCli = Join-Path $RepoRoot "src\delta_cli.py"
if (Test-Path $DeltaCli) {
    Write-Host "  Repository root detected: $RepoRoot" -ForegroundColor Gray
    Write-Host "  Full reference verification command:" -ForegroundColor Gray
    Write-Host "  python src/delta_cli.py verify-all" -ForegroundColor Yellow
} else {
    Write-Host "  Full DELTA repository root was not detected from this location." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Demo complete ===" -ForegroundColor Cyan
Write-Host "DELTA public message: cryptographic binding makes later tampering detectable." -ForegroundColor Cyan
