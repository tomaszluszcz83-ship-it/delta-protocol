$ErrorActionPreference = "Stop"

$demoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$artifactPath = Join-Path $demoDir "sample-artifact.txt"
$hashPath = Join-Path $demoDir "sample-artifact.sha256"
$runDir = Join-Path $demoDir ".demo-run"
$workingCopy = Join-Path $runDir "sample-artifact.tampered.txt"

Write-Host "=== DELTA Protocol Minimal Public Demo ==="
Write-Host "Profile: hash-based tamper-detection walkthrough"
Write-Host "Boundary: educational demo, not a signed DELTA bundle verifier"
Write-Host ""

if (!(Test-Path $artifactPath)) {
    Write-Host "[FAIL] Missing sample artifact." -ForegroundColor Red
    exit 1
}

if (!(Test-Path $hashPath)) {
    Write-Host "[FAIL] Missing declared SHA-256 file." -ForegroundColor Red
    exit 1
}

$expectedHash = ((Get-Content -Raw $hashPath) -replace "\s+", "").ToUpperInvariant()
$observedHash = (Get-FileHash -Path $artifactPath -Algorithm SHA256).Hash.ToUpperInvariant()

Write-Host "[1] Verifying original artifact"
Write-Host "  Expected: $expectedHash"
Write-Host "  Observed: $observedHash"

if ($expectedHash -ne $observedHash) {
    Write-Host "  [FAIL] Original artifact hash does not match expected value." -ForegroundColor Red
    exit 1
}

Write-Host "  [OK] Original artifact hash matches expected value." -ForegroundColor Green
Write-Host ""

if (Test-Path $runDir) {
    Remove-Item -Recurse -Force $runDir
}

New-Item -ItemType Directory -Force $runDir | Out-Null
Copy-Item -Path $artifactPath -Destination $workingCopy -Force

Write-Host "[2] Tampering with temporary working copy"

# Write bytes explicitly to avoid shell-dependent newline behavior.
[System.IO.File]::AppendAllText($workingCopy, "TAMPERED", [System.Text.Encoding]::UTF8)

$tamperedHash = (Get-FileHash -Path $workingCopy -Algorithm SHA256).Hash.ToUpperInvariant()

Write-Host "  Original expected hash: $expectedHash"
Write-Host "  Tampered observed hash: $tamperedHash"
Write-Host ""

Write-Host "[3] Verifying tampered artifact"

if ($tamperedHash -eq $expectedHash) {
    Write-Host "  [FAIL] Tampering was not detected." -ForegroundColor Red
    exit 1
}

Write-Host "  [FAIL] Tampered artifact hash mismatch detected." -ForegroundColor Red
Write-Host "  [OK] Demo succeeded: tampering was detected." -ForegroundColor Green
Write-Host ""

Remove-Item -Recurse -Force $runDir -ErrorAction SilentlyContinue

Write-Host "=== Demo complete ==="
Write-Host "DELTA public message: cryptographic binding makes later tampering detectable."

exit 0
