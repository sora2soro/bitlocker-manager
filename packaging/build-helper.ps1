<#
  build-helper.ps1  — build the Unlock Helper into a single .exe

  Run this ONCE on a Windows machine that has Python 3.11+.
  It produces  dist\blm-helper.exe  — that single file is what you copy to
  operator PCs. Those PCs need NOTHING installed (no Python, no repo).

  Usage:
      cd bitlocker-manager
      powershell -ExecutionPolicy Bypass -File packaging\build-helper.ps1
#>

$ErrorActionPreference = "Stop"

# ensure we're at the repo root (so the relative paths in the .spec resolve)
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "==> Installing PyInstaller (into the current Python)..."
python -m pip install --upgrade pyinstaller

Write-Host "==> Building blm-helper.exe ..."
python -m PyInstaller --clean --noconfirm packaging\blm-helper.spec

$exe = Join-Path $repo "dist\blm-helper.exe"
if (Test-Path $exe) {
    Write-Host ""
    Write-Host "SUCCESS. Built: $exe" -ForegroundColor Green
    Write-Host "Copy that single file to each operator PC, then run packaging\install-helper.ps1 there."
} else {
    Write-Error "Build finished but dist\blm-helper.exe was not found."
}
