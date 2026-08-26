<#
  install-helper.ps1 — install the Unlock Helper on an operator PC and make it
  start automatically at logon.

  Run this ONCE per operator PC. Easiest: double-click install-helper.cmd
  (which runs this with the right execution policy). Or run directly:
      powershell -ExecutionPolicy Bypass -File install-helper.ps1

  It does NOT need Python — it places blm-helper.exe and registers a logon
  Scheduled Task so the helper is always listening on 127.0.0.1:8765.

  Uninstall:
      powershell -ExecutionPolicy Bypass -File install-helper.ps1 -Uninstall
#>

param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$TaskName   = "BLM Unlock Helper"
$InstallDir = Join-Path $env:LOCALAPPDATA "BLMHelper"
$TargetExe  = Join-Path $InstallDir "blm-helper.exe"

function Fail($msg) { Write-Host "FAILED: $msg" -ForegroundColor Red; exit 1 }

if ($Uninstall) {
    schtasks /delete /tn "$TaskName" /f 2>$null | Out-Null
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    Write-Host "Unlock Helper removed." -ForegroundColor Yellow
    return
}

# --- 1. locate the exe shipped alongside this script ----------------------
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$sourceExe = Join-Path $scriptDir "blm-helper.exe"
if (-not (Test-Path $sourceExe)) {
    Fail "blm-helper.exe was not found next to this script (looked in $scriptDir). Unzip BOTH files into the same folder and run again."
}

# --- 2. copy the exe into a stable per-user location ----------------------
try {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force $sourceExe $TargetExe
} catch {
    Fail "could not copy the helper to $InstallDir. $_"
}

# --- 3. register the logon Scheduled Task, and CHECK it worked ------------
# schtasks is a native program: PowerShell's -ErrorAction Stop does NOT catch
# its failures, so we must inspect $LASTEXITCODE ourselves and then verify the
# task actually exists. (This is the bug the old installer had — it reported
# success even when task creation silently failed.)
schtasks /create /tn "$TaskName" /tr "`"$TargetExe`"" /sc onlogon /f 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "schtasks could not create the auto-start task (exit $LASTEXITCODE). If this PC restricts task creation, run this installer as Administrator."
}
# verify it's really there
schtasks /query /tn "$TaskName" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "the auto-start task was not found after creation. Auto-start is NOT set up."
}

# --- 4. start it now so the operator doesn't have to log out/in first -----
Start-Process -FilePath $TargetExe

Write-Host ""
Write-Host "SUCCESS — Unlock Helper installed and running." -ForegroundColor Green
Write-Host "  * Auto-start task '$TaskName' is registered (verified)."
Write-Host "  * It will relaunch automatically at every logon."
Write-Host "  * Verify now: open http://127.0.0.1:8765/ — you should see status ok."
