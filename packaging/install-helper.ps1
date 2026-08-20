<#
  install-helper.ps1 — install the Unlock Helper on an operator PC and make it
  start automatically at logon.

  Run this ONCE per operator PC (as that operator, or via your MDM/Intune).
  It does NOT need Python — it just places blm-helper.exe and registers a
  logon Scheduled Task so the helper is always listening on 127.0.0.1:8765.

  Usage (from the folder that contains blm-helper.exe):
      powershell -ExecutionPolicy Bypass -File install-helper.ps1

  Uninstall:
      powershell -ExecutionPolicy Bypass -File install-helper.ps1 -Uninstall
#>

param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$TaskName   = "BLM Unlock Helper"
$InstallDir = Join-Path $env:LOCALAPPDATA "BLMHelper"
$TargetExe  = Join-Path $InstallDir "blm-helper.exe"

if ($Uninstall) {
    schtasks /delete /tn "$TaskName" /f 2>$null
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    Write-Host "Unlock Helper removed." -ForegroundColor Yellow
    return
}

# 1. copy the exe into a stable per-user location
$sourceExe = Join-Path $PSScriptRoot "blm-helper.exe"
if (-not (Test-Path $sourceExe)) {
    Write-Error "blm-helper.exe not found next to this script. Build it first with build-helper.ps1 and copy both files here."
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $sourceExe $TargetExe

# 2. register a logon Scheduled Task (runs as the logged-in user, no admin rights needed to listen on localhost)
schtasks /create /tn "$TaskName" /tr "`"$TargetExe`"" /sc onlogon /f | Out-Null

# 3. start it now so the operator doesn't have to log out/in first
Start-Process -FilePath $TargetExe

Write-Host ""
Write-Host "Installed. The Unlock Helper is running and will auto-start at logon." -ForegroundColor Green
Write-Host "Verify: open http://127.0.0.1:8765/ in the browser — you should see {""status"":""ok"",...}."
