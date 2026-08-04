<#
  BitLocker Manager — field agent (M4)
  ------------------------------------
  PowerShell agent for fast field iteration (production target: signed .NET service + mTLS).

  Actions:
    provision : fetch the recovery key for an open checkout and write it onto the Pico
                (auto-detects the Pico by its CIRCUITPY volume label).
    rotate    : run ON an unlocked target — mint a new recovery key, drop the old, report it.
    wipe      : clear the key off the Pico.
    close     : close the checkout (needs wiped + rotated).
    login     : obtain an operator token (used by 'close').

  The key travels vault -> Pico -> target only. It is never printed to the console.

  Examples:
    .\blm-agent.ps1 provision -CheckoutId <id> -Token <token>
    .\blm-agent.ps1 wipe      -CheckoutId <id>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('login','provision','rotate','wipe','close')] [string]$Action,
  [string]$Api = "http://localhost:8000",
  [string]$CheckoutId,
  [string]$Token,          # single-use provisioning token (from the UI "Unlock" popup)
  [string]$AccessToken,    # operator token (for close)
  [string]$User,
  [string]$PicoDrive = '', # auto-detected from the CIRCUITPY label if left blank
  [string]$Drive     = 'C:'
)
$ErrorActionPreference = 'Stop'

function Invoke-Blm($Method, $Path, $Body, $Bearer) {
  $headers = @{}
  if ($Bearer) { $headers['Authorization'] = "Bearer $Bearer" }
  $json = if ($Body) { $Body | ConvertTo-Json -Compress } else { $null }
  Invoke-RestMethod -Method $Method -Uri "$Api$Path" -Headers $headers `
      -ContentType 'application/json' -Body $json
}

function Find-Pico {
  if ($PicoDrive) { return $PicoDrive.TrimEnd(':') + ':' }
  $v = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'CIRCUITPY' } | Select-Object -First 1
  if (-not $v -or -not $v.DriveLetter) {
    throw "Could not find the Pico. Is a CIRCUITPY drive plugged in? (Or pass -PicoDrive E:)"
  }
  return "$($v.DriveLetter):"
}

switch ($Action) {

  'login' {
    $pass = Read-Host "Password for $User" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
    $r = Invoke-Blm POST '/auth/login' @{ username=$User; password=$plain }
    if ($r.access_token) { Write-Host "Access token:`n$($r.access_token)"; break }
    $code = Read-Host "MFA code"
    $r = Invoke-Blm POST '/auth/mfa' @{ mfa_token=$r.mfa_token; code=$code }
    Write-Host "Access token (use with 'close' -AccessToken):`n$($r.access_token)"
  }

  'provision' {
    $pico = Find-Pico
    Write-Host "Found Pico at $pico"
    $r = Invoke-Blm POST "/checkouts/$CheckoutId/provision" `
           @{ provisioning_token=$Token; usb_serial="CIRCUITPY-$pico" }
    $key = $r.key_material                    # in memory only; never echoed
    Set-Content -Path (Join-Path "$pico\" 'blm_secret.txt') -Value $key -NoNewline -Encoding ASCII
    $key = $null
    Write-Host "Key written to $pico\blm_secret.txt. Replug the Pico into the locked device to type it."
  }

  'rotate' {
    $before = (manage-bde -protectors -get $Drive) -join "`n"
    $oldId = [regex]::Match($before, 'ID:\s*(\{[0-9A-Fa-f\-]+\})').Groups[1].Value
    manage-bde -protectors -add $Drive -RecoveryPassword | Out-Null
    $after = (manage-bde -protectors -get $Drive) -join "`n"
    $newKey = [regex]::Match($after, '(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})').Value
    $newId  = [regex]::Match($after, 'ID:\s*(\{[0-9A-Fa-f\-]+\})').Groups[1].Value
    if (-not $newKey) { throw "could not read new recovery password from manage-bde output" }
    if ($oldId -and $oldId -ne $newId) { manage-bde -protectors -delete $Drive -id $oldId | Out-Null }
    Invoke-Blm POST "/checkouts/$CheckoutId/rotate" @{ new_key_material=$newKey; new_key_identifier=$newId } | Out-Null
    $newKey = $null
    Write-Host "Rotated: old protector removed, new recovery key stored in the vault."
  }

  'wipe' {
    $pico = Find-Pico
    $target = Join-Path "$pico\" 'blm_secret.txt'
    if (Test-Path $target) {
      Set-Content -Path $target -Value ('0' * 64) -NoNewline -Encoding ASCII   # overwrite
      Remove-Item $target -Force
    }
    Invoke-Blm POST "/checkouts/$CheckoutId/wipe" @{} | Out-Null
    Write-Host "Pico wiped."
  }

  'close' {
    Invoke-Blm POST "/checkouts/$CheckoutId/close" @{} $AccessToken | Out-Null
    Write-Host "Checkout closed."
  }
}
