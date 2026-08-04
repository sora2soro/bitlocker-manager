<#
  BitLocker Manager — backfill (M1b)
  ----------------------------------
  THE fastest fix for "we keep losing keys." Run on a machine that is currently
  unlocked/accessible: it reads the existing recovery key and stores it in the
  vault, attributed to you (created_by). Enrol the whole reachable fleet this way
  and you stop losing keys on every machine you can still touch.

  It captures (never deletes) the current recovery password, so it is non-destructive.

  Usage:
    # get an operator token first (see blm-agent.ps1 login), then:
    .\backfill.ps1 -Api https://blm.internal -AccessToken <token> -Site Filandia -Drive C:
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Api,
  [Parameter(Mandatory)][string]$AccessToken,
  [Parameter(Mandatory)][string]$Site,
  [string]$Drive = 'C:',
  [string]$Department
)
$ErrorActionPreference = 'Stop'

function Invoke-Blm($Method, $Path, $Body) {
  $headers = @{ Authorization = "Bearer $AccessToken" }
  $json = if ($Body) { $Body | ConvertTo-Json -Compress } else { $null }
  Invoke-RestMethod -Method $Method -Uri "$Api$Path" -Headers $headers `
      -ContentType 'application/json' -Body $json
}

# 1) read this machine's recovery password + protector ID
$out = (manage-bde -protectors -get $Drive) -join "`n"
$key = [regex]::Match($out, '(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})').Value
$id  = [regex]::Match($out, 'ID:\s*(\{[0-9A-Fa-f\-]+\})').Groups[1].Value
if (-not $key) { throw "No recovery password found on $Drive. Is it BitLocker-encrypted with a recovery protector?" }

$hostname = $env:COMPUTERNAME
$serial   = (Get-CimInstance Win32_BIOS).SerialNumber

# 2) create (or reuse) the device record
Write-Host "Enrolling $hostname ($Site)…"
$device = Invoke-Blm POST '/devices' @{ hostname=$hostname; site=$Site; serial=$serial;
                                        volume_id=$id; department=$Department }

# 3) store the key as a backfill (attributed to the operator via the token)
Invoke-Blm POST "/devices/$($device.id)/keys" @{ key_material=$key; key_identifier=$id; source='backfill' } | Out-Null

$key = $null
Write-Host "Backfilled recovery key for $hostname into the vault (source=backfill)."
