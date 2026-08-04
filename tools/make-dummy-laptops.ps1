<#
  BitLocker Manager — dummy laptop generator (testing only)
  ---------------------------------------------------------
  Creates N fake devices with realistic hostnames, serials, Recovery Key IDs, and
  sample recovery keys, so you can test the Devices list and search at real scale.
  About 1 in 10 is left without a key so you see both "key on file" and "no key" badges.

  These are NOT real machines — the keys are random samples and won't unlock anything.
  For clean-up, see the note at the bottom.

  Usage (defaults assume the boss test account and localhost):
    .\make-dummy-laptops.ps1                       # 100 laptops
    .\make-dummy-laptops.ps1 -Count 250            # 250 laptops
    .\make-dummy-laptops.ps1 -Count 50 -Sites Filandia,Matina,Cebu

  If you changed the password or MFA secret, pass them:
    .\make-dummy-laptops.ps1 -Password "yourpw" -MfaSecret "YOURSECRET"
#>
[CmdletBinding()]
param(
  [string]$Api       = "http://localhost:8000",
  [string]$User      = "boss",
  [string]$Password  = "Test1234!",
  [string]$MfaSecret = "6FVU6LVSAYXV3HIB7WC7QTMNKV7KFOXE",
  [int]$Count        = 100,
  [string[]]$Sites   = @("Filandia","Matina"),
  [string]$Prefix    = "DSE"
)
$ErrorActionPreference = 'Stop'

Write-Host "Logging in as $User ..."
$login = irm "$Api/auth/login" -Method Post -ContentType application/json `
           -Body (@{ username=$User; password=$Password } | ConvertTo-Json)

if ($login.access_token) {
  $access = $login.access_token
} else {
  $code   = python -c "import pyotp; print(pyotp.TOTP('$MfaSecret').now())"
  $auth   = irm "$Api/auth/mfa" -Method Post -ContentType application/json `
              -Body (@{ mfa_token=$login.mfa_token; code=$code } | ConvertTo-Json)
  $access = $auth.access_token
}
if (-not $access) { throw "login failed — check -Password / -MfaSecret" }
$H = @{ Authorization = "Bearer $access" }

function New-RecoveryKey {
  (1..8 | ForEach-Object { "{0:D6}" -f (Get-Random -Minimum 0 -Maximum 1000000) }) -join '-'
}
function New-Serial {
  "SN-" + (-join ((48..57)+(65..90) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))
}

Write-Host "Creating $Count dummy laptops across: $($Sites -join ', ') ..."
$made = 0
for ($i = 1; $i -le $Count; $i++) {
  $site     = $Sites[($i - 1) % $Sites.Count]
  $siteCode = ($site.Substring(0, [Math]::Min(3, $site.Length))).ToUpper()
  $hostname = "{0}-{1}-{2:D3}" -f $Prefix, $siteCode, $i
  $guid     = ([guid]::NewGuid()).ToString().ToUpper()

  $dev = irm "$Api/devices" -Method Post -Headers $H -ContentType application/json `
           -Body (@{ hostname=$hostname; site=$site; serial=(New-Serial); volume_id=$guid } | ConvertTo-Json)

  # leave ~1 in 10 without a key, to show both status badges
  if ($i % 10 -ne 0) {
    irm "$Api/devices/$($dev.id)/keys" -Method Post -Headers $H -ContentType application/json `
      -Body (@{ key_material=(New-RecoveryKey); key_identifier=$guid; source='backfill' } | ConvertTo-Json) | Out-Null
  }

  $made++
  if ($made % 20 -eq 0) { Write-Host "  created $made / $Count ..." }
}

Write-Host "`nDone. Created $made dummy laptops."
Write-Host "Open the UI, refresh, and try the search box (hostname, serial, or Recovery Key ID)."

<#
  CLEAN-UP
  --------
  These commands add records; they don't remove them. To wipe ALL test data and
  start fresh, stop the server (Ctrl+C) and delete the database file, then restart:
      Remove-Item .\bitlocker_manager.db
  (That deletes everything, including your 'boss' account — you'd recreate it with
   tools\seed.py. Only do this on a test setup.)
#>
