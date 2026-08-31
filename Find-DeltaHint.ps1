<#
=====================================================================================
 Find-DeltaHint.ps1                                                           v1.0.0

 READ-ONLY. No admin needed. Deletes nothing, changes nothing.

 The work-account list on these machines is now CLEAN. The old address only shows up at
 sign-in prompts. That is a different problem: something is still handing the sign-in
 page a cached "login_hint" for the old account, so the user is sent straight to an
 "Enter password" screen for an identity they no longer use.

 This finds every place in the CURRENT USER's profile that still holds that address, and
 reports whether Edge is signed in with a work profile that has sync switched on -
 because Edge sync is the one store that can restore the account after a cache wipe.

 Run it as the affected user, in a normal (non-admin) PowerShell window:

   powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; New-Item -ItemType Directory 'C:\ProgramData\PMC' -Force | Out-Null; Invoke-WebRequest 'https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/Find-DeltaHint.ps1' -OutFile 'C:\ProgramData\PMC\Find-DeltaHint.ps1' -UseBasicParsing; & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\PMC\Find-DeltaHint.ps1'"
=====================================================================================
#>

[CmdletBinding()]
param(
    [string] $Needle = 'delta.mainettigroup.onmicrosoft.com',
    [int]    $MaxHits = 200
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

function W {
    param([string] $Text = '', [string] $Level = 'INFO')
    $c = 'Gray'
    switch ($Level) { 'STEP' {$c='Cyan'} 'WARN' {$c='Yellow'} 'HIT' {$c='Yellow'} 'OK' {$c='Green'} 'KEY' {$c='Magenta'} }
    Write-Host ("[{0,-4}] {1}" -f $Level, $Text) -ForegroundColor $c
}

$hits = New-Object System.Collections.ArrayList
function Hit { param($Where, $What) [void]$hits.Add([pscustomobject]@{ Where=$Where; What=$What }) }

W ('=' * 74) 'STEP'
W "  WHERE IS '$Needle' STILL CACHED?" 'STEP'
W ('=' * 74) 'STEP'
W ("User    : " + $env:USERNAME)
W ("Profile : " + $env:USERPROFILE)
W ''

# ---------------------------------------------------------------- 1. HKCU registry sweep
W '--- 1. Registry (HKCU) ---' 'STEP'
$roots = @(
    'HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity',
    'HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity',
    'HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Roaming',
    'HKCU:\SOFTWARE\Microsoft\IdentityCRL',
    'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin',
    'HKCU:\SOFTWARE\Microsoft\OneDrive',
    'HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins',
    'HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles',
    'HKCU:\SOFTWARE\Microsoft\AuthCookies',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD'
)
$regCount = 0
foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    $keys = @()
    try { $keys = @(Get-Item -LiteralPath $r) + @(Get-ChildItem -LiteralPath $r -Recurse -ErrorAction SilentlyContinue) } catch { }
    foreach ($k in $keys) {
        if ($regCount -ge $MaxHits) { break }
        # key NAME contains it
        if ($k.PSChildName -and $k.PSChildName -like "*$Needle*") {
            W ("  KEY   " + $k.Name) 'HIT'; Hit 'registry key' $k.Name; $regCount++
        }
        # any VALUE contains it
        try {
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                if ($v -is [string] -and $v -like "*$Needle*") {
                    W ("  VALUE " + $k.Name + " \ " + $n + " = " + $v) 'HIT'
                    Hit 'registry value' ($k.Name + '\' + $n); $regCount++
                }
                elseif ($v -is [string[]]) {
                    foreach ($s in $v) {
                        if ($s -like "*$Needle*") {
                            W ("  MULTI " + $k.Name + " \ " + $n + " = " + $s) 'HIT'
                            Hit 'registry value' ($k.Name + '\' + $n); $regCount++
                        }
                    }
                }
            }
        } catch { }
    }
}
if ($regCount -eq 0) { W '  nothing found in the registry locations checked.' 'OK' }

# ---------------------------------------------------------------- 2. identity caches on disk
W ''
W '--- 2. Identity / token caches on disk ---' 'STEP'
$dirs = @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\OneAuth'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\IdentityCache'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\TokenBroker'),
    (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'),
    (Join-Path $env:LOCALAPPDATA 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache'),
    (Join-Path $env:APPDATA    'Microsoft\Teams'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Office\16.0\Licensing'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Office\Licenses')
)
$fileCount = 0
foreach ($d in $dirs) {
    if (-not (Test-Path -LiteralPath $d)) { W ("  (absent) $d"); continue }
    $found = 0
    foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 4000)) {
        if ($fileCount -ge $MaxHits) { break }
        if ($f.Length -gt 40MB) { continue }
        $match = $false
        try {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            foreach ($enc in @([Text.Encoding]::ASCII, [Text.Encoding]::Unicode, [Text.Encoding]::UTF8)) {
                if ($enc.GetString($bytes).IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $match = $true; break }
            }
        } catch { }
        if ($match) {
            W ("  FILE  {0}   ({1:N0} bytes, written {2})" -f $f.FullName, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) 'HIT'
            Hit 'file' $f.FullName; $fileCount++; $found++
        }
    }
    if ($found -eq 0) { W ("  clean   $d") }
}
if ($fileCount -eq 0) { W '  no identity cache file contains the old address.' 'OK' }

# ---------------------------------------------------------------- 3. Edge profiles + sync
W ''
W '--- 3. Edge profiles (the one store that can restore after a wipe) ---' 'STEP'
$edgeUD = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
if (-not (Test-Path -LiteralPath $edgeUD)) { W '  Edge user data not present.' }
else {
    foreach ($pref in (Get-ChildItem -LiteralPath $edgeUD -Filter 'Preferences' -Recurse -Depth 1 -File -ErrorAction SilentlyContinue)) {
        $profName = Split-Path (Split-Path $pref.FullName -Parent) -Leaf
        $raw = ''
        try { $raw = Get-Content -LiteralPath $pref.FullName -Raw -ErrorAction Stop } catch { continue }

        $mails = [regex]::Matches($raw, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}') |
                 ForEach-Object { $_.Value } | Sort-Object -Unique
        $isDelta  = @($mails | Where-Object { $_ -like "*@$Needle" })
        $syncOn   = ($raw -match '"sync"\s*:\s*\{[^}]*"requested"\s*:\s*true')
        $isWork   = ($raw -match '"edge_account_type"|"is_aad_account"\s*:\s*true|"account_type"\s*:\s*"aad"')

        W ("  profile '{0}'" -f $profName)
        if ($mails.Count -gt 0) { W ("     signed-in identities : " + (($mails | Select-Object -First 6) -join ', ')) }
        W ("     work profile          : $isWork")
        W ("     sync requested        : $syncOn")
        if ($isDelta.Count -gt 0) {
            W ("     >>> HOLDS THE OLD ACCOUNT: " + ($isDelta -join ', ')) 'HIT'
            Hit 'edge profile' ("$profName -> " + ($isDelta -join ', '))
            if ($syncOn) {
                W '     >>> AND SYNC IS ON. Edge will restore this account from the cloud'  'KEY'
                W '         profile after any local cache wipe. Sign this profile out in'   'KEY'
                W '         Edge (Settings > Profiles) - clearing files will not hold.'     'KEY'
            }
        }
    }
}

# ---------------------------------------------------------------- 4. browser sign-in tiles
W ''
W '--- 4. Sign-in page "remembered account" tiles ---' 'STEP'
W '  These live in cookies/localStorage for login.microsoftonline.com and cannot be read'
W '  reliably from here. They are why the sign-in page jumps straight to "Enter password"'
W '  for the old address. Clear them per browser:'
W '     Edge/Chrome: Settings > Privacy > Cookies and site data > See all site data'
W '                  > search "microsoftonline" > delete'
W '     or on the sign-in page itself: click "Sign in with another account" /'
W '                  the account tile > "Forget this account"'

# ---------------------------------------------------------------- verdict
W ''
W ('=' * 74) 'STEP'
W '  RESULT' 'STEP'
W ('=' * 74) 'STEP'
if ($hits.Count -eq 0) {
    W 'The old address is not present in any store this script can read.' 'OK'
    W 'If a sign-in prompt still offers it, it is coming from browser cookies for'
    W 'login.microsoftonline.com (section 4) or from a server-side account tile.'
} else {
    W ("{0} location(s) still hold the old address:" -f $hits.Count) 'WARN'
    foreach ($g in ($hits | Group-Object Where)) {
        W ("  {0,-16} {1}" -f $g.Name, $g.Count)
    }
    W ''
    W 'Priority: deal with any "edge profile" hit FIRST. Files and registry can be cleared' 'KEY'
    W 'and will stay clear; a synced Edge work profile puts the account back.'              'KEY'
}
W ''
