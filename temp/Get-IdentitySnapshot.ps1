<#
=====================================================================================
 Get-IdentitySnapshot.ps1                                                     v1.0.0

 READ-ONLY. Captures every place on a Windows device that can hold a work-account
 identity, so two captures can be diffed to show exactly what a password reset put
 back and in what order.

 THIS SCRIPT CHANGES NOTHING. It never calls Remove-*, Set-*, Stop-*, or dsregcmd
 /leave. The only thing it writes is its own output folder.

 The single exception worth naming: to read a LOGGED-OFF user's registry it mounts
 that profile's NTUSER.DAT with "reg load" and unmounts it again at the end. Nothing
 in the hive is written, but if you want a capture that touches absolutely nothing,
 pass -NoOfflineHives and those profiles are skipped. The affected user will be
 signed in during the test anyway, so their hive is read live either way.

 THE TEST
   1.  On a device that is currently CLEAN and working:
           .\Get-IdentitySnapshot.ps1 -Label before
       Keep the .json it writes. That is the baseline.

   2.  Reset the user's password. Note the exact time.

   3.  Have the user reproduce the symptom - open Outlook / Teams, sign in, and let
       the old tenant appear.

   4.  On the same device:
           .\Get-IdentitySnapshot.ps1 -Label after -Compare C:\ProgramData\PMC\Snapshots\<before>.json

       That captures a second snapshot AND prints the diff: what was added, what
       changed, a chronological timeline of every file and key rewritten between the
       two captures, and every event log record in that window.

   Diffing two saved files later, on any machine:
           .\Get-IdentitySnapshot.ps1 -Baseline before.json -Current after.json

 WHO TO RUN IT AS
   In the AFFECTED USER'S OWN SESSION, elevated if possible. Elevation with a
   different admin account is fine for most areas but loses that user's Credential
   Manager - the script detects this and says so rather than reporting an empty vault
   as a clean one.

 WHAT IT CAPTURES
   device join state, every user profile, WAM broker account files (hash + times),
   token caches, workplace join, Office identity / licensing / AutoDiscover,
   Outlook mail profiles and the addresses inside them, OneDrive links, Credential
   Manager target names, the HKLM IdentityStore logon cache, IdentityCRL, device
   certificates, WorkplaceJoin and Edge policy, scheduled tasks, service state,
   browser signed-in accounts, new Outlook and Teams account stores, settings sync,
   and a bookmark of every relevant event log.
=====================================================================================
#>

[CmdletBinding()]
param(
    [string[]] $TargetDomain = @('delta.mainettigroup.onmicrosoft.com'),
    [string]   $OldTenantId  = '905cd5ac-a071-4697-a446-c9077a81e24b',
    [string]   $NewTenantId  = '152848e0-5270-46fc-b573-8719c78aa236',
    [string]   $Label        = 'snapshot',
    [string]   $Compare      = '',
    [string]   $Baseline     = '',
    [string]   $Current      = '',
    [switch]   $NoHash,
    [switch]   $NoEvents,
    [switch]   $NoOfflineHives,
    [string]   $OutRoot      = 'C:\ProgramData\PMC'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$Version   = '1.0.0'
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$StartedAt = Get-Date

function Convert-ArgList {
    param([string[]]$In)
    $out = New-Object System.Collections.ArrayList
    foreach ($i in $In) {
        if ($null -eq $i) { continue }
        foreach ($part in ([string]$i -split '[,;]')) {
            $v = ($part -replace '^[''"\s]+|[''"\s]+$','')
            if ($v) { [void]$out.Add($v) }
        }
    }
    return $out.ToArray()
}
$TargetDomain = @(Convert-ArgList $TargetDomain)
$Label        = ($Label    -replace '^[''"\s]+|[''"\s]+$','')
$Compare      = ($Compare  -replace '^[''"\s]+|[''"\s]+$','')
$Baseline     = ($Baseline -replace '^[''"\s]+|[''"\s]+$','')
$Current      = ($Current  -replace '^[''"\s]+|[''"\s]+$','')
if (-not $Label) { $Label = 'snapshot' }
$SafeLabel = ($Label -replace '[^A-Za-z0-9._-]','_')

$SnapDir = Join-Path $OutRoot 'Snapshots'
$RunDir  = Join-Path $SnapDir ("{0}-{1}-{2}" -f $env:COMPUTERNAME, $SafeLabel, $Stamp)
$RawDir  = Join-Path $RunDir 'raw'
$JsonOut = Join-Path $SnapDir ("{0}-{1}-{2}.json" -f $env:COMPUTERNAME, $SafeLabel, $Stamp)
$TxtOut  = Join-Path $SnapDir ("{0}-{1}-{2}.txt"  -f $env:COMPUTERNAME, $SafeLabel, $Stamp)
$DiffOut = Join-Path $SnapDir ("{0}-DIFF-{1}.txt" -f $env:COMPUTERNAME, $Stamp)

$DiffOnly = ($Baseline -and $Current)
if (-not $DiffOnly) {
    New-Item -ItemType Directory -Path $RawDir -Force | Out-Null
}

$script:Lines = New-Object System.Collections.ArrayList
function W {
    param([string]$Text='', [string]$Level='INFO')
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Text
    [void]$script:Lines.Add($line)
    $c = 'Gray'
    switch ($Level) {
        'STEP' { $c='Cyan'    }  'WARN' { $c='Yellow' }  'ERROR' { $c='Red'      }
        'HIT'  { $c='Red'     }  'OK'   { $c='Green'  }  'KEEP'  { $c='DarkGray' }
        'ADD'  { $c='Green'   }  'DEL'  { $c='Red'    }  'CHG'   { $c='Yellow'   }
        'KEY'  { $c='Magenta' }
    }
    Write-Host $line -ForegroundColor $c
}
function Section { param([string]$t) W ''; W ('-' * 78) 'STEP'; W "  $t" 'STEP'; W ('-' * 78) 'STEP' }

# ------------------------------------------------------------------ identity matching
function Test-UpnIsTarget {
    param([string]$Upn)
    if (-not $Upn) { return $false }
    $at = $Upn.LastIndexOf('@')
    if ($at -lt 0 -or $at -ge ($Upn.Length - 1)) { return $false }
    $suffix = $Upn.Substring($at + 1).ToLowerInvariant()
    foreach ($d in $TargetDomain) { if ($d -and $suffix -eq $d.ToLowerInvariant()) { return $true } }
    return $false
}
function Test-TextNamesTarget {
    param([string]$Text)
    if (-not $Text) { return $false }
    $t = $Text.ToLowerInvariant()
    foreach ($d in $TargetDomain) {
        if (-not $d) { continue }
        $dd = $d.ToLowerInvariant()
        $i = $t.IndexOf($dd)
        while ($i -ge 0) {
            $before = ''
            if ($i -gt 0) { $before = $t.Substring($i-1,1) }
            $after = ''
            $e = $i + $dd.Length
            if ($e -lt $t.Length) { $after = $t.Substring($e,1) }
            if (($before -eq '' -or $before -notmatch '[a-z0-9\-.]') -and
                ($after  -eq '' -or $after  -notmatch '[a-z0-9\-.]')) { return $true }
            $i = $t.IndexOf($dd, $i + 1)
        }
    }
    return $false
}
function Test-IsInteresting {
    <#
      Highlighting only - this decides what gets flagged for a human to look at, and
      nothing here is ever deleted. So it uses a plain substring match rather than the
      strict boundary rule: a false positive costs a wasted glance, a missed hit costs
      the root cause. "Manav@delta.x.com.xml" must flag, and under the strict rule the
      trailing ".xml" would suppress it.
      Test-UpnIsTarget stays strict and is what classifies an actual account.
    #>
    param([string]$Text)
    if (-not $Text) { return $false }
    $t = $Text.ToLowerInvariant()
    foreach ($d in $TargetDomain) { if ($d -and $t.Contains($d.ToLowerInvariant())) { return $true } }
    if ($OldTenantId -and $t.Contains($OldTenantId.ToLowerInvariant())) { return $true }
    return $false
}
function Get-UpnFromBytes {
    param([byte[]]$Bytes)
    $found = New-Object System.Collections.ArrayList
    foreach ($enc in @([Text.Encoding]::Unicode,[Text.Encoding]::UTF8,[Text.Encoding]::ASCII)) {
        try {
            $s = $enc.GetString($Bytes)
            foreach ($m in [regex]::Matches($s,'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')) {
                if ($found -notcontains $m.Value) { [void]$found.Add($m.Value) }
            }
        } catch { }
    }
    # Returned plain, never as ",$array" - every caller wraps this in @(), and the
    # comma form would hand them a one-element array holding the array instead.
    return $found.ToArray()
}
function RegVal { param([string]$Path,[string]$Name)
    try { return (Get-Item -LiteralPath $Path -ErrorAction Stop).GetValue($Name,$null) } catch { return $null }
}
function ToText {
    param($v)
    if ($null -eq $v) { return '' }
    if ($v -is [byte[]]) {
        $hex = ($v | Select-Object -First 24 | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        $txt = ''
        try { $txt = ([Text.Encoding]::Unicode.GetString($v) -replace '[^\x20-\x7E]',' ').Trim() } catch { }
        if ($txt.Length -gt 120) { $txt = $txt.Substring(0,120) }
        return ("bytes[{0}] {1} `"{2}`"" -f $v.Length, $hex, $txt)
    }
    if ($v -is [array]) { return (($v | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$v
}

# =====================================================================================
#  OBSERVATION ENGINE
#  Everything is recorded as a flat Area / Key / Value triple. Diffing two snapshots is
#  then a set operation rather than per-area comparison code, which means a change in a
#  place nobody thought to compare still shows up.
# =====================================================================================
$script:Obs = New-Object System.Collections.ArrayList
function Obs {
    param([string]$Area,[string]$Key,$Value)
    $v = ToText $Value
    [void]$script:Obs.Add([pscustomobject]@{ Area=$Area; Key=$Key; Value=$v })
}
function Add-FileObs {
    param([string]$Area,[string]$KeyPrefix,[System.IO.FileInfo]$File,[switch]$WithUpn)
    Obs $Area "$KeyPrefix|Size"      $File.Length
    Obs $Area "$KeyPrefix|LastWrite" $File.LastWriteTime.ToString('s')
    Obs $Area "$KeyPrefix|Created"   $File.CreationTime.ToString('s')
    if (-not $NoHash -and $File.Length -lt 8MB) {
        try { Obs $Area "$KeyPrefix|SHA256" ((Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash) } catch { }
    }
    if ($WithUpn -and $File.Length -lt 4MB) {
        try {
            $u = @(Get-UpnFromBytes ([IO.File]::ReadAllBytes($File.FullName)))
            if ($u.Count) { Obs $Area "$KeyPrefix|Upns" (($u | Sort-Object) -join '; ') }
        } catch { }
    }
}
function Add-KeyObs {
    # Every value under a registry key, plus the key's own last-write time.
    param([string]$Area,[string]$KeyPrefix,[string]$RegPath,[switch]$Recurse)
    if (-not (Test-Path $RegPath)) { return }
    $keys = @($RegPath)
    if ($Recurse) {
        foreach ($k in (Get-ChildItem -LiteralPath $RegPath -Recurse -ErrorAction SilentlyContinue)) { $keys += $k.PSPath }
    }
    foreach ($kp in $keys) {
        $item = Get-Item -LiteralPath $kp -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $rel = $kp -replace [regex]::Escape($RegPath),''
        $rel = $rel.TrimStart('\')
        $label = $KeyPrefix
        if ($rel) { $label = "$KeyPrefix\$rel" }
        Obs $Area "$label|(subkeys)" (@($item.GetSubKeyNames()) -join '; ')
        foreach ($vn in $item.Property) {
            $shown = $vn
            if (-not $shown) { $shown = '(default)' }
            Obs $Area "$label\$shown" (RegVal $kp $vn)
        }
    }
}

# =====================================================================================
#  CONTEXT
# =====================================================================================
function Invoke-Capture {
W ('=' * 78) 'STEP'
W ("  IDENTITY SNAPSHOT  v$Version   label=$Label") 'STEP'
W ('=' * 78) 'STEP'

$IsAdmin = $false; $WhoAmI = $env:USERNAME; $MySid = ''
try {
    $wid     = [Security.Principal.WindowsIdentity]::GetCurrent()
    $WhoAmI  = $wid.Name
    $MySid   = $wid.User.Value
    $IsAdmin = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
$IsSystem = ($WhoAmI -ieq 'NT AUTHORITY\SYSTEM')

W ("Captured at   : " + $StartedAt.ToString('yyyy-MM-dd HH:mm:ss zzz'))
W ("UTC           : " + $StartedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
W ("Computer      : $env:COMPUTERNAME")
W ("Running as    : $WhoAmI   (elevated=$IsAdmin, system=$IsSystem)")
W ("Running SID   : $MySid")
W ("Target domain : " + ($TargetDomain -join ', '))
W ("Old tenant    : $OldTenantId")
W ("New tenant    : $NewTenantId")
W ("Output        : $JsonOut")
W ''
W 'READ-ONLY. Nothing on this device is modified.' 'OK'

Obs 'Meta' 'CapturedLocal' $StartedAt.ToString('s')
Obs 'Meta' 'CapturedUtc'   $StartedAt.ToUniversalTime().ToString('s')
Obs 'Meta' 'Computer'      $env:COMPUTERNAME
Obs 'Meta' 'RunAs'         $WhoAmI
Obs 'Meta' 'RunAsSid'      $MySid
Obs 'Meta' 'Elevated'      $IsAdmin
Obs 'Meta' 'Label'         $Label
try { Obs 'Meta' 'LastBoot' ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s')) } catch { }
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Obs 'Meta' 'OS'    $os.Caption
    Obs 'Meta' 'Build' $os.BuildNumber
} catch { }
try { Obs 'Meta' 'TimeZone' ((Get-TimeZone).Id) } catch { }

# =====================================================================================
#  PROFILES  (both SID families)
# =====================================================================================
Section 'PROFILES'
$profiles = New-Object System.Collections.ArrayList
foreach ($k in (Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
    $sid  = $k.PSChildName
    $path = RegVal $k.PSPath 'ProfileImagePath'
    if (-not $path) { continue }
    $fam = ''
    if     ($sid -match '^S-1-5-21-') { $fam = 'LocalOrAD' }
    elseif ($sid -match '^S-1-12-1-') { $fam = 'EntraID'   }
    else   { continue }
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $nm = Split-Path $path -Leaf
    [void]$profiles.Add([pscustomobject]@{ Sid=$sid; Family=$fam; Path=$path; Name=$nm })
    Obs 'Profiles' "$nm|Sid"    $sid
    Obs 'Profiles' "$nm|Family" $fam
    Obs 'Profiles' "$nm|Path"   $path
    foreach ($vn in @('ProfileLoadTimeLow','ProfileLoadTimeHigh','LocalProfileLoadTimeLow','State','Flags')) {
        $v = RegVal $k.PSPath $vn
        if ($null -ne $v) { Obs 'Profiles' "$nm|$vn" $v }
    }
}
$LoadedHkuSids = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   ForEach-Object { $_.PSChildName } | Where-Object { $_ -notmatch '_Classes$' })
foreach ($p in $profiles) {
    $on = ($LoadedHkuSids -contains $p.Sid)
    Obs 'Profiles' "$($p.Name)|LoggedOn" $on
    W ("   [{0,-9}] {1,-16} {2,-11} {3}" -f $p.Family, $p.Name, $(if ($on) { 'signed in' } else { 'logged off' }), $p.Sid)
}
if ($MySid) {
    $me = @($profiles | Where-Object { $_.Sid -eq $MySid })
    if ($me.Count -eq 0) {
        W ''
        W 'The account running this script is NOT one of the profiles above. Credential' 'WARN'
        W 'Manager and any HKCU-only reads will be this account''s, not the affected'    'WARN'
        W 'user''s. Re-run in the affected user''s own session for a complete capture.'  'WARN'
        Obs 'Meta' 'RunAsIsProfileUser' $false
    } else {
        Obs 'Meta' 'RunAsIsProfileUser' $true
        Obs 'Meta' 'RunAsProfileName'   $me[0].Name
    }
}

# ------------------------------------------------------------------ offline hive helper
$loadedByUs = New-Object System.Collections.ArrayList
function Invoke-WithUserHive {
    param($P, [scriptblock]$Body)
    $root = "Registry::HKEY_USERS\$($P.Sid)"
    if (-not (Test-Path $root)) {
        if ($NoOfflineHives) { W ("   $($P.Name) is logged off and -NoOfflineHives is set - skipped") 'KEEP'; return }
        $dat = Join-Path $P.Path 'NTUSER.DAT'
        if ((Test-Path -LiteralPath $dat) -and $IsAdmin) {
            $null = & reg.exe load "HKU\$($P.Sid)" "$dat" 2>&1
            if ($LASTEXITCODE -eq 0) { [void]$loadedByUs.Add($P.Sid) }
            else { W ("   could not read the hive for $($P.Name) - skipped") 'WARN'; return }
        } else { return }
    }
    & $Body $root
}
function Dismount-UserHives {
    if ($loadedByUs.Count -eq 0) { return }
    [gc]::Collect(); Start-Sleep -Milliseconds 400
    foreach ($sid in @($loadedByUs)) { $null = & reg.exe unload "HKU\$sid" 2>&1 }
    $loadedByUs.Clear()
}

# =====================================================================================
#  1. DEVICE JOIN STATE
# =====================================================================================
Section 'DEVICE JOIN STATE'
if (Get-Command dsregcmd.exe -ErrorAction SilentlyContinue) {
    $raw = ''
    try { $raw = (& dsregcmd.exe /status 2>&1 | Out-String) } catch { }
    if ($raw) {
        Set-Content -LiteralPath (Join-Path $RawDir 'dsregcmd.txt') -Value $raw -Encoding UTF8
        $sect = 'Device'
        foreach ($l in ($raw -split "`r?`n")) {
            if ($l -match '^\s*\|\s*(.+?)\s*\|\s*$') { $sect = ($Matches[1].Trim() -replace '[^A-Za-z0-9]',''); continue }
            if ($l -match '^\s*([A-Za-z][A-Za-z0-9 _\-]+?)\s*:\s*(.*)$') {
                $n = $Matches[1].Trim(); $v = $Matches[2].Trim()
                Obs 'DeviceJoin' "$sect\$n" $v
            }
        }
        foreach ($n in @('AzureAdJoined','DomainJoined','WorkplaceJoined','WamDefaultSet','WamDefaultGUID',
                         'AzureAdPrt','AzureAdPrtAuthority','TenantId','TenantName','DeviceId','IdpDomain',
                         'Executing Account Name','WamDefaultAuthority','KeyProvider','KeySignTest')) {
            $hit = @($script:Obs | Where-Object { $_.Area -eq 'DeviceJoin' -and $_.Key -like "*\$n" })
            foreach ($h in $hit) { W ("   {0,-46} {1}" -f $h.Key, $h.Value) }
        }
    }
} else { W '   dsregcmd.exe not present' 'WARN' }
foreach ($tool in @(@{n='whoami';e='whoami.exe';a=@('/all')},
                    @{n='klist';e='klist.exe';a=@('sessions')},
                    @{n='klist-cloud';e='klist.exe';a=@('cloud_debug')})) {
    if (-not (Get-Command $tool.e -ErrorAction SilentlyContinue)) { continue }
    try {
        $o = & $tool.e @($tool.a) 2>&1 | Out-String
        Set-Content -LiteralPath (Join-Path $RawDir ($tool.n + '.txt')) -Value $o -Encoding UTF8
    } catch { }
}
try { Obs 'DeviceJoin' 'whoami|upn' ((& whoami.exe /upn 2>&1 | Out-String).Trim()) } catch { }

# =====================================================================================
#  2. WAM BROKER ACCOUNTS  -  the Settings accounts page reads this
# =====================================================================================
Section 'WAM BROKER ACCOUNTS'
foreach ($p in $profiles) {
    $base = Join-Path $p.Path 'AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy'
    $acc  = Join-Path $base 'AC\TokenBroker\Accounts'
    $cnt  = 0
    if (Test-Path -LiteralPath $acc) {
        foreach ($f in (Get-ChildItem -LiteralPath $acc -File -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $kp = "$($p.Name)|$($f.Name)"
            Add-FileObs 'WAM' $kp $f -WithUpn:($f.Extension -ieq '.tbacct')
            if ($f.Extension -ieq '.tbacct') {
                $cnt++
                $u = @()
                try { $u = @(Get-UpnFromBytes ([IO.File]::ReadAllBytes($f.FullName))) } catch { }
                $flag = 'KEEP'
                foreach ($x in $u) { if (Test-UpnIsTarget $x) { $flag = 'HIT' } }
                W ("   [{0}] {1}  {2}  {3}" -f $p.Name, $f.Name, $f.LastWriteTime.ToString('s'), ($u -join ', ')) $flag
            }
        }
    }
    Obs 'WAM' "$($p.Name)|AccountFileCount" $cnt
    foreach ($sub in @('AC\TokenBroker\Cache','Settings','LocalState','AC\Microsoft\Internet Explorer\DOMStore')) {
        $d = Join-Path $base $sub
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $fs = @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)
        Obs 'WAM' "$($p.Name)|$sub|FileCount" $fs.Count
        $newest = $fs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) { Obs 'WAM' "$($p.Name)|$sub|Newest" ($newest.Name + ' @ ' + $newest.LastWriteTime.ToString('s')) }
    }
}

# =====================================================================================
#  3. TOKEN CACHES  -  what Office and Teams enumerate accounts from
# =====================================================================================
Section 'TOKEN CACHES'
foreach ($p in $profiles) {
    foreach ($rel in @('AppData\Local\Microsoft\OneAuth',
                       'AppData\Local\Microsoft\IdentityCache',
                       'AppData\Local\Microsoft\TokenBroker\Cache',
                       'AppData\Local\Microsoft\Credentials',
                       'AppData\Roaming\Microsoft\Credentials',
                       'AppData\Roaming\Microsoft\Protect')) {
        $d = Join-Path $p.Path $rel
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $n = 0
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Sort-Object FullName)) {
            $n++
            $short = $f.FullName.Substring($d.Length).TrimStart('\')
            Add-FileObs 'TokenCache' "$($p.Name)|$rel|$short" $f -WithUpn:($rel -notlike '*Protect*' -and $rel -notlike '*Credentials*')
        }
        Obs 'TokenCache' "$($p.Name)|$rel|FileCount" $n
        W ("   [{0}] {1}  {2} file(s)" -f $p.Name, $rel, $n)
    }
}

# =====================================================================================
#  4. PER-USER REGISTRY  -  workplace join, Office, AutoDiscover, OneDrive, IdentityCRL
# =====================================================================================
Section 'PER-USER REGISTRY'
foreach ($p in $profiles) {
    Invoke-WithUserHive $p {
        param($root)
        $n = $p.Name
        Add-KeyObs 'WorkplaceJoin' "$n" "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" -Recurse
        Add-KeyObs 'AadBroker'     "$n" "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC" -Recurse
        foreach ($ver in @('16.0','15.0','14.0')) {
            Add-KeyObs 'OfficeIdentity' "$n|$ver" "$root\SOFTWARE\Microsoft\Office\$ver\Common\Identity"  -Recurse
            Add-KeyObs 'OfficeLicensing' "$n|$ver" "$root\SOFTWARE\Microsoft\Office\$ver\Common\Licensing" -Recurse
            Add-KeyObs 'AutoDiscover'   "$n|$ver" "$root\SOFTWARE\Microsoft\Office\$ver\Outlook\AutoDiscover" -Recurse
            Add-KeyObs 'OutlookAccounts' "$n|$ver" "$root\SOFTWARE\Microsoft\Office\$ver\Outlook\Profiles" -Recurse
            Add-KeyObs 'OfficeCommon'   "$n|$ver" "$root\SOFTWARE\Microsoft\Office\$ver\Common\Roaming\Identities" -Recurse
        }
        Add-KeyObs 'AutoDiscover' "$n|Exchange" "$root\SOFTWARE\Microsoft\Exchange\AutoDiscover" -Recurse
        Add-KeyObs 'OneDrive'     "$n" "$root\Software\Microsoft\OneDrive\Accounts" -Recurse
        Add-KeyObs 'IdentityCRL'  "$n" "$root\SOFTWARE\Microsoft\IdentityCRL" -Recurse
        Add-KeyObs 'SettingSync'  "$n" "$root\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Recurse
        Add-KeyObs 'AadAccount'   "$n" "$root\Software\Microsoft\Windows\CurrentVersion\AAD" -Recurse
        Add-KeyObs 'WorkAccount'  "$n" "$root\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Recurse
    }
    # every address that appears inside the Outlook mail profile blobs
    Invoke-WithUserHive $p {
        param($root)
        foreach ($ver in @('16.0','15.0','14.0')) {
            $pr = "$root\SOFTWARE\Microsoft\Office\$ver\Outlook\Profiles"
            if (-not (Test-Path $pr)) { continue }
            foreach ($prof in (Get-ChildItem -LiteralPath $pr -ErrorAction SilentlyContinue)) {
                $addr = New-Object System.Collections.ArrayList
                foreach ($sub in (Get-ChildItem -LiteralPath $prof.PSPath -Recurse -ErrorAction SilentlyContinue)) {
                    $item = Get-Item -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                    if (-not $item) { continue }
                    foreach ($vn in $item.Property) {
                        $raw = RegVal $sub.PSPath $vn
                        if ($raw -isnot [byte[]]) { continue }
                        foreach ($u in @(Get-UpnFromBytes $raw)) { if ($addr -notcontains $u) { [void]$addr.Add($u) } }
                    }
                }
                Obs 'OutlookAccounts' "$($p.Name)|$ver|$($prof.PSChildName)|Addresses" (($addr | Sort-Object) -join '; ')
                foreach ($a in $addr) {
                    $lvl = 'KEEP'; if (Test-UpnIsTarget $a) { $lvl = 'HIT' }
                    W ("   [{0}] profile '{1}' -> {2}" -f $p.Name, $prof.PSChildName, $a) $lvl
                }
            }
        }
    }
}

# =====================================================================================
#  5. MACHINE REGISTRY  -  IdentityStore logon cache, policy, device registration
#     HKLM\...\IdentityStore is where the Windows sign-in UI gets its names from. A
#     password reset makes Windows re-sync it, which is why it is worth watching.
# =====================================================================================
Section 'MACHINE REGISTRY'
Add-KeyObs 'IdentityStore' 'Cache'     'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache'     -Recurse
Add-KeyObs 'IdentityStore' 'LogonCache' 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache' -Recurse
Add-KeyObs 'IdentityStore' 'Providers' 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Providers'  -Recurse
Add-KeyObs 'DeviceReg' 'JoinInfo'  'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -Recurse
Add-KeyObs 'DeviceReg' 'TenantInfo' 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo' -Recurse
Add-KeyObs 'DeviceReg' 'AadJoin'   'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin' -Recurse
Add-KeyObs 'Policy' 'WorkplaceJoin' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' -Recurse
Add-KeyObs 'Policy' 'CloudManagement' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM' -Recurse
Add-KeyObs 'Policy' 'Enrollments'  'HKLM:\SOFTWARE\Microsoft\Enrollments' -Recurse
Add-KeyObs 'Policy' 'Edge'         'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
Add-KeyObs 'Policy' 'OfficePolicy' 'HKLM:\SOFTWARE\Policies\Microsoft\Office'   -Recurse
Add-KeyObs 'Policy' 'AadPolicy'    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
Add-KeyObs 'OfficeMachine' 'ClickToRun' 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
foreach ($a in @('IdentityStore','DeviceReg','Policy')) {
    W ("   {0,-14} {1} value(s)" -f $a, @($script:Obs | Where-Object { $_.Area -eq $a }).Count)
}

# =====================================================================================
#  6. CERTIFICATES  -  the device / workplace join certificate
# =====================================================================================
Section 'CERTIFICATES'
foreach ($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
    foreach ($c in (Get-ChildItem $store -ErrorAction SilentlyContinue)) {
        $iss = "$($c.Issuer)"
        if ($iss -notmatch 'MS-Organization|CN=MS-|Microsoft Intune|Workplace') { continue }
        $kp = "$store|$($c.Thumbprint)"
        Obs 'Certificates' "$kp|Subject"   "$($c.Subject)"
        Obs 'Certificates' "$kp|Issuer"    $iss
        Obs 'Certificates' "$kp|NotBefore" $c.NotBefore.ToString('s')
        Obs 'Certificates' "$kp|NotAfter"  $c.NotAfter.ToString('s')
        W ("   {0}  {1}  from {2}" -f $c.Thumbprint, $c.Subject, $c.NotBefore.ToString('s'))
    }
}

# =====================================================================================
#  7. SCHEDULED TASKS AND SERVICES  -  what could re-register the device on its own
# =====================================================================================
Section 'SCHEDULED TASKS AND SERVICES'
try {
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue |
                    Where-Object { $_.TaskPath -match 'Workplace Join|AAD|Azure|DeviceDirectory|EnterpriseMgmt|Windows Hello|CertificateServicesClient|TokenBroker' })) {
        $kp = "$($t.TaskPath)$($t.TaskName)"
        Obs 'ScheduledTasks' "$kp|State" "$($t.State)"
        try {
            $i = Get-ScheduledTaskInfo -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop
            Obs 'ScheduledTasks' "$kp|LastRun"    $(if ($i.LastRunTime)  { $i.LastRunTime.ToString('s')  } else { '' })
            Obs 'ScheduledTasks' "$kp|NextRun"    $(if ($i.NextRunTime)  { $i.NextRunTime.ToString('s')  } else { '' })
            Obs 'ScheduledTasks' "$kp|LastResult" $i.LastTaskResult
            W ("   {0,-62} {1,-10} last={2}" -f $kp, $t.State, $(if ($i.LastRunTime) { $i.LastRunTime.ToString('s') } else { 'never' }))
        } catch { }
    }
} catch { W '   Get-ScheduledTask unavailable' 'WARN' }
foreach ($svc in @('wlidsvc','TokenBroker','dmwappushservice','DmEnrollmentSvc','DeviceAssociationService',
                   'EntAppSvc','CertPropSvc','KeyIso','SessionEnv','WpnService','Schedule','CryptSvc')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if (-not $s) { continue }
    Obs 'Services' "$svc|Status" "$($s.Status)"
    try { Obs 'Services' "$svc|StartType" "$((Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction Stop).StartMode)" } catch { }
}

# =====================================================================================
#  8. BROWSERS
# =====================================================================================
Section 'BROWSERS'
foreach ($p in $profiles) {
    foreach ($b in @(@{N='Edge';R='AppData\Local\Microsoft\Edge\User Data'},
                     @{N='Chrome';R='AppData\Local\Google\Chrome\User Data'},
                     @{N='Brave';R='AppData\Local\BraveSoftware\Brave-Browser\User Data'})) {
        $ud = Join-Path $p.Path $b.R
        if (-not (Test-Path -LiteralPath $ud)) { continue }
        foreach ($bp in (Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })) {
            $pref = Join-Path $bp.FullName 'Preferences'
            if (-not (Test-Path -LiteralPath $pref)) { continue }
            $kp = "$($p.Name)|$($b.N)|$($bp.Name)"
            $fi = Get-Item -LiteralPath $pref -Force
            Obs 'Browser' "$kp|Preferences|LastWrite" $fi.LastWriteTime.ToString('s')
            $txt = ''
            try { $txt = [IO.File]::ReadAllText($pref) } catch { continue }
            $mails = @([regex]::Matches($txt,'"email"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } |
                       Where-Object { $_ -match '@' } | Select-Object -Unique | Sort-Object)
            Obs 'Browser' "$kp|Accounts" ($mails -join '; ')
            foreach ($m in $mails) {
                $lvl = 'KEEP'; if (Test-UpnIsTarget $m) { $lvl = 'HIT' }
                W ("   [{0}] {1}\{2} -> {3}" -f $p.Name, $b.N, $bp.Name, $m) $lvl
            }
        }
    }
}

# =====================================================================================
#  9. NEW OUTLOOK, TEAMS, OFFICE LICENCES, AUTODISCOVER CACHE
#     File inventory only - no mail store is ever opened or read.
# =====================================================================================
Section 'APP ACCOUNT STORES'
foreach ($p in $profiles) {
    foreach ($spec in @(
        @{A='NewOutlook'; R='AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache\Local'; Upn=$false}
        @{A='NewOutlook'; R='AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\Settings';         Upn=$false}
        @{A='Teams';      R='AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams';         Upn=$false}
        @{A='Teams';      R='AppData\Roaming\Microsoft\Teams';                                                   Upn=$false}
        @{A='CloudExp';   R='AppData\Local\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\LocalState'; Upn=$false}
    )) {
        $d = Join-Path $p.Path $spec.R
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $fs = @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -lt 4MB -and $_.Extension -notmatch '^\.(db|sqlite|db-wal|db-shm|log|etl)$' })
        Obs $spec.A "$($p.Name)|$($spec.R)|FileCount" $fs.Count
        $newest = $fs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) { Obs $spec.A "$($p.Name)|$($spec.R)|Newest" ($newest.Name + ' @ ' + $newest.LastWriteTime.ToString('s')) }
        foreach ($f in ($fs | Sort-Object FullName | Select-Object -First 400)) {
            $short = $f.FullName.Substring($d.Length).TrimStart('\')
            Obs $spec.A "$($p.Name)|$($spec.R)|$short|LastWrite" $f.LastWriteTime.ToString('s')
        }
    }
    foreach ($rel in @('AppData\Local\Microsoft\Office\Licenses','AppData\Local\Microsoft\Office\16.0\Licensing')) {
        $d = Join-Path $p.Path $rel
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Sort-Object FullName)) {
            $short = $f.FullName.Substring($d.Length).TrimStart('\')
            Add-FileObs 'OfficeLicenceFiles' "$($p.Name)|$rel|$short" $f -WithUpn
        }
    }
    $od = Join-Path $p.Path 'AppData\Local\Microsoft\Outlook'
    if (Test-Path -LiteralPath $od) {
        foreach ($f in (Get-ChildItem -LiteralPath $od -Filter '*.xml' -File -Force -Recurse -Depth 2 -ErrorAction SilentlyContinue | Sort-Object FullName)) {
            Add-FileObs 'AutoDiscoverCache' "$($p.Name)|$($f.Name)" $f -WithUpn
            $lvl = 'KEEP'; if (Test-IsInteresting $f.Name) { $lvl = 'HIT' }
            W ("   [{0}] autodiscover {1}  {2}" -f $p.Name, $f.Name, $f.LastWriteTime.ToString('s')) $lvl
        }
        foreach ($f in (Get-ChildItem -LiteralPath $od -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -imatch '^\.(ost|nst)$' })) {
            Obs 'MailFiles' "$($p.Name)|$($f.Name)|Size"      $f.Length
            Obs 'MailFiles' "$($p.Name)|$($f.Name)|LastWrite" $f.LastWriteTime.ToString('s')
        }
    }
}

# =====================================================================================
#  10. CREDENTIAL MANAGER  -  target names only. No secret is ever read or written.
# =====================================================================================
Section 'CREDENTIAL MANAGER'
if (-not ('SnapCredApi' -as [type])) {
@'
using System;
using System.Runtime.InteropServices;
public class SnapCredApi {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public UInt32 Flags; public UInt32 Type; public IntPtr TargetName; public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize; public IntPtr CredentialBlob; public UInt32 Persist;
        public UInt32 AttributeCount; public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredEnumerateW(string filter, int flag, out int count, out IntPtr pCredentials);
    [DllImport("advapi32.dll", SetLastError=false)]
    public static extern void CredFree(IntPtr cred);
}
'@ | ForEach-Object { try { Add-Type -TypeDefinition $_ -ErrorAction Stop } catch { } }
}
if ($IsSystem) {
    W '   Running as SYSTEM - this is SYSTEM''s vault, not the user''s. Re-run in the' 'WARN'
    W '   affected user''s session if you need the credential picture.'                'WARN'
    Obs 'Credentials' 'VaultContext' 'SYSTEM - not the user vault'
} else {
    Obs 'Credentials' 'VaultContext' $WhoAmI
}
if ('SnapCredApi' -as [type]) {
    $count = 0; $ptr = [IntPtr]::Zero
    if ([SnapCredApi]::CredEnumerateW($null, 0, [ref]$count, [ref]$ptr)) {
        try {
            for ($i = 0; $i -lt $count; $i++) {
                $pc = [Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $i * [IntPtr]::Size)
                $c  = [Runtime.InteropServices.Marshal]::PtrToStructure($pc, [Type]('SnapCredApi+CREDENTIAL' -as [type]))
                $t = ''; $u = ''
                if ($c.TargetName -ne [IntPtr]::Zero) { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.TargetName) }
                if ($c.UserName   -ne [IntPtr]::Zero) { $u = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.UserName) }
                $when = ''
                try {
                    $lw = ([long]$c.LastWritten.dwHighDateTime -shl 32) -bor ([long]$c.LastWritten.dwLowDateTime -band 0xFFFFFFFFL)
                    if ($lw -gt 0) { $when = [datetime]::FromFileTime($lw).ToString('s') }
                } catch { }
                Obs 'Credentials' "$t|User"        $u
                Obs 'Credentials' "$t|Type"        ([int]$c.Type)
                Obs 'Credentials' "$t|BlobSize"    ([int]$c.CredentialBlobSize)
                Obs 'Credentials' "$t|LastWritten" $when
                $lvl = 'KEEP'; if ((Test-IsInteresting $t) -or (Test-IsInteresting $u)) { $lvl = 'HIT' }
                W ("   {0,-19} {1,-58} {2}" -f $when, $t, $u) $lvl
            }
        } catch { } finally { try { [SnapCredApi]::CredFree($ptr) } catch { } }
        Obs 'Credentials' 'EntryCount' $count
    }
}

# =====================================================================================
#  11. EVENT LOG BOOKMARKS  -  so the "after" run can pull exactly the window between
# =====================================================================================
if (-not $NoEvents) {
Section 'EVENT LOG BOOKMARKS'
$WatchLogs = @(
    'Microsoft-Windows-AAD/Operational'
    'Microsoft-Windows-User Device Registration/Admin'
    'Microsoft-Windows-Workplace Join/Admin'
    'Microsoft-Windows-HelloForBusiness/Operational'
    'Microsoft-Windows-WebAuthN/Operational'
    'Microsoft-Windows-CAPI2/Operational'
    'Microsoft-Windows-Crypto-NCrypt/Operational'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-Windows-Winlogon/Operational'
    'Microsoft-Windows-Shell-Core/Operational'
    'Application'
    'System'
)
foreach ($log in $WatchLogs) {
    try {
        $e = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop
        Obs 'EventBookmark' "$log|LastRecordId" $e.RecordId
        Obs 'EventBookmark' "$log|LastTime"     $e.TimeCreated.ToString('s')
        W ("   {0,-52} id={1} @ {2}" -f $log, $e.RecordId, $e.TimeCreated.ToString('s'))
    } catch { Obs 'EventBookmark' "$log|LastRecordId" 'unavailable' }
}
}

Dismount-UserHives

# =====================================================================================
#  WRITE
# =====================================================================================
Section 'WRITE'
$hits = @($script:Obs | Where-Object { (Test-IsInteresting $_.Key) -or (Test-IsInteresting $_.Value) })
W ("Observations captured : {0}" -f $script:Obs.Count)
W ("Naming the old tenant : {0}" -f $hits.Count) $(if ($hits.Count) { 'HIT' } else { 'OK' })
foreach ($h in ($hits | Select-Object -First 40)) { W ("   {0,-16} {1}" -f $h.Area, $h.Key) 'HIT' }
if ($hits.Count -gt 40) { W ("   ... and {0} more (all in the json)" -f ($hits.Count - 40)) 'HIT' }

$snapshot = [ordered]@{
    SchemaVersion = 1
    Script        = 'Get-IdentitySnapshot.ps1'
    Version       = $Version
    Label         = $Label
    Computer      = $env:COMPUTERNAME
    CapturedLocal = $StartedAt.ToString('s')
    CapturedUtc   = $StartedAt.ToUniversalTime().ToString('s')
    RunAs         = $WhoAmI
    Elevated      = $IsAdmin
    TargetDomain  = $TargetDomain
    OldTenantId   = $OldTenantId
    NewTenantId   = $NewTenantId
    TargetHits    = $hits.Count
    Observations  = @($script:Obs)
}
try {
    $snapshot | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $JsonOut -Encoding UTF8
    W ("Snapshot : $JsonOut") 'OK'
} catch { W ("Could not write the snapshot: " + $_.Exception.Message) 'ERROR' }
try { Set-Content -LiteralPath $TxtOut -Value ($script:Lines -join "`r`n") -Encoding UTF8; W ("Log      : $TxtOut") } catch { }
W ("Raw      : $RawDir")
$script:Snapshot = $snapshot
return $snapshot
}

# =====================================================================================
#  DIFF ENGINE
# =====================================================================================
function Import-Snapshot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "snapshot file not found: $Path" }
    $j = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $j.Observations) { throw "not a snapshot file: $Path" }
    return $j
}
function Short { param([string]$s,[int]$n=140)
    if ($null -eq $s) { return '' }
    if ($s.Length -le $n) { return $s }
    return ($s.Substring(0,$n) + ' ...')
}
function Compare-Snapshot {
    param($A,$B,[switch]$Live)

    $script:Lines = New-Object System.Collections.ArrayList
    W ('=' * 78) 'STEP'
    W '  SNAPSHOT DIFF' 'STEP'
    W ('=' * 78) 'STEP'
    W ("BEFORE : {0,-10} {1}  on {2}  ({3} observations)" -f $A.Label, $A.CapturedLocal, $A.Computer, @($A.Observations).Count)
    W ("AFTER  : {0,-10} {1}  on {2}  ({3} observations)" -f $B.Label, $B.CapturedLocal, $B.Computer, @($B.Observations).Count)
    if ($A.Computer -ne $B.Computer) { W 'DIFFERENT COMPUTERS - this diff is not meaningful.' 'ERROR' }
    $t0 = [datetime]::MinValue; $t1 = [datetime]::MaxValue
    $null = [datetime]::TryParse($A.CapturedLocal, [ref]$t0)
    $null = [datetime]::TryParse($B.CapturedLocal, [ref]$t1)
    if ($t0 -ne [datetime]::MinValue -and $t1 -ne [datetime]::MaxValue) {
        W ("WINDOW : {0:n1} minutes" -f ($t1 - $t0).TotalMinutes)
    }

    # [char]1 as the separator - it cannot occur in a key. Written this way and not as
    # a `u{} escape because that escape does not exist in PowerShell 5.1.
    $SEP = [string][char]1
    $ha = @{}; foreach ($o in @($A.Observations)) { $ha[($o.Area + $SEP + $o.Key)] = $o.Value }
    $hb = @{}; foreach ($o in @($B.Observations)) { $hb[($o.Area + $SEP + $o.Key)] = $o.Value }

    $added = New-Object System.Collections.ArrayList
    $gone  = New-Object System.Collections.ArrayList
    $chg   = New-Object System.Collections.ArrayList
    foreach ($k in $hb.Keys) {
        if (-not $ha.ContainsKey($k)) { [void]$added.Add($k) }
        elseif ("$($ha[$k])" -ne "$($hb[$k])") { [void]$chg.Add($k) }
    }
    foreach ($k in $ha.Keys) { if (-not $hb.ContainsKey($k)) { [void]$gone.Add($k) } }

    function Split-K {
        param([string]$k)
        $i = $k.IndexOf([char]1)
        if ($i -lt 0) { return ,@('', $k) }
        return ,@($k.Substring(0,$i), $k.Substring($i+1))
    }

    # ---------------------------------------------------------------- prime suspects
    W ''
    W ('=' * 78) 'STEP'
    W '  PRIME SUSPECTS - anything naming the old tenant that was not there before' 'STEP'
    W ('=' * 78) 'STEP'
    $suspects = 0
    foreach ($k in ($added + $chg | Sort-Object)) {
        $parts = Split-K $k
        $val = "$($hb[$k])"
        if (-not ((Test-IsInteresting $parts[1]) -or (Test-IsInteresting $val))) { continue }
        $suspects++
        if ($added -contains $k) { W ("[NEW] {0,-18} {1}" -f $parts[0], $parts[1]) 'HIT'
                                   W ("      = {0}" -f (Short $val)) 'HIT' }
        else { W ("[CHG] {0,-18} {1}" -f $parts[0], $parts[1]) 'HIT'
               W ("      was {0}" -f (Short "$($ha[$k])")) 'KEEP'
               W ("      now {0}" -f (Short $val)) 'HIT' }
    }
    if ($suspects -eq 0) { W 'Nothing naming the old tenant appeared or changed between the two captures.' 'OK' }

    # ---------------------------------------------------------------- timeline
    W ''
    W ('=' * 78) 'STEP'
    W '  TIMELINE - everything rewritten between the two captures, in order' 'STEP'
    W ('=' * 78) 'STEP'
    $tl = New-Object System.Collections.ArrayList
    foreach ($k in ($added + $chg)) {
        $val = "$($hb[$k])"
        $dt = [datetime]::MinValue
        if (-not [datetime]::TryParse($val, [ref]$dt)) { continue }
        if ($dt -lt $t0.AddMinutes(-2) -or $dt -gt $t1.AddMinutes(2)) { continue }
        $parts = Split-K $k
        [void]$tl.Add([pscustomobject]@{ When=$dt; Area=$parts[0]; Key=$parts[1]
                                         Kind=$(if ($added -contains $k) { 'NEW' } else { 'CHG' })
                                         Hot=((Test-IsInteresting $parts[1]) -or (Test-IsInteresting $val)) })
    }
    if ($tl.Count -eq 0) { W 'Nothing on disk or in the registry was rewritten inside the window.' 'OK' }
    foreach ($e in ($tl | Sort-Object When)) {
        $lvl = 'INFO'; if ($e.Hot) { $lvl = 'HIT' }
        W ("{0}  {1}  {2,-18} {3}" -f $e.When.ToString('HH:mm:ss'), $e.Kind, $e.Area, (Short $e.Key 110)) $lvl
    }

    # ---------------------------------------------------------------- full diff
    W ''
    W ('=' * 78) 'STEP'
    W ("  FULL DIFF   +{0} added   -{1} removed   ~{2} changed" -f $added.Count, $gone.Count, $chg.Count) 'STEP'
    W ('=' * 78) 'STEP'
    $areas = @(@($added + $gone + $chg) | ForEach-Object { (Split-K $_)[0] } | Sort-Object -Unique)
    foreach ($a in $areas) {
        $aa = @($added | Where-Object { (Split-K $_)[0] -eq $a })
        $ag = @($gone  | Where-Object { (Split-K $_)[0] -eq $a })
        $ac = @($chg   | Where-Object { (Split-K $_)[0] -eq $a })
        W ''
        W ("--- {0}   +{1} -{2} ~{3}" -f $a, $aa.Count, $ag.Count, $ac.Count) 'STEP'
        foreach ($k in ($aa | Sort-Object)) { W ("  [+] {0}" -f (Split-K $k)[1]) 'ADD'
                                              W ("      {0}" -f (Short "$($hb[$k])")) 'ADD' }
        foreach ($k in ($ag | Sort-Object)) { W ("  [-] {0}" -f (Split-K $k)[1]) 'DEL'
                                              W ("      was {0}" -f (Short "$($ha[$k])")) 'DEL' }
        foreach ($k in ($ac | Sort-Object)) { W ("  [~] {0}" -f (Split-K $k)[1]) 'CHG'
                                              W ("      was {0}" -f (Short "$($ha[$k])")) 'KEEP'
                                              W ("      now {0}" -f (Short "$($hb[$k])")) 'CHG' }
    }

    # ---------------------------------------------------------------- event window
    if ($Live -and $t0 -ne [datetime]::MinValue) {
        W ''
        W ('=' * 78) 'STEP'
        W '  EVENT LOG - records written between the two captures' 'STEP'
        W ('=' * 78) 'STEP'
        $logs = @(@($A.Observations) | Where-Object { $_.Area -eq 'EventBookmark' -and $_.Key -like '*|LastRecordId' } |
                  ForEach-Object { ($_.Key -split '\|')[0] } | Sort-Object -Unique)
        if ($logs.Count -eq 0) { $logs = @('Microsoft-Windows-AAD/Operational','Microsoft-Windows-User Device Registration/Admin','Application','System') }
        foreach ($log in $logs) {
            $evts = @()
            try { $evts = @(Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$t0; EndTime=$t1 } -ErrorAction Stop) } catch { }
            if ($evts.Count -eq 0) { continue }
            W ''
            W ("--- {0}   {1} record(s)" -f $log, $evts.Count) 'STEP'
            $hot = @($evts | Where-Object { Test-IsInteresting $_.Message })
            foreach ($e in ($hot | Sort-Object TimeCreated)) {
                W ("  {0}  id={1,-6} {2}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, (Short ($e.Message -replace '\s+',' ') 160)) 'HIT'
            }
            foreach ($g in ($evts | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 12)) {
                $first = $g.Group | Sort-Object TimeCreated | Select-Object -First 1
                W ("  x{0,-4} id={1,-6} {2}  {3}" -f $g.Count, $g.Name, $first.TimeCreated.ToString('HH:mm:ss'),
                                                     (Short ($first.Message -replace '\s+',' ') 110))
            }
        }
        W ''
        W 'Full event text is not reproduced here. Pull a specific id with:' 'STEP'
        W ("  Get-WinEvent -FilterHashtable @{{LogName='<log>';Id=<id>;StartTime='{0}'}} | Format-List *" -f $t0.ToString('s')) 'STEP'
    } elseif (-not $Live) {
        W ''
        W 'Offline diff - event logs were not read. Run with -Compare on the device itself' 'WARN'
        W 'to get the event window as well.' 'WARN'
    }

    W ''
    W ("Diff written to: $DiffOut") 'OK'
    try { Set-Content -LiteralPath $DiffOut -Value ($script:Lines -join "`r`n") -Encoding UTF8 } catch { }
    return [pscustomobject]@{ Added=$added.Count; Removed=$gone.Count; Changed=$chg.Count; Suspects=$suspects }
}

# =====================================================================================
#  MAIN
# =====================================================================================
if ($DiffOnly) {
    $A = Import-Snapshot $Baseline
    $B = Import-Snapshot $Current
    $TargetDomain = @($A.TargetDomain); $OldTenantId = "$($A.OldTenantId)"
    $r = Compare-Snapshot $A $B
    if ($r.Suspects -gt 0) { exit 7 }
    exit 0
}

$null = Invoke-Capture
$B = $script:Snapshot

if ($Compare) {
    if ($Compare -ieq 'auto') {
        $cand = @(Get-ChildItem -LiteralPath $SnapDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.FullName -ne $JsonOut } | Sort-Object LastWriteTime -Descending)
        if ($cand.Count -eq 0) { W 'No earlier snapshot found to compare against.' 'WARN'; exit 0 }
        $Compare = $cand[0].FullName
        W ("Comparing against the most recent earlier snapshot: $Compare") 'STEP'
    }
    $A = Import-Snapshot $Compare
    $r = Compare-Snapshot $A $B -Live
    if ($r.Suspects -gt 0) { exit 7 }
}
exit 0
