<#
=====================================================================================
 Invoke-PostMigrationCleanup.ps1                                              v4.1.1

 Modular successor to clearFreeCache.ps1 v3.0.0.

 Pick exactly what runs with -Modules. Nothing runs that you did not ask for.

   .\Invoke-PostMigrationCleanup.ps1 -ListModules
   .\Invoke-PostMigrationCleanup.ps1 -Modules Delta -DryRun
   .\Invoke-PostMigrationCleanup.ps1 -Modules DeltaAccount,AppCache
   .\Invoke-PostMigrationCleanup.ps1 -Modules Safe

 -----------------------------------------------------------------------------------
 WHAT CHANGED FROM v3.0.0, AND WHY

 v3 had three functions that deleted EVERY work account on the device, not just the
 old tenant's. On a machine with the new tenant already signed in, running v3 signed
 that account out and removed it too:

   Invoke-WamAccountCleanup    cleared the whole TokenBroker\Accounts folder
   Invoke-OfficeIdentityReset  removed the whole Office ...\Common\Identity key
   Invoke-WorkplaceJoinLeave   bare "dsregcmd /leave", tenant-agnostic

 v4 walks those stores item by item and applies the UPN suffix gate to each one.
 The modules that genuinely cannot be scoped to one tenant (all Outlook profiles,
 all credentials, all OneDrive links) are separated out, kept out of every preset,
 and refuse to run without -IAcceptAllAccountImpact.

 v3 also filtered profiles with  ^S-1-5-21-  only, which silently skipped every
 Entra ID logon (S-1-12-1-*). That is why the delta account survived every run on
 DESKTOP-VP6IKCC. v4 enumerates both SID families.

 v3 read HKCU: in several places. Under the RMM the script runs as SYSTEM, where
 HKCU is SYSTEM's own hive - so those reads found nothing and reported success.
 v4 never touches HKCU; every per-user read goes through the profile list and, when
 the user is not logged on, an offline NTUSER.DAT load.

 -----------------------------------------------------------------------------------
 NEVER TOUCHED, IN ANY MODULE, EVER

   *.pst  *.olm  *.nst  *.mbox  *.eml  *.msg      mail data
   *.ost                                          unless -Modules OstFiles
   OneDrive / Desktop / Documents / Downloads     user data
   The device-level Entra join or AD domain join
   MDM enrolment
   Any account whose UPN does not end in @<TargetDomain>

 Everything removed is copied to C:\ProgramData\PMC\Cleanup\<stamp> first.
 Run ELEVATED.

 -----------------------------------------------------------------------------------
 DELETION THAT ACTUALLY DELETES
   Remove-Item -> strip ReadOnly/Hidden/System -> \\?\ long-path form -> robocopy /MIR
   from an empty folder. Each step is tried in turn, and the robocopy step re-runs the
   safety checks itself rather than trusting the caller.

 APPLICATIONS
   Closed politely first (CloseMainWindow), waited on for -GraceSeconds, then killed.
   Force-killing Outlook or Teams mid-write is how an OST gets corrupted.

 EXIT CODES
   0     clean
   1     at least one operation failed
   2     refused - bad module, a gated module without consent, or a missing prerequisite
   3     no profile matched
   5     a target item survived the run (see Recreated in the receipt)
   3010  success, restart required   <- what an RMM reads as "schedule the reboot"
   Precedence: 5 beats 1, 1 beats 3010. -NoReboot suppresses 3010 entirely.

 CONTEXT
   Designed to run from the RMM as SYSTEM. There is no user-session dispatch: every
   per-user read goes through the profile list and an offline NTUSER.DAT load. The one
   thing SYSTEM cannot reach is Credential Manager, which is per-user and DPAPI-sealed
   - DeltaCredentials says so and reports instead of acting. Those leftovers are
   orphaned tokens once the account files are gone.
=====================================================================================
#>

[CmdletBinding()]
param(
    [string[]] $Modules      = @('Delta'),
    [string[]] $TargetDomain = @('delta.mainettigroup.onmicrosoft.com'),
    [string]   $OldTenantId  = '905cd5ac-a071-4697-a446-c9077a81e24b',
    [switch]   $DryRun,
    [switch]   $SkipProcessKill,
    [switch]   $IAcceptAllAccountImpact,
    [switch]   $ListModules,
    [string[]] $OnlyUser     = @(),      # profile name or SID; default is every profile
    [ValidateRange(0,300)]
    [int]      $GraceSeconds = 20,       # polite close before force-kill, and reboot delay
    [switch]   $Reboot,                  # restart when the run finishes
    [switch]   $NoReboot,                # never restart, and never return 3010
    [switch]   $CaptureEvidence,         # dsregcmd / whoami / klist raw output into the log dir
    [string]   $OutRoot      = 'C:\ProgramData\PMC'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$Version     = '4.1.1'
$ScriptStart = Get-Date
$Stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'

# powershell.exe -File does not strip quotes from arguments, so a caller writing
#   -TargetDomain "delta.x.com"
# through an RMM can deliver the quotes as part of the string. Strip them here or
# every suffix comparison silently fails and the script reports "nothing to do".
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
$Modules      = @(Convert-ArgList $Modules)

if ($TargetDomain.Count -eq 0) {
    Write-Host 'No target domain supplied. Refusing to run.' -ForegroundColor Red
    exit 2
}

# =====================================================================================
#  MODULE REGISTRY
#
#  Scope  DeltaOnly    touches only items whose UPN ends in @<TargetDomain>
#         CacheOnly    deletes caches, no account is removed, no data is lost
#         SignsOut     no account is removed, but every account must re-authenticate
#         AllAccounts  affects accounts other than the target - gated
# =====================================================================================
$Registry = @(
  [pscustomobject]@{ Name='DeltaAccount';     Scope='DeltaOnly';   NeedsApps=$true
    Desc='Remove the old-tenant account from Settings: WAM broker files, WorkplaceJoin, Office identity.' }
  [pscustomobject]@{ Name='DeltaCredentials'; Scope='DeltaOnly';   NeedsApps=$false
    Desc='Credential Manager entries whose user or target names the old tenant. Others kept. Per-user and DPAPI-sealed, so under SYSTEM it reports rather than acts.' }
  [pscustomobject]@{ Name='DeltaOneDrive';    Scope='DeltaOnly';   NeedsApps=$true
    Desc='Unlink ONLY the old-tenant OneDrive business account. Synced files are never deleted.' }
  [pscustomobject]@{ Name='DeltaBrowser';     Scope='DeltaOnly';   NeedsApps=$true
    Desc='Delete the whole Chromium profile signed in with the old tenant - including its bookmarks and saved passwords. Backed up. Other profiles kept.' }
  [pscustomobject]@{ Name='DeltaAutoDiscover'; Scope='DeltaOnly';  NeedsApps=$true
    Desc='AutoDiscover entries and cached XML that point Outlook at the old tenant. This is what redirects a user back to the old sign-in page.' }
  [pscustomobject]@{ Name='DeltaOfficeLicense';Scope='DeltaOnly';  NeedsApps=$true
    Desc='Office vNext licence tokens issued to the old tenant. Other tenants'' licences are kept, so activation is not reset wholesale.' }
  [pscustomobject]@{ Name='AppCache';         Scope='CacheOnly';   NeedsApps=$true
    Desc='Teams / Office / Edge scratch caches. Nothing is signed out.' }
  [pscustomobject]@{ Name='OutlookCache';     Scope='CacheOnly';   NeedsApps=$true
    Desc='Outlook RoamCache and forms cache. No profiles, no mail, no OST.' }
  [pscustomobject]@{ Name='TokenCache';       Scope='SignsOut';    NeedsApps=$true
    Desc='OneAuth / IdentityCache token stores. EVERY account must sign in again.' }
  [pscustomobject]@{ Name='BrowserCache';     Scope='SignsOut';    NeedsApps=$true
    Desc='Browser cache and cookies for all profiles. Signs the user out of websites.' }
  [pscustomobject]@{ Name='OutlookProfileAll';Scope='AllAccounts'; NeedsApps=$true
    Desc='Delete ALL Outlook mail profiles. Every mailbox is reconfigured. Mail files untouched.' }
  [pscustomobject]@{ Name='CredentialsAll';   Scope='AllAccounts'; NeedsApps=$false
    Desc='Delete ALL Microsoft credentials in Credential Manager, every tenant.' }
  [pscustomobject]@{ Name='OneDriveAll';      Scope='AllAccounts'; NeedsApps=$true
    Desc='Unlink EVERY OneDrive business account. Synced files are never deleted.' }
  [pscustomobject]@{ Name='OstFiles';         Scope='AllAccounts'; NeedsApps=$true
    Desc='Delete .ost offline caches. Rebuilt on next sync. Never touches .pst / .olm.' }
)
# Presets describe BREADTH, not risk. Every one of them is tenant-scoped; none will
# remove another tenant's account. "Safe" means nothing is lost, not that it does less.
$DeltaSet = @('DeltaAccount','DeltaCredentials','DeltaOneDrive','DeltaAutoDiscover','DeltaOfficeLicense')
$Presets = [ordered]@{
  'Delta' = $DeltaSet
  'Safe'  = $DeltaSet + @('DeltaBrowser','AppCache','OutlookCache')
  'Full'  = $DeltaSet + @('DeltaBrowser','AppCache','OutlookCache','TokenCache','BrowserCache')
}
$PresetDesc = [ordered]@{
  'Delta' = 'everything tied to the old tenant, and nothing else - the fleet default'
  'Safe'  = 'Delta, plus its browser profile and every cache that loses nothing'
  'Full'  = 'Safe, plus the token and browser caches - every account signs in again'
}

if ($ListModules) {
    Write-Host ''
    Write-Host "  Invoke-PostMigrationCleanup.ps1  v$Version   modules" -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 96)) -ForegroundColor DarkGray
    foreach ($m in $Registry) {
        $c = 'Gray'
        switch ($m.Scope) {
            'DeltaOnly'   { $c = 'Green'  }
            'CacheOnly'   { $c = 'Gray'   }
            'SignsOut'    { $c = 'Yellow' }
            'AllAccounts' { $c = 'Red'    }
        }
        Write-Host ("  {0,-18} {1,-12} {2}" -f $m.Name, $m.Scope, $m.Desc) -ForegroundColor $c
    }
    Write-Host ('  ' + ('-' * 96)) -ForegroundColor DarkGray
    foreach ($k in $Presets.Keys) {
        Write-Host ("  preset {0,-6} = {1}" -f $k, ($Presets[$k] -join ', ')) -ForegroundColor Cyan
        Write-Host ("            {0,-6}   {1}" -f '', $PresetDesc[$k]) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Red modules affect accounts other than the old tenant. They are in no preset and' -ForegroundColor Red
    Write-Host '  refuse to run unless you also pass -IAcceptAllAccountImpact.' -ForegroundColor Red
    Write-Host ''
    exit 0
}

# ------------------------------------------------------------------ resolve -Modules
$Selected = New-Object System.Collections.ArrayList
$Unknown  = New-Object System.Collections.ArrayList
foreach ($tok in $Modules) {
    $hit = $false
    foreach ($k in $Presets.Keys) {
        if ($tok -ieq $k) { foreach ($n in $Presets[$k]) { if ($Selected -notcontains $n) { [void]$Selected.Add($n) } }; $hit = $true; break }
    }
    if ($hit) { continue }
    if ($tok -ieq 'All') {
        foreach ($n in $Presets['Full']) { if ($Selected -notcontains $n) { [void]$Selected.Add($n) } }
        Write-Host 'NOTE: "All" resolves to the Full preset. The all-account modules are never' -ForegroundColor Yellow
        Write-Host '      included by a preset - name them explicitly if you really want them.'  -ForegroundColor Yellow
        continue
    }
    $m = $Registry | Where-Object { $_.Name -ieq $tok } | Select-Object -First 1
    if ($m) { if ($Selected -notcontains $m.Name) { [void]$Selected.Add($m.Name) } }
    else    { [void]$Unknown.Add($tok) }
}
if ($Unknown.Count -gt 0) {
    Write-Host ("Unknown module(s): " + ($Unknown -join ', ')) -ForegroundColor Red
    Write-Host ("Valid: " + (($Registry | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Gray
    Write-Host ("Presets: " + (($Presets.Keys) -join ', ')) -ForegroundColor Gray
    exit 2
}
if ($Selected.Count -eq 0) { Write-Host 'No modules selected. Nothing to do.' -ForegroundColor Yellow; exit 0 }

$Gated = @($Registry | Where-Object { $Selected -contains $_.Name -and $_.Scope -eq 'AllAccounts' })
if ($Gated.Count -gt 0 -and -not $IAcceptAllAccountImpact) {
    Write-Host ''
    Write-Host 'REFUSING TO RUN.' -ForegroundColor Red
    Write-Host 'These modules affect work accounts other than the old tenant:' -ForegroundColor Red
    foreach ($g in $Gated) { Write-Host ("   {0}  -  {1}" -f $g.Name, $g.Desc) -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Re-run with -IAcceptAllAccountImpact if that is what you intend, or drop them.' -ForegroundColor Yellow
    Write-Host 'The delta-only work needs none of them: -Modules Delta' -ForegroundColor Yellow
    exit 2
}

# =====================================================================================
#  LOGGING / RECEIPT
# =====================================================================================
$LogDir    = Join-Path $OutRoot 'Logs'
$BackupDir = Join-Path $OutRoot "Cleanup\$Stamp"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile     = Join-Path $LogDir ("Cleanup-{0}-{1}.log"  -f $env:COMPUTERNAME, $Stamp)
$ReceiptFile = Join-Path $LogDir ("Cleanup-{0}-{1}.json" -f $env:COMPUTERNAME, $Stamp)
$FleetCsv    = Join-Path $OutRoot 'FleetSummary.csv'

function W {
    param([string]$Text='', [string]$Level='INFO')
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Text
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    $c = 'Gray'
    switch ($Level) {
        'STEP'  { $c='Cyan'     }  'WARN' { $c='Yellow'   }  'ERROR' { $c='Red'     }
        'GONE'  { $c='Green'    }  'OK'   { $c='Green'    }  'KEEP'  { $c='DarkGray'}
        'DRY'   { $c='Magenta'  }  'KEY'  { $c='Magenta'  }
    }
    Write-Host $line -ForegroundColor $c
}
function Section { param([string]$t) W ''; W ('-' * 78) 'STEP'; W "  $t" 'STEP'; W ('-' * 78) 'STEP' }

$script:Removed  = 0
$script:Failed   = 0
$script:Bytes    = 0
$script:Kept     = 0
$script:Steps    = New-Object System.Collections.ArrayList
$script:Errors   = New-Object System.Collections.ArrayList
$script:Actions  = New-Object System.Collections.ArrayList

function Add-Action {
    param([string]$Module,[string]$Kind,[string]$ProfileName,[string]$Upn,[string]$Item,[string]$Result)
    [void]$script:Actions.Add([pscustomobject]@{
        Module=$Module; Kind=$Kind; Profile=$ProfileName; Upn=$Upn; Item=$Item; Result=$Result })
}

# =====================================================================================
#  THE SAFETY GATE  (ported verbatim from Remove-DeltaAccount.ps1 v1.0.0, field proven)
# =====================================================================================
function Test-UpnIsTarget {
    <#
      Exact suffix match on '@domain'. Never a substring test.
        Manav@delta.mainettigroup.onmicrosoft.com            -> TRUE
        Mitigata.Manav@delta.mainettigroup.onmicrosoft.com   -> TRUE  (local part irrelevant)
        x@notdelta.mainettigroup.onmicrosoft.com             -> FALSE
        x@sub.delta.mainettigroup.onmicrosoft.com            -> FALSE
        x@delta.mainettigroup.onmicrosoft.com.evil.net       -> FALSE
        abhishek@mainetti.com                                -> FALSE
        '' / $null                                           -> FALSE
    #>
    param([string]$Upn)
    if (-not $Upn) { return $false }
    $at = $Upn.LastIndexOf('@')
    if ($at -lt 0 -or $at -ge ($Upn.Length - 1)) { return $false }
    $suffix = $Upn.Substring($at + 1).ToLowerInvariant()
    foreach ($d in $TargetDomain) { if ($d -and $suffix -eq $d.ToLowerInvariant()) { return $true } }
    return $false
}
function Test-TextNamesTarget {
    # For opaque blobs (credential target names, JSON) where there is no clean UPN field.
    # Still an anchored check: the domain must appear as a whole label-run, not a fragment.
    param([string]$Text)
    if (-not $Text) { return $false }
    $t = $Text.ToLowerInvariant()
    foreach ($d in $TargetDomain) {
        if (-not $d) { continue }
        $dd = $d.ToLowerInvariant()
        $i = $t.IndexOf($dd)
        while ($i -ge 0) {
            $before = if ($i -eq 0) { '' } else { $t.Substring($i-1,1) }
            $endIdx = $i + $dd.Length
            $after  = if ($endIdx -ge $t.Length) { '' } else { $t.Substring($endIdx,1) }
            $okB = ($before -eq '' -or $before -notmatch '[a-z0-9\-.]')
            $okA = ($after  -eq '' -or $after  -notmatch '[a-z0-9\-.]')
            if ($okB -and $okA) { return $true }
            $i = $t.IndexOf($dd, $i + 1)
        }
    }
    return $false
}
function Get-UpnFromBytes {
    param([byte[]]$Bytes)
    foreach ($enc in @([Text.Encoding]::Unicode,[Text.Encoding]::UTF8,[Text.Encoding]::ASCII)) {
        try {
            $s = $enc.GetString($Bytes)
            $m = [regex]::Match($s,'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
            if ($m.Success) { return $m.Value }
        } catch { }
    }
    return ''
}
function RegVal { param([string]$Path,[string]$Name)
    try { return (Get-Item -LiteralPath $Path -ErrorAction Stop).GetValue($Name,$null) } catch { return $null }
}


# =====================================================================================
#  ENVIRONMENT, PREREQUISITES, EVIDENCE
# =====================================================================================
function Write-Heartbeat {
    # Written before anything else can fail, so a machine that dies mid-run still says
    # what it got to. The RMM can read this even when the log never appeared.
    param([string]$State)
    try {
        $hb = Join-Path $OutRoot 'heartbeat.txt'
        $line = "{0}  {1}  {2}  v{3}  pid={4}" -f (Get-Date -Format 's'), $env:COMPUTERNAME, $State, $Version, $PID
        Set-Content -LiteralPath $hb -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}
function Get-EnvironmentSnapshot {
    $o = [ordered]@{
        Computer   = $env:COMPUTERNAME
        PSVersion  = $PSVersionTable.PSVersion.ToString()
        PSEdition  = "$($PSVersionTable.PSEdition)"
        Culture    = (Get-Culture).Name
        UICulture  = (Get-UICulture).Name
        OS         = ''
        Build      = ''
        FreeGB     = ''
        Domain     = ''
    }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $o.OS    = "$($os.Caption)"
        $o.Build = "$($os.BuildNumber)"
    } catch { }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $o.Domain = "$($cs.Domain)"
    } catch { }
    try {
        $d = Get-PSDrive -Name ((Split-Path $OutRoot -Qualifier) -replace ':','') -ErrorAction Stop
        $o.FreeGB = [math]::Round($d.Free / 1GB, 1)
    } catch { }
    return $o
}
function Test-Prerequisites {
    # Localisation note: nothing here parses localised console output. reg.exe and
    # robocopy are used for their exit codes only, and credentials go through the
    # Win32 API rather than cmdkey - which is what broke on the Italian machines.
    $need = @(
        @{ Cmd='reg.exe';      Why='offline NTUSER.DAT load for logged-off profiles'; Hard=$true  }
        @{ Cmd='robocopy.exe'; Why='fallback purge for long paths and locked folders'; Hard=$false }
        @{ Cmd='shutdown.exe'; Why='-Reboot';                                          Hard=$false }
    )
    $missing = @()
    foreach ($n in $need) {
        if (-not (Get-Command $n.Cmd -ErrorAction SilentlyContinue)) {
            $missing += $n.Cmd
            $lvl = if ($n.Hard) { 'ERROR' } else { 'WARN' }
            W ("  missing {0,-14} - {1}" -f $n.Cmd, $n.Why) $lvl
        }
    }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        W ("  PowerShell {0} - this script targets 5.1 or later" -f $PSVersionTable.PSVersion) 'ERROR'
        $missing += 'powershell5'
    }
    if ($missing.Count -eq 0) { W '  all prerequisites present.' 'OK' }
    return $missing
}
function Get-ActiveConsoleSids {
    # A loaded HKEY_USERS hive means that user is signed in right now. Locale
    # independent, unlike parsing quser / query session.
    $out = New-Object System.Collections.ArrayList
    foreach ($k in (Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $n = $k.PSChildName
        if ($n -match '_Classes$') { continue }
        if ($n -match '^S-1-5-21-' -or $n -match '^S-1-12-1-') { [void]$out.Add($n) }
    }
    return $out.ToArray()
}
function Invoke-CaptureTool {
    # Raw output, verbatim, never parsed. Exists so a failed run can be diagnosed
    # from the log bundle without asking someone to re-run commands by hand.
    param([string]$Name,[string]$Exe,[string[]]$Arguments=@())
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { W ("  $Exe not present, skipped") 'KEEP'; return }
    $dest = Join-Path $LogDir ("{0}-{1}-{2}.txt" -f $Name, $env:COMPUTERNAME, $Stamp)
    try {
        $raw = & $Exe @Arguments 2>&1 | Out-String
        Set-Content -LiteralPath $dest -Value $raw -Encoding UTF8
        W ("  captured $Name -> $dest")
    } catch { W ("  could not capture $Name : " + $_.Exception.Message) 'WARN' }
}

# =====================================================================================
#  DATA GUARDS
# =====================================================================================
# .ost is in this list until the OstFiles module is explicitly selected.
$script:MailExt = @('.pst','.olm','.nst','.mbox','.eml','.msg','.ost')
if ($Selected -contains 'OstFiles') { $script:MailExt = @($script:MailExt | Where-Object { $_ -ne '.ost' }) }
$script:DS             = [IO.Path]::DirectorySeparatorChar
$script:ProtectedPaths = New-Object System.Collections.ArrayList   # folder AND everything under it
$script:ProtectedRoots = New-Object System.Collections.ArrayList   # the folder itself only
$script:AllowedPaths   = New-Object System.Collections.ArrayList
$script:PstInventory   = New-Object System.Collections.ArrayList

function Add-Protected {
    param([string]$Path)
    if (-not $Path) { return }
    try { $f = [IO.Path]::GetFullPath($Path).TrimEnd($script:DS) } catch { return }
    if ($f -and ($script:ProtectedPaths -notcontains $f)) { [void]$script:ProtectedPaths.Add($f) }
}
function Add-ProtectedRoot {
    # A profile root: never cleared as a unit, but its subfolders are where the caches
    # live, so it must NOT shield everything beneath it.
    param([string]$Path)
    if (-not $Path) { return }
    try { $f = [IO.Path]::GetFullPath($Path).TrimEnd($script:DS) } catch { return }
    if ($f -and ($script:ProtectedRoots -notcontains $f)) { [void]$script:ProtectedRoots.Add($f) }
}
function Add-Allowed {
    # A cache folder that happens to sit inside a protected data folder - RoamCache lives
    # under the Outlook data directory. The mail-data scan still runs on it; only the
    # "inside a protected folder" rule is waived, and only for this exact subtree.
    param([string]$Path)
    if (-not $Path) { return }
    try { $f = [IO.Path]::GetFullPath($Path).TrimEnd($script:DS) } catch { return }
    if ($f -and ($script:AllowedPaths -notcontains $f)) { [void]$script:AllowedPaths.Add($f) }
}

function Test-PathIsSafeToClear {
    <#
      Returns $true only when every one of these holds:
        * the path resolves and is at least 4 segments deep
        * it sits inside a known user profile (or %SystemRoot%\Temp)
        * it is not, and does not contain, a protected user-data folder
        * no mail-data file exists anywhere under it (checked to depth 4)
    #>
    param([string]$Path,[switch]$ItemGuardOnly)
    if (-not $Path) { return $false }
    $full = ''
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd($script:DS) } catch { return $false }
    if (-not (Test-Path -LiteralPath $full)) { return $false }
    $segs = @($full.Split($script:DS) | Where-Object { $_ })
    if ($segs.Count -lt 4) { W ("  GUARD: too shallow, refusing: $full") 'WARN'; return $false }

    $inside = $false
    foreach ($r in $script:ContainerRoots) {
        if ($full -eq $r) { continue }
        if ($full.ToLower().StartsWith(($r.ToLower() + $script:DS))) { $inside = $true; break }
    }
    if (-not $inside) { W ("  GUARD: outside every profile root, refusing: $full") 'WARN'; return $false }

    $waived = $false
    foreach ($a in $script:AllowedPaths) {
        if ($full -ieq $a -or $full.ToLower().StartsWith(($a.ToLower() + $script:DS))) { $waived = $true; break }
    }
    foreach ($p in $script:ProtectedRoots) {
        if ($full -ieq $p) { W ("  GUARD: profile root, refusing: $full") 'WARN'; return $false }
        if ($p.ToLower().StartsWith(($full.ToLower() + $script:DS))) { W ("  GUARD: contains profile root $p, refusing: $full") 'WARN'; return $false }
    }
    foreach ($p in $script:ProtectedPaths) {
        if ($p.ToLower().StartsWith(($full.ToLower() + $script:DS))) { W ("  GUARD: contains protected $p, refusing: $full") 'WARN'; return $false }
        if ($waived) { continue }
        if ($full -ieq $p) { W ("  GUARD: protected folder, refusing: $full") 'WARN'; return $false }
        if ($full.ToLower().StartsWith(($p.ToLower() + $script:DS))) { W ("  GUARD: inside protected $p, refusing: $full") 'WARN'; return $false }
    }

    if ($ItemGuardOnly) { return $true }
    $bad = $null
    try {
        $bad = Get-ChildItem -LiteralPath $full -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
               Where-Object { $script:MailExt -contains $_.Extension.ToLowerInvariant() } |
               Select-Object -First 1
    } catch { }
    if ($bad) { W ("  GUARD: mail data under this path ({0}), refusing: {1}" -f $bad.Name, $full) 'WARN'; return $false }
    return $true
}

# =====================================================================================
#  DELETION THAT ACTUALLY DELETES
#  Remove-Item alone fails on three things that are common in real profiles:
#  ReadOnly/Hidden/System attributes, paths past 260 characters, and folders whose
#  handles are still open. Each gets its own escalation below.
# =====================================================================================
function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}
function Get-FolderSizeSafe {
    param([string]$Path)
    $t = 0
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) { $t += $f.Length }
    } catch { }
    return $t
}
function Clear-ItemAttributes {
    # ReadOnly | Hidden | System stop Remove-Item dead. Strip them, then retry.
    param([string]$Path)
    try {
        $items = @()
        $root = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($root) { $items += $root }
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $items += @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)
        }
        foreach ($i in $items) {
            try {
                if (($i.Attributes -band [IO.FileAttributes]::ReadOnly) -or
                    ($i.Attributes -band [IO.FileAttributes]::Hidden)   -or
                    ($i.Attributes -band [IO.FileAttributes]::System)) {
                    if ($i.PSIsContainer) { $i.Attributes = [IO.FileAttributes]::Directory }
                    else                  { $i.Attributes = [IO.FileAttributes]::Normal    }
                }
            } catch { }
        }
    } catch { }
}
function Get-LongPath {
    param([string]$Path)
    if ($Path -like '\\?\*')      { return $Path }
    if ($Path -like '\\*')        { return ('\\?\UNC\' + $Path.Substring(2)) }
    return ('\\?\' + $Path)
}
function Test-PathPurgeable {
    # Minimal independent re-check before robocopy mirrors an empty folder over it.
    # robocopy /MIR is unforgiving, so this never trusts the caller.
    param([string]$Path)
    $full = ''
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd($script:DS) } catch { return $false }
    if (@($full.Split($script:DS) | Where-Object { $_ }).Count -lt 4) { return $false }
    $inside = $false
    foreach ($r in $script:ContainerRoots) { if ($full.ToLower().StartsWith(($r.ToLower() + $script:DS))) { $inside = $true; break } }
    if (-not $inside) { return $false }
    foreach ($p in @($script:ProtectedPaths) + @($script:ProtectedRoots)) {
        if ($full -ieq $p) { return $false }
        if ($p.ToLower().StartsWith(($full.ToLower() + $script:DS))) { return $false }
    }
    $waived = $false
    foreach ($a in $script:AllowedPaths) { if ($full -ieq $a -or $full.ToLower().StartsWith(($a.ToLower() + $script:DS))) { $waived = $true; break } }
    if (-not $waived) {
        foreach ($p in $script:ProtectedPaths) { if ($full.ToLower().StartsWith(($p.ToLower() + $script:DS))) { return $false } }
    }
    try {
        $bad = Get-ChildItem -LiteralPath $full -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
               Where-Object { $script:MailExt -contains $_.Extension.ToLowerInvariant() } | Select-Object -First 1
        if ($bad) { return $false }
    } catch { }
    return $true
}
function Invoke-RobocopyPurge {
    # Mirrors an empty directory over the target. This is how long paths and folders
    # with open handles get cleared when Remove-Item will not.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    if (-not (Test-PathPurgeable $Path)) { W ("  GUARD: refusing robocopy purge of $Path") 'WARN'; return $false }
    if (-not (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) { return $false }
    $empty = Join-Path ([IO.Path]::GetTempPath()) ('pmc_empty_' + ([guid]::NewGuid().ToString('N').Substring(0,8)))
    try {
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        $null = & robocopy.exe $empty $Path /MIR /NFL /NDL /NJH /NJS /NC /NS /NP /R:1 /W:1 2>&1
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        $left = 0
        if (Test-Path -LiteralPath $Path) { $left = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count }
        if ($left -eq 0) { W ("  robocopy purge cleared $Path") 'GONE'; return $true }
        return $false
    } catch { return $false }
    finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
}
function Remove-ItemHard {
    <# Remove-Item, then attributes, then the \\?\ long-path form, then robocopy. #>
    param([string]$Path,[switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    try { Remove-Item -LiteralPath $Path -Force -Recurse:$Recurse -ErrorAction Stop; return $true } catch { }
    Clear-ItemAttributes $Path
    try { Remove-Item -LiteralPath $Path -Force -Recurse:$Recurse -ErrorAction Stop
          W ("  cleared attributes to remove $Path") 'GONE'; return $true } catch { }
    try {
        $lp = Get-LongPath $Path
        Remove-Item -LiteralPath $lp -Force -Recurse:$Recurse -ErrorAction Stop
        W ("  long-path form removed $Path") 'GONE'; return $true
    } catch { }
    if (Test-Path -LiteralPath $Path -PathType Container) { if (Invoke-RobocopyPurge $Path) { return $true } }
    return $false
}
function Remove-RegistryKeySafe {
    # Never deletes a key whose backup did not land on disk.
    param([string]$PsPath,[string]$Tag)
    if ($DryRun) { return $true }
    $before = @(Get-ChildItem -LiteralPath $BackupDir -Filter '*.reg' -ErrorAction SilentlyContinue).Count
    $okBackup = Backup-RegistryKey $PsPath $Tag
    $after  = @(Get-ChildItem -LiteralPath $BackupDir -Filter '*.reg' -ErrorAction SilentlyContinue).Count
    if (-not $okBackup -or $after -le $before) {
        W ("  REFUSING to delete $PsPath - the backup did not write") 'ERROR'
        $script:Failed++
        return $false
    }
    try { Remove-Item -LiteralPath $PsPath -Recurse -Force -ErrorAction Stop; return $true }
    catch { Write-ErrorDetail $_ ("removing $PsPath"); return $false }
}
function Write-ErrorDetail {
    param($ErrorRecord,[string]$Context='')
    $m = ''
    try {
        $m = "{0}: {1}" -f $Context, $ErrorRecord.Exception.Message
        W ("  ERROR $m") 'ERROR'
        if ($ErrorRecord.InvocationInfo) {
            W ("        at line {0}: {1}" -f $ErrorRecord.InvocationInfo.ScriptLineNumber,
                                             ($ErrorRecord.InvocationInfo.Line -replace '\s+',' ').Trim()) 'ERROR'
        }
        W ("        type {0}" -f $ErrorRecord.Exception.GetType().FullName) 'ERROR'
        if ($ErrorRecord.ScriptStackTrace) {
            foreach ($l in ($ErrorRecord.ScriptStackTrace -split "`n")) { W ("        $l") 'ERROR' }
        }
    } catch { }
    [void]$script:Errors.Add([pscustomobject]@{
        Context = $Context
        Message = "$($ErrorRecord.Exception.Message)"
        Type    = "$($ErrorRecord.Exception.GetType().FullName)"
        Line    = "$($ErrorRecord.InvocationInfo.ScriptLineNumber)"
        Stack   = "$($ErrorRecord.ScriptStackTrace)"
    })
    return $m
}

function Clear-FolderContent {
    <#
      Deletes the CONTENTS of a folder, never the folder itself, and never a
      mail-data file even if one slipped past Test-PathIsSafeToClear.

      -ItemGuardOnly relaxes the FOLDER-level mail veto for folders where a stray
      .msg is normal and should not veto the whole clear (the per-user Temp folder).
      The per-item guard below still refuses every mail file individually.
    #>
    param([string]$Path,[string]$Module,[string]$ProfileName,[switch]$ItemGuardOnly)
    if (-not (Test-PathIsSafeToClear $Path -ItemGuardOnly:$ItemGuardOnly)) { return }
    $n = 0; $b = 0; $skipped = 0
    foreach ($item in (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if ($item.PSIsContainer) {
            $hasMail = $null
            try {
                $hasMail = Get-ChildItem -LiteralPath $item.FullName -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
                           Where-Object { $script:MailExt -contains $_.Extension.ToLowerInvariant() } | Select-Object -First 1
            } catch { }
            if ($hasMail) { $skipped++; continue }
        } else {
            if ($script:MailExt -contains $item.Extension.ToLowerInvariant()) { $skipped++; continue }
        }
        $sz = 0
        if ($item.PSIsContainer) { $sz = Get-FolderSizeSafe $item.FullName } else { $sz = $item.Length }
        if ($DryRun) { $n++; $b += $sz; continue }
        if (Remove-ItemHard $item.FullName -Recurse) { $b += $sz; $n++ }
        else { W ("  could not remove " + $item.FullName) 'ERROR'; $script:Failed++ }
    }
    $script:Bytes += $b
    if ($n -gt 0 -or $skipped -gt 0) {
        $verb = if ($DryRun) { 'WOULD CLEAR' } else { 'cleared' }
        $lvl  = if ($DryRun) { 'DRY' } else { 'GONE' }
        W ("  {0} {1} item(s), {2}{3} from {4}" -f $verb, $n, (Format-Bytes $b), $(if ($skipped) { " (kept $skipped protected)" } else { '' }), $Path) $lvl
        Add-Action $Module 'CacheFolder' $ProfileName '' $Path ("$verb $n")
    }
}

function Backup-Item {
    param([string]$Path,[string]$Tag)
    if ($DryRun) { return $true }
    try {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        $leaf = Split-Path $Path -Leaf
        $dest = Join-Path $BackupDir ("{0}__{1}" -f $Tag, $leaf)
        Copy-Item -LiteralPath $Path -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}
function Backup-RegistryKey {
    param([string]$PsPath,[string]$Tag)
    if ($DryRun) { return $true }
    try {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        $hive = ($PsPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','') -replace '^HKEY_USERS','HKU'
        $hive = $hive -replace '^HKEY_LOCAL_MACHINE','HKLM'
        $safe = ($Tag -replace '[^A-Za-z0-9._-]','_')
        & reg.exe export $hive (Join-Path $BackupDir "$safe.reg") /y 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# =====================================================================================
#  CONTEXT
# =====================================================================================
$IsAdmin = $false; $WhoAmI = $env:USERNAME
try {
    $wid     = [Security.Principal.WindowsIdentity]::GetCurrent()
    $WhoAmI  = $wid.Name
    $IsAdmin = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
$IsSystem = ($WhoAmI -ieq 'NT AUTHORITY\SYSTEM')
Write-Heartbeat 'starting'

W ('=' * 78) 'STEP'
W ("  POST-MIGRATION CLEANUP  v$Version") 'STEP'
W ('=' * 78) 'STEP'
W ("Running as    : $WhoAmI   (elevated=$IsAdmin, system=$IsSystem)")
W ("Target domain : " + ($TargetDomain -join ', '))
W ("Old tenant    : $OldTenantId")
W ("Mode          : " + $(if ($DryRun) { 'DRY RUN - nothing will change' } else { 'LIVE' }))
W ("Log           : $LogFile")
W ''
W 'Modules selected:' 'STEP'
foreach ($m in $Registry) {
    if ($Selected -notcontains $m.Name) { continue }
    $lvl = 'INFO'
    if ($m.Scope -eq 'AllAccounts') { $lvl = 'WARN' }
    elseif ($m.Scope -eq 'SignsOut') { $lvl = 'WARN' }
    W ("   {0,-18} [{1}]  {2}" -f $m.Name, $m.Scope, $m.Desc) $lvl
}
$notRun = @($Registry | Where-Object { $Selected -notcontains $_.Name } | ForEach-Object { $_.Name })
if ($notRun.Count) { W ("Not running: " + ($notRun -join ', ')) 'KEEP' }
if (-not $IsAdmin) { W 'NOT ELEVATED - other users'' profiles cannot be cleaned. Re-run as admin.' 'WARN' }

W ''
W 'Environment:' 'STEP'
$EnvSnap = Get-EnvironmentSnapshot
foreach ($k in $EnvSnap.Keys) { W ("   {0,-10} {1}" -f $k, $EnvSnap[$k]) }
W ''
W 'Prerequisites:' 'STEP'
$MissingPrereq = @(Test-Prerequisites)
if ($MissingPrereq -contains 'reg.exe' -or $MissingPrereq -contains 'powershell5') {
    W 'A hard prerequisite is missing. Refusing to run.' 'ERROR'
    Write-Heartbeat 'aborted-prereq'
    exit 2
}
if ($CaptureEvidence) {
    W ''
    W 'Evidence capture:' 'STEP'
    Invoke-CaptureTool 'dsregcmd' 'dsregcmd.exe' @('/status')
    Invoke-CaptureTool 'whoami'   'whoami.exe'   @('/all')
    Invoke-CaptureTool 'klist'    'klist.exe'    @('sessions')
}

# =====================================================================================
#  PROFILES  -  BOTH SID FAMILIES
#     S-1-5-21-*   local account or on-prem AD
#     S-1-12-1-*   Entra ID logon   <-- the family v3 dropped
# =====================================================================================
$profiles = New-Object System.Collections.ArrayList
$script:ContainerRoots = New-Object System.Collections.ArrayList
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
    if ($OnlyUser.Count -gt 0) {
        $wanted = $false
        foreach ($u in $OnlyUser) { if ($nm -ieq $u -or $sid -ieq $u) { $wanted = $true; break } }
        if (-not $wanted) { continue }
    }
    [void]$profiles.Add([pscustomobject]@{ Sid=$sid; Family=$fam; Path=$path; Name=$nm; LoggedOn=$false })
    [void]$script:ContainerRoots.Add(([IO.Path]::GetFullPath($path).TrimEnd($script:DS)))
}
$ActiveSids = @(Get-ActiveConsoleSids)
foreach ($pr in $profiles) { $pr.LoggedOn = ($ActiveSids -contains $pr.Sid) }
if ($env:SystemRoot) { [void]$script:ContainerRoots.Add((Join-Path $env:SystemRoot 'Temp')) }
W ''
W ("Profiles to inspect ({0}): " -f $profiles.Count) 'STEP'
foreach ($p in $profiles) {
    $st = if ($p.LoggedOn) { 'signed in' } else { 'logged off' }
    W ("   [{0,-9}] {1,-16} {2,-11} {3}" -f $p.Family, $p.Name, $st, $p.Sid)
}
if ($OnlyUser.Count -gt 0) { W ("Restricted to -OnlyUser: " + ($OnlyUser -join ', ')) 'WARN' }
if (@($profiles | Where-Object { $_.LoggedOn }).Count -gt 0) {
    W 'A signed-in session can re-create what is removed while the script runs. The VERIFY' 'WARN'
    W 'pass at the end flags anything written after the start time.'                        'WARN'
}
if ($profiles.Count -eq 0) {
    W 'No profile matched. Nothing to do.' 'WARN'
    Write-Heartbeat 'no-profiles'
    exit 3
}

# ------------------------------------------------------------------ offline hive helper
$loadedHives = New-Object System.Collections.ArrayList
function Invoke-WithUserHive {
    param($P, [scriptblock]$Body)
    $root = "Registry::HKEY_USERS\$($P.Sid)"
    $need = $false
    if (-not (Test-Path $root)) {
        $dat = Join-Path $P.Path 'NTUSER.DAT'
        if ((Test-Path -LiteralPath $dat) -and $IsAdmin) {
            $null = & reg.exe load "HKU\$($P.Sid)" "$dat" 2>&1
            if ($LASTEXITCODE -eq 0) { $need = $true; [void]$loadedHives.Add($P.Sid) }
            else { W ("  could not load the hive for {0} (user logged on? file locked?)" -f $P.Name) 'WARN'; return }
        } else { return }
    }
    # NOTE: a hive loaded here stays loaded until Dismount-UserHives runs at the end of
    # the script. v1 of the remover unloaded it in a finally block, which meant any
    # registry item DISCOVERED from an offline profile had an invalid path by the time
    # the removal pass reached it. It fails safe (Remove-Item errors) rather than
    # deleting the wrong key, but it silently does nothing on logged-off profiles.
    & $Body $root
}
function Dismount-UserHives {
    if ($loadedHives.Count -eq 0) { return }
    [gc]::Collect(); Start-Sleep -Milliseconds 400
    foreach ($sid in @($loadedHives)) {
        $null = & reg.exe unload "HKU\$sid" 2>&1
        if ($LASTEXITCODE -ne 0) {
            [gc]::Collect(); Start-Sleep -Milliseconds 800
            $null = & reg.exe unload "HKU\$sid" 2>&1
            if ($LASTEXITCODE -ne 0) { W ("  hive HKU\$sid could not be unloaded - it will clear at reboot") 'WARN' }
        }
    }
    $loadedHives.Clear()
}

# =====================================================================================
#  REGISTER EVERYTHING THAT MUST NEVER BE DELETED
# =====================================================================================
Section 'PROTECT USER DATA'
foreach ($p in $profiles) {
    Add-ProtectedRoot $p.Path
    foreach ($leaf in @('Desktop','Documents','Downloads','Pictures','Videos','Music','Favorites','Links','Saved Games','Contacts','Searches')) {
        Add-Protected (Join-Path $p.Path $leaf)
    }
    # any OneDrive folder, however it is named (OneDrive - Contoso, OneDrive)
    foreach ($d in (Get-ChildItem -LiteralPath $p.Path -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like 'OneDrive*' })) { Add-Protected $d.FullName }

    Invoke-WithUserHive $p {
        param($root)
        # OneDrive known-folder-move targets and sync roots
        $acc = "$root\Software\Microsoft\OneDrive\Accounts"
        if (Test-Path $acc) {
            foreach ($a in (Get-ChildItem -LiteralPath $acc -ErrorAction SilentlyContinue)) {
                foreach ($n in @('UserFolder','ClientFirstSignInTimestampUserFolder')) {
                    $uf = RegVal $a.PSPath $n
                    if ($uf) { Add-Protected ([string]$uf) }
                }
            }
        }
        foreach ($shellKey in @("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                                "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")) {
            if (-not (Test-Path $shellKey)) { continue }
            foreach ($n in @('Desktop','Personal','My Pictures','My Video','My Music','{374DE290-123F-4565-9164-39C4925E467B}')) {
                $v = RegVal $shellKey $n
                if ($v) {
                    $expanded = [Environment]::ExpandEnvironmentVariables([string]$v)
                    if ($expanded -notmatch '%') { Add-Protected $expanded }
                }
            }
        }
        # every Outlook data file registered in every mail profile
        foreach ($ver in @('16.0','15.0','14.0')) {
            $prof = "$root\Software\Microsoft\Office\$ver\Outlook\Profiles"
            if (-not (Test-Path $prof)) { continue }
            foreach ($sub in (Get-ChildItem -LiteralPath $prof -Recurse -ErrorAction SilentlyContinue)) {
                foreach ($vn in (Get-Item -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).Property) {
                    $raw = RegVal $sub.PSPath $vn
                    if ($raw -isnot [byte[]]) { continue }
                    $txt = ''
                    try { $txt = [Text.Encoding]::Unicode.GetString($raw) } catch { }
                    foreach ($mm in [regex]::Matches($txt,'[A-Za-z]:\\[^\x00]{3,240}?\.(pst|ost|nst|olm)')) {
                        $fp = $mm.Value
                        Add-Protected (Split-Path $fp -Parent)
                        if ($fp -match '\.pst$') {
                            [void]$script:PstInventory.Add([pscustomobject]@{ Profile=$P.Name; File=$fp; Exists=(Test-Path -LiteralPath $fp) })
                        }
                    }
                }
            }
        }
    }
}
# The default Outlook data-file location, whether or not a profile points at it, plus
# new Outlook's local store. That one matters: olk keeps mail in a SQLite database with
# no .pst/.ost extension, so the mail-data extension guard would not catch it. This is
# the same failure mode as the macOS run that destroyed an "On My Computer" mailbox.
foreach ($p in $profiles) {
    Add-Protected (Join-Path $p.Path 'Documents\Outlook Files')
    Add-Protected (Join-Path $p.Path 'AppData\Local\Microsoft\Outlook')
    Add-Protected (Join-Path $p.Path 'AppData\Roaming\Microsoft\Outlook')
    Add-Protected (Join-Path $p.Path 'AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe')
    Add-Protected (Join-Path $p.Path 'AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe')
    # cache subtrees inside those protected folders that OutlookCache is allowed to clear
    Add-Allowed   (Join-Path $p.Path 'AppData\Local\Microsoft\Outlook\RoamCache')
    Add-Allowed   (Join-Path $p.Path 'AppData\Local\Microsoft\Outlook\Offline Address Books')
}
W ("Protected paths registered : {0} folders + {1} profile root(s)" -f $script:ProtectedPaths.Count, $script:ProtectedRoots.Count)
W ("Outlook .pst files found   : {0}" -f $script:PstInventory.Count)
foreach ($pst in $script:PstInventory) { W ("   [{0}] {1}" -f $pst.Profile, $pst.File) 'KEEP' }
if ($script:PstInventory.Count -gt 0) {
    $pstList = Join-Path $LogDir ("PstInventory-{0}-{1}.csv" -f $env:COMPUTERNAME, $Stamp)
    try { $script:PstInventory | Export-Csv -LiteralPath $pstList -NoTypeInformation -Encoding UTF8
          W ("Re-attach list written to $pstList") } catch { }
}
W 'None of the above is deleted by any module in this script.' 'OK'

# =====================================================================================
#  STEP RUNNER  -  one module failing never stops the rest
# =====================================================================================
function Invoke-Step {
    param([string]$Name,[string]$Title,[scriptblock]$Body)
    if ($Selected -notcontains $Name) { return }
    Section $Title
    $t0  = Get-Date
    $err = ''
    try { & $Body } catch { $err = $_.Exception.Message; W ("MODULE FAILED: $err") 'ERROR'; $script:Failed++ }
    [void]$script:Steps.Add([pscustomobject]@{
        Module=$Name; Seconds=[math]::Round(((Get-Date)-$t0).TotalSeconds,1); Error=$err })
}

# =====================================================================================
#  CLOSE THE APPS THAT HOLD THESE ACCOUNTS
# =====================================================================================
$needApps = @($Registry | Where-Object { $Selected -contains $_.Name -and $_.NeedsApps }).Count -gt 0
if ($needApps -and -not $DryRun) {
    Section 'CLOSE THE APPS THAT HOLD THESE ACCOUNTS'
    if ($SkipProcessKill) {
        W 'Skipped (-SkipProcessKill). Running apps may re-create what is removed, within seconds.' 'WARN'
    } else {
        $holders = @('Microsoft.AAD.BrokerPlugin','msedge','msedgewebview2','ms-teams','Teams','chrome',
                     'OUTLOOK','olk','WINWORD','EXCEL','POWERPNT','ONENOTE','MSACCESS','lync','ms-teamsupdate',
                     'OneDrive','SystemSettings','FileCoAuth','Microsoft.SharePoint')
        # Ask first. Force-killing Outlook or Teams mid-write is how an OST gets corrupted.
        $asked = 0
        foreach ($h in $holders) {
            foreach ($proc in @(Get-Process -Name $h -ErrorAction SilentlyContinue)) {
                try { if ($proc.CloseMainWindow()) { $asked++ } } catch { }
            }
        }
        if ($asked -gt 0) {
            W ("Asked $asked window(s) to close, waiting up to ${GraceSeconds}s...")
            $deadline = (Get-Date).AddSeconds($GraceSeconds)
            while ((Get-Date) -lt $deadline) {
                $left = 0
                foreach ($h in $holders) { $left += @(Get-Process -Name $h -ErrorAction SilentlyContinue).Count }
                if ($left -eq 0) { break }
                Start-Sleep -Milliseconds 500
            }
        }
        $killed = 0
        foreach ($h in $holders) {
            foreach ($proc in @(Get-Process -Name $h -ErrorAction SilentlyContinue)) {
                try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop; $killed++ } catch { }
            }
        }
        W ("Closed $asked gracefully, force-stopped $killed.")
        Start-Sleep -Seconds 3
    }
}

# =====================================================================================
#  MODULE: DeltaAccount                                                     DELTA ONLY
#  WAM broker files + WorkplaceJoin + Office connected identity, item by item.
# =====================================================================================
Invoke-Step 'DeltaAccount' 'DELTA ACCOUNT - remove from Settings' {
    $remove = New-Object System.Collections.ArrayList
    $keep   = New-Object System.Collections.ArrayList

    foreach ($p in $profiles) {
        $bd = Join-Path $p.Path 'AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'
        if (Test-Path -LiteralPath $bd) {
            foreach ($f in (Get-ChildItem -LiteralPath $bd -Filter '*.tbacct' -File -ErrorAction SilentlyContinue)) {
                $upn = ''
                try { $upn = Get-UpnFromBytes ([IO.File]::ReadAllBytes($f.FullName)) } catch { }
                $o = [pscustomobject]@{ Kind='BrokerFile'; Upn=$upn; ProfileName=$p.Name; Family=$p.Family
                                        Path=$f.FullName; Id=$f.Name; Dir=$bd; Written=$f.LastWriteTime }
                if (Test-UpnIsTarget $upn) { [void]$remove.Add($o) } else { [void]$keep.Add($o) }
            }
        }
        Invoke-WithUserHive $p {
            param($root)
            $wpj = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo"
            if (Test-Path $wpj) {
                foreach ($e in (Get-ChildItem -LiteralPath $wpj -ErrorAction SilentlyContinue)) {
                    $upn = RegVal $e.PSPath 'UserEmail'; if (-not $upn) { $upn = RegVal $e.PSPath 'UserPrincipalName' }
                    $tid = RegVal $e.PSPath 'TenantId'
                    $isT = (Test-UpnIsTarget $upn) -or ($tid -and $OldTenantId -and ([string]$tid).ToLower() -eq $OldTenantId.ToLower())
                    $o = [pscustomobject]@{ Kind='WorkplaceJoin'; Upn=[string]$upn; ProfileName=$p.Name; Family=$p.Family
                                            Path=$e.PSPath; Id=$e.PSChildName; Dir=[string]$tid; Written=$null }
                    if ($isT) { [void]$remove.Add($o) } else { [void]$keep.Add($o) }
                }
            }
            foreach ($ver in @('16.0','15.0')) {
                $oid = "$root\SOFTWARE\Microsoft\Office\$ver\Common\Identity\Identities"
                if (-not (Test-Path $oid)) { continue }
                foreach ($e in (Get-ChildItem -LiteralPath $oid -ErrorAction SilentlyContinue)) {
                    $upn = $null
                    foreach ($n in @('EmailAddress','PreferredUsername','SignInName','UserPrincipalName')) {
                        if (-not $upn) { $upn = RegVal $e.PSPath $n }
                    }
                    if (-not $upn) {
                        $m = [regex]::Match($e.PSChildName,'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
                        if ($m.Success) { $upn = $m.Value }
                    }
                    $o = [pscustomobject]@{ Kind='OfficeIdentity'; Upn=[string]$upn; ProfileName=$p.Name; Family=$p.Family
                                            Path=$e.PSPath; Id=$e.PSChildName; Dir=''; Written=$null }
                    if (Test-UpnIsTarget $upn) { [void]$remove.Add($o) } else { [void]$keep.Add($o) }
                }
                # the "signed out but remembered" hint, cleared only when it names the target
                $common = "$root\SOFTWARE\Microsoft\Office\$ver\Common\Identity"
                foreach ($vn in @('SignedOutADUserId','ADUserId','EmailAddress')) {
                    $v = RegVal $common $vn
                    if ($v -and (Test-UpnIsTarget ([string]$v))) {
                        [void]$remove.Add([pscustomobject]@{ Kind='OfficeHint'; Upn=[string]$v; ProfileName=$p.Name
                                          Family=$p.Family; Path=$common; Id=$vn; Dir=''; Written=$null })
                    }
                }
            }
        }
    }

    W ''
    W ("WILL REMOVE  ({0} item(s))" -f $remove.Count) 'STEP'
    if ($remove.Count -eq 0) { W '   nothing on this machine matches the target domain.' 'OK' }
    foreach ($g in ($remove | Group-Object ProfileName, Upn, Kind)) {
        $s = $g.Group[0]
        W ("   [{0,-9}] {1,-14} {2,-52} x{3}  {4}" -f $s.Family, $s.ProfileName, $s.Upn, $g.Count, $s.Kind) 'WARN'
    }
    W ''
    W ("WILL KEEP    ({0} item(s)) - untouched" -f $keep.Count) 'STEP'
    foreach ($g in ($keep | Group-Object ProfileName, Upn, Kind)) {
        $s = $g.Group[0]
        $shown = if ($s.Upn) { $s.Upn } else { '(unidentified - never touched)' }
        W ("   [{0,-9}] {1,-14} {2,-52} x{3}  {4}" -f $s.Family, $s.ProfileName, $shown, $g.Count, $s.Kind) 'KEEP'
    }
    $script:Kept += $keep.Count
    foreach ($k in $keep) { Add-Action 'DeltaAccount' $k.Kind $k.ProfileName $k.Upn $k.Id 'KEPT' }

    if ($DryRun) { W ''; W ("DRY RUN - {0} item(s) would be removed." -f $remove.Count) 'DRY'
                   foreach ($o in $remove) { Add-Action 'DeltaAccount' $o.Kind $o.ProfileName $o.Upn $o.Id 'WOULD REMOVE' }
                   return }
    if ($remove.Count -eq 0) { return }

    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    W ''
    W ("Backups -> $BackupDir")

    foreach ($o in $remove) {
        # the gate is re-checked immediately before every destructive action
        if ($o.Kind -ne 'WorkplaceJoin' -and -not (Test-UpnIsTarget $o.Upn)) {
            W ("  REFUSING (out of scope): {0}" -f $o.Id) 'KEEP'
            Add-Action 'DeltaAccount' $o.Kind $o.ProfileName $o.Upn $o.Id 'REFUSED'
            continue
        }
        switch ($o.Kind) {
            'BrokerFile' {
                try {
                    $base = [IO.Path]::GetFileNameWithoutExtension($o.Path)
                    foreach ($sib in (Get-ChildItem -LiteralPath $o.Dir -Filter "$base.*" -File -Force -ErrorAction SilentlyContinue)) {
                        $dest = Join-Path $BackupDir ("{0}__{1}" -f $o.ProfileName, $sib.Name)
                        Copy-Item -LiteralPath $sib.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                        if (-not (Remove-ItemHard $sib.FullName)) { throw "could not remove $($sib.Name)" }
                        $script:Removed++
                    }
                    W ("  [{0}] removed {1}  ({2})" -f $o.ProfileName, $o.Id, $o.Upn) 'GONE'
                    Add-Action 'DeltaAccount' 'BrokerFile' $o.ProfileName $o.Upn $o.Id 'REMOVED'
                } catch { W ("  [{0}] FAILED {1}: {2}" -f $o.ProfileName, $o.Id, $_.Exception.Message) 'ERROR'; $script:Failed++ }
            }
            'WorkplaceJoin' {
                try {
                    if (-not (Remove-RegistryKeySafe $o.Path ("$($o.ProfileName)-JoinInfo-$($o.Id)"))) { continue }
                    W ("  [{0}] removed WorkplaceJoin\{1}  ({2})" -f $o.ProfileName, $o.Id, $o.Upn) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaAccount' 'WorkplaceJoin' $o.ProfileName $o.Upn $o.Id 'REMOVED'
                    if ($o.Dir) {
                        $tp = ($o.Path -replace 'JoinInfo\\.*$', "TenantInfo\$($o.Dir)")
                        if (Test-Path $tp) {
                            if (Remove-RegistryKeySafe $tp ("$($o.ProfileName)-TenantInfo-$($o.Dir)")) {
                                W ("  [{0}] removed TenantInfo\{1}" -f $o.ProfileName, $o.Dir) 'GONE'
                            }
                        }
                    }
                    try {
                        # Cert:\CurrentUser is the CALLER's store. Under SYSTEM this is SYSTEM's
                        # store, so the user's device certificate is not reachable from here.
                        $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $o.Id }
                        if ($cert) { $cert | Remove-Item -Force -ErrorAction Stop; W '  removed the matching user certificate' 'GONE' }
                        elseif ($IsSystem) { W ("  user certificate {0} left in place - not reachable from SYSTEM; it is inert once JoinInfo is gone" -f $o.Id) 'KEEP' }
                    } catch { }
                } catch { W ("  [{0}] FAILED WorkplaceJoin: {1}" -f $o.ProfileName, $_.Exception.Message) 'ERROR'; $script:Failed++ }
            }
            'OfficeIdentity' {
                try {
                    if (-not (Remove-RegistryKeySafe $o.Path ("$($o.ProfileName)-OfficeIdentity"))) { continue }
                    W ("  [{0}] removed Office identity {1}  ({2})" -f $o.ProfileName, $o.Id, $o.Upn) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaAccount' 'OfficeIdentity' $o.ProfileName $o.Upn $o.Id 'REMOVED'
                } catch { W ("  [{0}] FAILED Office identity: {1}" -f $o.ProfileName, $_.Exception.Message) 'ERROR'; $script:Failed++ }
            }
            'OfficeHint' {
                try {
                    Remove-ItemProperty -LiteralPath $o.Path -Name $o.Id -Force -ErrorAction Stop
                    W ("  [{0}] cleared Office {1} ({2})" -f $o.ProfileName, $o.Id, $o.Upn) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaAccount' 'OfficeHint' $o.ProfileName $o.Upn $o.Id 'REMOVED'
                } catch { $script:Failed++ }
            }
        }
    }
}

# =====================================================================================
#  MODULE: DeltaCredentials                                                 DELTA ONLY
#  Win32 CredEnumerate / CredDelete. Locale independent - "cmdkey /list" parsing broke
#  on the Italian machines because the field labels are translated.
#  Only entries whose user name or target name resolves to the target domain go.
# =====================================================================================
if (-not ('PmcCredApi' -as [type])) {
@'
using System;
using System.Runtime.InteropServices;
public class PmcCredApi {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public UInt32 Flags;
        public UInt32 Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredEnumerateW(string filter, int flag, out int count, out IntPtr pCredentials);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredDeleteW(string target, int type, int flags);
    [DllImport("advapi32.dll", SetLastError=false)]
    public static extern void CredFree(IntPtr cred);
}
'@ | ForEach-Object { try { Add-Type -TypeDefinition $_ -ErrorAction Stop } catch { W ("Credential API unavailable: " + $_.Exception.Message) 'WARN' } }
}

function Get-StoredCredential {
    $out = New-Object System.Collections.ArrayList
    if (-not ('PmcCredApi' -as [type])) { return $out.ToArray() }
    $count = 0; $ptr = [IntPtr]::Zero
    if (-not [PmcCredApi]::CredEnumerateW($null, 0, [ref]$count, [ref]$ptr)) { return $out.ToArray() }
    try {
        for ($i = 0; $i -lt $count; $i++) {
            $pc = [Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $i * [IntPtr]::Size)
            $c  = [Runtime.InteropServices.Marshal]::PtrToStructure($pc, [Type]('PmcCredApi+CREDENTIAL' -as [type]))
            $t = ''; $u = ''
            if ($c.TargetName -ne [IntPtr]::Zero) { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.TargetName) }
            if ($c.UserName   -ne [IntPtr]::Zero) { $u = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.UserName) }
            [void]$out.Add([pscustomobject]@{ Target=$t; User=$u; Type=[int]$c.Type })
        }
    } catch { } finally { try { [PmcCredApi]::CredFree($ptr) } catch { } }
    return $out.ToArray()
}

Invoke-Step 'DeltaCredentials' 'DELTA CREDENTIALS - Credential Manager' {
    if ($IsSystem) {
        # Expected under the RMM, and not a failure. Credential Manager is per-user and
        # DPAPI-sealed; SYSTEM cannot read another user's vault, and the encrypted blobs
        # on disk cannot be attributed to a tenant without decrypting them - so there is
        # no safe way to delete only the old tenant's from here.
        W 'Running as SYSTEM, so only SYSTEM''s own vault is visible. This is expected'  'KEEP'
        W 'under the RMM and is not a failure: once DeltaAccount has removed the broker' 'KEEP'
        W 'files and Office identity, any leftover credential is an orphaned token that' 'KEEP'
        W 'nothing can redeem, and it clears on the user''s next sign-in.'               'KEEP'
    }
    $creds = @(Get-StoredCredential)
    W ("Credential entries visible: {0}" -f $creds.Count)
    $hit = @($creds | Where-Object { (Test-UpnIsTarget $_.User) -or (Test-TextNamesTarget $_.Target) -or (Test-TextNamesTarget $_.User) })
    $oth = @($creds | Where-Object { $hit -notcontains $_ })
    W ("  matching the old tenant : {0}" -f $hit.Count) 'WARN'
    W ("  everything else         : {0}  - kept" -f $oth.Count) 'KEEP'
    $script:Kept += $oth.Count

    foreach ($c in $hit) {
        $label = if ($c.User) { "$($c.Target)  [$($c.User)]" } else { $c.Target }
        if ($DryRun) { W ("  WOULD DELETE  $label") 'DRY'; Add-Action 'DeltaCredentials' 'Credential' '' $c.User $c.Target 'WOULD REMOVE'; continue }
        try {
            if ([PmcCredApi]::CredDeleteW($c.Target, $c.Type, 0)) {
                W ("  deleted  $label") 'GONE'; $script:Removed++
                Add-Action 'DeltaCredentials' 'Credential' '' $c.User $c.Target 'REMOVED'
            } else {
                W ("  could not delete $label (win32 " + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ")") 'ERROR'
                $script:Failed++
            }
        } catch { W ("  could not delete $label : " + $_.Exception.Message) 'ERROR'; $script:Failed++ }
    }
    if ($hit.Count -eq 0) { W '  no credential names the old tenant.' 'OK' }
}

# =====================================================================================
#  MODULE: DeltaOneDrive                                                    DELTA ONLY
#  Unlinks the old-tenant business account only. The synced folder on disk is left
#  exactly where it is - unlinking stops sync, it does not delete files.
# =====================================================================================
Invoke-Step 'DeltaOneDrive' 'DELTA ONEDRIVE - unlink the old tenant only' {
    $found = 0
    foreach ($p in $profiles) {
        Invoke-WithUserHive $p {
            param($root)
            $acc = "$root\Software\Microsoft\OneDrive\Accounts"
            if (-not (Test-Path $acc)) { return }
            foreach ($a in (Get-ChildItem -LiteralPath $acc -ErrorAction SilentlyContinue)) {
                if ($a.PSChildName -notmatch '^Business\d+$') { continue }
                $found++
                $email  = RegVal $a.PSPath 'UserEmail'
                if (-not $email) { $email = RegVal $a.PSPath 'UserName' }
                $tenant = RegVal $a.PSPath 'ConfiguredTenantId'
                $folder = RegVal $a.PSPath 'UserFolder'
                $isT = (Test-UpnIsTarget ([string]$email)) -or
                       ($tenant -and $OldTenantId -and ([string]$tenant).ToLower() -eq $OldTenantId.ToLower())
                if (-not $isT) {
                    W ("  [{0}] {1} -> {2}  KEPT" -f $p.Name, $a.PSChildName, $email) 'KEEP'
                    $script:Kept++
                    Add-Action 'DeltaOneDrive' 'OneDriveAccount' $p.Name ([string]$email) $a.PSChildName 'KEPT'
                    continue
                }
                if ($folder) { W ("  [{0}] synced folder stays on disk: {1}" -f $p.Name, $folder) 'KEEP' }
                if ($DryRun) {
                    W ("  [{0}] WOULD UNLINK {1} -> {2}" -f $p.Name, $a.PSChildName, $email) 'DRY'
                    Add-Action 'DeltaOneDrive' 'OneDriveAccount' $p.Name ([string]$email) $a.PSChildName 'WOULD REMOVE'
                    continue
                }
                try {
                    if (-not (Remove-RegistryKeySafe $a.PSPath ("$($p.Name)-OneDrive-$($a.PSChildName)"))) { continue }
                    W ("  [{0}] unlinked {1} -> {2}" -f $p.Name, $a.PSChildName, $email) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaOneDrive' 'OneDriveAccount' $p.Name ([string]$email) $a.PSChildName 'REMOVED'
                    $set = Join-Path $p.Path ("AppData\Local\Microsoft\OneDrive\settings\" + $a.PSChildName)
                    if (Test-Path -LiteralPath $set) {
                        Backup-Item $set ("$($p.Name)-OneDriveSettings") | Out-Null
                        if (Remove-ItemHard $set -Recurse) { W ("  [{0}] removed settings\{1}" -f $p.Name, $a.PSChildName) 'GONE' }
                    }
                } catch { W ("  [{0}] FAILED unlink {1}: {2}" -f $p.Name, $a.PSChildName, $_.Exception.Message) 'ERROR'; $script:Failed++ }
            }
        }
    }
    if ($found -eq 0) { W '  no OneDrive business account configured in any profile.' 'OK' }
    W '  No file in any OneDrive folder is deleted by this module.' 'OK'
}

# =====================================================================================
#  MODULE: DeltaBrowser                                                     DELTA ONLY
#  A browser profile is removed only when EVERY signed-in address in it belongs to the
#  target domain. A profile holding a mix is reported and left alone - clearing it
#  would sign the other accounts out too.
# =====================================================================================
Invoke-Step 'DeltaBrowser' 'DELTA BROWSER PROFILE' {
    $browsers = @(
        @{ Name='Edge';    Root='AppData\Local\Microsoft\Edge\User Data' }
        @{ Name='Chrome';  Root='AppData\Local\Google\Chrome\User Data'  }
        @{ Name='Brave';   Root='AppData\Local\BraveSoftware\Brave-Browser\User Data' }
        @{ Name='Vivaldi'; Root='AppData\Local\Vivaldi\User Data' }
        @{ Name='Opera';   Root='AppData\Roaming\Opera Software\Opera Stable' }
    )
    W 'Firefox has no per-profile signed-in-account record to match on, so it is not' 'KEEP'
    W 'in scope here. Its caches and cookies are covered by the BrowserCache module.'  'KEEP'
    $any = $false
    foreach ($p in $profiles) {
        foreach ($b in $browsers) {
            $ud = Join-Path $p.Path $b.Root
            if (-not (Test-Path -LiteralPath $ud)) { continue }
            $cands = @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })
            # Opera keeps a single profile at the root of its folder
            if ($cands.Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $ud 'Preferences'))) {
                $cands = @(Get-Item -LiteralPath $ud)
            }
            foreach ($bp in $cands) {
                $pref = Join-Path $bp.FullName 'Preferences'
                if (-not (Test-Path -LiteralPath $pref)) { continue }
                $txt = ''
                try { $txt = [IO.File]::ReadAllText($pref) } catch { continue }
                $emails = @([regex]::Matches($txt,'"email"\s*:\s*"([^"]+)"') |
                            ForEach-Object { $_.Groups[1].Value } |
                            Where-Object { $_ -match '@' } | Select-Object -Unique)
                if ($emails.Count -eq 0) { continue }
                $any = $true
                $tgt = @($emails | Where-Object { Test-UpnIsTarget $_ })
                $oth = @($emails | Where-Object { -not (Test-UpnIsTarget $_) })
                if ($tgt.Count -eq 0) {
                    W ("  [{0}] {1}\{2}  signed in as {3}  KEPT" -f $p.Name, $b.Name, $bp.Name, ($emails -join ', ')) 'KEEP'
                    $script:Kept++
                    continue
                }
                if ($oth.Count -gt 0) {
                    W ("  [{0}] {1}\{2} holds BOTH {3} and {4}" -f $p.Name, $b.Name, $bp.Name, ($tgt -join ','), ($oth -join ',')) 'WARN'
                    W  '        left alone - removing it would sign the other account out too.'  'WARN'
                    W  '        Remove the old profile from the browser''s own profile menu.'    'WARN'
                    $script:Kept++
                    Add-Action 'DeltaBrowser' 'BrowserProfile' $p.Name ($tgt -join ',') "$($b.Name)\$($bp.Name)" 'SKIPPED-MIXED'
                    continue
                }
                if ($DryRun) {
                    W ("  [{0}] WOULD REMOVE {1}\{2}  ({3})" -f $p.Name, $b.Name, $bp.Name, ($tgt -join ',')) 'DRY'
                    Add-Action 'DeltaBrowser' 'BrowserProfile' $p.Name ($tgt -join ',') "$($b.Name)\$($bp.Name)" 'WOULD REMOVE'
                    continue
                }
                try {
                    Backup-Item $bp.FullName ("$($p.Name)-$($b.Name)-$($bp.Name)") | Out-Null
                    if (-not (Remove-ItemHard $bp.FullName -Recurse)) { throw 'profile folder could not be removed' }
                    W ("  [{0}] removed {1}\{2}  ({3})" -f $p.Name, $b.Name, $bp.Name, ($tgt -join ',')) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaBrowser' 'BrowserProfile' $p.Name ($tgt -join ',') "$($b.Name)\$($bp.Name)" 'REMOVED'
                } catch { W ("  [{0}] FAILED {1}\{2}: {3}" -f $p.Name, $b.Name, $bp.Name, $_.Exception.Message) 'ERROR'; $script:Failed++ }
            }
        }
    }
    if (-not $any) { W '  no browser profile on this machine is signed in to a work account.' 'OK' }
}


# =====================================================================================
#  MODULE: DeltaAutoDiscover                                                DELTA ONLY
#  The entries that send Outlook back to the old tenant's sign-in page. Only values
#  and files that positively name the target domain are removed; anything unreadable
#  or unattributed is left where it is.
# =====================================================================================
Invoke-Step 'DeltaAutoDiscover' 'DELTA AUTODISCOVER - stop Outlook redirecting to the old tenant' {
    $hits = 0
    foreach ($p in $profiles) {
        Invoke-WithUserHive $p {
            param($root)
            foreach ($ver in @('16.0','15.0','14.0')) {
                foreach ($rel in @("SOFTWARE\Microsoft\Office\$ver\Outlook\AutoDiscover",
                                   "SOFTWARE\Microsoft\Office\$ver\Outlook\AutoDiscover\RedirectServers",
                                   "SOFTWARE\Microsoft\Exchange\AutoDiscover")) {
                    $k = "$root\$rel"
                    if (-not (Test-Path $k)) { continue }
                    $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
                    if (-not $item) { continue }
                    foreach ($vn in $item.Property) {
                        $vd = ''
                        try { $vd = [string](RegVal $k $vn) } catch { }
                        if (-not ((Test-TextNamesTarget $vn) -or (Test-TextNamesTarget $vd))) {
                            W ("  [{0}] kept {1}\{2}" -f $p.Name, (Split-Path $rel -Leaf), $vn) 'KEEP'
                            $script:Kept++
                            continue
                        }
                        $hits++
                        if ($DryRun) { W ("  [{0}] WOULD CLEAR {1}\{2} = {3}" -f $p.Name, (Split-Path $rel -Leaf), $vn, $vd) 'DRY'; continue }
                        Backup-RegistryKey $k ("$($p.Name)-AutoDiscover-$ver") | Out-Null
                        try {
                            Remove-ItemProperty -LiteralPath $k -Name $vn -Force -ErrorAction Stop
                            W ("  [{0}] cleared {1}\{2}" -f $p.Name, (Split-Path $rel -Leaf), $vn) 'GONE'
                            $script:Removed++
                            Add-Action 'DeltaAutoDiscover' 'AutoDiscoverValue' $p.Name '' "$rel\$vn" 'REMOVED'
                        } catch { $null = Write-ErrorDetail $_ "clearing $rel\$vn"; $script:Failed++ }
                    }
                }
                # Office connected-service profile keyed by UPN
                $prof = "$root\SOFTWARE\Microsoft\Office\$ver\Common\Identity\Profiles"
                if (Test-Path $prof) {
                    foreach ($e in (Get-ChildItem -LiteralPath $prof -ErrorAction SilentlyContinue)) {
                        if (-not (Test-UpnIsTarget $e.PSChildName)) { $script:Kept++; continue }
                        $hits++
                        if ($DryRun) { W ("  [{0}] WOULD REMOVE Identity\Profiles\{1}" -f $p.Name, $e.PSChildName) 'DRY'; continue }
                        if (Remove-RegistryKeySafe $e.PSPath ("$($p.Name)-IdentityProfile")) {
                            W ("  [{0}] removed Identity\Profiles\{1}" -f $p.Name, $e.PSChildName) 'GONE'
                            $script:Removed++
                            Add-Action 'DeltaAutoDiscover' 'IdentityProfile' $p.Name $e.PSChildName $e.PSChildName 'REMOVED'
                        }
                    }
                }
            }
        }
        # cached AutoDiscover XML. Extension gate is .xml only, so no mail file can match.
        $od = Join-Path $p.Path 'AppData\Local\Microsoft\Outlook'
        if (Test-Path -LiteralPath $od) {
            foreach ($f in (Get-ChildItem -LiteralPath $od -Filter '*.xml' -File -Force -Recurse -Depth 2 -ErrorAction SilentlyContinue)) {
                if ($f.Extension.ToLowerInvariant() -ne '.xml') { continue }
                $base  = [IO.Path]::GetFileNameWithoutExtension($f.Name)
                $named = (Test-UpnIsTarget $base) -or (Test-TextNamesTarget $base)
                if (-not $named -and $f.Length -lt 4MB) {
                    try { $named = Test-TextNamesTarget ([IO.File]::ReadAllText($f.FullName)) } catch { }
                }
                if (-not $named) { $script:Kept++; continue }
                $hits++
                if ($DryRun) { W ("  [{0}] WOULD DELETE {1}" -f $p.Name, $f.FullName) 'DRY'; continue }
                Backup-Item $f.FullName ("$($p.Name)-autodiscover") | Out-Null
                if (Remove-ItemHard $f.FullName) {
                    W ("  [{0}] deleted {1}" -f $p.Name, $f.Name) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaAutoDiscover' 'AutoDiscoverXml' $p.Name '' $f.FullName 'REMOVED'
                } else { $script:Failed++ }
            }
        }
    }
    if ($hits -eq 0) { W '  nothing points Outlook at the old tenant on this machine.' 'OK' }
}

# =====================================================================================
#  MODULE: DeltaOfficeLicense                                               DELTA ONLY
#  Office vNext licence tokens are per-identity files. Only the ones that name the
#  target domain go, so other tenants keep their activation. A licence file that
#  cannot be read, or that names nobody, is kept - a wrongly removed licence means a
#  re-activation prompt on a machine that was working.
# =====================================================================================
Invoke-Step 'DeltaOfficeLicense' 'DELTA OFFICE LICENCE - old tenant tokens only' {
    $hit = 0; $keptFiles = 0
    foreach ($p in $profiles) {
        foreach ($rel in @('AppData\Local\Microsoft\Office\Licenses',
                           'AppData\Local\Microsoft\Office\16.0\Licensing',
                           'AppData\Local\Microsoft\Office\Licenses16')) {
            $dir = Join-Path $p.Path $rel
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -Recurse -Depth 3 -ErrorAction SilentlyContinue)) {
                if ($script:MailExt -contains $f.Extension.ToLowerInvariant()) { continue }
                $base  = [IO.Path]::GetFileNameWithoutExtension($f.Name)
                $named = (Test-UpnIsTarget $base) -or (Test-TextNamesTarget $base)
                if (-not $named -and $f.Length -lt 4MB) {
                    try {
                        $bytes = [IO.File]::ReadAllBytes($f.FullName)
                        foreach ($enc in @([Text.Encoding]::UTF8,[Text.Encoding]::Unicode)) {
                            if (-not $named) { $named = Test-TextNamesTarget ($enc.GetString($bytes)) }
                        }
                    } catch { }
                }
                if (-not $named) { $keptFiles++; continue }
                $hit++
                if ($DryRun) { W ("  [{0}] WOULD DELETE licence {1}" -f $p.Name, $f.FullName) 'DRY'; continue }
                Backup-Item $f.FullName ("$($p.Name)-licence") | Out-Null
                if (Remove-ItemHard $f.FullName) {
                    W ("  [{0}] removed licence token {1}" -f $p.Name, $f.Name) 'GONE'
                    $script:Removed++
                    Add-Action 'DeltaOfficeLicense' 'LicenceToken' $p.Name '' $f.FullName 'REMOVED'
                } else { $script:Failed++ }
            }
        }
        Invoke-WithUserHive $p {
            param($root)
            foreach ($ver in @('16.0','15.0')) {
                foreach ($rel in @("SOFTWARE\Microsoft\Office\$ver\Common\Licensing\LicensingNext",
                                   "SOFTWARE\Microsoft\Office\$ver\Common\Licensing")) {
                    $k = "$root\$rel"
                    if (-not (Test-Path $k)) { continue }
                    $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
                    if (-not $item) { continue }
                    foreach ($vn in $item.Property) {
                        $vd = ''
                        try { $vd = [string](RegVal $k $vn) } catch { }
                        if (-not ((Test-TextNamesTarget $vn) -or (Test-TextNamesTarget $vd))) { $script:Kept++; continue }
                        $hit++
                        if ($DryRun) { W ("  [{0}] WOULD CLEAR Licensing\{1}" -f $p.Name, $vn) 'DRY'; continue }
                        Backup-RegistryKey $k ("$($p.Name)-Licensing-$ver") | Out-Null
                        try {
                            Remove-ItemProperty -LiteralPath $k -Name $vn -Force -ErrorAction Stop
                            W ("  [{0}] cleared Licensing\{1}" -f $p.Name, $vn) 'GONE'
                            $script:Removed++
                            Add-Action 'DeltaOfficeLicense' 'LicensingValue' $p.Name '' "$rel\$vn" 'REMOVED'
                        } catch { $null = Write-ErrorDetail $_ "clearing $rel\$vn"; $script:Failed++ }
                    }
                }
            }
        }
    }
    W ("  licence files kept because they do not name the old tenant: {0}" -f $keptFiles) 'KEEP'
    if ($hit -eq 0) { W '  no Office licence on this machine belongs to the old tenant.' 'OK' }
    W '  Machine-wide ClickToRun configuration and shared licensing are not touched.' 'KEEP'
}

# =====================================================================================
#  CACHE HELPERS
# =====================================================================================
function Remove-SafeFile {
    param([string]$Path,[string]$Module,[string]$ProfileName)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($script:MailExt -contains $ext) { W ("  GUARD: mail data, refusing: $Path") 'WARN'; return }
    $full = ''
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return }
    foreach ($p in $script:ProtectedPaths) {
        if ($full.ToLower().StartsWith(($p.ToLower() + $script:DS))) { W ("  GUARD: inside protected $p, refusing: $full") 'WARN'; return }
    }
    $sz = 0
    try { $sz = (Get-Item -LiteralPath $Path -Force).Length } catch { }
    if ($DryRun) { W ("  WOULD DELETE $Path  ({0})" -f (Format-Bytes $sz)) 'DRY'; return }
    if (Remove-ItemHard $Path) {
        $script:Bytes += $sz
        W ("  deleted $Path  ({0})" -f (Format-Bytes $sz)) 'GONE'
        Add-Action $Module 'File' $ProfileName '' $Path 'REMOVED'
    } else { W ("  could not remove $Path") 'ERROR'; $script:Failed++ }
}
function Clear-Each {
    param([object]$P,[string[]]$Relative,[string]$Module)
    foreach ($r in $Relative) {
        $full = Join-Path $P.Path $r
        if (Test-Path -LiteralPath $full) { Clear-FolderContent $full $Module $P.Name }
    }
}
# NOTE on "return ,$array": the comma protects a one-element result from being
# unrolled, but ONLY when the caller assigns directly ($x = f). A caller writing
# @(f) then gets a one-element array holding the array, and every -contains test
# against it silently returns false. Every function below returns the array plain
# and every call site wraps it in @(), which is correct for 0, 1 and n elements.
function Get-BrowserProfileDirs {
    param([object]$P)
    $out = New-Object System.Collections.ArrayList
    foreach ($root in @('AppData\Local\Microsoft\Edge\User Data',
                        'AppData\Local\Google\Chrome\User Data',
                        'AppData\Local\BraveSoftware\Brave-Browser\User Data',
                        'AppData\Local\Vivaldi\User Data',
                        'AppData\Roaming\Opera Software\Opera Stable')) {
        $ud = Join-Path $P.Path $root
        if (-not (Test-Path -LiteralPath $ud)) { continue }
        $found = 0
        foreach ($d in (Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })) {
            [void]$out.Add($d.FullName); $found++
        }
        if ($found -eq 0 -and (Test-Path -LiteralPath (Join-Path $ud 'Preferences'))) { [void]$out.Add($ud) }
    }
    return $out.ToArray()
}
function Get-FirefoxProfileDirs {
    param([object]$P)
    $out = New-Object System.Collections.ArrayList
    foreach ($root in @('AppData\Roaming\Mozilla\Firefox\Profiles','AppData\Local\Mozilla\Firefox\Profiles')) {
        $ud = Join-Path $P.Path $root
        if (-not (Test-Path -LiteralPath $ud)) { continue }
        foreach ($d in (Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue)) { [void]$out.Add($d.FullName) }
    }
    return $out.ToArray()
}

# =====================================================================================
#  MODULE: AppCache                                                         CACHE ONLY
#  Scratch caches only. No token store, no account list, nothing signs out.
#  Deliberately NOT included: Office\16.0\OfficeFileCache - the upload cache can hold
#  edits that have not reached the server yet.
# =====================================================================================
Invoke-Step 'AppCache' 'APP CACHE - scratch only, nothing signs out' {
    foreach ($p in $profiles) {
        W ("[{0}]" -f $p.Name) 'STEP'
        Clear-Each $p @(
            'AppData\Roaming\Microsoft\Teams\Cache'
            'AppData\Roaming\Microsoft\Teams\Code Cache'
            'AppData\Roaming\Microsoft\Teams\GPUCache'
            'AppData\Roaming\Microsoft\Teams\blob_storage'
            'AppData\Roaming\Microsoft\Teams\tmp'
            'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache'
            'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Code Cache'
            'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\GPUCache'
            'AppData\Local\Microsoft\Office\16.0\WebServiceCache'
            'AppData\Local\Microsoft\Office\16.0\MruServiceCache'
            'AppData\Local\Microsoft\Office\OTele'
        ) 'AppCache'
        $tmp = Join-Path $p.Path 'AppData\Local\Temp'
        if (Test-Path -LiteralPath $tmp) { Clear-FolderContent $tmp 'AppCache' $p.Name -ItemGuardOnly }
    }
    W 'Office upload cache (OfficeFileCache) skipped on purpose - it can hold unsynced edits.' 'KEEP'
}

# =====================================================================================
#  MODULE: OutlookCache                                                     CACHE ONLY
#  RoamCache and the forms cache. No mail profile, no data file, no OST.
#  New Outlook (olk) local storage is protected - it holds mail, not cache.
# =====================================================================================
Invoke-Step 'OutlookCache' 'OUTLOOK CACHE - RoamCache and forms only' {
    foreach ($p in $profiles) {
        W ("[{0}]" -f $p.Name) 'STEP'
        Clear-Each $p @(
            'AppData\Local\Microsoft\Outlook\RoamCache'
            'AppData\Local\Microsoft\FORMS'
            'AppData\Local\Microsoft\Windows\INetCache\Content.Outlook'
        ) 'OutlookCache'
    }
    W 'Not touched: any .pst / .ost / .nst, every mail profile, and new Outlook local storage.' 'KEEP'
}

# =====================================================================================
#  MODULE: TokenCache                                                        SIGNS OUT
#  Clears the shared token stores. Every work account on the device has to sign in
#  again - none of them is removed. TokenBroker\Accounts is NOT touched here; that
#  is the account list, and only DeltaAccount edits it, item by item.
# =====================================================================================
Invoke-Step 'TokenCache' 'TOKEN CACHE - all accounts must re-authenticate' {
    W 'This signs every work account out of Office, Teams and OneDrive. No account is removed.' 'WARN'
    foreach ($p in $profiles) {
        W ("[{0}]" -f $p.Name) 'STEP'
        Clear-Each $p @(
            'AppData\Local\Microsoft\OneAuth'
            'AppData\Local\Microsoft\IdentityCache'
            'AppData\Local\Microsoft\TokenBroker\Cache'
            'AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Cache'
        ) 'TokenCache'
    }
    W 'TokenBroker\Accounts left alone - that is the account list, not a cache.' 'KEEP'
}

# =====================================================================================
#  MODULE: BrowserCache                                                      SIGNS OUT
# =====================================================================================
Invoke-Step 'BrowserCache' 'BROWSER CACHE - signs the user out of websites' {
    foreach ($p in $profiles) {
        W ("[{0}]" -f $p.Name) 'STEP'
        foreach ($bp in @(Get-BrowserProfileDirs $p)) {
            foreach ($sub in @('Cache','Code Cache','GPUCache','Service Worker','Storage\ext')) {
                $full = Join-Path $bp $sub
                if (Test-Path -LiteralPath $full) { Clear-FolderContent $full 'BrowserCache' $p.Name }
            }
            foreach ($f in @('Network\Cookies','Network\Cookies-journal','Network\Trust Tokens')) {
                Remove-SafeFile (Join-Path $bp $f) 'BrowserCache' $p.Name
            }
        }
        foreach ($fp in @(Get-FirefoxProfileDirs $p)) {
            foreach ($sub in @('cache2','startupCache','thumbnails','sessionstore-backups','storage\default')) {
                $full = Join-Path $fp $sub
                if (Test-Path -LiteralPath $full) { Clear-FolderContent $full 'BrowserCache' $p.Name }
            }
            foreach ($f in @('cookies.sqlite','cookies.sqlite-wal','cookies.sqlite-shm','sessionstore.jsonlz4')) {
                Remove-SafeFile (Join-Path $fp $f) 'BrowserCache' $p.Name
            }
        }
        # WinINET / legacy IE stores, which Office and Teams still authenticate through.
        # INetCache\Content.Outlook is skipped - OutlookCache owns that one.
        $inet = Join-Path $p.Path 'AppData\Local\Microsoft\Windows\INetCache'
        if (Test-Path -LiteralPath $inet) {
            foreach ($c in (Get-ChildItem -LiteralPath $inet -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($c.Name -ieq 'Content.Outlook') { W '  INetCache\Content.Outlook left to the OutlookCache module' 'KEEP'; continue }
                Clear-FolderContent $c.FullName 'BrowserCache' $p.Name
            }
        }
        Clear-Each $p @('AppData\Local\Microsoft\Windows\WebCache',
                        'AppData\Local\Microsoft\Windows\INetCookies') 'BrowserCache'
    }
    W 'Bookmarks, passwords, history and profile settings are not touched.' 'KEEP'
}

# =====================================================================================
#  MODULE: OutlookProfileAll                                              ALL ACCOUNTS
#  Deletes every Outlook mail profile in every user profile. Every mailbox is
#  reconfigured on next launch. Mail FILES are never deleted - the .pst re-attach list
#  written earlier in this run is what you use to put them back.
# =====================================================================================
Invoke-Step 'OutlookProfileAll' 'OUTLOOK PROFILES - ALL ACCOUNTS, NOT JUST THE OLD TENANT' {
    W 'This removes mail profiles for EVERY account, including the new tenant.' 'WARN'
    W ("Any .pst listed in PstInventory-{0}-{1}.csv must be re-attached by hand." -f $env:COMPUTERNAME, $Stamp) 'WARN'
    foreach ($p in $profiles) {
        Invoke-WithUserHive $p {
            param($root)
            foreach ($ver in @('16.0','15.0','14.0')) {
                $prof = "$root\Software\Microsoft\Office\$ver\Outlook\Profiles"
                if (-not (Test-Path $prof)) { continue }
                foreach ($e in (Get-ChildItem -LiteralPath $prof -ErrorAction SilentlyContinue)) {
                    if ($DryRun) { W ("  [{0}] WOULD REMOVE profile {1} ({2})" -f $p.Name, $e.PSChildName, $ver) 'DRY'; continue }
                    try {
                        if (-not (Remove-RegistryKeySafe $e.PSPath ("$($p.Name)-OutlookProfile-$ver-$($e.PSChildName)"))) { continue }
                        W ("  [{0}] removed mail profile {1} ({2})" -f $p.Name, $e.PSChildName, $ver) 'GONE'
                        $script:Removed++
                        Add-Action 'OutlookProfileAll' 'OutlookProfile' $p.Name '' $e.PSChildName 'REMOVED'
                    } catch { $script:Failed++ }
                }
                $cur = "$root\Software\Microsoft\Office\$ver\Outlook"
                foreach ($vn in @('DefaultProfile')) {
                    if ((RegVal $cur $vn) -and -not $DryRun) {
                        try { Remove-ItemProperty -LiteralPath $cur -Name $vn -Force -ErrorAction Stop } catch { }
                    }
                }
            }
        }
    }
    W 'No .pst, .ost, .olm or .nst file was deleted.' 'OK'
}

# =====================================================================================
#  MODULE: CredentialsAll                                                 ALL ACCOUNTS
# =====================================================================================
Invoke-Step 'CredentialsAll' 'CREDENTIALS - ALL MICROSOFT ENTRIES, EVERY TENANT' {
    if ($IsSystem) { W 'Running as SYSTEM - this only sees SYSTEM''s vault, not the user''s.' 'WARN' }
    $pat = @('MicrosoftOffice','MicrosoftAccount','SSO_POP_Device','msteams','office','onmicrosoft',
             'login.windows.net','login.microsoftonline','OneDrive','virtualapp/didlogical','outlook',
             'sharepoint','WindowsLive','MicrosoftAzure','enterpriseregistration')
    $creds = @(Get-StoredCredential)
    W ("Credential entries visible: {0}" -f $creds.Count)
    foreach ($c in $creds) {
        $isMs = $false
        foreach ($x in $pat) { if ($c.Target -and $c.Target.ToLower().Contains($x.ToLower())) { $isMs = $true; break } }
        if (-not $isMs) { W ("  kept (not a Microsoft entry): {0}" -f $c.Target) 'KEEP'; $script:Kept++; continue }
        if ($DryRun) { W ("  WOULD DELETE {0}" -f $c.Target) 'DRY'; continue }
        try {
            if ([PmcCredApi]::CredDeleteW($c.Target, $c.Type, 0)) {
                W ("  deleted {0}" -f $c.Target) 'GONE'; $script:Removed++
                Add-Action 'CredentialsAll' 'Credential' '' $c.User $c.Target 'REMOVED'
            } else { $script:Failed++ }
        } catch { $script:Failed++ }
    }
}

# =====================================================================================
#  MODULE: OneDriveAll                                                    ALL ACCOUNTS
# =====================================================================================
Invoke-Step 'OneDriveAll' 'ONEDRIVE - UNLINK EVERY BUSINESS ACCOUNT' {
    W 'Every OneDrive business link is removed, including the new tenant''s.' 'WARN'
    foreach ($p in $profiles) {
        Invoke-WithUserHive $p {
            param($root)
            $acc = "$root\Software\Microsoft\OneDrive\Accounts"
            if (-not (Test-Path $acc)) { return }
            foreach ($a in (Get-ChildItem -LiteralPath $acc -ErrorAction SilentlyContinue)) {
                if ($a.PSChildName -notmatch '^Business\d+$') { continue }
                $email  = RegVal $a.PSPath 'UserEmail'
                $folder = RegVal $a.PSPath 'UserFolder'
                if ($folder) { W ("  [{0}] synced folder stays on disk: {1}" -f $p.Name, $folder) 'KEEP' }
                if ($DryRun) { W ("  [{0}] WOULD UNLINK {1} -> {2}" -f $p.Name, $a.PSChildName, $email) 'DRY'; continue }
                try {
                    if (-not (Remove-RegistryKeySafe $a.PSPath ("$($p.Name)-OneDrive-$($a.PSChildName)"))) { continue }
                    W ("  [{0}] unlinked {1} -> {2}" -f $p.Name, $a.PSChildName, $email) 'GONE'
                    $script:Removed++
                    Add-Action 'OneDriveAll' 'OneDriveAccount' $p.Name ([string]$email) $a.PSChildName 'REMOVED'
                    $set = Join-Path $p.Path ("AppData\Local\Microsoft\OneDrive\settings\" + $a.PSChildName)
                    if (Test-Path -LiteralPath $set) { $null = Remove-ItemHard $set -Recurse }
                } catch { $script:Failed++ }
            }
        }
    }
    W 'No synced file was deleted.' 'OK'
}

# =====================================================================================
#  MODULE: OstFiles                                                       ALL ACCOUNTS
#  .ost is a server-side cache and is rebuilt on the next sync. It is still every
#  mailbox on the device, and rebuilding a large one costs hours of bandwidth.
#  Only the .ost extension is ever matched here.
# =====================================================================================
Invoke-Step 'OstFiles' 'OST FILES - offline caches for every mailbox' {
    W 'Rebuilt automatically on the next sync. Large mailboxes will take a long time.' 'WARN'
    $dirs = New-Object System.Collections.ArrayList
    foreach ($p in $profiles) {
        [void]$dirs.Add([pscustomobject]@{ P=$p; D=(Join-Path $p.Path 'AppData\Local\Microsoft\Outlook') })
        [void]$dirs.Add([pscustomobject]@{ P=$p; D=(Join-Path $p.Path 'Documents\Outlook Files') })
    }
    $n = 0
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d.D)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d.D -Filter '*.ost' -File -Force -Recurse -Depth 2 -ErrorAction SilentlyContinue)) {
            if ($f.Extension.ToLowerInvariant() -ne '.ost') { continue }   # belt and braces
            $mb = [math]::Round($f.Length / 1MB, 1)
            if ($DryRun) { W ("  [{0}] WOULD DELETE {1}  ({2} MB)" -f $d.P.Name, $f.FullName, $mb) 'DRY'; $n++; continue }
            try {
                if (-not (Remove-ItemHard $f.FullName)) { throw 'file is locked' }
                W ("  [{0}] deleted {1}  ({2} MB)" -f $d.P.Name, $f.Name, $mb) 'GONE'
                $script:Removed++; $script:Bytes += $f.Length; $n++
                Add-Action 'OstFiles' 'OstFile' $d.P.Name '' $f.FullName 'REMOVED'
            } catch { W ("  [{0}] FAILED {1}: {2}" -f $d.P.Name, $f.Name, $_.Exception.Message) 'ERROR'; $script:Failed++ }
        }
    }
    if ($n -eq 0) { W '  no .ost file found.' 'OK' }
}

# =====================================================================================
#  VERIFY
# =====================================================================================
$stillThere = 0; $reborn = 0
if ($Selected -contains 'DeltaAccount' -and -not $DryRun) {
    Section 'VERIFY'
    Start-Sleep -Seconds 2
    foreach ($p in $profiles) {
        $bd = Join-Path $p.Path 'AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'
        if (-not (Test-Path -LiteralPath $bd)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $bd -Filter '*.tbacct' -File -ErrorAction SilentlyContinue)) {
            $upn = ''
            try { $upn = Get-UpnFromBytes ([IO.File]::ReadAllBytes($f.FullName)) } catch { }
            if (Test-UpnIsTarget $upn) {
                $stillThere++
                if ($f.LastWriteTime -gt $ScriptStart) { $reborn++ }
                W ("  STILL PRESENT [{0}] {1}  written {2}" -f $p.Name, $upn, $f.LastWriteTime.ToString('HH:mm:ss')) 'WARN'
            }
        }
    }
    if ($stillThere -eq 0) { W 'CLEAN - no account on the target domain remains in any profile.' 'OK' }
}

Dismount-UserHives

# =====================================================================================
#  SUMMARY
# =====================================================================================
Section 'SUMMARY'
$mb = [math]::Round($script:Bytes / 1MB, 1)
W ("Modules run   : " + ($Selected -join ', '))
W ("Items removed : {0}" -f $script:Removed)
W ("Items kept    : {0}  (other tenants, other users)" -f $script:Kept)
W ("Failures      : {0}" -f $script:Failed)
W ("Freed         : {0}" -f (Format-Bytes $script:Bytes))
if ($Selected -contains 'DeltaAccount' -and -not $DryRun) { W ("Target items still present : {0}" -f $stillThere) }
foreach ($st in $script:Steps) {
    $lvl = if ($st.Error) { 'ERROR' } else { 'INFO' }
    W ("   {0,-18} {1,6}s  {2}" -f $st.Module, $st.Seconds, $st.Error) $lvl
}
if ($reborn -gt 0) {
    W ''
    W ("$reborn item(s) were written AFTER this script started - they are being RE-CREATED.") 'KEY'
    W 'Someone is signed in to an app with the old account in an active session.'             'KEY'
    W 'Sign that app out (or log the user off) and run this again.'                            'KEY'
}

$RebootNeeded = ((-not $DryRun) -and ($script:Removed -gt 0) -and (-not $NoReboot))

$receipt = [ordered]@{
    Version      = $Version
    Computer     = $env:COMPUTERNAME
    RunAs        = $WhoAmI
    Elevated     = $IsAdmin
    System       = $IsSystem
    Started      = $ScriptStart.ToString('s')
    Finished     = (Get-Date).ToString('s')
    DryRun       = [bool]$DryRun
    TargetDomain = $TargetDomain
    OldTenantId  = $OldTenantId
    Modules      = @($Selected)
    Environment  = $EnvSnap
    MissingTools = @($MissingPrereq)
    Profiles     = @($profiles | ForEach-Object { @{ Name=$_.Name; Sid=$_.Sid; Family=$_.Family; LoggedOn=$_.LoggedOn } })
    Removed      = $script:Removed
    Kept         = $script:Kept
    Failed       = $script:Failed
    FreedMB      = $mb
    StillPresent = $stillThere
    Recreated    = $reborn
    RebootNeeded = $RebootNeeded
    PstFiles     = @($script:PstInventory | ForEach-Object { $_.File })
    Steps        = @($script:Steps)
    Errors       = @($script:Errors)
    Actions      = @($script:Actions)
}
try { $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReceiptFile -Encoding UTF8
      W ("Receipt : $ReceiptFile") } catch { W ("Could not write the receipt: " + $_.Exception.Message) 'WARN' }

try {
    $row = [pscustomobject]@{
        Timestamp=(Get-Date).ToString('s'); Computer=$env:COMPUTERNAME; Version=$Version
        Modules=($Selected -join '+'); DryRun=[bool]$DryRun; Profiles=$profiles.Count
        Removed=$script:Removed; Kept=$script:Kept; Failed=$script:Failed; FreedMB=$mb
        StillPresent=$stillThere; Recreated=$reborn; RebootNeeded=$RebootNeeded
    }
    if (Test-Path -LiteralPath $FleetCsv) { $row | Export-Csv -LiteralPath $FleetCsv -NoTypeInformation -Encoding UTF8 -Append }
    else                                  { $row | Export-Csv -LiteralPath $FleetCsv -NoTypeInformation -Encoding UTF8 }
    W ("Fleet   : $FleetCsv")
} catch { }

W ''
if ($DryRun) { W 'DRY RUN - nothing on this machine was changed.' 'DRY' }
else {
    W 'A sign-out or restart is needed before Settings stops showing the account - that page' 'STEP'
    W 'caches its list, so a stale entry there is not a failed removal.'                      'STEP'
    W ("Backups : $BackupDir")
}
W ("Log     : $LogFile")

# =====================================================================================
#  EXIT AND REBOOT
#  Precedence: a surviving target item beats a failure, a failure beats a pending
#  reboot. 3010 is what an RMM reads as "done, now schedule the restart".
# =====================================================================================
$code = 0; $why = 'clean'
if     ($stillThere -gt 0)  { $code = 5;    $why = 'a target item survived the run' }
elseif ($script:Failed -gt 0) { $code = 1;  $why = "$($script:Failed) operation(s) failed" }
elseif ($RebootNeeded)      { $code = 3010; $why = 'success, restart required' }

W ''
W ("Exit code : {0}  ({1})" -f $code, $why) 'STEP'
Write-Heartbeat ("finished-$code")

if ($Reboot -and $RebootNeeded -and -not $NoReboot -and -not $DryRun) {
    if ($code -eq 5 -or $code -eq 1) {
        W 'Not restarting - this run did not finish cleanly. Fix the failures first.' 'WARN'
    } elseif (Get-Command shutdown.exe -ErrorAction SilentlyContinue) {
        W ("RESTARTING in {0}s. Run 'shutdown /a' to cancel." -f $GraceSeconds) 'KEY'
        & shutdown.exe /r /t $GraceSeconds /c "Post-migration cleanup - restarting to finish removing the old work account." | Out-Null
    } else {
        W 'shutdown.exe not available - restart this machine by hand.' 'WARN'
    }
} elseif ($RebootNeeded -and -not $Reboot) {
    W 'Restart pending. Pass -Reboot to restart from the script, or let your RMM act on 3010.' 'STEP'
}
exit $code
