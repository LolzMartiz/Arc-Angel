#Requires -Version 5.1
<#
.SYNOPSIS
    Selectively removes ONE work account ("Access work or school") from Windows, matched by
    its e-mail domain or tenant ID. Every other work account on the device is left alone.

.DESCRIPTION
    Windows Settings > Accounts > Access work or school can list several unrelated things:

      1. Microsoft Entra REGISTERED accounts (per-user "Add work or school account").
         A device can hold SEVERAL of these, one per tenant. These are what this script
         removes, and it removes only the ones whose UPN matches -Domain / -TenantId.

      2. Microsoft Entra JOINED / Hybrid joined DEVICE. There is only ever one, it belongs
         to the machine rather than the user, and removing it can prevent users signing in
         to Windows at all. Detected and reported; only removed with -AllowDeviceLeave.

      3. MDM (Intune) enrolment. Detected and REPORTED ONLY - never removed, because
         unenrolling locally orphans the record in the MDM console.

    WHY THIS IS SURGICAL RATHER THAN 'dsregcmd /leave'
    --------------------------------------------------
    'dsregcmd /leave' is all-or-nothing: it drops the user's registration (or the device
    join) wholesale. When a machine has both an OLD and a NEW tenant account, that is
    exactly what you must not do. This script instead removes the specific registration
    object for the matching account:

      HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\<thumbprint>
      HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\<tenantId>
      the matching MS-Organization-Access certificate (key name IS its thumbprint)
      HKCU\SOFTWARE\Microsoft\IdentityCRL\StoredIdentities\<upn>
      HKCU\...\Office\16.0\Common\Identity\Identities\<upn...>
      TokenBroker account files for that UPN

    NO SCHEDULED TASK, NO USER PHASE
    --------------------------------
    All of the above is registry or file state, so it is reachable from SYSTEM by loading
    each user's NTUSER.DAT - including the user certificate, which lives in the hive at
    Software\Microsoft\SystemCertificates\My\Certificates\<thumbprint>. That removes the
    most fragile part of a normal cleanup script: nothing here depends on the script
    existing as a file, on a scheduled task, or on the user being signed in.

.PARAMETER Domain
    Remove work accounts whose UPN ends with this domain. Accepts several.
    Default: delta.mainettigroup.onmicrosoft.com

.PARAMETER TenantId
    Additionally (or instead) match on tenant GUID. Use when UserEmail is absent from the
    registration, which happens on some Windows builds.

.PARAMETER ListOnly
    Enumerate every work account found and exit. Changes nothing. Run this first.

.PARAMETER DryRun
    Do a full pass, report every action, write nothing.

.PARAMETER AllUsers
    Process every local profile, not just the signed-in user.

.PARAMETER AllowDeviceLeave
    Permit removal of a DEVICE-level Entra join when it is the thing that matches.
    Read the warning in the log first: on a cloud-only Entra joined device this can lock
    users out of Windows. Confirm a working local administrator account exists.

.PARAMETER Diagnostic
    Verbose telemetry: environment snapshot, raw tool output, per-step timing.

.PARAMETER LogDir
    Default C:\ProgramData\PMC\Logs

.EXAMPLE
    .\Remove-WorkAccount.ps1 -ListOnly
    Shows every work account on the device and which ones would match. Changes nothing.

.EXAMPLE
    .\Remove-WorkAccount.ps1 -Domain 'delta.mainettigroup.onmicrosoft.com' -DryRun

.EXAMPLE
    .\Remove-WorkAccount.ps1 -Domain 'delta.mainettigroup.onmicrosoft.com' -AllUsers

.NOTES
    Exit codes
      0     matching account(s) removed, or nothing matched (idempotent - safe to re-run)
      1     completed with warnings
      2     fatal error
      5     a match was found but is a DEVICE-level join and -AllowDeviceLeave was absent
      64    not running elevated / bad invocation
#>

[CmdletBinding()]
param(
    [string[]] $Domain = @('delta.mainettigroup.onmicrosoft.com'),
    [string[]] $TenantId = @(),
    [switch]   $ListOnly,
    [switch]   $DryRun,
    [switch]   $AllUsers,
    [switch]   $AllowDeviceLeave,
    [switch]   $Diagnostic,
    [string]   $LogDir = 'C:\ProgramData\PMC\Logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# =============================================================================================
#  STATE
# =============================================================================================
$script:Version        = '1.1.0'
$script:WorkRoot       = 'C:\ProgramData\PMC'
$script:LogDir         = $LogDir
$script:LogFile        = $null
$script:BackupDir      = $null
$script:HeartbeatPath  = 'C:\Windows\Temp\Remove-WorkAccount-heartbeat.log'
$script:WarnCount      = 0
$script:ErrorCount     = 0
$script:Accounts       = New-Object System.Collections.ArrayList   # everything discovered
$script:Removed        = New-Object System.Collections.ArrayList
$script:Kept           = New-Object System.Collections.ArrayList
$script:Steps          = New-Object System.Collections.ArrayList
$script:Failures       = New-Object System.Collections.ArrayList
$script:Diag           = [ordered]@{}
$script:RawCaptures    = [ordered]@{}
$script:LoadedHives    = New-Object System.Collections.ArrayList
$script:DeviceMatch    = $false
$script:JoinState      = $null
$script:ExitOverride   = 0
$script:RestartAdvised = $false
$script:CurrentStep    = 'startup'
$script:TranscriptOn   = $false
$script:TranscriptFile = ''

# Normalise the domain list: accept '@contoso.com', 'contoso.com', mixed case.
$script:TargetDomains = @()
foreach ($d in $Domain) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    $script:TargetDomains += ($d.Trim().TrimStart('@').ToLowerInvariant())
}
$script:TargetTenants = @()
foreach ($t in $TenantId) {
    if ([string]::IsNullOrWhiteSpace($t)) { continue }
    $script:TargetTenants += ($t.Trim().Trim('{','}').ToLowerInvariant())
}

# =============================================================================================
#  LOGGING
# =============================================================================================
function Write-Heartbeat {
    param([string] $Message)
    try {
        Add-Content -LiteralPath $script:HeartbeatPath -Encoding UTF8 -ErrorAction SilentlyContinue `
            -Value ('[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Message)
    } catch { }
}

function Initialize-Logging {
    try {
        if (-not (Test-Path -LiteralPath $script:LogDir)) {
            New-Item -ItemType Directory -Path $script:LogDir -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $script:LogDir = Join-Path $env:TEMP 'RemoveWorkAccount'
        New-Item -ItemType Directory -Path $script:LogDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogFile   = Join-Path $script:LogDir ("RemoveWorkAccount-{0}-{1}.log" -f $env:COMPUTERNAME, $stamp)
    $script:BackupDir = Join-Path $script:WorkRoot ("WorkAccountBackups\{0}" -f $stamp)
    try { New-Item -ItemType Directory -Path $script:BackupDir -Force -ErrorAction Stop | Out-Null } catch { }
    try { Set-Content -LiteralPath $script:LogFile -Value '' -ErrorAction Stop } catch { $script:LogFile = $null }

    $script:TranscriptFile = Join-Path $script:LogDir ("Transcript-{0}-{1}.log" -f $env:COMPUTERNAME, $stamp)
    try {
        Start-Transcript -LiteralPath $script:TranscriptFile -Force -ErrorAction Stop | Out-Null
        $script:TranscriptOn = $true
    }
    catch { $script:TranscriptFile = "not started: $($_.Exception.Message)" }
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [ValidateSet('INFO','OK','WARN','ERROR','STEP','SKIP','DRY','KEEP','GONE')]
        [string] $Level = 'INFO'
    )
    $line = '[{0}] [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'GONE'  { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow; $script:WarnCount++ }
        'ERROR' { Write-Host $line -ForegroundColor Red;    $script:ErrorCount++ }
        'STEP'  { Write-Host $line -ForegroundColor Cyan }
        'SKIP'  { Write-Host $line -ForegroundColor DarkGray }
        'KEEP'  { Write-Host $line -ForegroundColor DarkCyan }
        'DRY'   { Write-Host $line -ForegroundColor Magenta }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
    # Emits NOTHING to the pipeline. Returning a value here would inject it into the output
    # of every function that logs, and those values then get collected as if they were data.
}

function Write-Diag {
    param([string] $Message)
    $line = '[{0}] [DIAG ] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    if ($Diagnostic) { Write-Host $line -ForegroundColor DarkCyan }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
}

function Write-ErrorDetail {
    param(
        [Parameter(Mandatory)] [string] $Step,
        [Parameter(Mandatory)] $ErrorRecord,
        [string] $Context = ''
    )
    $d = [ordered]@{
        Step = $Step; Context = $Context; Time = (Get-Date).ToString('s')
        Message = ''; ExceptionType = ''; HResult = ''; ScriptLine = ''; LineNumber = ''; Inner = ''
    }
    try {
        if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
            $ex = $ErrorRecord.Exception
            $d.Message       = [string]$ex.Message
            $d.ExceptionType = $ex.GetType().FullName
            try { $d.HResult = '0x{0:X8}' -f $ex.HResult } catch { }
            try {
                $d.ScriptLine = ([string]$ErrorRecord.InvocationInfo.Line).Trim()
                $d.LineNumber = [string]$ErrorRecord.InvocationInfo.ScriptLineNumber
            } catch { }
            $chain = @(); $i = $ex.InnerException; $g = 0
            while ($i -and $g -lt 4) { $chain += ('{0}: {1}' -f $i.GetType().Name, $i.Message); $i = $i.InnerException; $g++ }
            $d.Inner = ($chain -join ' <- ')
        }
        else { $d.Message = [string]$ErrorRecord }
    }
    catch { $d.Message = 'unparseable error record' }

    [void]$script:Failures.Add([pscustomobject]$d)
    Write-Log "FAILURE in '$Step'$(if($Context){" ($Context)"}): $($d.Message)" 'ERROR'
    Write-Diag "  type $($d.ExceptionType) hresult $($d.HResult) line $($d.LineNumber)"
    if ($d.Inner) { Write-Diag "  inner: $($d.Inner)" }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Action,
        [string] $Context = ''
    )
    $script:CurrentStep = $Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    Write-Diag "STEP START: $Name $(if($Context){"[$Context]"})"
    try { & $Action }
    catch { $status = 'FAILED'; Write-ErrorDetail -Step $Name -ErrorRecord $_ -Context $Context }
    finally {
        $sw.Stop()
        [void]$script:Steps.Add([pscustomobject]@{
            Step = $Name; Context = $Context; Status = $status
            DurationMs = [int]$sw.ElapsedMilliseconds; Time = (Get-Date).ToString('s')
        })
        Write-Diag "STEP END  : $Name -> $status ($([int]$sw.ElapsedMilliseconds) ms)"
    }
}

# =============================================================================================
#  REGISTRY PATH HELPER
#  Join-Path on a registry path depends on the PSDrive already existing and on the provider
#  being loaded, which makes it a needless failure point. Registry paths are simple strings,
#  so build them as strings.
# =============================================================================================
function Join-RegPath {
    param([Parameter(Mandatory)][string] $Base, [Parameter(Mandatory)][string] $Child)
    return ($Base.TrimEnd('\') + '\' + $Child.Trim('\'))
}

# =============================================================================================
#  MATCHING  (pure logic - the single most important decision in this script)
# =============================================================================================
function Test-AccountMatchesTarget {
    <#
        Returns an object describing WHETHER and WHY an account matches.
        Deliberately conservative: an account that cannot be positively identified is
        NEVER treated as a match, so an unidentifiable registration is left in place
        rather than removed on a guess.
    #>
    param(
        [AllowEmptyString()] [AllowNull()] [string] $Upn,
        [AllowEmptyString()] [AllowNull()] [string] $Tenant
    )

    $result = [pscustomobject]@{ IsMatch = $false; Reason = ''; Identified = $false }

    $u = if ($Upn) { $Upn.Trim().ToLowerInvariant() } else { '' }
    $t = if ($Tenant) { $Tenant.Trim().Trim('{','}').ToLowerInvariant() } else { '' }

    if ($u -or $t) { $result.Identified = $true }

    # Tenant GUID match takes precedence - it is unambiguous.
    if ($t -and $script:TargetTenants.Count -gt 0) {
        foreach ($tt in $script:TargetTenants) {
            if ($t -eq $tt) {
                $result.IsMatch = $true
                $result.Reason  = "tenant id matches $tt"
                return $result
            }
        }
    }

    # Domain match on the UPN suffix. Must be a real suffix match on '@domain',
    # so 'contoso.com' never matches 'notcontoso.com' or 'contoso.com.evil.net'.
    if ($u -and $script:TargetDomains.Count -gt 0) {
        $at = $u.LastIndexOf('@')
        if ($at -ge 0 -and $at -lt ($u.Length - 1)) {
            $suffix = $u.Substring($at + 1)
            foreach ($td in $script:TargetDomains) {
                if ($suffix -eq $td) {
                    $result.IsMatch = $true
                    $result.Reason  = "UPN domain is $td"
                    return $result
                }
            }
        }
    }

    if (-not $result.Identified) {
        $result.Reason = 'no UPN or tenant id recorded - cannot identify, will NOT be touched'
    }
    else {
        $result.Reason = 'does not match the target domain/tenant'
    }
    return $result
}

# =============================================================================================
#  CONTEXT / PROFILES / HIVES
# =============================================================================================
function Get-ContextInfo {
    $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr  = New-Object System.Security.Principal.WindowsPrincipal($id)
    [pscustomobject]@{
        Name     = $id.Name
        Sid      = $id.User.Value
        IsSystem = ($id.User.Value -eq 'S-1-5-18')
        IsAdmin  = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-ActiveConsoleSids {
    $sids = New-Object System.Collections.ArrayList
    try {
        foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction Stop)) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o -and $o.User) {
                    $acct = if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User }
                    $sid  = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($sids -notcontains $sid) { [void]$sids.Add($sid) }
                }
            } catch { }
        }
    } catch { Write-Diag "explorer.exe owner enumeration failed: $($_.Exception.Message)" }
    return $sids
}

function Get-TargetProfiles {
    param([switch] $IncludeAll)

    $out    = New-Object System.Collections.ArrayList
    $active = @(Get-ActiveConsoleSids)
    $listKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    $entries = @()
    try { $entries = @(Get-ChildItem -LiteralPath $listKey -ErrorAction Stop) }
    catch { Write-Log "Cannot read ProfileList: $($_.Exception.Message)" 'ERROR'; return $out }

    foreach ($e in $entries) {
        $sid = Split-Path $e.PSPath -Leaf
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
        $parts = $sid -split '-'
        $rid = 0
        if (-not [int]::TryParse($parts[$parts.Count-1], [ref]$rid)) { continue }
        if ($rid -lt 500) { continue }

        $path = $null
        try { $path = (Get-ItemProperty -LiteralPath $e.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath }
        catch { continue }
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        try { $path = [System.Environment]::ExpandEnvironmentVariables($path) } catch { }
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $leaf = Split-Path $path -Leaf
        if ($leaf -match '^(Default|Default User|Public|All Users|systemprofile|LocalService|NetworkService|TEMP)$') { continue }
        if ($path -match '(?i)\\config\\systemprofile') { continue }

        $name = $leaf
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }

        $isActive = ($active -contains $sid)
        if (-not $IncludeAll -and -not $isActive) { continue }

        [void]$out.Add([pscustomobject]@{
            Sid = $sid; UserName = $name; ShortName = $leaf
            ProfilePath = $path.TrimEnd('\')
            LocalApp = Join-Path $path.TrimEnd('\') 'AppData\Local'
            IsActive = $isActive
        })
    }
    return $out
}

function Initialize-HkuDrive {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        try { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null }
        catch { Write-Log "Could not map HKU: $($_.Exception.Message)" 'WARN' }
    }
}

function Open-UserHive {
    param([Parameter(Mandatory)] $Profile)
    Initialize-HkuDrive
    $root = "HKU:\$($Profile.Sid)"
    if (Test-Path -LiteralPath $root) { return $root }

    $hive = Join-Path $Profile.ProfilePath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $hive)) {
        Write-Log "NTUSER.DAT missing for $($Profile.UserName) - cannot inspect this profile." 'WARN'
        return $null
    }
    $null = & reg.exe load "HKU\$($Profile.Sid)" "$hive" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Could not load hive for $($Profile.UserName) (exit $LASTEXITCODE) - profile skipped." 'WARN'
        return $null
    }
    [void]$script:LoadedHives.Add($Profile.Sid)
    Write-Diag "loaded offline hive for $($Profile.UserName)"
    return $root
}

function Close-LoadedHives {
    if ($script:LoadedHives.Count -eq 0) { return }
    [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 400
    foreach ($sid in @($script:LoadedHives)) {
        for ($i = 1; $i -le 3; $i++) {
            $null = & reg.exe unload "HKU\$sid" 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Diag "unloaded hive $sid"; break }
            [gc]::Collect(); Start-Sleep -Seconds 1
            if ($i -eq 3) { Write-Log "Hive $sid stayed loaded; it releases at next restart." 'WARN' }
        }
    }
    $script:LoadedHives.Clear()
}

# =============================================================================================
#  SAFE REGISTRY REMOVAL  (always exports a .reg backup first)
# =============================================================================================
function Backup-RegistryKey {
    param([Parameter(Mandatory)][string] $PsPath, [Parameter(Mandatory)][string] $Name)
    if (-not (Test-Path -LiteralPath $PsPath)) { return $true }
    if ($DryRun -or $ListOnly) { return $true }

    $regPath = $PsPath
    $regPath = $regPath -replace '^HKU:\\',  'HKEY_USERS\'
    $regPath = $regPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
    $regPath = $regPath -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
    $regPath = $regPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $file = Join-Path $script:BackupDir (("{0}.reg" -f $Name) -replace '[^\w\.\-]', '_')
    try {
        $null = & reg.exe export "$regPath" "$file" /y 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Diag "backup written: $file"; return $true }
        Write-Log "Backup export returned $LASTEXITCODE for $regPath - key will NOT be removed." 'WARN'
        return $false
    }
    catch {
        Write-Log "Backup failed for $regPath - key will NOT be removed. $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Remove-RegistryKeySafe {
    param(
        [Parameter(Mandatory)][string] $PsPath,
        [Parameter(Mandatory)][string] $BackupName,
        [string] $Description = ''
    )
    if (-not (Test-Path -LiteralPath $PsPath)) {
        Write-Log "  $Description - not present." 'SKIP'
        return $true
    }
    if ($ListOnly) { return $true }
    if ($DryRun) {
        Write-Log "  WOULD remove $PsPath  ($Description)" 'DRY'
        return $true
    }
    if (-not (Backup-RegistryKey -PsPath $PsPath -Name $BackupName)) {
        Write-Log "  $Description - SKIPPED: safety backup could not be written." 'WARN'
        return $false
    }
    try {
        Remove-Item -LiteralPath $PsPath -Recurse -Force -ErrorAction Stop
        Write-Log "  removed: $PsPath" 'GONE'
        return $true
    }
    catch {
        Write-ErrorDetail -Step 'remove-registry-key' -ErrorRecord $_ -Context $PsPath
        return $false
    }
}

# =============================================================================================
#  DISCOVERY
# =============================================================================================
function Add-DiscoveredAccount {
    <#
        Single gate for everything that lands in $script:Accounts. Anything that is not a
        properly shaped account object is rejected and logged rather than being carried
        along and blowing up later in an unrelated place.
    #>
    param([Parameter(Mandatory)][AllowNull()] $Candidate)

    if ($null -eq $Candidate) { return }

    # Must be a real custom object. Primitives (an int, a string) would otherwise reach the
    # property checks below and throw under StrictMode - which is exactly the failure this
    # gate exists to stop.
    $typeName = ''
    try { $typeName = $Candidate.GetType().Name } catch { }
    if ($typeName -ne 'PSCustomObject') {
        Write-Diag ("rejected non-object discovery result [{0}]: {1}" -f $typeName, ([string]$Candidate))
        return
    }

    $names = @()
    try { $names = @($Candidate.PSObject.Properties | ForEach-Object { $_.Name }) } catch { }
    foreach ($needed in @('Kind','User','Upn','TenantId','Thumbprint','JoinKey')) {
        if ($names -notcontains $needed) {
            Write-Diag ("rejected malformed account object (missing '{0}')" -f $needed)
            return
        }
    }
    [void]$script:Accounts.Add($Candidate)
}

function Get-DeviceJoinState {
    $r = [pscustomobject]@{
        Available = $false; AzureAdJoined = $false; DomainJoined = $false
        WorkplaceJoined = $false; MdmEnrolled = $false
        TenantName = ''; TenantId = ''; DeviceId = ''; MdmUrl = ''; ExecutingAccount = ''
    }
    $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return $r }
    $out = @()
    try { $out = @(& $exe /status 2>&1) } catch { return $r }
    if ($out.Count -eq 0) { return $r }
    $r.Available = $true
    $script:RawCaptures['dsregcmd_status'] = ($out | ForEach-Object { [string]$_ }) -join "`n"

    foreach ($line in $out) {
        $t = [string]$line
        if     ($t -match '^\s*AzureAdJoined\s*:\s*(\S+)')   { $r.AzureAdJoined   = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*DomainJoined\s*:\s*(\S+)')    { $r.DomainJoined    = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*WorkplaceJoined\s*:\s*(\S+)') { $r.WorkplaceJoined = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*TenantName\s*:\s*(.+)$')      { $r.TenantName = $Matches[1].Trim() }
        elseif ($t -match '^\s*TenantId\s*:\s*(.+)$')        { if (-not $r.TenantId) { $r.TenantId = $Matches[1].Trim() } }
        elseif ($t -match '^\s*DeviceId\s*:\s*(.+)$')        { $r.DeviceId = $Matches[1].Trim() }
        elseif ($t -match '^\s*MdmUrl\s*:\s*(.+)$')          { $r.MdmUrl = $Matches[1].Trim() }
        elseif ($t -match '(?i)Executing Account Name\s*:\s*(.+)$') {
            $v = $Matches[1]
            if ($v -match '([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})') { $r.ExecutingAccount = $Matches[1] }
        }
    }
    if ($r.MdmUrl) { $r.MdmEnrolled = $true }
    return $r
}

function Get-WorkplaceAccounts {
    <# Per-user Entra REGISTERED accounts. This is where multiple work accounts live. #>
    param([Parameter(Mandatory)] $Profile, [Parameter(Mandatory)][string] $HiveRoot)

    $found   = New-Object System.Collections.ArrayList
    $joinKey = Join-RegPath $HiveRoot 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo'
    if (-not (Test-Path -LiteralPath $joinKey)) {
        Write-Log "  no WorkplaceJoin registrations for $($Profile.UserName)" 'SKIP'
        return $found
    }

    foreach ($k in @(Get-ChildItem -LiteralPath $joinKey -ErrorAction SilentlyContinue)) {
        $thumb = Split-Path $k.PSPath -Leaf
        $upn = ''; $tid = ''; $idp = ''
        try {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
            foreach ($n in @('UserEmail','UserPrincipalName','AccountEmail')) {
                if (-not $upn -and ($p.PSObject.Properties.Name -contains $n)) { $upn = [string]$p.$n }
            }
            foreach ($n in @('TenantId','TenantID')) {
                if (-not $tid -and ($p.PSObject.Properties.Name -contains $n)) { $tid = [string]$p.$n }
            }
            if ($p.PSObject.Properties.Name -contains 'IdpDomain') { $idp = [string]$p.IdpDomain }
        }
        catch { Write-Diag "could not read JoinInfo\$thumb : $($_.Exception.Message)" }

        # Tenant display name, when Windows recorded one.
        $tname = ''
        if ($tid) {
            $ti = Join-RegPath $HiveRoot ("SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\{0}" -f $tid)
            if (Test-Path -LiteralPath $ti) {
                try {
                    $tp = Get-ItemProperty -LiteralPath $ti -ErrorAction Stop
                    foreach ($n in @('DisplayName','TenantDisplayName','TenantName')) {
                        if (-not $tname -and ($tp.PSObject.Properties.Name -contains $n)) { $tname = [string]$tp.$n }
                    }
                } catch { }
            }
        }

        [void]$found.Add([pscustomobject]@{
            Kind       = 'EntraRegistered'
            User       = $Profile.UserName
            Sid        = $Profile.Sid
            Upn        = $upn
            TenantId   = $tid
            TenantName = $tname
            Thumbprint = $thumb
            IdpDomain  = $idp
            HiveRoot   = $HiveRoot
            JoinKey    = (Join-RegPath $joinKey $thumb)
        })
    }
    return @($found | Where-Object { $_ -is [pscustomobject] })
}

function Get-StoredIdentityAccounts {
    <# Accounts the Microsoft identity stack remembers - these also surface in pickers. #>
    param([Parameter(Mandatory)] $Profile, [Parameter(Mandatory)][string] $HiveRoot)

    $found = New-Object System.Collections.ArrayList
    foreach ($rel in @('SOFTWARE\Microsoft\IdentityCRL\StoredIdentities',
                       'SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities')) {
        $key = Join-RegPath $HiveRoot $rel
        if (-not (Test-Path -LiteralPath $key)) { continue }
        foreach ($k in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
            $leaf = Split-Path $k.PSPath -Leaf
            # Office stores keys like  user_domain.com_ADAL  or  user@domain.com
            $upn = $leaf -replace '_(ADAL|LiveId|OrgId)$', ''
            # Only accept it if it genuinely looks like a UPN. Guessing here could match -
            # and therefore delete - the wrong account, so an unparseable name stays blank
            # and is reported as unidentified rather than removed.
            if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$') { $upn = '' }
            [void]$found.Add([pscustomobject]@{
                Kind       = 'StoredIdentity'
                User       = $Profile.UserName
                Sid        = $Profile.Sid
                Upn        = $upn
                TenantId   = ''
                TenantName = ''
                Thumbprint = ''
                IdpDomain  = ''
                HiveRoot   = $HiveRoot
                JoinKey    = (Join-RegPath $key $leaf)
            })
        }
    }
    return @($found | Where-Object { $_ -is [pscustomobject] })
}

function Get-MdmEnrollments {
    $found = New-Object System.Collections.ArrayList
    $key = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $key)) { return $found }
    foreach ($k in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
        $leaf = Split-Path $k.PSPath -Leaf
        if ($leaf -notmatch '^[0-9A-Fa-f\-]{8,}') { continue }
        try {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
            $upn = ''
            if ($p.PSObject.Properties.Name -contains 'UPN') { $upn = [string]$p.UPN }
            $prov = ''
            if ($p.PSObject.Properties.Name -contains 'ProviderID') { $prov = [string]$p.ProviderID }
            if (-not $upn -and -not $prov) { continue }
            [void]$found.Add([pscustomobject]@{
                Kind = 'MdmEnrollment'; User = '(device)'; Sid = ''; Upn = $upn
                TenantId = ''; TenantName = $prov; Thumbprint = $leaf; IdpDomain = ''
                HiveRoot = ''; JoinKey = (Join-RegPath $key $leaf)
            })
        } catch { }
    }
    return $found
}

# =============================================================================================
#  REMOVAL
# =============================================================================================
function Remove-EntraRegisteredAccount {
    <#
        Removes exactly one per-user Entra registered account and nothing else:
        its JoinInfo key, its certificate (key name == thumbprint), its TenantInfo entry
        (only when no other registration still needs it), and its cached identity entries.
    #>
    param([Parameter(Mandatory)] $Account)

    Write-Log "--- Removing work account: $($Account.Upn) [$($Account.User)] ---" 'STEP'
    Write-Log "    tenant     : $($Account.TenantId) $(if($Account.TenantName){"($($Account.TenantName))"})"
    Write-Log "    thumbprint : $($Account.Thumbprint)"

    $ok = $true
    $safeName = ('{0}-{1}' -f ($Account.User -replace '[^\w\.-]','_'), $Account.Thumbprint)

    # 1. the registration object itself
    if (-not (Remove-RegistryKeySafe -PsPath $Account.JoinKey -BackupName "JoinInfo-$safeName" -Description 'WorkplaceJoin registration')) { $ok = $false }

    # 2. the MS-Organization-Access certificate. In the hive it is a key named by thumbprint.
    if ($Account.Thumbprint -match '^[0-9A-Fa-f]{40}$') {
        foreach ($store in @('My','AAD Token Issuer')) {
            $certKey = Join-RegPath $Account.HiveRoot ("SOFTWARE\Microsoft\SystemCertificates\{0}\Certificates\{1}" -f $store, $Account.Thumbprint)
            if (Test-Path -LiteralPath $certKey) {
                if (-not (Remove-RegistryKeySafe -PsPath $certKey -BackupName "Cert-$store-$safeName" -Description "device certificate ($store)")) { $ok = $false }
            }
        }
        # If this profile happens to be the live user, also clear the live cert store view.
        try {
            $ctx = Get-ContextInfo
            if ($ctx.Sid -eq $Account.Sid -and -not $DryRun -and -not $ListOnly) {
                $c = Get-Item -Path ("Cert:\CurrentUser\My\{0}" -f $Account.Thumbprint) -ErrorAction SilentlyContinue
                if ($c) { Remove-Item -Path ("Cert:\CurrentUser\My\{0}" -f $Account.Thumbprint) -Force -ErrorAction Stop; Write-Log '  removed live certificate from CurrentUser\My' 'GONE' }
            }
        } catch { Write-Diag "live cert removal skipped: $($_.Exception.Message)" }
    }
    else {
        Write-Log '  registration key name is not a certificate thumbprint - no certificate removed.' 'WARN'
    }

    # 3. TenantInfo - shared, so only remove it when nothing else references this tenant.
    if ($Account.TenantId) {
        $stillUsed = @($script:Accounts | Where-Object {
            $_.Kind -eq 'EntraRegistered' -and $_.Sid -eq $Account.Sid -and
            $_.TenantId -eq $Account.TenantId -and $_.Thumbprint -ne $Account.Thumbprint
        })
        $tiKey = Join-RegPath $Account.HiveRoot ("SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\{0}" -f $Account.TenantId)
        if ($stillUsed.Count -gt 0) {
            Write-Log "  TenantInfo kept - $($stillUsed.Count) other registration(s) still use this tenant." 'KEEP'
        }
        elseif (Test-Path -LiteralPath $tiKey) {
            if (-not (Remove-RegistryKeySafe -PsPath $tiKey -BackupName "TenantInfo-$safeName" -Description 'WorkplaceJoin TenantInfo')) { $ok = $false }
        }
    }

    # 4. cached identity entries for this exact UPN
    if ($Account.Upn) {
        foreach ($rel in @('SOFTWARE\Microsoft\IdentityCRL\StoredIdentities',
                           'SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities')) {
            $parent = Join-RegPath $Account.HiveRoot $rel
            if (-not (Test-Path -LiteralPath $parent)) { continue }
            foreach ($k in @(Get-ChildItem -LiteralPath $parent -ErrorAction SilentlyContinue)) {
                $leaf = Split-Path $k.PSPath -Leaf
                $norm = ($leaf -replace '_(ADAL|LiveId|OrgId)$','').Replace('_','@').ToLowerInvariant()
                if ($norm -eq $Account.Upn.ToLowerInvariant() -or $leaf.ToLowerInvariant().StartsWith($Account.Upn.ToLowerInvariant())) {
                    $ps = Join-RegPath $parent $leaf
                    [void](Remove-RegistryKeySafe -PsPath $ps -BackupName "Identity-$safeName-$($leaf -replace '[^\w\.-]','_')" -Description "cached identity ($leaf)")
                }
            }
        }
    }

    # 5. token broker account files for this UPN (file state, reachable from SYSTEM)
    if ($Account.Upn -and -not $ListOnly) {
        $prof = @($script:Profiles | Where-Object { $_.Sid -eq $Account.Sid })
        if ($prof.Count -eq 1) {
            $tb = Join-Path $prof[0].LocalApp 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'
            if (Test-Path -LiteralPath $tb) {
                foreach ($f in @(Get-ChildItem -LiteralPath $tb -File -Force -ErrorAction SilentlyContinue)) {
                    $hit = $false
                    try { if ((Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) -match [regex]::Escape($Account.Upn)) { $hit = $true } } catch { }
                    if (-not $hit) { continue }
                    if ($DryRun) { Write-Log "  WOULD delete broker account file $($f.Name)" 'DRY'; continue }
                    try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; Write-Log "  removed broker account file $($f.Name)" 'GONE' }
                    catch { Write-Log "  could not remove $($f.Name): $($_.Exception.Message)" 'WARN' }
                }
            }
        }
    }

    if ($ok) {
        [void]$script:Removed.Add($Account)
        $script:RestartAdvised = $true
        Write-Log "  Work account '$($Account.Upn)' removed." 'OK'
    }
    else {
        Write-Log "  Work account '$($Account.Upn)' only partially removed - see warnings above." 'WARN'
    }
    return $ok
}

function Invoke-DeviceLeave {
    param([Parameter(Mandatory)] $JoinState)

    Write-Log '*********************************************************************' 'WARN'
    Write-Log ' THE MATCH IS A DEVICE-LEVEL ENTRA JOIN, NOT A PER-USER ACCOUNT' 'WARN'
    Write-Log '*********************************************************************' 'WARN'
    Write-Log " tenant: $($JoinState.TenantName) / $($JoinState.TenantId)"

    if (-not $AllowDeviceLeave) {
        Write-Log ' SKIPPED. Removing a device join can prevent users signing in to Windows.' 'WARN'
        Write-Log ' Confirm a working LOCAL administrator account exists on this machine, then' 'WARN'
        Write-Log ' re-run with -AllowDeviceLeave if you really intend to unjoin the device.' 'WARN'
        return $false
    }
    if ($DryRun -or $ListOnly) {
        Write-Log ' WOULD run: dsregcmd.exe /leave  (device level)' 'DRY'
        return $false
    }
    try {
        $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
        $null = & $exe /leave 2>&1
        Write-Log "dsregcmd /leave returned exit code $LASTEXITCODE." 'INFO'
        if ($LASTEXITCODE -eq 0) { Write-Log 'Device removed from the tenant. A restart is required.' 'OK' }
        else { Write-Log 'Device leave did not report success - check dsregcmd /status.' 'WARN' }
        $script:RestartAdvised = $true
        Write-Log 'Remember to delete the stale device object in the OLD tenant (Entra > Devices).' 'INFO'
        return $true
    }
    catch { Write-ErrorDetail -Step 'device-leave' -ErrorRecord $_; return $false }
}

# =============================================================================================
#  REPORTING
# =============================================================================================
function Write-AccountTable {
    param([Parameter(Mandatory)] $Accounts)
    if (@($Accounts).Count -eq 0) { Write-Log 'No work accounts of any kind were found on this device.' 'INFO'; return }
    Write-Log '-----------------------------------------------------------------------------' 'STEP'
    Write-Log ' WORK ACCOUNTS FOUND ON THIS DEVICE' 'STEP'
    Write-Log '-----------------------------------------------------------------------------' 'STEP'
    foreach ($a in $Accounts) {
        $m = Test-AccountMatchesTarget -Upn $a.Upn -Tenant $a.TenantId
        $verdict = if ($m.IsMatch) { 'MATCH -> will be removed' } else { 'keep' }
        Write-Log ("  [{0}] {1}" -f $a.Kind, $(if ($a.Upn) { $a.Upn } else { '(no UPN recorded)' }))
        Write-Log ("        profile : {0}" -f $a.User)
        if ($a.TenantId)   { Write-Log ("        tenant  : {0} {1}" -f $a.TenantId, $(if($a.TenantName){"($($a.TenantName))"})) }
        if ($a.Thumbprint) { Write-Log ("        id      : {0}" -f $a.Thumbprint) }
        Write-Log ("        verdict : {0}  ({1})" -f $verdict, $m.Reason) $(if ($m.IsMatch) { 'WARN' } else { 'KEEP' })
    }
    Write-Log '-----------------------------------------------------------------------------' 'STEP'
}

function Write-Summary {
    $dur = (Get-Date) - $script:StartTime
    Write-Log '' 'INFO'
    Write-Log '=================================================================' 'STEP'
    Write-Log '                        SUMMARY' 'STEP'
    Write-Log '=================================================================' 'STEP'
    Write-Log ("Computer          : {0}" -f $env:COMPUTERNAME)
    Write-Log ("Script version    : {0}" -f $script:Version)
    Write-Log ("Mode              : {0}" -f $(if ($ListOnly) { 'LIST ONLY - nothing changed' } elseif ($DryRun) { 'DRY RUN - nothing changed' } else { 'LIVE' }))
    Write-Log ("Target domain(s)  : {0}" -f (($script:TargetDomains) -join ', '))
    if ($script:TargetTenants.Count) { Write-Log ("Target tenant(s)  : {0}" -f (($script:TargetTenants) -join ', ')) }
    Write-Log ("Accounts found    : {0}" -f $script:Accounts.Count)
    Write-Log ("Accounts removed  : {0}" -f $script:Removed.Count)
    Write-Log ("Accounts kept     : {0}" -f $script:Kept.Count)
    foreach ($k in $script:Kept)    { Write-Log ("   KEPT    : {0} [{1}]" -f $(if($k.Upn){$k.Upn}else{'(unidentified)'}), $k.Kind) 'KEEP' }
    foreach ($r in $script:Removed) { Write-Log ("   REMOVED : {0} [{1}]" -f $r.Upn, $r.Kind) 'GONE' }
    Write-Log ("Warnings          : {0}" -f $script:WarnCount)
    Write-Log ("Errors            : {0}" -f $script:ErrorCount)
    $failed = @($script:Steps | Where-Object { $_.Status -eq 'FAILED' })
    Write-Log ("Steps run         : {0} (failed: {1})" -f $script:Steps.Count, $failed.Count)
    foreach ($f in $failed) { Write-Log ("   FAILED STEP: {0} [{1}]" -f $f.Step, $f.Context) 'ERROR' }
    if ($script:RestartAdvised) {
        Write-Log 'Restart / sign-out: RECOMMENDED - the Settings page refreshes after that.' 'WARN'
    }
    Write-Log ("Registry backups  : {0}" -f $script:BackupDir)
    Write-Log ("Log file          : {0}" -f $script:LogFile)
    Write-Log '=================================================================' 'STEP'

    # JSON receipt for the RMM
    try {
        $receipt = [pscustomobject]@{
            Version = $script:Version; Computer = $env:COMPUTERNAME
            Mode = $(if ($ListOnly) { 'ListOnly' } elseif ($DryRun) { 'DryRun' } else { 'Live' })
            TargetDomains = @($script:TargetDomains); TargetTenants = @($script:TargetTenants)
            StartedUtc = $script:StartTime.ToUniversalTime().ToString('s')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('s')
            AccountsFound = @($script:Accounts | Select-Object Kind,User,Upn,TenantId,TenantName,Thumbprint)
            AccountsRemoved = @($script:Removed | Select-Object Kind,User,Upn,TenantId,Thumbprint)
            AccountsKept = @($script:Kept | Select-Object Kind,User,Upn,TenantId,Thumbprint)
            Warnings = $script:WarnCount; Errors = $script:ErrorCount
            Steps = @($script:Steps); Failures = @($script:Failures)
            Environment = $script:Diag; RawToolOutput = $script:RawCaptures
            RestartAdvised = $script:RestartAdvised
            BackupDir = $script:BackupDir; LogFile = $script:LogFile
        }
        $f = Join-Path $script:LogDir ("receipt-workaccount-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $receipt | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $f -Encoding UTF8 -Force
        Write-Log "Receipt written: $f" 'INFO'
    }
    catch { Write-Log "Could not write receipt: $($_.Exception.Message)" 'WARN' }

    # Event log so the outcome is collectable centrally
    try {
        $src = 'RemoveWorkAccount'
        if (-not [System.Diagnostics.EventLog]::SourceExists($src)) { New-EventLog -LogName Application -Source $src -ErrorAction Stop }
        $type = if ($script:ErrorCount -gt 0) { 'Error' } elseif ($script:WarnCount -gt 0) { 'Warning' } else { 'Information' }
        Write-EventLog -LogName Application -Source $src -EntryType $type -EventId 9101 -ErrorAction Stop `
            -Message ("RemoveWorkAccount v$($script:Version): found=$($script:Accounts.Count) removed=$($script:Removed.Count) kept=$($script:Kept.Count) warnings=$($script:WarnCount) errors=$($script:ErrorCount) log=$($script:LogFile)")
    }
    catch { Write-Diag "event log skipped: $($_.Exception.Message)" }

    # one CSV line per device, for fleet comparison
    try {
        $csv  = Join-Path $script:LogDir 'WorkAccountFleetSummary.csv'
        $head = 'TimestampUtc,Computer,Mode,TargetDomains,Found,Removed,Kept,Warnings,Errors,RestartAdvised,RemovedUpns'
        if (-not (Test-Path -LiteralPath $csv)) { Set-Content -LiteralPath $csv -Value $head -Encoding UTF8 -ErrorAction Stop }
        Add-Content -LiteralPath $csv -Encoding UTF8 -ErrorAction Stop -Value ('{0},{1},{2},"{3}",{4},{5},{6},{7},{8},{9},"{10}"' -f `
            (Get-Date).ToUniversalTime().ToString('s'), $env:COMPUTERNAME,
            $(if ($ListOnly) { 'ListOnly' } elseif ($DryRun) { 'DryRun' } else { 'Live' }),
            (($script:TargetDomains) -join ';'), $script:Accounts.Count, $script:Removed.Count, $script:Kept.Count,
            $script:WarnCount, $script:ErrorCount, $script:RestartAdvised,
            ((@($script:Removed | ForEach-Object { $_.Upn })) -join ';'))
        Write-Log "Fleet summary appended: $csv" 'INFO'
    }
    catch { Write-Diag "fleet CSV skipped: $($_.Exception.Message)" }
}

# =============================================================================================
#  MAIN
# =============================================================================================
$script:StartTime = Get-Date
$script:Profiles  = @()

Write-Heartbeat "START pid=$PID domains=$(($script:TargetDomains) -join ';') mode=$(if($ListOnly){'list'}elseif($DryRun){'dry'}else{'live'})"
Initialize-Logging

Write-Log '=================================================================' 'STEP'
Write-Log " Remove Work Account by domain   v$($script:Version)" 'STEP'
Write-Log ' Removes ONLY the matching work account. All others are left alone.' 'STEP'
Write-Log '=================================================================' 'STEP'
Write-Log ("Target domain(s)  : {0}" -f (($script:TargetDomains) -join ', '))
if ($script:TargetTenants.Count) { Write-Log ("Target tenant(s)  : {0}" -f (($script:TargetTenants) -join ', ')) }
Write-Log ("Log file          : {0}" -f $script:LogFile)

$exitCode = 0

try {
    if ($script:TargetDomains.Count -eq 0 -and $script:TargetTenants.Count -eq 0) {
        Write-Log 'No -Domain or -TenantId supplied - nothing could be matched. Aborting.' 'ERROR'
        $exitCode = 64
        throw 'NO_TARGET'
    }

    $ctx = Get-ContextInfo
    Write-Log ("Running as        : {0}" -f $ctx.Name)
    Write-Log ("SYSTEM context    : {0}" -f $ctx.IsSystem)
    Write-Log ("Elevated          : {0}" -f $ctx.IsAdmin)
    $script:Diag['RunAsUser'] = $ctx.Name
    $script:Diag['IsSystem']  = $ctx.IsSystem
    $script:Diag['IsAdmin']   = $ctx.IsAdmin

    if (-not $ctx.IsAdmin) {
        Write-Log 'Must run elevated (or as SYSTEM from an RMM). Nothing was changed.' 'ERROR'
        $exitCode = 64
        throw 'NOT_ELEVATED'
    }

    # --- environment, for fleet triage ---
    Invoke-Step -Name 'diag:environment' -Action {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $script:Diag['OSCaption'] = $os.Caption
            $script:Diag['OSBuild']   = $os.BuildNumber
        } catch { $script:Diag['OSCaption'] = "CIM failed: $($_.Exception.Message)" }
        $script:Diag['PSVersion'] = $PSVersionTable.PSVersion.ToString()
        try { $script:Diag['UICulture'] = (Get-UICulture).Name } catch { }
        foreach ($k in $script:Diag.Keys) { Write-Log ("  {0,-14}: {1}" -f $k, $script:Diag[$k]) }
    }

    # --- device level ---
    Invoke-Step -Name 'discover:device' -Action {
        $script:JoinState = Get-DeviceJoinState
        $joinState = $script:JoinState
        Write-Log '--- Device level ---' 'STEP'
        if (-not $joinState.Available) { Write-Log 'dsregcmd unavailable - device state unknown.' 'WARN'; return }
        Write-Log ("Entra ID joined   : {0}" -f $joinState.AzureAdJoined)
        Write-Log ("Domain joined     : {0}" -f $joinState.DomainJoined)
        Write-Log ("Workplace joined  : {0}" -f $joinState.WorkplaceJoined)
        Write-Log ("MDM enrolled      : {0}" -f $joinState.MdmEnrolled)
        if ($joinState.TenantName) { Write-Log ("Device tenant     : {0} / {1}" -f $joinState.TenantName, $joinState.TenantId) }
        if ($joinState.ExecutingAccount) { Write-Log ("Signed-in account : {0}" -f $joinState.ExecutingAccount) }

        if ($joinState.AzureAdJoined) {
            $m = Test-AccountMatchesTarget -Upn $joinState.ExecutingAccount -Tenant $joinState.TenantId
            Add-DiscoveredAccount ([pscustomobject]@{
                Kind = 'EntraJoinedDevice'; User = '(device)'; Sid = ''
                Upn = $joinState.ExecutingAccount; TenantId = $joinState.TenantId
                TenantName = $joinState.TenantName; Thumbprint = $joinState.DeviceId
                IdpDomain = ''; HiveRoot = ''; JoinKey = ''
            })
            if ($m.IsMatch) { $script:DeviceMatch = $true }
        }
    }

    # --- MDM: report only ---
    Invoke-Step -Name 'discover:mdm' -Action {
        $mdm = @(Get-MdmEnrollments)
        foreach ($e in $mdm) { Add-DiscoveredAccount $e }
        if ($mdm.Count -gt 0) {
            Write-Log "--- MDM enrolments (reported only, never removed) ---" 'STEP'
            foreach ($e in $mdm) { Write-Log ("  {0}  provider={1}" -f $(if($e.Upn){$e.Upn}else{'(no UPN)'}), $e.TenantName) 'INFO' }
        }
    }

    # --- per-user accounts ---
    $script:Profiles = @(Get-TargetProfiles -IncludeAll:$AllUsers)
    if ($script:Profiles.Count -eq 0 -and -not $AllUsers) {
        Write-Log 'No signed-in profile found; retrying across all local profiles.' 'WARN'
        $script:Profiles = @(Get-TargetProfiles -IncludeAll)
    }
    Write-Log ("Profiles to inspect: {0}" -f (($script:Profiles | ForEach-Object { $_.UserName }) -join ', '))

    foreach ($p in $script:Profiles) {
        Invoke-Step -Name 'discover:user' -Context $p.UserName -Action {
            Write-Log "--- Profile: $($p.UserName) ---" 'STEP'
            $hive = Open-UserHive -Profile $p
            if (-not $hive) { return }
            foreach ($a in @(Get-WorkplaceAccounts   -Profile $p -HiveRoot $hive)) { Add-DiscoveredAccount $a }
            foreach ($a in @(Get-StoredIdentityAccounts -Profile $p -HiveRoot $hive)) { Add-DiscoveredAccount $a }
        }
    }

    # --- report everything discovered, with the verdict for each ---
    Write-AccountTable -Accounts $script:Accounts

    if ($ListOnly) {
        Write-Log 'ListOnly requested - no changes made.' 'STEP'
    }
    else {
        # --- remove per-user registrations that match; keep the rest ---
        $registrations = @($script:Accounts | Where-Object { $_.Kind -eq 'EntraRegistered' })
        $matched = @()
        foreach ($a in $registrations) {
            $m = Test-AccountMatchesTarget -Upn $a.Upn -Tenant $a.TenantId
            if ($m.IsMatch) { $matched += $a } else { [void]$script:Kept.Add($a) }
        }

        # Record every non-registration account as kept too, so the summary and the receipt
        # agree with the verdict table above instead of reporting "kept: 0".
        foreach ($other in @($script:Accounts | Where-Object { $_.Kind -ne 'EntraRegistered' })) {
            $mo = Test-AccountMatchesTarget -Upn $other.Upn -Tenant $other.TenantId
            if (-not $mo.IsMatch) { [void]$script:Kept.Add($other) }
        }

        if ($matched.Count -eq 0) {
            Write-Log 'No per-user work account matched the target domain/tenant.' 'INFO'
            Write-Log 'Nothing to do for this device - safe to re-run at any time.' 'INFO'
        }
        foreach ($a in $matched) {
            Invoke-Step -Name 'remove:account' -Context $a.Upn -Action { [void](Remove-EntraRegisteredAccount -Account $a) }
        }

        # stored identities that match but had no registration of their own
        foreach ($a in @($script:Accounts | Where-Object { $_.Kind -eq 'StoredIdentity' })) {
            $m = Test-AccountMatchesTarget -Upn $a.Upn -Tenant $a.TenantId
            if (-not $m.IsMatch) { continue }
            if (@($script:Removed | Where-Object { $_.Upn -and $a.Upn -and $_.Upn.ToLowerInvariant() -eq $a.Upn.ToLowerInvariant() }).Count -gt 0) { continue }
            Invoke-Step -Name 'remove:cached-identity' -Context $a.Upn -Action {
                Write-Log "--- Removing cached identity: $($a.Upn) [$($a.User)] ---" 'STEP'
                if (Remove-RegistryKeySafe -PsPath $a.JoinKey -BackupName ("Identity-{0}" -f ($a.Upn -replace '[^\w\.-]','_')) -Description 'cached identity') {
                    [void]$script:Removed.Add($a)
                    $script:RestartAdvised = $true
                }
            }
        }

        # --- device-level join, only if it is what matched ---
        if ($script:DeviceMatch -and $script:JoinState) {
            Invoke-Step -Name 'remove:device-join' -Action {
                if (-not (Invoke-DeviceLeave -JoinState $script:JoinState)) {
                    if (-not $AllowDeviceLeave) { $script:ExitOverride = 5 }
                }
            }
        }

        # --- verification pass: prove the account really is gone ---
        if ($script:Removed.Count -gt 0 -and -not $DryRun) {
            Invoke-Step -Name 'verify' -Action {
                Write-Log '--- Verification ---' 'STEP'
                $stillThere = 0
                foreach ($r in @($script:Removed | Where-Object { $_.Kind -eq 'EntraRegistered' })) {
                    if (Test-Path -LiteralPath $r.JoinKey) {
                        Write-Log "  STILL PRESENT: $($r.Upn) ($($r.JoinKey))" 'ERROR'
                        $stillThere++
                    }
                    else { Write-Log "  confirmed gone: $($r.Upn)" 'OK' }
                }
                if ($stillThere -eq 0) { Write-Log '  All removed accounts verified gone from the registry.' 'OK' }
                # And confirm the ones we intended to keep are untouched.
                foreach ($k in @($script:Kept | Where-Object { $_.Kind -eq 'EntraRegistered' })) {
                    if (Test-Path -LiteralPath $k.JoinKey) { Write-Log "  kept intact: $($k.Upn)" 'KEEP' }
                    else { Write-Log "  WARNING - an account we meant to KEEP is missing: $($k.Upn)" 'ERROR' }
                }
            }
        }
    }
}
catch {
    if ($_.Exception.Message -notin @('NO_TARGET','NOT_ELEVATED')) {
        Write-ErrorDetail -Step "fatal:$($script:CurrentStep)" -ErrorRecord $_
        $exitCode = 2
    }
}
finally {
    Close-LoadedHives
    Write-Summary
}

if ($exitCode -eq 0 -and $script:ExitOverride -ne 0) { $exitCode = $script:ExitOverride }
if ($exitCode -eq 0) {
    if     ($script:ErrorCount -gt 0) { $exitCode = 2 }
    elseif ($script:WarnCount  -gt 0) { $exitCode = 1 }
}

Write-Log "Exiting with code $exitCode." 'INFO'
Write-Heartbeat "END exit=$exitCode found=$($script:Accounts.Count) removed=$($script:Removed.Count) kept=$($script:Kept.Count)"
if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { } }

# Never reboots. The Settings page refreshes after the user signs out or restarts.
exit $exitCode
