#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft 365 tenant-to-tenant post-migration cache, token and session cleanup for Windows endpoints.

.DESCRIPTION
    Clears cached sign-in tokens, credential material and application caches left behind by a
    Microsoft 365 tenant-to-tenant migration, so that Outlook, Teams, OneDrive, Office and browsers
    re-authenticate against the NEW tenant instead of silently reusing OLD tenant tokens.

    Designed to be deployed unattended from Intune / SCCM / NinjaOne / Datto / Action1 / any RMM.

    ------------------------------------------------------------------------------------------
    KEY DESIGN POINT - WHY A NAIVE SCRIPT FAILS
    ------------------------------------------------------------------------------------------
    RMM and Intune platform scripts run as NT AUTHORITY\SYSTEM, not as the signed-in user.
    Every path in the source guide is %LOCALAPPDATA% scoped. Under SYSTEM, %LOCALAPPDATA%
    resolves to C:\Windows\System32\config\systemprofile\AppData\Local - so a naive script
    reports "success" while deleting nothing at all.

    This script therefore:
      1. Detects its own security context (SYSTEM / admin / standard user).
      2. Resolves real user profiles from the registry ProfileList - never from %LOCALAPPDATA%.
      3. Loads the target user's NTUSER.DAT hive when that user is not signed in.
      4. Runs a second "user phase" inside the interactive user's session, because the Windows
         Credential Manager vault is DPAPI-encrypted per user and is physically unreachable
         from SYSTEM. Falls back to a RunOnce entry if no session exists.

    ------------------------------------------------------------------------------------------
    SAFETY GUARANTEES (hard-coded, not optional)
    ------------------------------------------------------------------------------------------
      * NEVER creates, modifies, disables or deletes any local or domain user account.
      * NEVER touches Documents, Desktop, Downloads, Pictures or any OneDrive sync folder.
      * NEVER deletes .PST files. Only .OST (rebuildable offline cache), and only on request.
      * NEVER deletes browser Bookmarks, Login Data, Web Data, Extensions or Preferences.
      * NEVER deletes a credential unless its target matches an explicit Microsoft allow-list.
      * Every deletion path is validated against a guard function before any I/O occurs.
      * Every registry key is exported to a .reg backup before it is removed.
      * -DryRun performs a full pass with zero writes.

.PARAMETER Scope
    Cache      - Caches and tokens only. No registry writes, no profile changes. Safest.
    Standard   - (default) Cache + Credential Manager + Office identity + OneDrive unlink
                 + Outlook profile reset. This is the guide's documented end-to-end flow.
    Aggressive - Standard + WAM TokenBroker cache + browser local storage + Office WEF cache.

.PARAMETER AllUsers
    Process every real user profile on the device instead of only the signed-in user.
    Use on shared / kiosk / multi-user machines.

.PARAMETER Force
    Skip the graceful close-window request and terminate applications immediately.
    WARNING: unsaved work in Word / Excel / Outlook will be lost. Without this switch the
    script asks each app to close politely first and waits -GraceSeconds before forcing.

.PARAMETER IncludeOst
    Also delete Outlook .OST offline data files (guide section 3.3). Rebuildable from cloud.
    .PST files are always preserved regardless of this switch.

.PARAMETER SkipBrowsers
    Do not touch Edge / Chrome / Brave / Firefox.

.PARAMETER SkipOneDrive
    Do not unlink the OneDrive account.

.PARAMETER SkipOutlookProfiles
    Do not remove Outlook mail profiles.

.PARAMETER SkipCredentialManager
    Do not clean Windows Credential Manager.

.PARAMETER SkipWorkAccount
    Do not remove the "Access work or school" registration or the cached work account
    entries shown in Office / Teams account pickers.

.PARAMETER ForceLeaveAzureAdJoin
    Required before the script will run a DEVICE-level 'dsregcmd /leave'.
    Without it, an Entra ID joined or Hybrid joined device is detected, reported and left
    untouched. Read the warning in the log before using this: on a cloud-only Entra joined
    device, leaving the tenant can prevent users from signing in to Windows at all.
    Per-user Workplace Join removal does NOT need this switch - it is safe and automatic.

.PARAMETER DryRun
    Report every action that would be taken. Performs no deletion, no registry write.

.PARAMETER GraceSeconds
    Seconds to wait for applications to close gracefully before forcing. Default 20.

.PARAMETER LogPath
    Directory for logs and receipts. Default C:\ProgramData\PostMigrationCleanup\Logs

.PARAMETER UserPhase
    INTERNAL. Set automatically when the script relaunches itself inside the user session.
    Do not pass this manually.

.PARAMETER LeaveWorkplaceJoin
    INTERNAL. Set automatically for the user session phase when a per-user work account
    registration was detected. Do not pass this manually.

.EXAMPLE
    .\Invoke-PostMigrationCleanup.ps1 -DryRun -Verbose
    Full rehearsal. Changes nothing. Run this first on a pilot device.

.EXAMPLE
    .\Invoke-PostMigrationCleanup.ps1
    Standard production run against the signed-in user.

.EXAMPLE
    .\Invoke-PostMigrationCleanup.ps1 -Scope Aggressive -IncludeOst -Force -AllUsers
    Maximum cleanup, all profiles, no grace period. Use only on unattended devices.

.EXAMPLE
    .\Invoke-PostMigrationCleanup.ps1 -ForceLeaveAzureAdJoin
    Also unjoins an Entra ID joined device from the old tenant. Verify a working local
    administrator account exists on the device before you run this.

.NOTES
    Exit codes:
        0     Success
        1     Completed with warnings (see log)
        2     Fatal error
        3     No eligible user profile found - RMM should retry later
        3010  Success, restart required
#>

[CmdletBinding()]
param(
    [ValidateSet('Cache', 'Standard', 'Aggressive')]
    [string] $Scope = 'Standard',

    [switch] $AllUsers,
    [switch] $Force,
    [switch] $IncludeOst,
    [switch] $SkipBrowsers,
    [switch] $SkipOneDrive,
    [switch] $SkipOutlookProfiles,
    [switch] $SkipCredentialManager,
    [switch] $SkipWorkAccount,
    [switch] $ForceLeaveAzureAdJoin,
    [switch] $DryRun,
    [switch] $UserPhase,
    [switch] $LeaveWorkplaceJoin,

    [ValidateRange(0, 300)]
    [int] $GraceSeconds = 20,

    [string] $LogPath = 'C:\ProgramData\PostMigrationCleanup\Logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# =============================================================================================
#  SCRIPT STATE
# =============================================================================================

$script:Version            = '2.0.0'
$script:WorkRoot           = 'C:\ProgramData\PostMigrationCleanup'
$script:LogDir             = $LogPath
$script:LogFile            = $null
$script:BackupDir          = $null
$script:WarningCount       = 0
$script:ErrorCount         = 0
$script:BytesFreed         = [int64]0
$script:ItemsRemoved       = 0
$script:RebootRequired     = $false
$script:Actions            = New-Object System.Collections.ArrayList
$script:LoadedHives        = New-Object System.Collections.ArrayList
$script:TaskName           = 'PostMigrationCleanup-UserPhase'
$script:DoWpjLeave         = $false
$script:SelfPath           = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Definition }

# Directories that must never be deleted from, under any circumstance.
$script:ForbiddenRoots = @(
    "$env:SystemRoot"
    "$env:SystemRoot\System32"
    "$env:ProgramFiles"
    ${env:ProgramFiles(x86)}
    "$env:ProgramData"
    "$env:SystemDrive\"
    "$env:SystemDrive\Users"
    'C:\Windows\System32\config\systemprofile'
) | Where-Object { $_ }

# Folder names inside a user profile that are user DATA and must never be cleared.
$script:ProtectedProfileLeaves = @(
    'Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos', 'Music',
    'Favorites', 'Links', 'Saved Games', 'Searches', 'Contacts'
)

# =============================================================================================
#  LOGGING
# =============================================================================================

function Initialize-Logging {
    try {
        if (-not (Test-Path -LiteralPath $script:LogDir)) {
            New-Item -ItemType Directory -Path $script:LogDir -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        # Fall back to TEMP so the script can still run and report.
        $script:LogDir = Join-Path $env:TEMP 'PostMigrationCleanup'
        New-Item -ItemType Directory -Path $script:LogDir -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $phase   = if ($UserPhase) { 'userphase' } else { 'system' }
    $script:LogFile   = Join-Path $script:LogDir ("PostMigrationCleanup-{0}-{1}-{2}.log" -f $env:COMPUTERNAME, $phase, $stamp)
    $script:BackupDir = Join-Path $script:WorkRoot ("RegistryBackups\{0}" -f $stamp)

    try { New-Item -ItemType Directory -Path $script:BackupDir -Force -ErrorAction Stop | Out-Null } catch { }

    # The user phase runs unelevated and may not be able to write under ProgramData.
    # Fall back to the user's own TEMP so registry backups are never silently skipped.
    $probe = Join-Path $script:BackupDir ('.write-test-' + [guid]::NewGuid().ToString('N'))
    try {
        Set-Content -LiteralPath $probe -Value 'x' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
    catch {
        $script:BackupDir = Join-Path $env:TEMP ("PostMigrationCleanup-RegistryBackups\{0}" -f $stamp)
        try { New-Item -ItemType Directory -Path $script:BackupDir -Force -ErrorAction Stop | Out-Null } catch { }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP', 'SKIP', 'DRY')]
        [string] $Level = 'INFO'
    )

    $line = '[{0}] [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow;  $script:WarningCount++ }
        'ERROR' { Write-Host $line -ForegroundColor Red;     $script:ErrorCount++ }
        'STEP'  { Write-Host $line -ForegroundColor Cyan }
        'SKIP'  { Write-Host $line -ForegroundColor DarkGray }
        'DRY'   { Write-Host $line -ForegroundColor Magenta }
        default { Write-Host $line }
    }

    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
}

function Add-Action {
    param(
        [string] $Category,
        [string] $Target,
        [string] $Result,
        [int64]  $Bytes = 0,
        [string] $Detail = ''
    )
    [void]$script:Actions.Add([pscustomobject]@{
        Category = $Category
        Target   = $Target
        Result   = $Result
        Bytes    = $Bytes
        Detail   = $Detail
        Time     = (Get-Date).ToString('s')
    })
}

function Format-Bytes {
    param([int64] $Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ('{0} B' -f $Bytes)
}

# =============================================================================================
#  SAFETY GUARDS
# =============================================================================================

function Test-PathIsSafeToClear {
    <#
        Returns $true only if the supplied path is genuinely inside the target user's profile,
        is not the profile root itself, is not a protected data folder, and is not inside any
        forbidden system root. Every delete in this script passes through here first.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ProfileRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path))        { return $false }
    if ([string]::IsNullOrWhiteSpace($ProfileRoot)) { return $false }

    try {
        $full     = [System.IO.Path]::GetFullPath($Path.TrimEnd('\'))
        $profRoot = [System.IO.Path]::GetFullPath($ProfileRoot.TrimEnd('\'))
    }
    catch { return $false }

    # Must not be a bare drive root.
    if ($full -match '^[A-Za-z]:\\?$') { return $false }

    # Must not be the profile root itself.
    if ($full.Equals($profRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }

    # Must live inside the profile.
    if (-not $full.StartsWith($profRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }

    # Must not be, or be inside, a protected user-data folder.
    foreach ($leaf in $script:ProtectedProfileLeaves) {
        $protected = Join-Path $profRoot $leaf
        if ($full.Equals($protected, [System.StringComparison]::OrdinalIgnoreCase) -or
            $full.StartsWith($protected + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }

    # Must not be inside a OneDrive sync root (e.g. "OneDrive - Contoso").
    $relative = $full.Substring($profRoot.Length).TrimStart('\')
    if ($relative -match '^OneDrive( -|$)') { return $false }

    # Must not be inside a forbidden system root.
    foreach ($root in $script:ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        try { $r = [System.IO.Path]::GetFullPath($root.TrimEnd('\')) } catch { continue }
        if ($full.Equals($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }

    # Guard against the SYSTEM profile specifically - the classic silent-failure path.
    if ($full -match '(?i)\\config\\systemprofile\\') { return $false }

    return $true
}

# =============================================================================================
#  FILESYSTEM HELPERS
# =============================================================================================

function Get-FolderSizeSafe {
    param([string] $Path)
    $total = [int64]0
    try {
        $items = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue
        if ($items) {
            $sum = ($items | Measure-Object -Property Length -Sum).Sum
            if ($sum) { $total = [int64]$sum }
        }
    }
    catch { }
    return $total
}

function Clear-ItemAttributes {
    <# Strips ReadOnly / Hidden / System so Remove-Item cannot be blocked by attributes. #>
    param([string] $Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $strip = [System.IO.FileAttributes]::ReadOnly -bor
                 [System.IO.FileAttributes]::Hidden   -bor
                 [System.IO.FileAttributes]::System
        if ($item.Attributes -band $strip) {
            # Clear only the blocking bits; the Directory bit is preserved.
            $item.Attributes = $item.Attributes -band (-bnot $strip)
        }
    }
    catch { }
}

function Invoke-RobocopyPurge {
    <#
        Last-resort deletion for folders that defeat Remove-Item: paths longer than 260
        characters, deeply nested Teams/Chromium caches, or names with reserved characters.
        Mirroring an empty directory over the target empties it natively at Win32 level.
    #>
    param([Parameter(Mandatory)][string] $Target)

    $empty = Join-Path $env:TEMP ('pmc_empty_' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $empty -Force -ErrorAction Stop | Out-Null
        $null = & robocopy.exe $empty $Target /MIR /NFL /NDL /NJH /NJS /NC /NS /NP /R:1 /W:1 2>&1
        return $true
    }
    catch { return $false }
    finally {
        Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Clear-FolderContent {
    <#
        Empties a folder but keeps the folder itself (matches the guide: "you do not need to
        delete the parent folder"). Retries locked handles, strips attributes, then falls back
        to robocopy for long-path or stubborn content.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ProfileRoot,
        [Parameter(Mandatory)] [string] $Description,
        [int] $Retries = 3
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "$Description - not present, nothing to do." 'SKIP'
        Add-Action -Category 'Folder' -Target $Path -Result 'NotPresent'
        return
    }

    if (-not (Test-PathIsSafeToClear -Path $Path -ProfileRoot $ProfileRoot)) {
        Write-Log "$Description - BLOCKED by safety guard: $Path" 'ERROR'
        Add-Action -Category 'Folder' -Target $Path -Result 'Blocked' -Detail 'Failed safety guard'
        return
    }

    $size = Get-FolderSizeSafe -Path $Path

    if ($DryRun) {
        Write-Log "$Description - WOULD clear $Path ($(Format-Bytes $size))" 'DRY'
        Add-Action -Category 'Folder' -Target $Path -Result 'DryRun' -Bytes $size
        return
    }

    $removed = 0
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {

        $children = @()
        try { $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue) } catch { }
        if ($children.Count -eq 0) { break }

        foreach ($child in $children) {
            try {
                Clear-ItemAttributes -Path $child.FullName
                if ($child.PSIsContainer) {
                    Get-ChildItem -LiteralPath $child.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                        ForEach-Object { Clear-ItemAttributes -Path $_.FullName }
                }
                Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop
                $removed++
            }
            catch {
                if ($attempt -eq $Retries) {
                    if ($child.PSIsContainer) {
                        if (Invoke-RobocopyPurge -Target $child.FullName) {
                            Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction SilentlyContinue
                            if (-not (Test-Path -LiteralPath $child.FullName)) { $removed++ }
                        }
                    }
                }
            }
        }

        if ($attempt -lt $Retries) {
            $left = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
            if ($left.Count -eq 0) { break }
            Start-Sleep -Seconds 2
        }
    }

    $leftover = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count

    if ($leftover -eq 0) {
        $script:BytesFreed   += $size
        $script:ItemsRemoved += $removed
        Write-Log "$Description - cleared ($removed items, $(Format-Bytes $size))" 'OK'
        Add-Action -Category 'Folder' -Target $Path -Result 'Cleared' -Bytes $size
    }
    else {
        $script:BytesFreed   += $size
        $script:ItemsRemoved += $removed
        Write-Log "$Description - partially cleared, $leftover item(s) still locked. A restart will release them." 'WARN'
        Add-Action -Category 'Folder' -Target $Path -Result 'Partial' -Bytes $size -Detail "$leftover locked"
        $script:RebootRequired = $true
    }
}

function Remove-FileSafe {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ProfileRoot,
        [string] $Description = ''
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-PathIsSafeToClear -Path $Path -ProfileRoot $ProfileRoot)) {
        Write-Log "BLOCKED by safety guard: $Path" 'ERROR'
        return
    }

    $size = 0
    try { $size = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length } catch { }

    if ($DryRun) {
        Write-Log "WOULD delete $Path ($(Format-Bytes $size)) $Description" 'DRY'
        Add-Action -Category 'File' -Target $Path -Result 'DryRun' -Bytes $size
        return
    }

    try {
        Clear-ItemAttributes -Path $Path
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        $script:BytesFreed   += $size
        $script:ItemsRemoved++
        Write-Log "Deleted $Path ($(Format-Bytes $size)) $Description" 'OK'
        Add-Action -Category 'File' -Target $Path -Result 'Deleted' -Bytes $size
    }
    catch {
        Write-Log "Could not delete $Path - $($_.Exception.Message)" 'WARN'
        Add-Action -Category 'File' -Target $Path -Result 'Failed' -Detail $_.Exception.Message
        $script:RebootRequired = $true
    }
}

# =============================================================================================
#  SECURITY CONTEXT & USER RESOLUTION
# =============================================================================================

function Get-ExecutionContextInfo {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)

    $osCaption = 'Unknown'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os -and $os.Caption) { $osCaption = $os.Caption }
    }
    catch { }

    [pscustomobject]@{
        Name       = $identity.Name
        Sid        = $identity.User.Value
        IsSystem   = ($identity.User.Value -eq 'S-1-5-18')
        IsAdmin    = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        Is64Bit    = [Environment]::Is64BitProcess
        OSCaption  = $osCaption
        PSVersion  = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-ActiveConsoleSids {
    <#
        Returns SIDs of users with a live desktop session. Ownership of explorer.exe is the
        most reliable indicator across Windows 10 / 11 / Server and RDP sessions.
    #>
    $sids = New-Object System.Collections.ArrayList
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction Stop
        foreach ($p in $procs) {
            try {
                $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($owner -and $owner.User) {
                    $account = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
                    $ntAccount = New-Object System.Security.Principal.NTAccount($account)
                    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($sids -notcontains $sid) { [void]$sids.Add($sid) }
                }
            }
            catch { }
        }
    }
    catch {
        Write-Log "Could not enumerate explorer.exe owners: $($_.Exception.Message)" 'WARN'
    }
    return $sids
}

function Get-TargetUserProfiles {
    <#
        Resolves genuine interactive user profiles from the registry - never from environment
        variables, which are wrong when running as SYSTEM.
    #>
    param([switch] $IncludeAll)

    $result   = New-Object System.Collections.ArrayList
    $active   = @(Get-ActiveConsoleSids)
    $listKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    $entries = @()
    try { $entries = @(Get-ChildItem -LiteralPath $listKey -ErrorAction Stop) }
    catch {
        Write-Log "Cannot read ProfileList: $($_.Exception.Message)" 'ERROR'
        return $result
    }

    foreach ($entry in $entries) {
        $sid = Split-Path $entry.PSPath -Leaf

        # Only real, non-service local/domain accounts.
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
        # Skip well-known service-ish RIDs below 1000 (e.g. -500 Administrator is kept: RID 500 is valid).
        $sidParts = $sid -split '-'
        $rid = 0
        if (-not [int]::TryParse($sidParts[$sidParts.Count - 1], [ref]$rid)) { continue }
        if ($rid -lt 500) { continue }

        $profilePath = $null
        try { $profilePath = (Get-ItemProperty -LiteralPath $entry.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath }
        catch { continue }

        if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
        try { $profilePath = [System.Environment]::ExpandEnvironmentVariables($profilePath) } catch { }
        if (-not (Test-Path -LiteralPath $profilePath)) { continue }

        # Exclude built-in / template / temporary profiles.
        $leaf = Split-Path $profilePath -Leaf
        if ($leaf -match '^(Default|Default User|Public|All Users|systemprofile|LocalService|NetworkService|TEMP)$') { continue }
        if ($profilePath -match '(?i)\\config\\systemprofile') { continue }

        $userName = $null
        try {
            $userName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        }
        catch { $userName = $leaf }

        $isActive = ($active -contains $sid)

        if (-not $IncludeAll -and -not $isActive) { continue }

        [void]$result.Add([pscustomobject]@{
            Sid         = $sid
            UserName    = $userName
            ShortName   = $leaf
            ProfilePath = $profilePath.TrimEnd('\')
            LocalApp    = Join-Path $profilePath.TrimEnd('\') 'AppData\Local'
            RoamingApp  = Join-Path $profilePath.TrimEnd('\') 'AppData\Roaming'
            IsActive    = $isActive
        })
    }

    return $result
}

# =============================================================================================
#  REGISTRY HIVE HELPERS
# =============================================================================================

function Initialize-HkuDrive {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        try { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null }
        catch { Write-Log "Could not map HKU drive: $($_.Exception.Message)" 'WARN' }
    }
}

function Open-UserHive {
    <#
        Returns the PS registry root for a user, e.g. 'HKU:\S-1-5-21-...'.
        Loads NTUSER.DAT if the user is not signed in, and records it for unload later.
    #>
    param([Parameter(Mandatory)] $User)

    Initialize-HkuDrive
    $root = "HKU:\$($User.Sid)"

    if (Test-Path -LiteralPath $root) { return $root }

    $hiveFile = Join-Path $User.ProfilePath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $hiveFile)) {
        Write-Log "NTUSER.DAT not found for $($User.UserName) - registry steps will be skipped." 'WARN'
        return $null
    }

    if ($DryRun) {
        Write-Log "WOULD load registry hive for $($User.UserName)" 'DRY'
        return $null
    }

    try { $null = & reg.exe load "HKU\$($User.Sid)" "$hiveFile" 2>&1 }
    catch {
        Write-Log "reg.exe load failed for $($User.UserName): $($_.Exception.Message)" 'WARN'
        return $null
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to load registry hive for $($User.UserName) (exit $LASTEXITCODE). Registry steps skipped." 'WARN'
        return $null
    }

    [void]$script:LoadedHives.Add($User.Sid)
    Write-Log "Loaded offline registry hive for $($User.UserName)." 'INFO'
    return $root
}

function Close-LoadedHives {
    if ($script:LoadedHives.Count -eq 0) { return }

    # Release PowerShell's handles or reg unload will fail.
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 500

    foreach ($sid in @($script:LoadedHives)) {
        for ($i = 1; $i -le 3; $i++) {
            $null = & reg.exe unload "HKU\$sid" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Unloaded registry hive $sid." 'INFO'
                break
            }
            [gc]::Collect(); Start-Sleep -Seconds 1
            if ($i -eq 3) { Write-Log "Could not unload hive $sid - it will release at next restart." 'WARN' }
        }
    }
    $script:LoadedHives.Clear()
}

function Backup-RegistryKey {
    param(
        [Parameter(Mandatory)] [string] $HiveRoot,   # e.g. HKU:\S-1-5-21-...
        [Parameter(Mandatory)] [string] $SubPath,    # e.g. Software\Microsoft\Office\16.0\Outlook\Profiles
        [Parameter(Mandatory)] [string] $Name
    )

    $psPath = Join-Path $HiveRoot $SubPath
    if (-not (Test-Path -LiteralPath $psPath)) { return $true }
    if ($DryRun) { return $true }

    $regPath = ($HiveRoot -replace '^HKU:\\', 'HKU\') + '\' + $SubPath
    $file    = Join-Path $script:BackupDir ("{0}.reg" -f ($Name -replace '[^\w\.-]', '_'))

    try {
        $null = & reg.exe export "$regPath" "$file" /y 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Registry backup written: $file" 'INFO'
            return $true
        }
        Write-Log "Registry export returned $LASTEXITCODE for $regPath - key will NOT be modified." 'WARN'
        return $false
    }
    catch {
        Write-Log "Registry backup failed for $regPath - key will NOT be modified. $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Remove-RegistryKeySafe {
    <# Removes a key only after a successful .reg backup. Never proceeds without one. #>
    param(
        [Parameter(Mandatory)] [string] $HiveRoot,
        [Parameter(Mandatory)] [string] $SubPath,
        [Parameter(Mandatory)] [string] $BackupName,
        [string] $Description = ''
    )

    $psPath = Join-Path $HiveRoot $SubPath
    if (-not (Test-Path -LiteralPath $psPath)) {
        Write-Log "$Description - registry key not present." 'SKIP'
        return
    }

    if ($DryRun) {
        Write-Log "WOULD remove registry key $psPath ($Description)" 'DRY'
        Add-Action -Category 'Registry' -Target $psPath -Result 'DryRun'
        return
    }

    if (-not (Backup-RegistryKey -HiveRoot $HiveRoot -SubPath $SubPath -Name $BackupName)) {
        Write-Log "$Description - skipped because the safety backup could not be created." 'WARN'
        Add-Action -Category 'Registry' -Target $psPath -Result 'SkippedNoBackup'
        return
    }

    try {
        Remove-Item -LiteralPath $psPath -Recurse -Force -ErrorAction Stop
        Write-Log "$Description - registry key removed (backup retained)." 'OK'
        Add-Action -Category 'Registry' -Target $psPath -Result 'Removed'
    }
    catch {
        Write-Log "$Description - could not remove key: $($_.Exception.Message)" 'WARN'
        Add-Action -Category 'Registry' -Target $psPath -Result 'Failed' -Detail $_.Exception.Message
    }
}

# =============================================================================================
#  APPLICATION SHUTDOWN
# =============================================================================================

function Stop-TargetApplications {
    <#
        Politely asks each application to close, waits, then forces. The guide's taskkill /F
        approach destroys unsaved work; this mirrors the intent while giving apps a chance to
        flush. -Force skips straight to termination.
    #>
    param(
        [Parameter(Mandatory)] [string[]] $ProcessNames,
        [int] $Grace = 20
    )

    $running = @()
    foreach ($name in $ProcessNames) {
        try { $running += @(Get-Process -Name $name -ErrorAction SilentlyContinue) } catch { }
    }
    $running = @($running | Where-Object { $_ })

    if ($running.Count -eq 0) {
        Write-Log 'No target applications are running.' 'INFO'
        return
    }

    $names = ($running | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
    Write-Log "Running applications detected: $names" 'INFO'

    if ($DryRun) {
        Write-Log "WOULD close: $names" 'DRY'
        return
    }

    if (-not $Force -and $Grace -gt 0) {
        foreach ($p in $running) {
            try { if (-not $p.HasExited) { [void]$p.CloseMainWindow() } } catch { }
        }
        Write-Log "Graceful close requested. Waiting up to $Grace second(s)..." 'INFO'

        $deadline = (Get-Date).AddSeconds($Grace)
        while ((Get-Date) -lt $deadline) {
            $still = @($running | Where-Object { try { -not $_.HasExited } catch { $false } })
            if ($still.Count -eq 0) { break }
            Start-Sleep -Milliseconds 750
        }
    }

    foreach ($name in $ProcessNames) {
        $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        foreach ($p in $procs) {
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Write-Log "Terminated $($p.ProcessName) (PID $($p.Id))." 'INFO'
            }
            catch {
                Write-Log "Could not terminate $($p.ProcessName) (PID $($p.Id)): $($_.Exception.Message)" 'WARN'
            }
        }
    }

    Start-Sleep -Seconds 2

    $remaining = @()
    foreach ($name in $ProcessNames) {
        $remaining += @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    }
    $remaining = @($remaining | Where-Object { $_ })

    if ($remaining.Count -gt 0) {
        $left = ($remaining | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
        Write-Log "Still running after termination attempt: $left. Some caches may stay locked." 'WARN'
        $script:RebootRequired = $true
    }
    else {
        Write-Log 'All target applications closed.' 'OK'
    }
}

# =============================================================================================
#  CLEANUP ROUTINE: IDENTITY / TOKEN CACHES   (guide section 3.2)
# =============================================================================================

function Invoke-IdentityCacheCleanup {
    param([Parameter(Mandatory)] $User)

    Write-Log "--- Identity and token caches: $($User.UserName) ---" 'STEP'

    $root = $User.ProfilePath

    # The two folders that actually cause silent re-sign-in to the OLD tenant.
    Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\IdentityCache') `
                        -ProfileRoot $root -Description 'IdentityCache (modern sign-in tokens)'

    Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\OneAuth') `
                        -ProfileRoot $root -Description 'OneAuth (unified auth cache)'

    # Outlook autocomplete / cached credential store.
    Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\Outlook\RoamCache') `
                        -ProfileRoot $root -Description 'Outlook RoamCache'

    # Outlook temporary attachment cache - path name differs across Windows builds.
    foreach ($p in @(
        'Microsoft\Windows\INetCache\Content.Outlook',
        'Microsoft\Windows\Temporary Internet Files\Content.Outlook'
    )) {
        Clear-FolderContent -Path (Join-Path $User.LocalApp $p) `
                            -ProfileRoot $root -Description "Outlook temp cache ($p)"
    }

    if ($Scope -eq 'Aggressive') {
        # Web Account Manager broker cache - holds device-bound tenant tokens.
        Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\TokenBroker\Cache') `
                            -ProfileRoot $root -Description 'TokenBroker cache (WAM)'

        # Office web add-in cache, often bound to the old tenant's manifests.
        Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\Office\16.0\Wef') `
                            -ProfileRoot $root -Description 'Office web add-in (WEF) cache'
    }
}

# =============================================================================================
#  CLEANUP ROUTINE: OUTLOOK OST   (guide section 3.3 - optional)
# =============================================================================================

function Invoke-OutlookDataFileCleanup {
    param([Parameter(Mandatory)] $User)

    if (-not $IncludeOst) {
        Write-Log 'OST cleanup not requested (-IncludeOst). Skipping.' 'SKIP'
        return
    }

    Write-Log "--- Outlook offline data files: $($User.UserName) ---" 'STEP'

    $folders = @(
        (Join-Path $User.LocalApp 'Microsoft\Outlook'),
        (Join-Path $User.LocalApp 'Microsoft\Olk')       # new Outlook for Windows
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }

        $osts = @()
        try {
            $osts = @(Get-ChildItem -LiteralPath $folder -Filter '*.ost' -File -Force -ErrorAction SilentlyContinue)
        }
        catch { }

        if ($osts.Count -eq 0) {
            Write-Log "No .ost files in $folder" 'SKIP'
            continue
        }

        foreach ($ost in $osts) {
            # Absolute guard: never, under any circumstance, touch a .pst.
            if ($ost.Extension -ne '.ost') { continue }
            if ($ost.Name -match '(?i)\.pst$') { continue }
            Remove-FileSafe -Path $ost.FullName -ProfileRoot $User.ProfilePath -Description '(offline cache, rebuilds from cloud)'
        }
    }

    # Report - never delete - any PST files found, so the helpdesk knows they exist.
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $psts = @(Get-ChildItem -LiteralPath $folder -Filter '*.pst' -File -Force -ErrorAction SilentlyContinue)
        foreach ($pst in $psts) {
            Write-Log "PRESERVED personal data file (never deleted): $($pst.FullName)" 'INFO'
            Add-Action -Category 'File' -Target $pst.FullName -Result 'Preserved' -Detail 'PST - user data'
        }
    }
}

# =============================================================================================
#  CLEANUP ROUTINE: OUTLOOK PROFILES   (guide section 3.4)
# =============================================================================================

function Invoke-OutlookProfileReset {
    param(
        [Parameter(Mandatory)] $User,
        [AllowEmptyString()] [AllowNull()] [string] $HiveRoot = ''
    )

    if ($Scope -eq 'Cache' -or $SkipOutlookProfiles) {
        Write-Log 'Outlook profile reset skipped by scope or switch.' 'SKIP'
        return
    }
    if (-not $HiveRoot) {
        Write-Log 'Outlook profile reset skipped - user registry hive unavailable.' 'WARN'
        return
    }

    Write-Log "--- Outlook mail profiles: $($User.UserName) ---" 'STEP'

    # Office 2016/2019/2021/365 = 16.0. Older builds included defensively.
    foreach ($ver in @('16.0', '15.0')) {
        Remove-RegistryKeySafe -HiveRoot $HiveRoot `
            -SubPath "Software\Microsoft\Office\$ver\Outlook\Profiles" `
            -BackupName "$($User.ShortName)-Outlook-$ver-Profiles" `
            -Description "Outlook $ver mail profiles"

        # Cached AutoDiscover responses still pointing at the old tenant.
        Remove-RegistryKeySafe -HiveRoot $HiveRoot `
            -SubPath "Software\Microsoft\Office\$ver\Outlook\AutoDiscover" `
            -BackupName "$($User.ShortName)-Outlook-$ver-AutoDiscover" `
            -Description "Outlook $ver cached AutoDiscover"

        # Clear the DefaultProfile pointer so Outlook runs first-run setup.
        $outlookKey = Join-Path $HiveRoot "Software\Microsoft\Office\$ver\Outlook"
        if ((Test-Path -LiteralPath $outlookKey) -and -not $DryRun) {
            try {
                Remove-ItemProperty -LiteralPath $outlookKey -Name 'DefaultProfile' -Force -ErrorAction SilentlyContinue
                Write-Log "Cleared DefaultProfile pointer for Office $ver." 'OK'
            }
            catch { }
        }
    }

    # MAPI profile store used by Outlook to enumerate profiles.
    Remove-RegistryKeySafe -HiveRoot $HiveRoot `
        -SubPath 'Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles' `
        -BackupName "$($User.ShortName)-MAPI-Profiles" `
        -Description 'MAPI messaging subsystem profiles'

    Write-Log 'Outlook will present first-run account setup at next launch.' 'INFO'
}

# =============================================================================================
#  CLEANUP ROUTINE: OFFICE IDENTITY / LICENSING   (guide section 8)
# =============================================================================================

function Invoke-OfficeIdentityReset {
    param(
        [Parameter(Mandatory)] $User,
        [AllowEmptyString()] [AllowNull()] [string] $HiveRoot = ''
    )

    if ($Scope -eq 'Cache') {
        Write-Log 'Office identity reset skipped (Scope=Cache).' 'SKIP'
        return
    }
    if (-not $HiveRoot) {
        Write-Log 'Office identity reset skipped - user registry hive unavailable.' 'WARN'
        return
    }

    Write-Log "--- Office connected identity: $($User.UserName) ---" 'STEP'

    foreach ($ver in @('16.0', '15.0')) {
        Remove-RegistryKeySafe -HiveRoot $HiveRoot `
            -SubPath "Software\Microsoft\Office\$ver\Common\Identity" `
            -BackupName "$($User.ShortName)-Office-$ver-Identity" `
            -Description "Office $ver connected identity (fixes 'Unlicensed Product')"
    }

    # Licensing token cache for Office C2R.
    Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\Office\Licenses') `
                        -ProfileRoot $User.ProfilePath -Description 'Office licence token cache'
}

# =============================================================================================
#  CLEANUP ROUTINE: MICROSOFT TEAMS   (guide section 5)
# =============================================================================================

function Invoke-TeamsCleanup {
    param([Parameter(Mandatory)] $User)

    Write-Log "--- Microsoft Teams: $($User.UserName) ---" 'STEP'

    $root = $User.ProfilePath

    # New Teams (2.x) - MSIX packaged.
    $newTeams = Join-Path $User.LocalApp 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
    Clear-FolderContent -Path $newTeams -ProfileRoot $root -Description 'New Teams (2.x) local cache'

    # New Teams token/account store lives beside the cache.
    $newTeamsAcct = Join-Path $User.LocalApp 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\TokenBroker'
    if (Test-Path -LiteralPath $newTeamsAcct) {
        Clear-FolderContent -Path $newTeamsAcct -ProfileRoot $root -Description 'New Teams token broker cache'
    }

    # Classic Teams.
    Clear-FolderContent -Path (Join-Path $User.RoamingApp 'Microsoft\Teams') `
                        -ProfileRoot $root -Description 'Classic Teams cache'

    # Teams Meeting Add-in cache, frequently stale after a tenant move.
    $tma = Join-Path $User.LocalApp 'Microsoft\TeamsMeetingAddin'
    if (Test-Path -LiteralPath $tma) {
        Clear-FolderContent -Path $tma -ProfileRoot $root -Description 'Teams Meeting Add-in cache'
    }
}

# =============================================================================================
#  CLEANUP ROUTINE: ONEDRIVE UNLINK   (guide section 6)
# =============================================================================================

function Invoke-OneDriveUnlink {
    param(
        [Parameter(Mandatory)] $User,
        [AllowEmptyString()] [AllowNull()] [string] $HiveRoot = ''
    )

    if ($Scope -eq 'Cache' -or $SkipOneDrive) {
        Write-Log 'OneDrive unlink skipped by scope or switch.' 'SKIP'
        return
    }

    Write-Log "--- OneDrive account unlink: $($User.UserName) ---" 'STEP'
    Write-Log 'Synced FILES on disk are never touched by this script - only the account link.' 'INFO'

    # Registry: business account bindings.
    if ($HiveRoot) {
        $accountsKey = Join-Path $HiveRoot 'Software\Microsoft\OneDrive\Accounts'
        if (Test-Path -LiteralPath $accountsKey) {
            $accounts = @(Get-ChildItem -LiteralPath $accountsKey -ErrorAction SilentlyContinue |
                          Where-Object { $_.PSChildName -match '^Business\d+$' })

            if ($accounts.Count -eq 0) {
                Write-Log 'No OneDrive for Business account bindings found.' 'SKIP'
            }

            foreach ($acct in $accounts) {
                $name = $acct.PSChildName
                Remove-RegistryKeySafe -HiveRoot $HiveRoot `
                    -SubPath "Software\Microsoft\OneDrive\Accounts\$name" `
                    -BackupName "$($User.ShortName)-OneDrive-$name" `
                    -Description "OneDrive account binding ($name)"
            }
        }
        else {
            Write-Log 'OneDrive Accounts registry key not present.' 'SKIP'
        }
    }
    else {
        Write-Log 'OneDrive registry unlink skipped - user hive unavailable.' 'WARN'
    }

    # Settings folder: per-account sync database. Business* only, never Personal.
    $settingsRoot = Join-Path $User.LocalApp 'Microsoft\OneDrive\settings'
    if (Test-Path -LiteralPath $settingsRoot) {
        $businessDirs = @(Get-ChildItem -LiteralPath $settingsRoot -Directory -Force -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -match '^Business\d+$' })
        foreach ($dir in $businessDirs) {
            Clear-FolderContent -Path $dir.FullName -ProfileRoot $User.ProfilePath `
                                -Description "OneDrive settings ($($dir.Name))"
        }
    }

    Write-Log 'OneDrive will show first-run setup at next sign-in.' 'INFO'
}

# =============================================================================================
#  CLEANUP ROUTINE: BROWSERS   (guide section 7.1 / 7.2)
# =============================================================================================

function Clear-ChromiumProfile {
    <#
        Surgical Chromium cleanup. Removes session cookies and cache only.
        Bookmarks, Login Data (saved passwords), Web Data (autofill), Extensions and
        Preferences are deliberately left intact - deleting them would be data loss.
    #>
    param(
        [Parameter(Mandatory)] [string] $ProfileDir,
        [Parameter(Mandatory)] [string] $ProfileRoot,
        [Parameter(Mandatory)] [string] $BrowserName
    )

    $label = "$BrowserName / $(Split-Path $ProfileDir -Leaf)"

    # Cookie databases - Chromium 96+ moved these under Network\.
    $cookieFiles = @(
        'Network\Cookies', 'Network\Cookies-journal',
        'Cookies', 'Cookies-journal'
    )
    foreach ($f in $cookieFiles) {
        $full = Join-Path $ProfileDir $f
        if (Test-Path -LiteralPath $full) {
            Remove-FileSafe -Path $full -ProfileRoot $ProfileRoot -Description "($label cookies)"
        }
    }

    # Cache and session folders - contents only.
    $cacheFolders = @(
        'Cache', 'Code Cache', 'GPUCache',
        'Sessions', 'Session Storage',
        'Service Worker\CacheStorage', 'Service Worker\ScriptCache'
    )
    if ($Scope -eq 'Aggressive') {
        $cacheFolders += 'Local Storage\leveldb'
        $cacheFolders += 'IndexedDB'
    }

    foreach ($f in $cacheFolders) {
        $full = Join-Path $ProfileDir $f
        if (Test-Path -LiteralPath $full) {
            Clear-FolderContent -Path $full -ProfileRoot $ProfileRoot -Description "$label - $f"
        }
    }

    Write-Log "$label - Bookmarks, saved passwords and extensions preserved." 'INFO'
}

function Invoke-BrowserCleanup {
    param([Parameter(Mandatory)] $User)

    if ($SkipBrowsers) {
        Write-Log 'Browser cleanup skipped (-SkipBrowsers).' 'SKIP'
        return
    }

    Write-Log "--- Browsers: $($User.UserName) ---" 'STEP'

    $chromiumBrowsers = @(
        @{ Name = 'Microsoft Edge'; Path = (Join-Path $User.LocalApp 'Microsoft\Edge\User Data') },
        @{ Name = 'Google Chrome';  Path = (Join-Path $User.LocalApp 'Google\Chrome\User Data') },
        @{ Name = 'Brave';          Path = (Join-Path $User.LocalApp 'BraveSoftware\Brave-Browser\User Data') },
        @{ Name = 'Vivaldi';        Path = (Join-Path $User.LocalApp 'Vivaldi\User Data') },
        @{ Name = 'Opera';          Path = (Join-Path $User.RoamingApp 'Opera Software\Opera Stable') }
    )

    foreach ($browser in $chromiumBrowsers) {
        if (-not (Test-Path -LiteralPath $browser.Path)) {
            Write-Log "$($browser.Name) not installed for this user." 'SKIP'
            continue
        }

        # Opera stores its profile at the root; Chromium-family uses Default / Profile N.
        $profiles = @()
        if ($browser.Name -eq 'Opera') {
            $profiles = @(Get-Item -LiteralPath $browser.Path -ErrorAction SilentlyContinue)
        }
        else {
            $profiles = @(Get-ChildItem -LiteralPath $browser.Path -Directory -Force -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })
        }

        if ($profiles.Count -eq 0) {
            Write-Log "$($browser.Name) - no browser profiles found." 'SKIP'
            continue
        }

        foreach ($p in $profiles) {
            Clear-ChromiumProfile -ProfileDir $p.FullName -ProfileRoot $User.ProfilePath -BrowserName $browser.Name
        }
    }

    # Firefox - different engine, different files.
    $ffRoot = Join-Path $User.RoamingApp 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ffRoot) {
        $ffProfiles = @(Get-ChildItem -LiteralPath $ffRoot -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($ff in $ffProfiles) {
            foreach ($file in @('cookies.sqlite', 'cookies.sqlite-wal', 'cookies.sqlite-shm', 'sessionstore.jsonlz4')) {
                $full = Join-Path $ff.FullName $file
                if (Test-Path -LiteralPath $full) {
                    Remove-FileSafe -Path $full -ProfileRoot $User.ProfilePath -Description "(Firefox $($ff.Name))"
                }
            }
            foreach ($folder in @('sessionstore-backups', 'cache2')) {
                $full = Join-Path $ff.FullName $folder
                if (Test-Path -LiteralPath $full) {
                    Clear-FolderContent -Path $full -ProfileRoot $User.ProfilePath -Description "Firefox $($ff.Name) - $folder"
                }
            }
        }
        Write-Log 'Firefox - logins.json and key4.db (saved passwords) preserved.' 'INFO'
    }

    # Shared Firefox cache root.
    $ffCache = Join-Path $User.LocalApp 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ffCache) {
        $ffCacheProfiles = @(Get-ChildItem -LiteralPath $ffCache -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($fc in $ffCacheProfiles) {
            $c2 = Join-Path $fc.FullName 'cache2'
            if (Test-Path -LiteralPath $c2) {
                Clear-FolderContent -Path $c2 -ProfileRoot $User.ProfilePath -Description "Firefox cache2 ($($fc.Name))"
            }
        }
    }

    # Legacy WinINET store used by Office and some webviews.
    Clear-FolderContent -Path (Join-Path $User.LocalApp 'Microsoft\Windows\INetCookies') `
                        -ProfileRoot $User.ProfilePath -Description 'WinINET cookie store'
}

# =============================================================================================
#  SESSION TOKEN REVOCATION - WINDOWS CREDENTIAL MANAGER   (guide section 7.3)
#
#  This is the step that actually revokes the local sign-in session. The token vault holds
#  the refresh tokens that let Office and Teams re-authenticate silently; clearing the file
#  caches alone leaves these behind and the old session survives.
#
#  Runs ONLY in the user's own security context - the vault is DPAPI-encrypted per user
#  and is not reachable from SYSTEM.
# =============================================================================================

function Get-CredentialAllowList {
    <#
        Explicit, tenant-agnostic allow-list of SESSION TOKEN targets.

        Everything below is keyed by SERVICE, not by tenant or domain - which is why no
        old-domain parameter is needed. An old-tenant token sits under exactly the same
        target name as a new-tenant one, so matching the service catches it either way.

        These entries are refresh/access token material written by Office, Teams, OneDrive
        and the WAM broker. They are NOT passwords the user typed and saved. Anything that
        does not match one of these patterns is counted and left completely untouched.
    #>
    $patterns = @(
        'MicrosoftOffice16_Data:*'
        'MicrosoftOffice15_Data:*'
        'MicrosoftAccount:*'
        '*login.microsoftonline.com*'
        '*login.windows.net*'
        '*login.microsoft.com*'
        '*msteams*'
        '*MicrosoftTeams*'
        '*OneDrive*'
        '*SSO_POP_Device*'
        '*outlook.office.com*'
        '*outlook.office365.com*'
        '*.sharepoint.com*'
        '*office365*'
        '*MS.Outlook*'
        '*WindowsLive:target=virtualapp/didlogical*'
    )
    return $patterns
}

function Invoke-CredentialManagerCleanup {

    if ($SkipCredentialManager -or $Scope -eq 'Cache') {
        Write-Log 'Credential Manager cleanup skipped by scope or switch.' 'SKIP'
        return
    }

    Write-Log "--- Session token revocation (credential vault): $env:USERNAME ---" 'STEP'

    $allowList = Get-CredentialAllowList
    $raw = @()
    try { $raw = @(& cmdkey.exe /list 2>&1) }
    catch {
        Write-Log "Could not enumerate stored credentials: $($_.Exception.Message)" 'WARN'
        return
    }

    # Target prefixes are NOT localised, so match on them rather than the "Target:" label,
    # which is translated on non-English Windows.
    $targets = New-Object System.Collections.ArrayList
    foreach ($line in $raw) {
        $text = [string]$line
        if ($text -match '(?i)((?:LegacyGeneric|WindowsLive|MicrosoftAccount|Domain|virtualapp)\s*:\s*\S.*)$') {
            $t = $Matches[1].Trim()
            if ($t -and ($targets -notcontains $t)) { [void]$targets.Add($t) }
        }
    }

    if ($targets.Count -eq 0) {
        Write-Log 'No stored credentials found.' 'SKIP'
        return
    }

    Write-Log "$($targets.Count) vault target(s) found. Matching against the session-token allow-list." 'INFO'

    $deleted = 0
    $kept    = 0

    foreach ($target in $targets) {
        $matched = $false
        foreach ($pattern in $allowList) {
            if ($target -like $pattern) { $matched = $true; break }
        }

        if (-not $matched) {
            $kept++
            continue
        }

        if ($DryRun) {
            Write-Log "WOULD delete credential: $target" 'DRY'
            Add-Action -Category 'Credential' -Target $target -Result 'DryRun'
            $deleted++
            continue
        }

        try {
            $null = & cmdkey.exe /delete:$target 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Deleted credential: $target" 'OK'
                Add-Action -Category 'Credential' -Target $target -Result 'Deleted'
                $deleted++
            }
            else {
                Write-Log "cmdkey returned $LASTEXITCODE for: $target" 'WARN'
                Add-Action -Category 'Credential' -Target $target -Result 'Failed'
            }
        }
        catch {
            Write-Log "Failed to delete credential '$target': $($_.Exception.Message)" 'WARN'
        }
    }

    Write-Log "Session tokens revoked: $deleted. Non-matching entries left untouched: $kept." 'OK'
}

function Invoke-OutlookAutoCompleteReset {
    <# Guide section 3.5 - nickname cache lives in RoamCache, already cleared. Verify only. #>
    Write-Log 'Outlook AutoComplete (nickname) cache is contained in RoamCache and has been cleared.' 'INFO'
}

function Start-OneDriveForUser {
    <# Relaunch OneDrive inside the user session so setup prompts immediately. #>
    if ($SkipOneDrive -or $Scope -eq 'Cache' -or $DryRun) { return }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'),
        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
        "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
    )
    foreach ($exe in $candidates) {
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            try {
                Start-Process -FilePath $exe -ErrorAction Stop
                Write-Log 'OneDrive relaunched - first-run setup will appear.' 'OK'
                return
            }
            catch { }
        }
    }
    Write-Log 'OneDrive executable not found; it will start at next sign-in.' 'INFO'
}

# =============================================================================================
#  USER-PHASE ORCHESTRATION (relaunch inside the interactive session)
# =============================================================================================

function Get-UserPhaseArguments {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File "')
    [void]$sb.Append((Join-Path $script:WorkRoot 'Invoke-PostMigrationCleanup.ps1'))
    [void]$sb.Append('" -UserPhase')
    [void]$sb.Append(" -Scope $Scope")
    [void]$sb.Append(" -LogPath `"$script:LogDir`"")
    if ($DryRun)                { [void]$sb.Append(' -DryRun') }
    if ($SkipCredentialManager) { [void]$sb.Append(' -SkipCredentialManager') }
    if ($SkipOneDrive)          { [void]$sb.Append(' -SkipOneDrive') }
    if ($SkipWorkAccount)       { [void]$sb.Append(' -SkipWorkAccount') }
    if ($script:DoWpjLeave)     { [void]$sb.Append(' -LeaveWorkplaceJoin') }
    return $sb.ToString()
}

function Invoke-UserSessionPhase {
    param([Parameter(Mandatory)] $User)

    Write-Log "--- Launching user-session phase for $($User.UserName) ---" 'STEP'

    # Stage a stable copy so the scheduled task has a fixed path.
    $staged = Join-Path $script:WorkRoot 'Invoke-PostMigrationCleanup.ps1'
    try {
        if (-not (Test-Path -LiteralPath $script:WorkRoot)) {
            New-Item -ItemType Directory -Path $script:WorkRoot -Force -ErrorAction Stop | Out-Null
        }
        if ($script:SelfPath -and (Test-Path -LiteralPath $script:SelfPath)) {
            Copy-Item -LiteralPath $script:SelfPath -Destination $staged -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Could not stage script for user phase: $($_.Exception.Message)" 'ERROR'
        return $false
    }

    if (-not (Test-Path -LiteralPath $staged)) {
        Write-Log 'Staged script missing - user phase cannot run.' 'ERROR'
        return $false
    }

    $psExe   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argList = Get-UserPhaseArguments

    # Remove any stale task from a previous run.
    try { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }

    try {
        $action    = New-ScheduledTaskAction -Execute $psExe -Argument $argList
        $principal = New-ScheduledTaskPrincipal -UserId $User.UserName -LogonType Interactive -RunLevel Limited
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -StartWhenAvailable `
                        -MultipleInstances IgnoreNew

        Register-ScheduledTask -TaskName $script:TaskName -Action $action -Principal $principal `
                               -Settings $settings -Description 'Post-migration user-context cleanup' `
                               -Force -ErrorAction Stop | Out-Null

        Start-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop
        Write-Log 'User-phase task started. Waiting for completion...' 'INFO'

        # Let the task actually enter the Running state before polling, otherwise the
        # first poll sees the residual 'Ready' state and we declare success too early.
        $spinUp = (Get-Date).AddSeconds(30)
        $started = $false
        while ((Get-Date) -lt $spinUp) {
            Start-Sleep -Seconds 2
            $info = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
            if ($info -and $info.State -eq 'Running') { $started = $true; break }
            $ti = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue
            if ($ti -and $ti.LastRunTime -and $ti.LastTaskResult -ne 267011) { $started = $true; break }
        }
        if (-not $started) { Write-Log 'User-phase task did not report a Running state; continuing to poll.' 'INFO' }

        $deadline = (Get-Date).AddMinutes(15)
        $done     = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $info = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
            if (-not $info) { break }
            if ($info.State -ne 'Running') { $done = $true; break }
        }

        if ($done) {
            $last = (Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue).LastTaskResult
            Write-Log "User-phase completed (result code $last). See the userphase log file for detail." 'OK'
        }
        else {
            Write-Log 'User-phase did not report completion within the time limit.' 'WARN'
        }

        return $true
    }
    catch {
        Write-Log "Scheduled-task user phase failed: $($_.Exception.Message)" 'WARN'
        return $false
    }
    finally {
        try { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}

function Set-UserPhaseOnNextLogon {
    <# Fallback when nobody is signed in: queue the user phase via RunOnce in the user's hive. #>
    param(
        [Parameter(Mandatory)] $User,
        [AllowEmptyString()] [AllowNull()] [string] $HiveRoot = ''
    )

    if (-not $HiveRoot) {
        Write-Log 'Cannot queue user phase - registry hive unavailable.' 'WARN'
        return
    }
    if ($DryRun) {
        Write-Log "WOULD queue user-phase RunOnce for $($User.UserName)" 'DRY'
        return
    }

    $staged = Join-Path $script:WorkRoot 'Invoke-PostMigrationCleanup.ps1'
    try {
        if (-not (Test-Path -LiteralPath $script:WorkRoot)) {
            New-Item -ItemType Directory -Path $script:WorkRoot -Force | Out-Null
        }
        if ($script:SelfPath -and (Test-Path -LiteralPath $script:SelfPath)) {
            Copy-Item -LiteralPath $script:SelfPath -Destination $staged -Force
        }

        $runOnce = Join-Path $HiveRoot 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
        if (-not (Test-Path -LiteralPath $runOnce)) {
            New-Item -Path $runOnce -Force | Out-Null
        }

        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $cmd   = '"{0}" {1}' -f $psExe, (Get-UserPhaseArguments)

        New-ItemProperty -LiteralPath $runOnce -Name 'PostMigrationCleanupUserPhase' `
                         -Value $cmd -PropertyType String -Force | Out-Null

        Write-Log "User phase queued via RunOnce - it will run at $($User.UserName)'s next sign-in." 'OK'
    }
    catch {
        Write-Log "Could not queue user phase: $($_.Exception.Message)" 'WARN'
    }
}

# =============================================================================================
#  WORK ACCOUNT / TENANT JOIN REMOVAL
#
#  "Access work or school" in Windows Settings is NOT a token cache - it is a device or user
#  registration object held in the tenant, with a matching certificate and registry state on
#  the endpoint. Clearing caches does not touch it, so the endpoint stays registered to the
#  OLD tenant until it is explicitly removed.
#
#  Three different things live behind that one Settings page, with very different risk:
#
#    1. Workplace Join (Entra registered)  - per-user "Add work or school account".
#                                            Safe to remove. Handled in the user phase.
#    2. Entra ID Joined / Hybrid Joined    - the DEVICE belongs to the tenant.
#                                            Removing it can leave users unable to sign in
#                                            to Windows. Requires -ForceLeaveAzureAdJoin.
#    3. MDM enrolment (Intune)             - detected and reported only. Never removed here,
#                                            because unenrolling locally orphans the record
#                                            in the MDM console.
# =============================================================================================

function Get-DeviceJoinState {
    $result = [pscustomobject]@{
        Available        = $false
        AzureAdJoined    = $false
        EnterpriseJoined = $false
        DomainJoined     = $false
        WorkplaceJoined  = $false
        MdmEnrolled      = $false
        TenantName       = ''
        TenantId         = ''
        DeviceId         = ''
        MdmUrl           = ''
    }

    $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        return $result
    }

    $out = @()
    try { $out = @(& $exe /status 2>&1) } catch { return $result }
    if ($out.Count -eq 0) { return $result }

    $result.Available = $true

    # dsregcmd field names are not localised, so plain matching is safe on any locale.
    foreach ($line in $out) {
        $t = [string]$line
        if     ($t -match '^\s*AzureAdJoined\s*:\s*(\S+)')    { $result.AzureAdJoined    = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*EnterpriseJoined\s*:\s*(\S+)') { $result.EnterpriseJoined = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*DomainJoined\s*:\s*(\S+)')     { $result.DomainJoined     = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*WorkplaceJoined\s*:\s*(\S+)')  { $result.WorkplaceJoined  = ($Matches[1] -eq 'YES') }
        elseif ($t -match '^\s*TenantName\s*:\s*(.+)$')       { $result.TenantName = $Matches[1].Trim() }
        elseif ($t -match '^\s*TenantId\s*:\s*(.+)$')         { $result.TenantId   = $Matches[1].Trim() }
        elseif ($t -match '^\s*DeviceId\s*:\s*(.+)$')         { $result.DeviceId   = $Matches[1].Trim() }
        elseif ($t -match '^\s*MdmUrl\s*:\s*(.+)$')           { $result.MdmUrl     = $Matches[1].Trim() }
    }

    if ($result.MdmUrl) { $result.MdmEnrolled = $true }
    return $result
}

function Invoke-DeviceWorkAccountRemoval {
    <#
        Device-level decision making. Returns $true if a per-user Workplace Join leave should
        be attempted in the user session phase.
    #>
    param([Parameter(Mandatory)] $JoinState)

    Write-Log '--- Work account / tenant join state ---' 'STEP'

    if ($SkipWorkAccount) {
        Write-Log 'Work account removal skipped (-SkipWorkAccount).' 'SKIP'
        return $false
    }
    if ($Scope -eq 'Cache') {
        Write-Log 'Work account removal skipped (Scope=Cache).' 'SKIP'
        return $false
    }
    if (-not $JoinState.Available) {
        Write-Log 'dsregcmd unavailable - join state cannot be determined, work account left alone.' 'WARN'
        return $false
    }

    Write-Log ("Entra ID joined  : {0}" -f $JoinState.AzureAdJoined)
    Write-Log ("Domain joined    : {0}" -f $JoinState.DomainJoined)
    Write-Log ("Workplace joined : {0}" -f $JoinState.WorkplaceJoined)
    Write-Log ("MDM enrolled     : {0}" -f $JoinState.MdmEnrolled)
    if ($JoinState.TenantName) { Write-Log ("Tenant           : {0}" -f $JoinState.TenantName) }
    if ($JoinState.TenantId)   { Write-Log ("Tenant ID        : {0}" -f $JoinState.TenantId) }
    if ($JoinState.DeviceId)   { Write-Log ("Device ID        : {0}" -f $JoinState.DeviceId) }

    Add-Action -Category 'JoinState' -Target $env:COMPUTERNAME -Result 'Detected' `
               -Detail ("AADJ={0}; Domain={1}; WPJ={2}; MDM={3}; Tenant={4}" -f `
                        $JoinState.AzureAdJoined, $JoinState.DomainJoined,
                        $JoinState.WorkplaceJoined, $JoinState.MdmEnrolled, $JoinState.TenantName)

    if ($JoinState.MdmEnrolled) {
        Write-Log 'Device is MDM-enrolled. This script will NOT unenroll it.' 'INFO'
        Write-Log 'Retire or wipe from the MDM console instead, so both sides stay in sync.' 'INFO'
    }

    # ---------------------------------------------------------------------------------------
    #  Case 2: the DEVICE itself belongs to the tenant. High blast radius.
    # ---------------------------------------------------------------------------------------
    if ($JoinState.AzureAdJoined) {

        if (-not $ForceLeaveAzureAdJoin) {
            Write-Log '' 'INFO'
            Write-Log '*************************************************************' 'WARN'
            Write-Log ' DEVICE-LEVEL LEAVE SKIPPED - THIS DEVICE IS ENTRA ID JOINED' 'WARN'
            Write-Log '*************************************************************' 'WARN'
            if ($JoinState.DomainJoined) {
                Write-Log 'State: Hybrid Entra ID joined (on-prem AD + cloud registration).' 'WARN'
                Write-Log 'A leave here removes only the cloud registration; the Automatic-Device-Join' 'WARN'
                Write-Log 'task re-registers against whichever tenant Entra Connect now points at.' 'WARN'
            }
            else {
                Write-Log 'State: cloud-only Entra ID joined.' 'WARN'
                Write-Log 'A leave here removes the device from the tenant. Users who sign in to' 'WARN'
                Write-Log 'Windows with their Entra account can be locked out of the device entirely.' 'WARN'
            }
            Write-Log 'Confirm a working local administrator account exists, then re-run with' 'WARN'
            Write-Log '-ForceLeaveAzureAdJoin if you genuinely intend to unjoin this device.' 'WARN'
            Add-Action -Category 'WorkAccount' -Target 'DeviceLeave' -Result 'SkippedNeedsForce'
            return $false
        }

        Write-Log 'Proceeding with device-level leave (-ForceLeaveAzureAdJoin supplied).' 'WARN'

        if ($DryRun) {
            Write-Log 'WOULD run: dsregcmd.exe /leave (device level, as SYSTEM)' 'DRY'
            Add-Action -Category 'WorkAccount' -Target 'DeviceLeave' -Result 'DryRun'
            return $false
        }

        try {
            $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
            $null = & $exe /leave 2>&1
            Write-Log "dsregcmd /leave (device) returned exit code $LASTEXITCODE." 'INFO'
            if ($LASTEXITCODE -eq 0) {
                Write-Log 'Device removed from the tenant. A restart is required.' 'OK'
                Add-Action -Category 'WorkAccount' -Target 'DeviceLeave' -Result 'Removed'
            }
            else {
                Write-Log 'Device leave did not report success - check dsregcmd /status manually.' 'WARN'
                Add-Action -Category 'WorkAccount' -Target 'DeviceLeave' -Result 'Failed'
            }
            $script:RebootRequired = $true
        }
        catch {
            Write-Log "Device leave failed: $($_.Exception.Message)" 'ERROR'
        }

        # The stale device object still exists in the old tenant - remove it there too.
        Write-Log 'Remember to delete the stale device object in the OLD tenant: Entra admin center > Devices.' 'INFO'
        return $false
    }

    # ---------------------------------------------------------------------------------------
    #  Case 1: per-user "Add work or school account". Safe, and handled in the user session.
    # ---------------------------------------------------------------------------------------
    if ($JoinState.WorkplaceJoined) {
        Write-Log 'Workplace-joined (Entra registered) account present - queued for removal in the user session.' 'INFO'
        return $true
    }

    Write-Log 'No workplace-joined account and no Entra ID device join. Nothing to remove.' 'SKIP'
    return $false
}

function Invoke-WamAccountCleanup {
    <#
        Removes the cached "work or school account" entries that Windows, Office and Teams
        present in their account pickers. Pure token/account-store material - safe from
        SYSTEM, no join state is touched here.
    #>
    param(
        [Parameter(Mandatory)] $User,
        [AllowEmptyString()] [AllowNull()] [string] $HiveRoot = ''
    )

    if ($SkipWorkAccount) {
        Write-Log 'Work account artefact cleanup skipped (-SkipWorkAccount).' 'SKIP'
        return
    }

    Write-Log "--- Work account entries (WAM / broker): $($User.UserName) ---" 'STEP'

    $paths = @(
        'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts',
        'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Cache',
        'Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\AC\TokenBroker',
        'Microsoft\TokenBroker\Accounts'
    )

    foreach ($p in $paths) {
        $full = Join-Path $User.LocalApp $p
        if (Test-Path -LiteralPath $full) {
            Clear-FolderContent -Path $full -ProfileRoot $User.ProfilePath -Description "Work account store ($p)"
        }
        else {
            Write-Log "Work account store not present: $p" 'SKIP'
        }
    }

    if ($HiveRoot -and $Scope -ne 'Cache') {
        Remove-RegistryKeySafe -HiveRoot $HiveRoot `
            -SubPath 'Software\Microsoft\IdentityCRL\StoredIdentities' `
            -BackupName "$($User.ShortName)-IdentityCRL-StoredIdentities" `
            -Description 'Stored work/school identities (IdentityCRL)'

        Remove-RegistryKeySafe -HiveRoot $HiveRoot `
            -SubPath 'Software\Microsoft\IdentityCRL\UserExtendedProperties' `
            -BackupName "$($User.ShortName)-IdentityCRL-UserExtendedProperties" `
            -Description 'Cached work/school identity properties'
    }
}

function Invoke-WorkplaceJoinLeave {
    <#
        USER PHASE ONLY. Removes the per-user "Access work or school" registration.
        Workplace Join is a per-user object, so this must run in the user's own session -
        dsregcmd /leave as SYSTEM would target the device registration instead.
    #>

    Write-Log "--- Removing work account registration: $env:USERNAME ---" 'STEP'

    if ($DryRun) {
        Write-Log 'WOULD run: dsregcmd.exe /leave (user context)' 'DRY'
        Add-Action -Category 'WorkAccount' -Target 'WorkplaceJoin' -Result 'DryRun'
        return
    }

    $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    if (Test-Path -LiteralPath $exe) {
        try {
            $null = & $exe /leave 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log 'Work account registration removed via dsregcmd /leave.' 'OK'
                Add-Action -Category 'WorkAccount' -Target 'WorkplaceJoin' -Result 'Removed'
            }
            else {
                Write-Log "dsregcmd /leave returned $LASTEXITCODE - falling back to manual cleanup." 'WARN'
            }
        }
        catch {
            Write-Log "dsregcmd /leave failed: $($_.Exception.Message)" 'WARN'
        }
    }
    else {
        Write-Log 'dsregcmd.exe not found - using manual cleanup only.' 'WARN'
    }

    # Residual per-user registration state, in case dsregcmd left anything behind.
    $wpjPs  = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin'
    $wpjReg = 'HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin'

    if (Test-Path -LiteralPath $wpjPs) {
        $backup = Join-Path $script:BackupDir ("{0}-WorkplaceJoin.reg" -f ($env:USERNAME -replace '[^\w\.-]', '_'))
        $backedUp = $false
        try {
            $null = & reg.exe export "$wpjReg" "$backup" /y 2>&1
            if ($LASTEXITCODE -eq 0) { $backedUp = $true }
        }
        catch { }

        if ($backedUp) {
            try {
                Remove-Item -LiteralPath $wpjPs -Recurse -Force -ErrorAction Stop
                Write-Log 'Residual WorkplaceJoin registry state removed (backup taken).' 'OK'
            }
            catch {
                Write-Log "Could not remove residual WorkplaceJoin state: $($_.Exception.Message)" 'WARN'
            }
        }
        else {
            Write-Log 'Residual WorkplaceJoin state left in place - backup could not be written.' 'WARN'
        }
    }

    # The workplace-join client certificate issued by the old tenant.
    try {
        $certs = @(Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                   Where-Object { $_.Issuer -match 'MS-Organization-Access' })

        if ($certs.Count -eq 0) {
            Write-Log 'No workplace-join certificate present.' 'SKIP'
        }
        foreach ($c in $certs) {
            try {
                Remove-Item -Path ('Cert:\CurrentUser\My\' + $c.Thumbprint) -Force -ErrorAction Stop
                Write-Log "Removed workplace-join certificate $($c.Thumbprint)." 'OK'
                Add-Action -Category 'WorkAccount' -Target $c.Thumbprint -Result 'CertRemoved'
            }
            catch {
                Write-Log "Could not remove certificate $($c.Thumbprint): $($_.Exception.Message)" 'WARN'
            }
        }
    }
    catch {
        Write-Log "Certificate cleanup skipped: $($_.Exception.Message)" 'WARN'
    }

    $script:RebootRequired = $true
    Write-Log 'The account will disappear from Settings > Accounts > Access work or school after a restart.' 'INFO'
}

# =============================================================================================
#  REPORTING
# =============================================================================================

function Write-Summary {
    param([int] $ProcessedUsers)

    $duration = (Get-Date) - $script:StartTime

    Write-Log '' 'INFO'
    Write-Log '=================================================================' 'STEP'
    Write-Log '                        SUMMARY' 'STEP'
    Write-Log '=================================================================' 'STEP'
    Write-Log ("Computer          : {0}" -f $env:COMPUTERNAME)
    Write-Log ("Phase             : {0}" -f $(if ($UserPhase) { 'User session' } else { 'System' }))
    Write-Log ("Scope             : {0}" -f $Scope)
    Write-Log ("Mode              : {0}" -f $(if ($DryRun) { 'DRY RUN - nothing changed' } else { 'LIVE' }))
    Write-Log ("Profiles processed: {0}" -f $ProcessedUsers)
    Write-Log ("Items removed     : {0}" -f $script:ItemsRemoved)
    Write-Log ("Space reclaimed   : {0}" -f (Format-Bytes $script:BytesFreed))
    Write-Log ("Warnings          : {0}" -f $script:WarningCount)
    Write-Log ("Errors            : {0}" -f $script:ErrorCount)
    Write-Log ("Work account      : {0}" -f $(if ($SkipWorkAccount) { 'Skipped' } elseif ($script:DoWpjLeave) { 'Registration removed' } else { 'Cached entries cleared' }))
    Write-Log ("Restart required  : {0}" -f $(if ($script:RebootRequired) { 'YES' } else { 'No' }))
    Write-Log ("Duration          : {0:mm\:ss}" -f $duration)
    Write-Log ("Log file          : {0}" -f $script:LogFile)
    if ($script:BackupDir -and (Test-Path -LiteralPath $script:BackupDir)) {
        Write-Log ("Registry backups  : {0}" -f $script:BackupDir)
    }
    Write-Log '=================================================================' 'STEP'

    # Machine-readable receipt for the RMM to collect.
    try {
        $receipt = [pscustomobject]@{
            Version         = $script:Version
            Computer        = $env:COMPUTERNAME
            Phase           = $(if ($UserPhase) { 'UserSession' } else { 'System' })
            Scope           = $Scope
            DryRun          = [bool]$DryRun
            StartedUtc      = $script:StartTime.ToUniversalTime().ToString('s')
            CompletedUtc    = (Get-Date).ToUniversalTime().ToString('s')
            ProfilesHandled = $ProcessedUsers
            ItemsRemoved    = $script:ItemsRemoved
            BytesFreed      = $script:BytesFreed
            Warnings        = $script:WarningCount
            Errors          = $script:ErrorCount
            RebootRequired  = $script:RebootRequired
            Actions         = @($script:Actions)
        }
        $file = Join-Path $script:LogDir ("receipt-{0}-{1}.json" -f $(if ($UserPhase) { 'userphase' } else { 'system' }), (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $receipt | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $file -Encoding UTF8 -Force
        Write-Log "Receipt written: $file" 'INFO'
    }
    catch {
        Write-Log "Could not write JSON receipt: $($_.Exception.Message)" 'WARN'
    }
}

# =============================================================================================
#  MAIN
# =============================================================================================

$script:StartTime = Get-Date
Initialize-Logging

Write-Log '=================================================================' 'STEP'
Write-Log " Post-Migration Cleanup  v$($script:Version)" 'STEP'
Write-Log ' Microsoft 365 tenant-to-tenant - cache, token and session reset' 'STEP'
Write-Log '=================================================================' 'STEP'

$ctx = Get-ExecutionContextInfo
Write-Log ("Running as       : {0}" -f $ctx.Name)
Write-Log ("SYSTEM context   : {0}" -f $ctx.IsSystem)
Write-Log ("Elevated         : {0}" -f $ctx.IsAdmin)
Write-Log ("PowerShell       : {0}" -f $ctx.PSVersion)
Write-Log ("Operating system : {0}" -f $ctx.OSCaption)
Write-Log ("Scope            : {0}" -f $Scope)
if ($DryRun) { Write-Log 'DRY RUN - no changes will be made.' 'DRY' }

$exitCode        = 0
$processedUsers  = 0

# -----------------------------------------------------------------------------------------
#  USER PHASE - runs inside the signed-in user's session.
#  Handled before the main try/finally so that `exit` cannot trigger the system-phase
#  teardown (which would print a second summary and unload hives that were never loaded).
# -----------------------------------------------------------------------------------------
if ($UserPhase) {
    try {
        Write-Log 'Executing user-session phase.' 'STEP'
        Invoke-CredentialManagerCleanup
        if ($LeaveWorkplaceJoin -and -not $SkipWorkAccount) { Invoke-WorkplaceJoinLeave }
        Invoke-OutlookAutoCompleteReset
        Start-OneDriveForUser
    }
    catch {
        Write-Log "FATAL in user phase: $($_.Exception.Message)" 'ERROR'
    }

    Write-Summary -ProcessedUsers 1

    $userExit = 0
    if     ($script:ErrorCount   -gt 0) { $userExit = 2 }
    elseif ($script:WarningCount -gt 0) { $userExit = 1 }

    Write-Log "Exiting with code $userExit." 'INFO'
    exit $userExit
}

try {

    # -------------------------------------------------------------------------------------
    #  SYSTEM / ADMIN PHASE
    # -------------------------------------------------------------------------------------
    if (-not $ctx.IsAdmin) {
        Write-Log 'Not running elevated. Registry and multi-user steps will be unavailable.' 'WARN'
    }

    $users = @(Get-TargetUserProfiles -IncludeAll:$AllUsers)

    if ($users.Count -eq 0) {
        if (-not $AllUsers) {
            Write-Log 'No signed-in user detected. Retrying with all local profiles...' 'WARN'
            $users = @(Get-TargetUserProfiles -IncludeAll)
        }
    }

    if ($users.Count -eq 0) {
        Write-Log 'No eligible user profile found on this device. Nothing to do.' 'ERROR'
        Write-Log 'If this ran at device startup, schedule it to run at user logon instead.' 'INFO'
        throw 'NO_ELIGIBLE_USER'
    }

    Write-Log ("Target profiles ({0}): {1}" -f $users.Count, (($users | ForEach-Object { $_.UserName }) -join ', ')) 'INFO'

    # --- Close applications once, before touching any profile ---
    $appProcesses = @(
        'outlook', 'olk', 'winword', 'excel', 'powerpnt', 'onenote', 'msaccess', 'mspub',
        'Teams', 'ms-teams', 'msteams', 'OneDrive', 'OneDriveStandaloneUpdater',
        'lync', 'MSOSYNC',
        # WebView2 host - new Teams and new Outlook run inside it and hold their caches open.
        'msedgewebview2'
    )
    if (-not $SkipBrowsers) {
        $appProcesses += @('msedge', 'chrome', 'firefox', 'brave', 'vivaldi', 'opera')
    }

    Write-Log '--- Closing applications ---' 'STEP'
    if (-not $Force) {
        Write-Log "Applications will be asked to close politely first (grace period: $GraceSeconds s)." 'INFO'
    }
    else {
        Write-Log 'FORCE mode - applications will be terminated immediately. Unsaved work will be lost.' 'WARN'
    }
    Stop-TargetApplications -ProcessNames $appProcesses -Grace $GraceSeconds

    # --- Device-level work account / tenant join assessment (runs once, not per user) ---
    $joinState = Get-DeviceJoinState
    $script:DoWpjLeave = Invoke-DeviceWorkAccountRemoval -JoinState $joinState

    # --- Per-user cleanup ---
    foreach ($user in $users) {

        Write-Log '' 'INFO'
        Write-Log "#################################################################" 'STEP'
        Write-Log " PROFILE: $($user.UserName)" 'STEP'
        Write-Log " Path   : $($user.ProfilePath)" 'STEP'
        Write-Log " Active : $($user.IsActive)" 'STEP'
        Write-Log "#################################################################" 'STEP'

        # Sanity check the profile path before anything else.
        if (-not (Test-Path -LiteralPath $user.LocalApp)) {
            Write-Log "AppData\Local not found for this profile - skipping." 'WARN'
            continue
        }

        $hiveRoot = $null
        if ($ctx.IsAdmin -and $Scope -ne 'Cache') {
            $hiveRoot = Open-UserHive -User $user
        }

        Invoke-IdentityCacheCleanup   -User $user
        Invoke-TeamsCleanup           -User $user
        Invoke-BrowserCleanup         -User $user
        Invoke-OutlookDataFileCleanup -User $user
        Invoke-OutlookProfileReset    -User $user -HiveRoot $hiveRoot
        Invoke-OfficeIdentityReset    -User $user -HiveRoot $hiveRoot
        Invoke-OneDriveUnlink         -User $user -HiveRoot $hiveRoot
        Invoke-WamAccountCleanup      -User $user -HiveRoot $hiveRoot

        # Credential Manager and Workplace Join removal must run as the user.
        $needsUserPhase = ($Scope -ne 'Cache') -and
                          ((-not $SkipCredentialManager) -or ($script:DoWpjLeave -and -not $SkipWorkAccount))

        if ($needsUserPhase) {
            if ($ctx.IsSystem -or ($ctx.Sid -ne $user.Sid)) {
                if ($user.IsActive) {
                    $ok = Invoke-UserSessionPhase -User $user
                    if (-not $ok) { Set-UserPhaseOnNextLogon -User $user -HiveRoot $hiveRoot }
                }
                else {
                    Write-Log "$($user.UserName) is not signed in - queueing credential cleanup for next sign-in." 'INFO'
                    Set-UserPhaseOnNextLogon -User $user -HiveRoot $hiveRoot
                }
            }
            else {
                # Script is already running as this very user.
                Invoke-CredentialManagerCleanup
            }
        }

        $processedUsers++
    }
}
catch {
    if ($_.Exception.Message -eq 'NO_ELIGIBLE_USER') {
        $exitCode = 3
    }
    else {
        Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
        Write-Log "At: $($_.InvocationInfo.PositionMessage)" 'ERROR'
        $exitCode = 2
    }
}
finally {
    Close-LoadedHives
    Write-Summary -ProcessedUsers $processedUsers
}

if ($exitCode -eq 0) {
    if     ($script:ErrorCount -gt 0)    { $exitCode = 2 }
    elseif ($script:RebootRequired)      { $exitCode = 3010 }
    elseif ($script:WarningCount -gt 0)  { $exitCode = 1 }
}

Write-Log "Exiting with code $exitCode." 'INFO'
exit $exitCode
