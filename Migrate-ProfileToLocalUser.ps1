<#
.SYNOPSIS
    Re-links an existing (e.g. orphaned Entra/AzureAD) Windows profile to a NEW local
    user account, in place - no file copying. Scriptable ProfWiz-style migration.

.DESCRIPTION
    DRY-RUN BY DEFAULT. Nothing changes without -Execute.

    What it does (the same mechanics ForensiT User Profile Wizard performs):
      1. Finds the source profile's SID from HKLM ProfileList by its folder path
      2. Verifies the profile is NOT in use (hive not loaded) - aborts otherwise
      3. Creates the new local user (or reuses it, but only if it has never logged on)
      4. Backs up the ProfileList keys to .reg files
      5. Creates a ProfileList entry for the new user's SID pointing at the OLD folder,
         and removes the old SID's entry
      6. Grants the new user Full Control on the profile folder (ACL add, not replace)
      7. Loads NTUSER.DAT and UsrClass.dat and grants the new user Full Control with
         inheritance on the hive roots
      8. Logs every action to a transcript + summary

    NOT Microsoft-supported. Pilot on ONE machine (David's) before fleet use.
    Known limitation (same as ProfWiz): DPAPI secrets (saved browser passwords,
    Credential Manager, EFS) do not survive a SID change.

.EXAMPLE
    # Dry run (elevated, from TempAdmin, target user David not yet created)
    .\Migrate-ProfileToLocalUser.ps1 -SourceProfilePath 'C:\Users\david.amsellem' -NewUsername 'David'

    # Real run (elevated) - -MakeAdmin so David-local can later run dsregcmd /leave
    # and delete TempAdmin himself
    .\Migrate-ProfileToLocalUser.ps1 -SourceProfilePath 'C:\Users\david.amsellem' -NewUsername 'David' -NewPassword 'TempP@ss123!' -MakeAdmin -Execute
    # Then: reboot -> log in as David (local) -> verify files/apps -> register new-tenant
    # account in Settings. dsregcmd /leave is DEFERRED until verification passes -
    # while the device hasn't left the tenant, the .reg backup gives full rollback.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SourceProfilePath,   # e.g. C:\Users\david.amsellem
    [Parameter(Mandatory)] [string]$NewUsername,          # e.g. X
    [string]$NewPassword,                                 # required with -Execute if user doesn't exist
    [switch]$MakeAdmin,                                   # add new user to Administrators
    [switch]$Execute                                      # without this: report only
)

$ErrorActionPreference = 'Stop'
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir  = 'C:\ProgramData\PMC\ProfileMigration'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript -Path "$logDir\migrate-$stamp.log" | Out-Null

function Fail($msg) { Write-Host "ABORT: $msg" -ForegroundColor Red; Stop-Transcript | Out-Null; exit 1 }

# --- 0. Preconditions -------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Run elevated (as TempAdmin), not as the profile owner.'
}
$SourceProfilePath = $SourceProfilePath.TrimEnd('\')
if (-not (Test-Path $SourceProfilePath)) { Fail "Profile folder not found: $SourceProfilePath" }

# --- 1. Find source SID in ProfileList --------------------------------------
$plRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$srcEntry = Get-ChildItem $plRoot | Where-Object {
    (Get-ItemProperty $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath -ieq $SourceProfilePath
}
if (-not $srcEntry)      { Fail "No ProfileList entry points at $SourceProfilePath" }
if (@($srcEntry).Count -gt 1) { Fail "Multiple ProfileList entries point at that folder - resolve manually." }
$srcSid = Split-Path $srcEntry.Name -Leaf
Write-Host "Source profile : $SourceProfilePath"
Write-Host "Source SID     : $srcSid $(if ($srcSid -like 'S-1-12-1-*') { '(Entra ID account)' })"

# --- 2. Profile must not be in use ------------------------------------------
if ((Test-Path "Registry::HKEY_USERS\$srcSid") -or (Test-Path "Registry::HKEY_USERS\${srcSid}_Classes")) {
    Fail 'Source profile hive is loaded - that user is logged on (or a service holds the hive). Log them off / reboot first.'
}

# --- 3. New local user -------------------------------------------------------
$existing = Get-LocalUser -Name $NewUsername -ErrorAction SilentlyContinue
if ($existing) {
    $newSid = $existing.SID.Value
    if (Get-ChildItem $plRoot | Where-Object { (Split-Path $_.Name -Leaf) -eq $newSid }) {
        Fail "$NewUsername already has a profile. Target account must never have logged on."
    }
    Write-Host "Target user    : $NewUsername (exists, never logged on) SID $newSid"
} else {
    Write-Host "Target user    : $NewUsername (will be created)"
    if ($Execute) {
        if (-not $NewPassword) { Fail '-NewPassword required to create the user with -Execute.' }
        $sec = ConvertTo-SecureString $NewPassword -AsPlainText -Force
        try {
            New-LocalUser -Name $NewUsername -Password $sec -PasswordNeverExpires:$false | Out-Null
        } catch {
            Fail "Could not create '$NewUsername' - likely local password policy (length/complexity). Error: $($_.Exception.Message)"
        }
        Add-LocalGroupMember -Group 'Users' -Member $NewUsername
        if ($MakeAdmin) { Add-LocalGroupMember -Group 'Administrators' -Member $NewUsername }
        $newSid = (Get-LocalUser -Name $NewUsername).SID.Value
        Write-Host "Created. SID   : $newSid"
    }
}

if (-not $Execute) {
    Write-Host "`nDRY RUN complete - no changes made. Planned actions:" -ForegroundColor Green
    Write-Host "  1. Create local user '$NewUsername'$(if ($MakeAdmin) {' (admin)'})"
    Write-Host "  2. Backup ProfileList keys to $logDir"
    Write-Host "  3. ProfileList: map new SID -> $SourceProfilePath ; remove entry for $srcSid"
    Write-Host "  4. icacls grant Full Control on folder to $NewUsername (recursive, additive)"
    Write-Host "  5. Grant Full Control on NTUSER.DAT + UsrClass.dat hives"
    Write-Host "Re-run with -Execute to apply."
    Stop-Transcript | Out-Null; exit 0
}

# --- 4. Backups ---------------------------------------------------------------
$plWin = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
& reg export "$plWin\$srcSid" "$logDir\ProfileList-$srcSid-$stamp.reg" /y | Out-Null
Write-Host "Backed up old ProfileList key -> $logDir"

# --- 5. Re-link ProfileList ---------------------------------------------------
$old = Get-ItemProperty $srcEntry.PSPath
New-Item -Path "$plRoot\$newSid" -Force | Out-Null
Set-ItemProperty "$plRoot\$newSid" -Name ProfileImagePath -Value $SourceProfilePath -Type ExpandString
Set-ItemProperty "$plRoot\$newSid" -Name Flags -Value 0 -Type DWord
Set-ItemProperty "$plRoot\$newSid" -Name State -Value 0 -Type DWord
Remove-Item $srcEntry.PSPath -Recurse -Force
Write-Host "ProfileList: $newSid -> $SourceProfilePath ; removed $srcSid"

# --- 6. Folder ACL ------------------------------------------------------------
Write-Host 'Granting folder permissions (this takes a few minutes)...'
& icacls $SourceProfilePath /grant "*${newSid}:(OI)(CI)F" /T /C /Q
& icacls $SourceProfilePath /setowner "*$newSid" /T /C /Q

# --- 7. Registry hive ACLs ----------------------------------------------------
function Grant-HiveAccess([string]$datPath, [string]$mount) {
    if (-not (Test-Path $datPath)) { Write-Host "  (skip, not found: $datPath)"; return }
    & reg load "HKU\$mount" $datPath | Out-Null
    try {
        $acl  = Get-Acl "Registry::HKEY_USERS\$mount"
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($newSid)),
            'FullControl', 'ContainerInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl "Registry::HKEY_USERS\$mount" $acl
        Write-Host "  Granted FullControl on $datPath"
    } finally {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg unload "HKU\$mount" | Out-Null
    }
}
Write-Host 'Granting registry hive permissions...'
Grant-HiveAccess "$SourceProfilePath\NTUSER.DAT" "PMC_NTUSER"
Grant-HiveAccess "$SourceProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat" "PMC_USRCLASS"

# --- 8. Summary ---------------------------------------------------------------
Write-Host "`n================ DONE ================" -ForegroundColor Green
Write-Host "Profile $SourceProfilePath is now assigned to $env:COMPUTERNAME\$NewUsername"
Write-Host 'Next: REBOOT, log in as the new user, verify desktop/files/Outlook.'
Write-Host 'IMPORTANT: do NOT log in with the old Entra account again - its profile mapping'
Write-Host '           is gone; such a login would create a fresh empty profile folder.'
Write-Host "Rollback: restore $logDir\ProfileList-$srcSid-$stamp.reg and delete the new SID key"
Write-Host '          (rollback to the old account login only works while the device has NOT left the tenant).'
Write-Host 'Known loss (same as ProfWiz): saved browser passwords / Credential Manager / EFS (DPAPI).'
Stop-Transcript | Out-Null
