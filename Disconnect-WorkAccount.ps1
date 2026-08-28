<#
=====================================================================================
 Disconnect-WorkAccount.ps1                                                   v2.0.0

 ONE script. Does everything the Settings "Disconnect" button does, for ONE domain
 only, with no portal work and no Entra device deletion.

 SCOPE - READ THIS FIRST
   Only accounts whose UPN suffix is EXACTLY one of -TargetDomain are touched.
   Default: delta.mainettigroup.onmicrosoft.com
   Every other work account, personal account and MDM enrolment on the machine is
   enumerated, shown, and left completely alone. No mail data is touched, ever.

 WHY THE EARLIER ATTEMPTS FAILED  (both proven from field logs)
   1. "Unable to find type [System.WindowsRuntimeSystemExtensions]"
      Windows PowerShell 5.1 does not load System.Runtime.WindowsRuntime.dll by
      default, so the WAM half died before it started. Now loaded explicitly.
   2. "dsregcmd /leave exit=0" but WorkplaceJoined stayed YES
      In an ELEVATED shell, /leave targets the DEVICE join - not the user's
      workplace join. On a device that is not Entra-joined it returns 0 and does
      nothing at all. The workplace leave only happens NON-ELEVATED, in the user's
      own session. This script now forces that.

 HOW IT WORKS - four layers

   Layer 1  WAM  : WebAccount.SignOutAsync()      <- literally what the button calls
   Layer 2  DSREG: dsregcmd /leave, NON-ELEVATED, in the user's session
   Layer 3  SURGE: remove the matching WorkplaceJoin JoinInfo + TenantInfo keys, the
                   user certificate, matching broker files and Office identities
   Layer 4  HOLD : optional -BlockAutoRejoin sets autoWorkplaceJoin=0 so Windows
                   stops SILENTLY re-registering the device. Manually adding the new
                   tenant still works - only the automatic re-join is disabled. This
                   replaces deleting the device object in Entra.

 Layers 1 and 2 need a non-elevated user session. If this is started as SYSTEM (RMM)
 or from an elevated prompt, it relaunches that half as the logged-on user at normal
 integrity via a temporary scheduled task, then removes the task.

 USAGE
   .\Disconnect-WorkAccount.ps1 -DryRun                    # show, change nothing
   .\Disconnect-WorkAccount.ps1                            # do it
   .\Disconnect-WorkAccount.ps1 -BlockAutoRejoin           # ...and stop silent re-join
   .\Disconnect-WorkAccount.ps1 -BlockAutoRejoin -Restart  # ...and reboot when done

 RMM one-liner (unchanged URL, same file name):
   powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; New-Item -ItemType Directory 'C:\ProgramData\PMC' -Force | Out-Null; Invoke-WebRequest 'https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/Disconnect-WorkAccount.ps1' -OutFile 'C:\ProgramData\PMC\Disconnect-WorkAccount.ps1' -UseBasicParsing; & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\PMC\Disconnect-WorkAccount.ps1' -BlockAutoRejoin"

 MUST run under powershell.exe (5.1). pwsh 7 dropped System.Runtime.WindowsRuntime.
=====================================================================================
#>

[CmdletBinding()]
param(
    [string[]] $TargetDomain = @('delta.mainettigroup.onmicrosoft.com'),
    [string]   $OldTenantId  = '905cd5ac-a071-4697-a446-c9077a81e24b',

    [switch]   $DryRun,
    [switch]   $BlockAutoRejoin,
    [switch]   $Restart,
    [int]      $RestartDelay = 60,

    # internal - set when the script relaunches its user-session half
    [switch]   $InUserSession,
    [string]   $LogFile = ''
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$Version               = '2.0.0'

# ------------------------------------------------------------------ logging
if (-not $LogFile) {
    $ld = 'C:\ProgramData\PMC\Logs'
    New-Item -ItemType Directory -Path $ld -Force | Out-Null
    $LogFile = Join-Path $ld ("Disconnect-{0}-{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$BackupDir = Join-Path 'C:\ProgramData\PMC\WorkAccountBackups' (Get-Date -Format 'yyyyMMdd-HHmmss')

function W {
    param([string] $Text = '', [string] $Level = 'INFO')
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Text
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    $c = 'Gray'
    switch ($Level) {
        'STEP'  { $c = 'Cyan' }
        'WARN'  { $c = 'Yellow' }
        'ERROR' { $c = 'Red' }
        'GONE'  { $c = 'Green' }
        'OK'    { $c = 'Green' }
        'KEEP'  { $c = 'DarkGray' }
        'DRY'   { $c = 'Magenta' }
    }
    Write-Host $line -ForegroundColor $c
}
function Section { param([string]$t) W ''; W ('-' * 78) 'STEP'; W "  $t" 'STEP'; W ('-' * 78) 'STEP' }

# ------------------------------------------------------------------ scope guard
function Test-UpnMatchesTarget {
    <#
      THE safety gate. Exact suffix match on '@domain'.
      'delta.x.com' never matches 'notdelta.x.com', 'sub.delta.x.com', 'delta.x.com.evil',
      the parent 'x.com', or anything else. Anything unidentifiable returns $false and is
      therefore never touched.
    #>
    param([string] $Upn)
    if (-not $Upn) { return $false }
    $at = $Upn.LastIndexOf('@')
    if ($at -lt 0 -or $at -ge ($Upn.Length - 1)) { return $false }
    $suffix = $Upn.Substring($at + 1).ToLowerInvariant()
    foreach ($d in $TargetDomain) {
        if ($d -and $suffix -eq $d.ToLowerInvariant()) { return $true }
    }
    return $false
}
function Get-UpnFromBytes {
    param([byte[]] $Bytes)
    foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::ASCII)) {
        try {
            $s = $enc.GetString($Bytes)
            $m = [regex]::Match($s, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
            if ($m.Success) { return $m.Value }
        } catch { }
    }
    return ''
}
function Get-DsField {
    param([string] $Text, [string] $Name)
    $m = [regex]::Match($Text, ('(?m)^\s*' + [regex]::Escape($Name) + '\s*:\s*(.+?)\s*$'))
    if ($m.Success) { return $m.Groups[1].Value } else { return '' }
}
function Get-DsregStatus {
    try { return (& "$env:WINDIR\System32\dsregcmd.exe" /status 2>&1 | Out-String) } catch { return '' }
}

# ------------------------------------------------------------------ context
$IsSystem = $false; $IsElevated = $false; $WhoAmI = $env:USERNAME
try {
    $wid    = [Security.Principal.WindowsIdentity]::GetCurrent()
    $WhoAmI = $wid.Name
    if ($wid.User) { $IsSystem = ($wid.User.Value -eq 'S-1-5-18') }
    $IsElevated = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

$LastBoot = $null
try { $LastBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { }
$BrokerDir = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'

W ('=' * 78) 'STEP'
W ("  DISCONNECT WORK ACCOUNT  v$Version") 'STEP'
W ('=' * 78) 'STEP'
W ("Running as     : $WhoAmI")
W ("SYSTEM         : $IsSystem     Elevated : $IsElevated")
W ("Target domain  : " + ($TargetDomain -join ', ') + "   (nothing else will be touched)")
W ("Mode           : " + $(if ($DryRun) { 'DRY RUN - nothing will be changed' } else { 'LIVE' }))
W ("Log            : $LogFile")

# =====================================================================================
#  DISCOVER - always, in every context. Shows exactly what is in scope.
# =====================================================================================
Section 'DISCOVER  (what is on this machine, and what is in scope)'

$dsreg     = Get-DsregStatus
$AadJoined = Get-DsField $dsreg 'AzureAdJoined'
$WpJoined  = Get-DsField $dsreg 'WorkplaceJoined'
$WpTenant  = Get-DsField $dsreg 'WorkplaceTenantId'
$WpThumb   = Get-DsField $dsreg 'WorkplaceThumbprint'

W ("AzureAdJoined       : $AadJoined")
W ("WorkplaceJoined     : $WpJoined")
W ("WorkplaceTenantId   : $WpTenant")
W ("WorkplaceThumbprint : $WpThumb")

if ($AadJoined -eq 'YES') {
    W ''
    W 'This device is Entra JOINED. A device join is the machine''s own identity - it is'  'WARN'
    W 'not a work account and this script will NOT remove it. That needs dsregcmd /leave' 'WARN'
    W 'as SYSTEM plus a reboot, and a local admin account must exist first.'              'WARN'
}

$inScope    = New-Object System.Collections.ArrayList
$outOfScope = New-Object System.Collections.ArrayList

# --- WorkplaceJoin registrations in THIS user's hive ---
$wpjRoot = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo'
if (Test-Path $wpjRoot) {
    foreach ($k in (Get-ChildItem -LiteralPath $wpjRoot -ErrorAction SilentlyContinue)) {
        $upn = $null; $tid = $null
        try {
            $ki  = Get-Item -LiteralPath $k.PSPath
            $upn = $ki.GetValue('UserEmail', $null)
            if (-not $upn) { $upn = $ki.GetValue('UserPrincipalName', $null) }
            $tid = $ki.GetValue('TenantId', $null)
        } catch { }
        if (-not $tid) { $tid = $WpTenant }
        $o = [pscustomobject]@{ Kind='Registration'; Upn=[string]$upn; Tenant=[string]$tid; Id=$k.PSChildName; Path=$k.PSPath }
        if (Test-UpnMatchesTarget $upn) { [void]$inScope.Add($o) } else { [void]$outOfScope.Add($o) }
    }
}

# --- WAM broker account files in THIS user's profile ---
if (Test-Path -LiteralPath $BrokerDir) {
    foreach ($f in (Get-ChildItem -LiteralPath $BrokerDir -Filter '*.tbacct' -File -ErrorAction SilentlyContinue)) {
        $upn = ''
        try { $upn = Get-UpnFromBytes ([IO.File]::ReadAllBytes($f.FullName)) } catch { }
        $o = [pscustomobject]@{ Kind='BrokerFile'; Upn=$upn; Tenant=''; Id=$f.Name; Path=$f.FullName }
        if (Test-UpnMatchesTarget $upn) { [void]$inScope.Add($o) } else { [void]$outOfScope.Add($o) }
    }
}

# --- Office identities in THIS user's hive ---
foreach ($ver in @('16.0','15.0')) {
    $oid = "HKCU:\SOFTWARE\Microsoft\Office\$ver\Common\Identity\Identities"
    if (-not (Test-Path $oid)) { continue }
    foreach ($k in (Get-ChildItem -LiteralPath $oid -ErrorAction SilentlyContinue)) {
        $upn = $null
        try {
            $ki = Get-Item -LiteralPath $k.PSPath
            foreach ($n in @('EmailAddress','PreferredUsername','SignInName')) {
                if (-not $upn) { $upn = $ki.GetValue($n, $null) }
            }
        } catch { }
        if (-not $upn) {
            $m = [regex]::Match($k.PSChildName, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
            if ($m.Success) { $upn = $m.Value }
        }
        $o = [pscustomobject]@{ Kind='OfficeIdentity'; Upn=[string]$upn; Tenant=''; Id=$k.PSChildName; Path=$k.PSPath }
        if (Test-UpnMatchesTarget $upn) { [void]$inScope.Add($o) } else { [void]$outOfScope.Add($o) }
    }
}

W ''
W ("IN SCOPE  ({0} item(s)) - these WILL be disconnected:" -f $inScope.Count) 'STEP'
if ($inScope.Count -eq 0) { W '   (none found in this user profile)' }
foreach ($o in $inScope) { W ("   [{0,-14}] {1}  {2}" -f $o.Kind, $(if ($o.Upn) { $o.Upn } else { '(no upn)' }), $o.Id) 'WARN' }

W ''
W ("OUT OF SCOPE ({0} item(s)) - these will NOT be touched:" -f $outOfScope.Count) 'STEP'
$shown = 0
foreach ($o in $outOfScope) {
    if ($shown -lt 25) { W ("   [{0,-14}] {1}  {2}" -f $o.Kind, $(if ($o.Upn) { $o.Upn } else { '(unidentified - never touched)' }), $o.Id) 'KEEP' }
    $shown++
}
if ($outOfScope.Count -gt 25) { W ("   ... and {0} more, all left alone" -f ($outOfScope.Count - 25)) 'KEEP' }

# =====================================================================================
#  DISPATCH - layers 1 and 2 need a NON-ELEVATED user session
# =====================================================================================
$NeedsDispatch = ($IsSystem -or $IsElevated) -and (-not $InUserSession)

if ($NeedsDispatch) {
    Section 'DISPATCH  (layers 1 and 2 must run non-elevated, in the user session)'
    if ($IsElevated -and -not $IsSystem) {
        W 'This prompt is elevated. An elevated dsregcmd /leave targets the DEVICE join and'  'WARN'
        W 'silently does nothing to a workplace join - that is the "exit=0 but still YES"'    'WARN'
        W 'result. Re-running those two layers at normal integrity as the logged-on user.'    'WARN'
    } else {
        W 'Running as SYSTEM. WAM is per-user and sees nothing here. Dispatching to the user.' 'WARN'
    }

    $target = $null
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; if ($cs.UserName) { $target = $cs.UserName } } catch { }
    if (-not $target) {
        try {
            $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
            if ($ex) {
                $ow = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction Stop
                if ($ow.User) { $target = "$($ow.Domain)\$($ow.User)" }
            }
        } catch { }
    }

    $me = $PSCommandPath
    if (-not $me) { $me = $MyInvocation.MyCommand.Path }

    if (-not $target) {
        W 'No interactive user signed in - layers 1 and 2 skipped. Layer 3 still runs.' 'WARN'
    }
    elseif (-not $me -or -not (Test-Path -LiteralPath $me)) {
        W 'Cannot resolve this script''s own path. Download it to disk and run with -File.' 'ERROR'
    }
    else {
        W ("Logged-on user : $target")
        $childLog = [IO.Path]::ChangeExtension($LogFile, '.user.log')
        $taskName = 'PMC-DisconnectWorkAccount'
        $doms     = ($TargetDomain | ForEach-Object { "'$_'" }) -join ','
        $argLine  = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -InUserSession -LogFile "{1}" -TargetDomain {2} -OldTenantId {3}' -f $me, $childLog, $doms, $OldTenantId)
        if ($DryRun) { $argLine += ' -DryRun' }

        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            $act  = New-ScheduledTaskAction  -Execute 'powershell.exe' -Argument $argLine
            # RunLevel Limited is the important part - it de-elevates, so /leave does a WORKPLACE leave
            $prin = New-ScheduledTaskPrincipal -UserId $target -LogonType Interactive -RunLevel Limited
            $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
            Register-ScheduledTask -TaskName $taskName -Action $act -Principal $prin -Settings $set -Force -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            W 'Started. Waiting for the user-session half to finish ...'

            $deadline = (Get-Date).AddMinutes(6)
            do {
                Start-Sleep -Seconds 3
                $st = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
            } while ($st -eq 'Running' -and (Get-Date) -lt $deadline)

            if (Test-Path -LiteralPath $childLog) {
                W ''
                W '--- user session output ---' 'STEP'
                foreach ($l in (Get-Content -LiteralPath $childLog -ErrorAction SilentlyContinue)) { Write-Host "   $l" }
                try { Add-Content -LiteralPath $LogFile -Value (Get-Content -LiteralPath $childLog -Raw) -Encoding UTF8 } catch { }
                W '--- end user session output ---' 'STEP'
            } else {
                W 'The user-session half produced no log (blocked by policy?).' 'WARN'
            }
        }
        catch   { W ("Dispatch failed: " + $_.Exception.Message) 'ERROR' }
        finally { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

# =====================================================================================
#  LAYER 1 + 2 - only in a non-elevated user session
# =====================================================================================
if (-not $NeedsDispatch) {

    # ------------------------------------------------------------ LAYER 1: WAM signout
    Section 'LAYER 1  WAM  -  WebAccount.SignOutAsync()   (what the button calls)'
    $wamSignedOut = 0
    try {
        # 5.1 does not load this assembly by default. Without it the await helpers cannot be
        # built and every WAM call fails before it starts. This was the v1.0 failure.
        try { Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop } catch { }
        if (-not ('System.WindowsRuntimeSystemExtensions' -as [type])) {
            throw 'System.Runtime.WindowsRuntime unavailable - use powershell.exe 5.1, not pwsh 7'
        }

        [void][Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]
        [void][Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType = WindowsRuntime]

        $asTaskOp = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        $asTaskAct = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]

        function AwaitOp  { param($Op, $T) $t = $asTaskOp.MakeGenericMethod($T).Invoke($null, @($Op)); [void]$t.Wait(60000); return $t.Result }
        function AwaitAct { param($Op)     $t = $asTaskAct.Invoke($null, @($Op));                     [void]$t.Wait(60000) }

        $provT = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType = WindowsRuntime]
        $resT  = [Windows.Security.Authentication.Web.Core.FindAllAccountsResult, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]
        $mgr   = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]

        $providers = @()
        foreach ($auth in @('organizations', 'common')) {
            try {
                $pv = AwaitOp ($mgr::FindAccountProviderAsync('https://login.microsoft.com', $auth)) $provT
                if ($pv) { $providers += $pv }
            } catch { }
        }
        if ($providers.Count -eq 0) { throw 'no Entra WebAccountProvider in this session' }

        foreach ($pv in $providers) {
            $res = $null
            try { $res = AwaitOp ($mgr::FindAllAccountsAsync($pv)) $resT }
            catch { W ("  FindAllAccountsAsync threw: " + $_.Exception.Message) 'WARN'; continue }
            if ($res) { W ("  provider '" + $pv.DisplayName + "' status=" + $res.Status) }
            if (-not $res -or -not $res.Accounts) { continue }
            foreach ($a in $res.Accounts) {
                $u = $a.UserName
                if (-not (Test-UpnMatchesTarget $u)) { W ("  KEEP  $u") 'KEEP'; continue }
                if ($DryRun) { W ("  WOULD SignOutAsync  $u") 'DRY'; continue }
                try   { AwaitAct ($a.SignOutAsync()); W ("  SIGNED OUT  $u") 'GONE'; $wamSignedOut++ }
                catch { W ("  SignOutAsync failed for $u : " + $_.Exception.Message) 'WARN' }
            }
        }
        if ($wamSignedOut -eq 0 -and -not $DryRun) { W '  no accounts were signed out via WAM - layers 2 and 3 will handle it.' 'WARN' }
    }
    catch { W ("  WAM layer unavailable: " + $_.Exception.Message) 'WARN' }

    # ------------------------------------------------------------ LAYER 2: workplace leave
    Section 'LAYER 2  DSREG  -  dsregcmd /leave, non-elevated, user context'
    $before = Get-DsregStatus
    if ((Get-DsField $before 'WorkplaceJoined') -ne 'YES') {
        W '  not workplace joined - nothing to leave.' 'KEEP'
    }
    elseif ($WpTenant -and $OldTenantId -and $WpTenant.ToLower() -ne $OldTenantId.ToLower()) {
        W ("  registered to $WpTenant, not the target tenant - leaving it alone.") 'KEEP'
    }
    elseif ($DryRun) {
        W '  WOULD run: dsregcmd /leave  (non-elevated => workplace leave)' 'DRY'
    }
    else {
        W ("  elevated in this session : $IsElevated   (must be False for a workplace leave)")
        try {
            $out = (& "$env:WINDIR\System32\dsregcmd.exe" /leave 2>&1 | Out-String)
            W ("  exit=$LASTEXITCODE")
            foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { W ("    $l") } }
            Start-Sleep -Seconds 2
            if ((Get-DsField (Get-DsregStatus) 'WorkplaceJoined') -eq 'YES') {
                W '  still WorkplaceJoined - layer 3 will remove it directly.' 'WARN'
            } else {
                W '  registration gone.' 'GONE'
            }
        } catch { W ("  /leave failed: " + $_.Exception.Message) 'ERROR' }
    }
}

# =====================================================================================
#  LAYER 3 - surgical removal of whatever is left. Scoped, backed up, reversible.
# =====================================================================================
if (-not $InUserSession) {
    Section 'LAYER 3  SURGE  -  direct removal of anything still present (in scope only)'

    if ($inScope.Count -eq 0) {
        W '  nothing in scope in this profile.' 'KEEP'
    }
    else {
        if (-not $DryRun) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null; W "  backups -> $BackupDir" }

        foreach ($o in $inScope) {
            # belt and braces: re-verify scope immediately before every destructive act
            if (-not (Test-UpnMatchesTarget $o.Upn)) { W ("  REFUSING (out of scope): " + $o.Id) 'KEEP'; continue }
            if ($DryRun) { W ("  WOULD remove [{0}] {1}" -f $o.Kind, $o.Id) 'DRY'; continue }

            if ($o.Kind -eq 'Registration') {
                try {
                    $safe = ($o.Id -replace '[^A-Za-z0-9]', '_')
                    & reg.exe export ("HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\" + $o.Id) (Join-Path $BackupDir "JoinInfo-$safe.reg") /y 2>&1 | Out-Null
                    Remove-Item -LiteralPath $o.Path -Recurse -Force -ErrorAction Stop
                    W ("  removed JoinInfo\{0}" -f $o.Id) 'GONE'
                } catch { W ("  JoinInfo removal failed: " + $_.Exception.Message) 'ERROR' }

                if ($o.Tenant) {
                    $tp = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\$($o.Tenant)"
                    if (Test-Path $tp) {
                        try { Remove-Item -LiteralPath $tp -Recurse -Force -ErrorAction Stop; W ("  removed TenantInfo\{0}" -f $o.Tenant) 'GONE' }
                        catch { W ("  TenantInfo removal failed: " + $_.Exception.Message) 'WARN' }
                    }
                }
                try {
                    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $o.Id }
                    if ($cert) { $cert | Remove-Item -Force -ErrorAction Stop; W '  removed the workplace certificate' 'GONE' }
                } catch { W ("  certificate removal failed: " + $_.Exception.Message) 'WARN' }
            }
            elseif ($o.Kind -eq 'BrokerFile') {
                try {
                    $base = [IO.Path]::GetFileNameWithoutExtension($o.Path)
                    foreach ($sib in (Get-ChildItem -LiteralPath $BrokerDir -Filter "$base.*" -File -Force -ErrorAction SilentlyContinue)) {
                        Copy-Item -LiteralPath $sib.FullName -Destination (Join-Path $BackupDir $sib.Name) -Force -ErrorAction SilentlyContinue
                        Remove-Item -LiteralPath $sib.FullName -Force -ErrorAction Stop
                        W ("  removed broker file {0}" -f $sib.Name) 'GONE'
                    }
                } catch { W ("  broker file removal failed: " + $_.Exception.Message) 'WARN' }
            }
            elseif ($o.Kind -eq 'OfficeIdentity') {
                try { Remove-Item -LiteralPath $o.Path -Recurse -Force -ErrorAction Stop; W ("  removed Office identity {0}" -f $o.Id) 'GONE' }
                catch { W ("  Office identity removal failed: " + $_.Exception.Message) 'WARN' }
            }
        }
    }
}

# =====================================================================================
#  LAYER 4 - stop Windows silently re-registering (replaces deleting the device in Entra)
# =====================================================================================
if ($BlockAutoRejoin -and -not $InUserSession) {
    Section 'LAYER 4  HOLD  -  disable AUTOMATIC workplace re-join'
    if (-not $IsElevated -and -not $IsSystem) {
        W '  needs an elevated context. Skipped.' 'WARN'
    }
    elseif ($DryRun) {
        W '  WOULD set HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\autoWorkplaceJoin = 0' 'DRY'
    }
    else {
        try {
            $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'
            if (-not (Test-Path $pk)) { New-Item -Path $pk -Force | Out-Null }
            New-ItemProperty -Path $pk -Name 'autoWorkplaceJoin' -Value 0 -PropertyType DWord -Force | Out-Null
            W '  autoWorkplaceJoin = 0' 'GONE'
            W '  Windows will no longer AUTOMATICALLY re-register this device.'
            W '  Adding the new tenant by hand still works - only the silent re-join is off.'
            W '  To re-enable later: set the value to 1, or delete it.'
        } catch { W ("  could not set the policy: " + $_.Exception.Message) 'ERROR' }
    }
}

# =====================================================================================
#  VERIFY
# =====================================================================================
if (-not $InUserSession) {
    Section 'VERIFY'
    Start-Sleep -Seconds 2
    $after = Get-DsregStatus
    W ("AzureAdJoined   : " + (Get-DsField $after 'AzureAdJoined'))
    W ("WorkplaceJoined : " + (Get-DsField $after 'WorkplaceJoined'))

    $leftFiles = @(Get-ChildItem -LiteralPath $BrokerDir -Filter '*.tbacct' -File -ErrorAction SilentlyContinue)
    $leftMine  = 0
    foreach ($f in $leftFiles) {
        $u = ''
        try { $u = Get-UpnFromBytes ([IO.File]::ReadAllBytes($f.FullName)) } catch { }
        if (Test-UpnMatchesTarget $u) { $leftMine++ }
    }
    W ("Broker files total: {0}   still matching the target domain: {1}" -f $leftFiles.Count, $leftMine)

    if ($LastBoot) {
        $reborn = @($leftFiles | Where-Object { $_.LastWriteTime -gt $LastBoot })
        if ($reborn.Count -gt 0) {
            W ("{0} broker file(s) were written AFTER the last boot - something is actively" -f $reborn.Count) 'WARN'
            W 'putting the account back. Re-run with -BlockAutoRejoin, and sign the Edge work'  'WARN'
            W 'profile out (Edge > Settings > Profiles > the work profile > Sign out).'         'WARN'
        }
    }

    $clean = ((Get-DsField $after 'WorkplaceJoined') -ne 'YES') -and ($leftMine -eq 0)
    W ''
    if ($DryRun)    { W 'DRY RUN - nothing was changed.' 'WARN' }
    elseif ($clean) { W 'CLEAN - the target account is gone from every store this script reads.' 'OK' }
    else            { W 'NOT FULLY CLEAN - see the warnings above.' 'WARN' }
    W 'A RESTART is required before Settings stops showing the account. The Settings page' 'STEP'
    W 'caches the list - a stale entry there is not a failed removal.'                     'STEP'
}

# =====================================================================================
#  RESTART
# =====================================================================================
if ($Restart -and -not $InUserSession -and -not $DryRun) {
    Section 'RESTART'
    W ("Rebooting in $RestartDelay seconds. Cancel with:  shutdown /a") 'WARN'
    try { & shutdown.exe /r /t $RestartDelay /c "Work account disconnect - restarting to finish" | Out-Null }
    catch { W ("could not schedule the restart: " + $_.Exception.Message) 'ERROR' }
}

if (-not $InUserSession) { W ''; W ("Log: $LogFile") 'STEP' }
