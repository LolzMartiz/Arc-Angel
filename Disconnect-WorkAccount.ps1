<#
=====================================================================================
 Disconnect-WorkAccount.ps1                                                   v1.0.0

 Does what the Settings "Disconnect" button does - by calling the SAME APIs Windows
 Settings calls - instead of deleting broker files off disk.

 WHY THIS IS DIFFERENT FROM Remove-WorkAccount.ps1
 -------------------------------------------------
 Remove-WorkAccount.ps1 deletes .tbacct files from
   %LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts
 The Settings UI never does that. It calls the Web Account Manager (WAM):

     WebAuthenticationCoreManager.FindAllAccountsAsync(provider)
     account.SignOutAsync()

 Deleting the file removes the account's *storage*. SignOutAsync removes the account's
 *registration with the broker*. If you delete the file while the broker still has the
 account in its own state, the broker can write it straight back - which is exactly what
 "I removed 18 files, rebooted, and it is still there" looks like.

 It also runs in the RIGHT PLACE. WAM is a per-user, per-session API. Called from SYSTEM
 (i.e. from an RMM agent) it sees no accounts and silently does nothing. This script
 detects that and relaunches its own working half inside the logged-on user's session via
 a temporary scheduled task, then cleans the task up.

 WHAT IT HANDLES
   1. WAM / broker accounts   -> SignOutAsync   (Settings > Accounts > Email & accounts)
   2. Workplace Join (Entra registered, per user)
                              -> dsregcmd /leave in USER context
   3. Entra JOINED device     -> reported, and only removed with -LeaveAzureAdJoin,
                                 because that is a device-wide, reboot-required change

 SAFETY
   * Only accounts whose UPN suffix exactly matches -TargetDomain are touched.
   * -DryRun shows what would happen and calls nothing.
   * Never touches mail data, profiles, .pst/.ost, or any other account.
   * The device-level leave is opt-in only and refuses to run if the signed-in Windows
     user belongs to the tenant being left (that would orphan their profile).

 USAGE
   # test on one machine, see what it finds, change nothing
   .\Disconnect-WorkAccount.ps1 -DryRun

   # do it
   .\Disconnect-WorkAccount.ps1

   # also leave a device-level Entra join (reboot required, read the warning first)
   .\Disconnect-WorkAccount.ps1 -LeaveAzureAdJoin

 RMM one-liner:
   powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; New-Item -ItemType Directory 'C:\ProgramData\PMC' -Force | Out-Null; Invoke-WebRequest 'https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/Disconnect-WorkAccount.ps1' -OutFile 'C:\ProgramData\PMC\Disconnect-WorkAccount.ps1' -UseBasicParsing; & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\PMC\Disconnect-WorkAccount.ps1'"
=====================================================================================
#>

[CmdletBinding()]
param(
    [string[]] $TargetDomain     = @('delta.mainettigroup.onmicrosoft.com'),
    [string]   $OldTenantId      = '905cd5ac-a071-4697-a446-c9077a81e24b',
    [switch]   $LeaveAzureAdJoin,
    [switch]   $DryRun,

    # internal - set when the script relaunches itself inside the user session
    [switch]   $InUserSession,
    [string]   $LogFile = ''
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$Version               = '1.0.0'

if (-not $LogFile) {
    $dir = 'C:\ProgramData\PMC\Logs'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $LogFile = Join-Path $dir ("Disconnect-{0}-{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

function W {
    param([string] $Text = '', [string] $Level = 'INFO')
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Text
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    $c = 'Gray'
    switch ($Level) {
        'STEP' { $c = 'Cyan' }; 'WARN' { $c = 'Yellow' }; 'ERROR' { $c = 'Red' }
        'GONE' { $c = 'Green' }; 'KEEP' { $c = 'DarkGray' }; 'DRY' { $c = 'Magenta' }
    }
    Write-Host $line -ForegroundColor $c
}

function Test-UpnMatchesTarget {
    <# Exact suffix match on '@domain'. 'contoso.com' never matches 'notcontoso.com'. #>
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

# ------------------------------------------------------------------ context
$IsSystem = $false
$WhoAmI   = $env:USERNAME
try {
    $wid    = [Security.Principal.WindowsIdentity]::GetCurrent()
    $WhoAmI = $wid.Name
    if ($wid.User) { $IsSystem = ($wid.User.Value -eq 'S-1-5-18') }
} catch { }

W ('=' * 78) 'STEP'
W ("  DISCONNECT WORK ACCOUNT  v$Version   (GUI-equivalent, API based)") 'STEP'
W ('=' * 78) 'STEP'
W ("Running as     : $WhoAmI")
W ("SYSTEM context : $IsSystem")
W ("Target domain  : " + ($TargetDomain -join ', '))
W ("Mode           : " + $(if ($DryRun) { 'DRY RUN - nothing will be changed' } else { 'LIVE' }))
W ("Log            : $LogFile")

# =====================================================================================
#  PART A - running as SYSTEM: hand the user-session work to the logged-on user
# =====================================================================================
if ($IsSystem -and -not $InUserSession) {
    W ''
    W 'WAM is a per-user API. Running as SYSTEM it can see no accounts, so the user half' 'WARN'
    W 'of this job must run inside the logged-on user session.' 'WARN'

    $target = $null
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.UserName) { $target = $cs.UserName }
    } catch { }
    if (-not $target) {
        try {
            $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
            if ($ex) {
                $o = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction Stop
                if ($o.User) { $target = "$($o.Domain)\$($o.User)" }
            }
        } catch { }
    }

    if (-not $target) {
        W 'No interactive user is signed in. The WAM half cannot run now.' 'ERROR'
        W 'Re-run this while the user is logged on, or deploy it as a logon task.' 'ERROR'
    }
    else {
        W ("Logged-on user : $target") 'STEP'
        $childLog = [IO.Path]::ChangeExtension($LogFile, '.user.log')
        $taskName = 'PMC-DisconnectWorkAccount'
        $me       = $PSCommandPath
        if (-not $me) { $me = $MyInvocation.MyCommand.Path }

        if (-not $me -or -not (Test-Path -LiteralPath $me)) {
            W 'Cannot determine this script''s own path (was it piped into iex?).' 'ERROR'
            W 'Download it to disk and run it with -File. See the header for the one-liner.' 'ERROR'
        }
        else {
            $argLine = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -InUserSession -LogFile "{1}" -TargetDomain {2} -OldTenantId {3}' -f `
                        $me, $childLog, (($TargetDomain | ForEach-Object { "'$_'" }) -join ','), $OldTenantId)
            if ($DryRun) { $argLine += ' -DryRun' }

            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                $act  = New-ScheduledTaskAction  -Execute 'powershell.exe' -Argument $argLine
                $prin = New-ScheduledTaskPrincipal -UserId $target -LogonType Interactive -RunLevel Limited
                $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
                Register-ScheduledTask -TaskName $taskName -Action $act -Principal $prin -Settings $set -Force -ErrorAction Stop | Out-Null
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                W 'Started the user-session half. Waiting for it to finish ...'

                $deadline = (Get-Date).AddMinutes(6)
                do {
                    Start-Sleep -Seconds 3
                    $st = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
                } while ($st -eq 'Running' -and (Get-Date) -lt $deadline)

                if (Test-Path -LiteralPath $childLog) {
                    W ''
                    W '--- output from the user session ---' 'STEP'
                    foreach ($l in (Get-Content -LiteralPath $childLog -ErrorAction SilentlyContinue)) { Write-Host "  $l" }
                    try { Add-Content -LiteralPath $LogFile -Value (Get-Content -LiteralPath $childLog -Raw) -Encoding UTF8 } catch { }
                    W '--- end user session output ---' 'STEP'
                } else {
                    W 'The user-session half produced no log. It may have been blocked by policy.' 'WARN'
                }
            }
            catch {
                W ("Could not run in the user session: " + $_.Exception.Message) 'ERROR'
            }
            finally {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
}

# =====================================================================================
#  PART B - the actual disconnect (runs in a user context)
# =====================================================================================
if (-not $IsSystem -or $InUserSession) {

    # ---------------------------------------------------------------- dsregcmd state
    W ''
    W '--- current join state ---' 'STEP'
    $dsreg = ''
    try { $dsreg = (& "$env:WINDIR\System32\dsregcmd.exe" /status 2>&1 | Out-String) } catch { }
    function DsField { param([string]$n)
        $m = [regex]::Match($dsreg, ('(?m)^\s*' + [regex]::Escape($n) + '\s*:\s*(.+?)\s*$'))
        if ($m.Success) { return $m.Groups[1].Value } else { return '' }
    }
    $AadJoined  = DsField 'AzureAdJoined'
    $WpJoined   = DsField 'WorkplaceJoined'
    $DevTenant  = DsField 'TenantId'
    $DevTenantN = DsField 'TenantName'
    $WpTenant   = DsField 'WorkplaceTenantId'
    $ExecAcct   = DsField 'Executing Account Name'

    W ("AzureAdJoined     : $AadJoined   (tenant $DevTenant $DevTenantN)")
    W ("WorkplaceJoined   : $WpJoined   (tenant $WpTenant)")
    W ("Executing account : $ExecAcct")

    $deviceJoinedToOld = ($AadJoined -eq 'YES' -and $DevTenant -and $DevTenant.ToLower() -eq $OldTenantId.ToLower())
    if ($deviceJoinedToOld) {
        W ''
        W 'THIS DEVICE IS ENTRA *JOINED* TO THE OLD TENANT.' 'WARN'
        W 'That entry is the machine''s own identity. It is not a broker account and not a' 'WARN'
        W 'registration - no API below will remove it, and neither will the Disconnect'    'WARN'
        W 'button (Windows greys it out or demands a reboot). It comes off only with'      'WARN'
        W 'dsregcmd /leave as SYSTEM. Re-run with -LeaveAzureAdJoin if that is intended.'  'WARN'
    }

    # ---------------------------------------------------------------- 1. WAM sign-out
    W ''
    W '--- 1. WAM / broker accounts (what Settings > Email & accounts shows) ---' 'STEP'

    $wamOk       = $false
    $wamSignedOut = 0
    $wamSeen      = 0
    try {
        # WinRT projection into Windows PowerShell 5.1
        [void][Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]
        [void][Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType = WindowsRuntime]

        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        })[0]
        $asTaskAction = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
        })[0]

        function Await { param($Op, $Type)
            $t = $asTaskGeneric.MakeGenericMethod($Type).Invoke($null, @($Op))
            [void]$t.Wait(60000)
            return $t.Result
        }
        function AwaitAction { param($Op)
            $t = $asTaskAction.Invoke($null, @($Op))
            [void]$t.Wait(60000)
        }

        # Always use the fully-qualified WinRT form - the short form only resolves once the
        # projection has been loaded, and that is exactly what we cannot assume here.
        $provType = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType = WindowsRuntime]
        $mgr      = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]

        # 'organizations' = any Entra tenant. Also try the consumer/AAD combined authority.
        $providers = @()
        foreach ($auth in @('organizations', 'https://login.microsoft.com')) {
            try {
                $p = Await ($mgr::FindAccountProviderAsync('https://login.microsoft.com', $auth)) $provType
                if ($p) { $providers += $p }
            } catch { }
        }
        if ($providers.Count -eq 0) { throw 'no Entra WebAccountProvider available in this session' }

        $resultType = [Windows.Security.Authentication.Web.Core.FindAllAccountsResult, Windows.Security.Authentication.Web.Core, ContentType = WindowsRuntime]
        foreach ($p in $providers) {
            $res = $null
            try { $res = Await ($mgr::FindAllAccountsAsync($p)) $resultType }
            catch { W ("  FindAllAccountsAsync threw: " + $_.Exception.Message) 'WARN'; continue }
            if ($res) { W ("  provider '" + $p.DisplayName + "' -> status=" + $res.Status) }
            if (-not $res -or -not $res.Accounts) { continue }
            $wamOk = $true
            foreach ($acct in $res.Accounts) {
                $wamSeen++
                $upn = $acct.UserName
                if (-not (Test-UpnMatchesTarget $upn)) {
                    W ("  KEEP  $upn") 'KEEP'
                    continue
                }
                if ($DryRun) {
                    W ("  WOULD sign out $upn  (WebAccount.SignOutAsync)") 'DRY'
                    continue
                }
                try {
                    AwaitAction ($acct.SignOutAsync())
                    W ("  SIGNED OUT $upn") 'GONE'
                    $wamSignedOut++
                } catch {
                    W ("  sign-out failed for $upn : " + $_.Exception.Message) 'WARN'
                }
            }
        }
        if (-not $wamOk) { W '  the WAM provider returned no accounts to this process.' 'WARN' }
        else             { W ("  $wamSeen account(s) visible, $wamSignedOut signed out.") }
    }
    catch {
        W ("  WAM API unavailable here: " + $_.Exception.Message) 'WARN'
        W '  (this is expected under SYSTEM, in Server Core, or with the broker disabled)' 'WARN'
    }

    # ---------------------------------------------------------------- 2. workplace leave
    W ''
    W '--- 2. Workplace Join / Entra registration (Access work or school) ---' 'STEP'
    if ($WpJoined -ne 'YES') {
        W '  not workplace joined - nothing to leave.' 'KEEP'
    }
    elseif ($WpTenant -and $OldTenantId -and $WpTenant.ToLower() -ne $OldTenantId.ToLower()) {
        W ("  registered to $WpTenant, which is NOT the target tenant - leaving it alone.") 'KEEP'
    }
    elseif ($DryRun) {
        W '  WOULD run: dsregcmd /leave   (user context - drops this user''s registration)' 'DRY'
    }
    else {
        try {
            $out = (& "$env:WINDIR\System32\dsregcmd.exe" /leave 2>&1 | Out-String)
            W ("  dsregcmd /leave exit=$LASTEXITCODE")
            foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { W ("    $l") } }
        } catch {
            W ("  dsregcmd /leave failed: " + $_.Exception.Message) 'ERROR'
        }
    }

    # ---------------------------------------------------------------- 3. verify
    W ''
    W '--- 3. verify ---' 'STEP'
    Start-Sleep -Seconds 2
    $after = ''
    try { $after = (& "$env:WINDIR\System32\dsregcmd.exe" /status 2>&1 | Out-String) } catch { }
    $m1 = [regex]::Match($after, '(?m)^\s*WorkplaceJoined\s*:\s*(.+?)\s*$')
    $m2 = [regex]::Match($after, '(?m)^\s*AzureAdJoined\s*:\s*(.+?)\s*$')
    W ("AzureAdJoined   : " + $(if ($m2.Success) { $m2.Groups[1].Value } else { '?' }))
    W ("WorkplaceJoined : " + $(if ($m1.Success) { $m1.Groups[1].Value } else { '?' }))

    $left = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts') -Filter '*.tbacct' -File -ErrorAction SilentlyContinue)
    W ("Broker files remaining in this profile: " + $left.Count)
    W ''
    W 'Open Settings > Accounts and check BOTH pages: "Access work or school" AND' 'STEP'
    W '"Email & accounts". They are different lists backed by different stores.'    'STEP'
}

# =====================================================================================
#  PART C - device-level Entra leave (opt-in, SYSTEM, reboot)
# =====================================================================================
if ($LeaveAzureAdJoin) {
    W ''
    W '--- device-level Entra leave requested ---' 'STEP'
    if (-not $IsSystem) {
        W 'dsregcmd /leave for a DEVICE join must run as SYSTEM. Re-run from the RMM agent' 'ERROR'
        W 'or via psexec -s. Nothing was changed.' 'ERROR'
    }
    else {
        $execAcct = ''
        try {
            $st = (& "$env:WINDIR\System32\dsregcmd.exe" /status 2>&1 | Out-String)
            $m  = [regex]::Match($st, '(?m)^\s*Executing Account Name\s*:\s*(.+?)\s*$')
            if ($m.Success) { $execAcct = $m.Groups[1].Value }
        } catch { }

        $userIsFromTenant = $false
        foreach ($d in $TargetDomain) { if ($execAcct -and $execAcct.ToLower().Contains($d.ToLowerInvariant())) { $userIsFromTenant = $true } }
        if ($execAcct -match 'AzureAd\\') { $userIsFromTenant = $true }

        if ($userIsFromTenant) {
            W 'REFUSING: the signed-in Windows user is an account from the tenant being left.' 'ERROR'
            W ("  executing account: $execAcct") 'ERROR'
            W 'Leaving now would orphan that Windows profile and the user could not log in.'  'ERROR'
            W 'Create a LOCAL administrator account, sign in as that, then re-run.'            'ERROR'
        }
        elseif ($DryRun) {
            W 'WOULD run: dsregcmd /leave as SYSTEM, then a reboot is required.' 'DRY'
        }
        else {
            try {
                $out = (& "$env:WINDIR\System32\dsregcmd.exe" /leave 2>&1 | Out-String)
                W ("dsregcmd /leave exit=$LASTEXITCODE")
                foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { W ("  $l") } }
                W 'REBOOT REQUIRED for this to take effect.' 'WARN'
            } catch {
                W ("device leave failed: " + $_.Exception.Message) 'ERROR'
            }
        }
    }
}

W ''
W ("Log written to: $LogFile") 'STEP'
