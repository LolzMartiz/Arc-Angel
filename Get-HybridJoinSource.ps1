<#
=====================================================================================
 Get-HybridJoinSource.ps1                                                     v1.0.0

 READ-ONLY. Answers one question:

     Which Entra tenant does on-premises Active Directory tell every domain-joined
     Windows device to register itself with?

 WHY THIS MATTERS
   A domain-joined Windows device does not decide its own Entra tenant. It reads a
   Service Connection Point (SCP) out of the AD forest configuration partition:

     CN=62a0ff2e-97b9-4513-943f-0d221bd30080,
     CN=Device Registration Configuration,CN=Services,CN=Configuration,<forest>

   The SCP's "keywords" attribute holds azureADId (a tenant GUID) and azureADName.
   Every domain-joined device in the forest hybrid-joins to THAT tenant, automatically,
   on a schedule, forever.

   If the SCP still points at the OLD tenant, then no endpoint cleanup can ever hold.
   You delete the registration; the Automatic-Device-Join task reads the SCP, sees the
   old tenant, and registers again - often within a minute. That matches the observed
   behaviour exactly: a NEW certificate thumbprint and NEW broker files appearing
   seconds after a verified-clean removal.

 It also reports the on-prem UPN suffix, because a suffix that is not a verified domain
 in the tenant is why synced users end up as
     <alias>@<tenant>.onmicrosoft.com
 instead of <alias>@<company>.com.

 Run on ONE domain-joined device. No RSAT needed. Nothing is modified.

   powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-HybridJoinSource.ps1
=====================================================================================
#>

[CmdletBinding()]
param(
    [string] $OldTenantId = '905cd5ac-a071-4697-a446-c9077a81e24b',
    [string] $NewTenantId = '152848e0-5270-46fc-b573-8719c78aa236'
)

$ErrorActionPreference = 'Continue'

function W {
    param([string] $Text = '', [string] $Level = 'INFO')
    $c = 'Gray'
    switch ($Level) { 'STEP' { $c='Cyan' }; 'WARN' { $c='Yellow' }; 'ERROR' { $c='Red' }; 'OK' { $c='Green' }; 'KEY' { $c='Magenta' } }
    Write-Host ("[{0,-5}] {1}" -f $Level, $Text) -ForegroundColor $c
}

W ('=' * 76) 'STEP'
W '  WHERE DO DOMAIN-JOINED DEVICES GET THEIR ENTRA TENANT FROM?' 'STEP'
W ('=' * 76) 'STEP'
W ("Old tenant : $OldTenantId")
W ("New tenant : $NewTenantId")
W ''

# ------------------------------------------------------------------ 1. domain membership
W '--- 1. Domain membership ---' 'STEP'
$domain = ''; $isDomainJoined = $false
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $isDomainJoined = [bool]$cs.PartOfDomain
    $domain = $cs.Domain
    W ("PartOfDomain : $isDomainJoined")
    W ("Domain       : $domain")
} catch { W ("could not read computer system: " + $_.Exception.Message) 'WARN' }

if (-not $isDomainJoined) {
    W 'This device is NOT AD domain-joined, so it has no SCP to read.' 'WARN'
    W 'Run this on one of the domain-joined machines instead.' 'WARN'
}

# ------------------------------------------------------------------ 2. the SCP
W ''
W '--- 2. Service Connection Point in AD (the authoritative source) ---' 'STEP'
$scpTenantId = ''; $scpTenantName = ''
try {
    $rootDse   = [ADSI]"LDAP://RootDSE"
    $configNC  = $rootDse.configurationNamingContext
    if (-not $configNC) { throw 'could not read configurationNamingContext (is this machine on the domain network?)' }
    W ("Config NC    : $configNC")

    $scpPath = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,$configNC"
    W ("SCP path     : $scpPath")

    $scp = [ADSI]$scpPath
    if (-not $scp.Path) { throw 'SCP object not found' }

    $kw = @($scp.Keywords)
    if ($kw.Count -eq 0) { W 'SCP exists but has no keywords - hybrid join is not configured.' 'WARN' }
    foreach ($k in $kw) {
        W ("  keyword    : $k")
        if ($k -like 'azureADId:*')   { $scpTenantId   = $k.Substring(10).Trim() }
        if ($k -like 'azureADName:*') { $scpTenantName = $k.Substring(12).Trim() }
    }
}
catch {
    W ("Could not read the SCP: " + $_.Exception.Message) 'WARN'
    W 'If this device is off the corporate network or not domain-joined, that is expected.' 'WARN'
}

# ------------------------------------------------------------------ 3. policy override
W ''
W '--- 3. Registry/policy override (takes precedence over the SCP if set) ---' 'STEP'
$cdjTid = ''; $cdjName = ''
foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD',
                 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin')) {
    if (Test-Path $p) {
        try {
            $k = Get-Item -LiteralPath $p
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                W ("  $p\$n = $v")
                if ($n -eq 'TenantId')   { $cdjTid  = [string]$v }
                if ($n -eq 'TenantName') { $cdjName = [string]$v }
            }
            if ($k.GetValueNames().Count -eq 0) { W "  $p  (present, no values)" }
        } catch { }
    } else { W "  $p  (not present)" }
}

# ------------------------------------------------------------------ 4. what the device did
W ''
W '--- 4. What this device actually registered to ---' 'STEP'
$ds = ''
try { $ds = (& "$env:WINDIR\System32\dsregcmd.exe" /status 2>&1 | Out-String) } catch { }
function F { param($n)
    $m = [regex]::Match($ds, ('(?m)^\s*' + [regex]::Escape($n) + '\s*:\s*(.+?)\s*$'))
    if ($m.Success) { return $m.Groups[1].Value } else { return '' }
}
W ("AzureAdJoined     : " + (F 'AzureAdJoined'))
W ("DomainJoined      : " + (F 'DomainJoined'))
W ("WorkplaceJoined   : " + (F 'WorkplaceJoined'))
W ("Device TenantId   : " + (F 'TenantId') + '  ' + (F 'TenantName'))
W ("WorkplaceTenantId : " + (F 'WorkplaceTenantId'))
W ("Executing account : " + (F 'Executing Account Name'))

# ------------------------------------------------------------------ 5. on-prem UPN suffix
W ''
W '--- 5. On-prem UPN suffix (why synced users become @tenant.onmicrosoft.com) ---' 'STEP'
try {
    $me = [ADSI]"LDAP://<SID=$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>"
    if ($me.Path) {
        $upn = [string]$me.userPrincipalName
        $sam = [string]$me.sAMAccountName
        W ("Signed-in AD user : $sam")
        W ("On-prem UPN       : $upn")
        if ($upn -and $upn.Contains('@')) {
            $suffix = $upn.Split('@')[-1]
            W ("On-prem suffix    : $suffix")
            W ''
            W 'If this suffix is NOT a verified domain in the target tenant, Entra Connect'   'KEY'
            W 'rewrites the UPN on sync to <alias>@<tenant>.onmicrosoft.com. That is exactly' 'KEY'
            W 'how users end up signing in as @delta.mainettigroup.onmicrosoft.com.'          'KEY'
        }
    } else { W 'Not signed in with a domain account - skipping.' }
} catch { W ("could not read the AD user: " + $_.Exception.Message) 'WARN' }

# ------------------------------------------------------------------ verdict
W ''
W ('=' * 76) 'STEP'
W '  VERDICT' 'STEP'
W ('=' * 76) 'STEP'

$effectiveTid  = $cdjTid
$effectiveFrom = 'registry policy'
if (-not $effectiveTid) { $effectiveTid = $scpTenantId; $effectiveFrom = 'AD SCP' }

if (-not $effectiveTid) {
    W 'No tenant is configured for automatic device registration that this device can see.' 'WARN'
    W 'Either hybrid join is not configured, or this machine cannot reach a domain controller.' 'WARN'
}
elseif ($effectiveTid.ToLower() -eq $OldTenantId.ToLower()) {
    W ("Domain-joined devices are told to register to the OLD tenant  ($effectiveTid)") 'ERROR'
    W ("Source: $effectiveFrom   name: $scpTenantName")
    W ''
    W 'THIS IS THE ROOT CAUSE OF THE ACCOUNT COMING BACK.' 'ERROR'
    W 'Every domain-joined device in this forest will keep re-registering to the old'  'ERROR'
    W 'tenant automatically, no matter how many times it is cleaned locally. Endpoint' 'ERROR'
    W 'scripts cannot win against this.'                                               'ERROR'
    W ''
    W 'Fix, on the AD / Entra Connect side - not on the endpoints:' 'KEY'
    W '  1. Re-point or remove the SCP so it names the NEW tenant.' 'KEY'
    W '     (Entra Connect wizard > Configure device options, or Initialize-ADSyncDomainJoinedComputerSync)' 'KEY'
    W '  2. Confirm Entra Connect is syncing to the NEW tenant, not the old one.' 'KEY'
    W '  3. Verify the on-prem UPN suffix as a domain in the NEW tenant and set users to it,' 'KEY'
    W '     so synced users stop becoming @<old-tenant>.onmicrosoft.com.' 'KEY'
    W '  4. THEN clean the endpoints. In that order it holds.' 'KEY'
}
elseif ($effectiveTid.ToLower() -eq $NewTenantId.ToLower()) {
    W ("Domain-joined devices are told to register to the NEW tenant ($effectiveTid) - correct.") 'OK'
    W ("Source: $effectiveFrom   name: $scpTenantName")
    W 'If the old account still returns, the cause is elsewhere - collect the endpoint evidence.' 'WARN'
}
else {
    W ("Devices are told to register to tenant $effectiveTid, which is NEITHER the old nor") 'WARN'
    W ("the new tenant you gave me. Source: $effectiveFrom   name: $scpTenantName") 'WARN'
}
W ''
