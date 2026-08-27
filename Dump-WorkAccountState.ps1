#Requires -Version 5.1
<#
    Dump-WorkAccountState.ps1  - READ ONLY. Changes nothing.

    Shows every place Windows can hold a "work account", so we can see exactly which store
    is still feeding Settings and Edge. Run as the affected user, elevated.
#>
[CmdletBinding()]
param([string] $Domain = 'delta.mainettigroup.onmicrosoft.com')

$ErrorActionPreference = 'Continue'
$out = Join-Path $env:TEMP ("WorkAccountDump-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
function W { param($t) $t | Tee-Object -FilePath $out -Append | Out-Null; Write-Host $t }

W "=== WORK ACCOUNT STATE DUMP  $(Get-Date -Format s) ==="
W "user: $env:USERNAME   computer: $env:COMPUTERNAME   looking for: $Domain"
W ""

W "--- 1. dsregcmd ---"
try { (& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1 | Select-String -Pattern 'Joined|WorkAccount|TenantId|TenantName|Prt|DeviceId') | ForEach-Object { W "   $_" } } catch { W "   FAILED: $_" }
W ""

W "--- 2. WorkplaceJoin registry (per-user registrations) ---"
foreach ($k in @('JoinInfo','TenantInfo','AADNGC','DeviceValidity')) {
    $p = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\$k"
    if (Test-Path $p) {
        W "   [$k] EXISTS"
        Get-ChildItem $p -EA SilentlyContinue | ForEach-Object {
            W "      subkey: $($_.PSChildName)"
            try { (Get-ItemProperty $_.PSPath -EA Stop).PSObject.Properties |
                  Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { W "         $($_.Name) = $($_.Value)" } } catch {}
        }
    } else { W "   [$k] absent" }
}
W ""

W "--- 3. TOKEN BROKER account files (WAM - the likely culprit) ---"
$tb = "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker"
if (Test-Path $tb) {
    foreach ($sub in @('Accounts','Cache')) {
        $d = Join-Path $tb $sub
        if (-not (Test-Path $d)) { W "   $sub : absent"; continue }
        $files = @(Get-ChildItem $d -File -Force -Recurse -EA SilentlyContinue)
        W "   $sub : $($files.Count) file(s)"
        foreach ($f in $files) {
            $hit = ''
            try {
                $b = [System.IO.File]::ReadAllBytes($f.FullName)
                foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::ASCII, [Text.Encoding]::UTF8)) {
                    $txt = $enc.GetString($b)
                    foreach ($m in ([regex]'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}').Matches($txt)) {
                        if ($hit -notlike "*$($m.Value)*") { $hit += "$($m.Value) " }
                    }
                }
            } catch {}
            W ("      {0}  [{1} bytes]  UPNs seen: {2}" -f $f.Name, $f.Length, $(if($hit){$hit}else{'(none)'}))
        }
    }
} else { W "   broker package folder absent" }
W ""

W "--- 4. IdentityCRL / Office identities (raw key names) ---"
foreach ($rel in @('SOFTWARE\Microsoft\IdentityCRL\StoredIdentities',
                   'SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties',
                   'SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities',
                   'SOFTWARE\Microsoft\Office\16.0\Common\Identity\Profiles')) {
    $p = "HKCU:\$rel"
    if (Test-Path $p) {
        W "   [$rel]"
        Get-ChildItem $p -EA SilentlyContinue | ForEach-Object { W "      $($_.PSChildName)" }
    } else { W "   [$rel] absent" }
}
W ""

W "--- 5. Credential Manager entries mentioning the domain ---"
try { (& cmdkey.exe /list 2>&1) | Where-Object { $_ -match 'Target|Ziel|Destinazione|microsoft|Mainetti|delta' } | ForEach-Object { W "   $_" } } catch { W "   FAILED" }
W ""

W "--- 6. Anything anywhere in HKCU mentioning the target domain ---"
$found = 0
foreach ($root in @('HKCU:\SOFTWARE\Microsoft\IdentityCRL','HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin','HKCU:\SOFTWARE\Microsoft\Office','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD')) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -EA SilentlyContinue | ForEach-Object {
        if ($_.PSChildName -like "*$Domain*") { W "   KEYNAME: $($_.PSPath)"; $found++ }
        try { (Get-ItemProperty $_.PSPath -EA Stop).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            if ("$($_.Value)" -like "*$Domain*") { W "   VALUE  : $($_.Name) in $($_.PSPath) = $($_.Value)"; $script:found++ } } } catch {}
    }
}
if ($found -eq 0) { W "   nothing found referencing $Domain" }
W ""
W "=== DUMP SAVED TO: $out ==="
W "Send that file back."
