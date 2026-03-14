param(
    [string]$ServerUrl = "https://tt.greenleafpacific.com",
    [string]$ApiKey = "",
    [int]$LookbackMinutes = 10
)

$ErrorActionPreference = "Stop"

function Test-ActivityWatch {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:5600/api/0/buckets" -UseBasicParsing -TimeoutSec 5
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    } catch {
        return $false
    }
}

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Restarting installer with administrator rights..."
        $argList = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", "`"$PSCommandPath`""
            "-ServerUrl", "`"$ServerUrl`""
            "-LookbackMinutes", "$LookbackMinutes"
        )
        if ($ApiKey) {
            $argList += @("-ApiKey", "`"$ApiKey`"")
        }
        Start-Process powershell.exe -Verb RunAs -ArgumentList ($argList -join " ")
        exit 0
    }
}

Ensure-Admin

Write-Host ""
Write-Host "Company Monitor client installer"
Write-Host "Server: $ServerUrl"
Write-Host ""

if (-not (Test-ActivityWatch)) {
    Write-Warning "ActivityWatch local API is not reachable on http://127.0.0.1:5600."
    Write-Warning "Start ActivityWatch first, then rerun this installer."
    exit 1
}

$defaultDeviceId = $env:COMPUTERNAME.ToLower()
$defaultDeviceLabel = $env:COMPUTERNAME

$deviceLabel = Read-Host "How should this PC appear in the dashboard? [`"$defaultDeviceLabel`"]"
if ([string]::IsNullOrWhiteSpace($deviceLabel)) {
    $deviceLabel = $defaultDeviceLabel
}

$deviceId = Read-Host "Technical device ID [`"$defaultDeviceId`"]"
if ([string]::IsNullOrWhiteSpace($deviceId)) {
    $deviceId = $defaultDeviceId
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $ApiKey = Read-Host "Paste the ingest API key"
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Warning "API key is required."
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installScript = Join-Path $scriptDir "install-client.ps1"

if (-not (Test-Path $installScript)) {
    Write-Warning "install-client.ps1 not found next to this script."
    exit 1
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript `
    -DeviceId $deviceId `
    -DeviceLabel $deviceLabel `
    -ApiKey $ApiKey `
    -ServerUrl $ServerUrl `
    -LookbackMinutes $LookbackMinutes

Write-Host ""
Write-Host "Setup complete."
Write-Host "Open the dashboard in a minute and verify that this device appears."
