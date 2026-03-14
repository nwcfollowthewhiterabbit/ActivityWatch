param(
    [Parameter(Mandatory = $true)]
    [string]$DeviceId,

    [Parameter(Mandatory = $true)]
    [string]$DeviceLabel,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [string]$ServerUrl = "https://tt.greenleafpacific.com",
    [int]$LookbackMinutes = 10
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$appDir = Join-Path $env:ProgramData "CompanyMonitor"
$agentPath = Join-Path $appDir "sync_agent.ps1"
$servicePath = Join-Path $appDir "sync_service.ps1"
$configPath = Join-Path $appDir "config.json"
$serviceName = "CompanyMonitorSync"

New-Item -ItemType Directory -Force -Path $appDir | Out-Null
Copy-Item -Force (Join-Path $scriptDir "sync_agent.ps1") $agentPath
Copy-Item -Force (Join-Path $scriptDir "sync_service.ps1") $servicePath

$config = @{
    server_url = $ServerUrl
    api_key = $ApiKey
    device_id = $DeviceId
    device_label = $DeviceLabel
    activitywatch_url = "http://localhost:5600/api/0"
    lookback_minutes = $LookbackMinutes
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $configPath

$legacyTaskName = "CompanyMonitorSync"
cmd.exe /c "schtasks /Query /TN ""$legacyTaskName"" >nul 2>&1"
if ($LASTEXITCODE -eq 0) {
    cmd.exe /c "schtasks /Delete /TN ""$legacyTaskName"" /F >nul 2>&1"
}

cmd.exe /c "sc query ""$serviceName"" >nul 2>&1"
if ($LASTEXITCODE -ne 0) {
    $binPath = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$servicePath`" -ConfigPath `"$configPath`""
    cmd.exe /c "sc create ""$serviceName"" binPath= ""$binPath"" start= auto DisplayName= ""Company Monitor Sync"""
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create Windows service $serviceName"
    }
} else {
    cmd.exe /c "sc stop ""$serviceName"" >nul 2>&1"
}

cmd.exe /c "sc failure ""$serviceName"" reset= 86400 actions= restart/60000/restart/60000/restart/60000" >nul 2>&1
cmd.exe /c "sc description ""$serviceName"" ""Syncs ActivityWatch data to Company Monitor server""" >nul 2>&1

try {
    & powershell -ExecutionPolicy Bypass -File $agentPath -ConfigPath $configPath
} catch {
    Write-Warning "Initial sync run failed: $($_.Exception.Message)"
}

cmd.exe /c "sc start ""$serviceName"" >nul 2>&1"

Write-Host "Company Monitor client installed."
Write-Host "Config: $configPath"
Write-Host "Service: $serviceName"
Write-Host "Log:    $(Join-Path $appDir 'agent.log')"
