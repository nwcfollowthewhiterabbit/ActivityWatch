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
$configPath = Join-Path $appDir "config.json"
$runnerPath = Join-Path $appDir "run-sync.ps1"
$taskName = "CompanyMonitorSync"

New-Item -ItemType Directory -Force -Path $appDir | Out-Null
Copy-Item -Force (Join-Path $scriptDir "sync_agent.ps1") $agentPath

$config = @{
    server_url = $ServerUrl
    api_key = $ApiKey
    device_id = $DeviceId
    device_label = $DeviceLabel
    activitywatch_url = "http://localhost:5600/api/0"
    lookback_minutes = $LookbackMinutes
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $configPath

$runner = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$appDir'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$agentPath' -ConfigPath '$configPath'
"@
Set-Content -Path $runnerPath -Value $runner -Encoding UTF8

$taskCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`""
schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
schtasks.exe /Create /SC MINUTE /MO 1 /TN $taskName /TR $taskCommand /F | Out-Null

try {
    & powershell -ExecutionPolicy Bypass -File $runnerPath
} catch {
    Write-Warning "Initial sync run failed: $($_.Exception.Message)"
}

schtasks.exe /Run /TN $taskName | Out-Null

Write-Host "Company Monitor client installed."
Write-Host "Config: $configPath"
Write-Host "Task:   $taskName"
Write-Host "Log:    $(Join-Path $appDir 'agent.log')"
