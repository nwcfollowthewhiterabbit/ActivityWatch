param(
    [string]$ConfigPath = "$env:ProgramData\CompanyMonitor\config.json",
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = "Stop"

$appDir = Split-Path -Parent $ConfigPath
$serviceLogPath = Join-Path $appDir "service.log"
$agentPath = Join-Path $appDir "sync_agent.ps1"

function Write-ServiceLog {
    param([string]$Message)

    $timestamp = [DateTime]::UtcNow.ToString("o")
    Add-Content -Path $serviceLogPath -Value "$timestamp $Message" -Encoding UTF8
}

New-Item -ItemType Directory -Force -Path $appDir | Out-Null
Write-ServiceLog "Service runner started"

while ($true) {
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath -ConfigPath $ConfigPath
        Write-ServiceLog "Sync cycle finished"
    } catch {
        Write-ServiceLog "Sync cycle failed: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $IntervalSeconds
}
