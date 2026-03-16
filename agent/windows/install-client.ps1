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
$nssmRoot = Join-Path $appDir "nssm"
$nssmZip = Join-Path $nssmRoot "nssm.zip"
$nssmExtractDir = Join-Path $nssmRoot "pkg"
$bundledNssmZip = Join-Path $scriptDir "vendor\nssm.zip"
$nssmDownloadUrl = "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip"

function Invoke-Nssm {
    param(
        [string[]]$Arguments,
        [switch]$IgnoreErrors
    )

    & $script:NssmExe @Arguments | Out-Null
    if (-not $IgnoreErrors -and $LASTEXITCODE -ne 0) {
        throw "NSSM command failed: $($Arguments -join ' ')"
    }
}

function Ensure-Nssm {
    New-Item -ItemType Directory -Force -Path $nssmRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $nssmExtractDir | Out-Null

    $archDir = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $candidate = Get-ChildItem -Path $nssmExtractDir -Filter nssm.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match [regex]::Escape($archDir) } |
        Select-Object -First 1
    if (Test-Path $candidate) {
        return $candidate.FullName
    }

    if (Test-Path $bundledNssmZip) {
        Copy-Item -Force $bundledNssmZip $nssmZip
    } else {
        Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $nssmZip
    }
    Expand-Archive -Path $nssmZip -DestinationPath $nssmExtractDir -Force

    $candidate = Get-ChildItem -Path $nssmExtractDir -Filter nssm.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match [regex]::Escape($archDir) } |
        Select-Object -First 1

    if (-not $candidate) {
        throw "nssm.exe not found after extraction"
    }

    return $candidate.FullName
}

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
cmd.exe /c "schtasks /Query /TN ""$legacyTaskName""" | Out-Null
if ($LASTEXITCODE -eq 0) {
    cmd.exe /c "schtasks /Delete /TN ""$legacyTaskName"" /F" | Out-Null
}

$script:NssmExe = Ensure-Nssm

cmd.exe /c "sc.exe query ""$serviceName""" | Out-Null
if ($LASTEXITCODE -eq 0) {
    cmd.exe /c "sc.exe stop ""$serviceName""" | Out-Null
    Start-Sleep -Seconds 2
    try {
        Invoke-Nssm -Arguments @("remove", $serviceName, "confirm") -IgnoreErrors
    } catch {
        cmd.exe /c "sc.exe delete ""$serviceName""" | Out-Null
    }
    Start-Sleep -Seconds 2
}

Invoke-Nssm -Arguments @(
    "install",
    $serviceName,
    "powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $servicePath,
    "-ConfigPath",
    $configPath
)
Invoke-Nssm -Arguments @("set", $serviceName, "AppDirectory", $appDir)
Invoke-Nssm -Arguments @("set", $serviceName, "DisplayName", "Company Monitor Sync")
Invoke-Nssm -Arguments @("set", $serviceName, "Description", "Syncs ActivityWatch data to Company Monitor server")
Invoke-Nssm -Arguments @("set", $serviceName, "Start", "SERVICE_AUTO_START")
Invoke-Nssm -Arguments @("set", $serviceName, "ObjectName", "LocalSystem")
Invoke-Nssm -Arguments @("set", $serviceName, "AppStdout", (Join-Path $appDir "service-stdout.log"))
Invoke-Nssm -Arguments @("set", $serviceName, "AppStderr", (Join-Path $appDir "service-stderr.log"))
Invoke-Nssm -Arguments @("set", $serviceName, "AppRotateFiles", "1")
Invoke-Nssm -Arguments @("set", $serviceName, "AppRotateOnline", "0")
Invoke-Nssm -Arguments @("set", $serviceName, "AppExit", "Default", "Restart")
Invoke-Nssm -Arguments @("set", $serviceName, "AppThrottle", "1500")
Invoke-Nssm -Arguments @("set", $serviceName, "AppRestartDelay", "60000")

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath -ConfigPath $configPath
} catch {
    Write-Warning "Initial sync run failed: $($_.Exception.Message)"
}

Invoke-Nssm -Arguments @("start", $serviceName)

Write-Host "Company Monitor client installed."
Write-Host "Config:   $configPath"
Write-Host "Service:  $serviceName"
Write-Host "NSSM:     $script:NssmExe"
Write-Host "Log:      $(Join-Path $appDir 'agent.log')"
Write-Host "Svc Log:  $(Join-Path $appDir 'service.log')"
