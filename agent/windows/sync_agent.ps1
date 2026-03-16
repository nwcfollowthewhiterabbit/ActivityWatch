param(
    [string]$ConfigPath = "$env:ProgramData\CompanyMonitor\config.json"
)

$ErrorActionPreference = "Stop"

$appDir = Split-Path -Parent $ConfigPath
$statePath = Join-Path $appDir "state.json"
$queueDir = Join-Path $appDir "queue"
$logPath = Join-Path $appDir "agent.log"
$lockPath = Join-Path $appDir "sync.lock"

function Write-Log {
    param([string]$Message)

    $timestamp = [DateTime]::UtcNow.ToString("o")
    $line = "$timestamp $Message"
    Add-Content -Path $logPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Read-JsonFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return $null
    }
    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return $raw | ConvertFrom-Json
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    $dir = Split-Path -Parent $Path
    if ($dir) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $json = $Data | ConvertTo-Json -Depth 10
    Set-Content -Path $Path -Value $json -Encoding UTF8
}

function Parse-DateUtc {
    param([string]$Value)
    return [DateTime]::Parse($Value, $null, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

function To-IsoUtc {
    param([DateTime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-EventEnd {
    param([object]$Event)

    $start = Parse-DateUtc $Event.timestamp
    $duration = 0.0
    if ($null -ne $Event.duration) {
        $duration = [double]$Event.duration
    }
    return $start.AddSeconds([Math]::Max($duration, 0))
}

function Test-Overlap {
    param(
        [DateTime]$StartA,
        [DateTime]$EndA,
        [DateTime]$StartB,
        [DateTime]$EndB
    )

    $left = if ($StartA -gt $StartB) { $StartA } else { $StartB }
    $right = if ($EndA -lt $EndB) { $EndA } else { $EndB }
    return $left -lt $right
}

function Get-BestOverlapEvent {
    param(
        [DateTime]$TargetStart,
        [DateTime]$TargetEnd,
        [object[]]$Events
    )

    $bestEvent = $null
    $bestSeconds = 0.0

    foreach ($event in $Events) {
        $start = Parse-DateUtc $event.timestamp
        $end = Get-EventEnd $event
        if (-not (Test-Overlap -StartA $TargetStart -EndA $TargetEnd -StartB $start -EndB $end)) {
            continue
        }
        $overlapStart = if ($TargetStart -gt $start) { $TargetStart } else { $start }
        $overlapEnd = if ($TargetEnd -lt $end) { $TargetEnd } else { $end }
        $seconds = ($overlapEnd - $overlapStart).TotalSeconds
        if ($seconds -gt $bestSeconds) {
            $bestSeconds = $seconds
            $bestEvent = $event
        }
    }

    return $bestEvent
}

function Invoke-JsonGet {
    param([string]$Uri)

    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 20
    } catch {
        $response = $_.Exception.Response
        if ($response -and ($response.StatusCode.value__ -eq 307 -or $response.StatusCode.value__ -eq 308)) {
            $location = $response.Headers["Location"]
            if ($location) {
                return Invoke-RestMethod -Method Get -Uri $location -TimeoutSec 20
            }
        }
        throw
    }
}

function Invoke-JsonPost {
    param(
        [string]$Uri,
        [object]$Body,
        [hashtable]$Headers
    )

    $json = $Body | ConvertTo-Json -Depth 10
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    if (-not $Headers) {
        $Headers = @{}
    }
    $Headers["Content-Type"] = "application/json; charset=utf-8"

    try {
        return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $bytes -TimeoutSec 30
    } catch {
        $response = $_.Exception.Response
        if ($response -and ($response.StatusCode.value__ -eq 307 -or $response.StatusCode.value__ -eq 308)) {
            $location = $response.Headers["Location"]
            if ($location) {
                return Invoke-RestMethod -Method Post -Uri $location -Headers $Headers -Body $bytes -TimeoutSec 30
            }
        }
        throw
    }
}

function Get-BucketId {
    param(
        [pscustomobject]$Buckets,
        [string]$Prefix,
        [string]$Hostname
    )

    $candidates = @()
    foreach ($bucket in $Buckets.PSObject.Properties) {
        if ($bucket.Name.StartsWith($Prefix)) {
            $score = 0
            if ($bucket.Name.ToLower().Contains($Hostname.ToLower())) {
                $score = 10
            }
            $created = ""
            if ($bucket.Value.created) {
                $created = [string]$bucket.Value.created
            }
            $candidates += [PSCustomObject]@{
                BucketId = $bucket.Name
                Score = $score
                Created = $created
            }
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    return ($candidates | Sort-Object Score, Created -Descending | Select-Object -First 1).BucketId
}

function Get-BucketEvents {
    param(
        [string]$BaseUrl,
        [string]$BucketId,
        [DateTime]$Start,
        [DateTime]$End
    )

    if (-not $BucketId) {
        return @()
    }

    $query = "start=$([uri]::EscapeDataString($Start.ToString('o')))&end=$([uri]::EscapeDataString($End.ToString('o')))&limit=-1"
    $encodedBucket = [uri]::EscapeDataString($BucketId)
    $uri = "$BaseUrl/buckets/$encodedBucket/events?$query"
    $result = Invoke-JsonGet -Uri $uri

    if ($null -eq $result) {
        return @()
    }
    if ($result -is [System.Array]) {
        return $result
    }
    return @($result)
}

function Ensure-Lock {
    if (Test-Path $lockPath) {
        $age = ([DateTime]::UtcNow - (Get-Item $lockPath).LastWriteTimeUtc).TotalSeconds
        if ($age -lt 55) {
            throw "Another sync is already running"
        }
        Remove-Item -Force $lockPath
    }
    Set-Content -Path $lockPath -Value $PID -Encoding ASCII
}

function Release-Lock {
    if (Test-Path $lockPath) {
        Remove-Item -Force $lockPath
    }
}

function Get-State {
    $state = Read-JsonFile -Path $statePath
    if ($null -eq $state) {
        return [PSCustomObject]@{
            window_cursor = $null
        }
    }
    return $state
}

function Save-State {
    param([object]$State)
    Write-JsonFile -Path $statePath -Data $State
}

function Enqueue-Batch {
    param([object]$Payload)
    New-Item -ItemType Directory -Force -Path $queueDir | Out-Null
    $name = "{0}.json" -f ([DateTime]::UtcNow.ToString("yyyyMMddHHmmssfff"))
    Write-JsonFile -Path (Join-Path $queueDir $name) -Data $Payload
}

function Flush-Queue {
    param([object]$Config)

    if (-not (Test-Path $queueDir)) {
        return $true
    }

    $files = Get-ChildItem -Path $queueDir -Filter *.json | Sort-Object Name
    foreach ($file in $files) {
        try {
            $payload = Read-JsonFile -Path $file.FullName
            $response = Invoke-JsonPost -Uri ("{0}/api/v1/ingest" -f $Config.server_url.TrimEnd('/')) -Body $payload -Headers @{ "X-API-Key" = $Config.api_key }
            Write-Log "Flushed queued batch $($file.Name): inserted=$($response.inserted) duplicates=$($response.duplicates)"
            Remove-Item -Force $file.FullName
        } catch {
            Write-Log "Queue flush paused on $($file.Name): $($_.Exception.Message)"
            return $false
        }
    }

    return $true
}

function Build-PayloadEvents {
    param(
        [object]$Config,
        [string]$Hostname,
        [string]$Username,
        [object[]]$WindowEvents,
        [object[]]$AfkEvents,
        [object[]]$WebEvents
    )

    $payload = @()

    foreach ($event in $WindowEvents) {
        $start = Parse-DateUtc $event.timestamp
        $end = Get-EventEnd $event
        if ($end -le $start) {
            continue
        }

        $windowData = if ($event.data) { $event.data } else { [PSCustomObject]@{} }
        $afkEvent = Get-BestOverlapEvent -TargetStart $start -TargetEnd $end -Events $AfkEvents
        $webEvent = Get-BestOverlapEvent -TargetStart $start -TargetEnd $end -Events $WebEvents
        $afkData = if ($afkEvent -and $afkEvent.data) { $afkEvent.data } else { [PSCustomObject]@{} }
        $webData = if ($webEvent -and $webEvent.data) { $webEvent.data } else { [PSCustomObject]@{} }

        $payload += [PSCustomObject]@{
            device_id = $Config.device_id
            device_label = $Config.device_label
            hostname = $Hostname
            username = $Username
            timestamp_start = To-IsoUtc $start
            timestamp_end = To-IsoUtc $end
            app = $windowData.app
            window_title = $windowData.title
            url = $webData.url
            is_afk = ($afkData.status -eq "afk")
            source = "aw-watcher-window"
        }
    }

    return @($payload)
}

try {
    New-Item -ItemType Directory -Force -Path $appDir | Out-Null
    Ensure-Lock

    $config = Read-JsonFile -Path $ConfigPath
    if ($null -eq $config) {
        throw "Config file not found: $ConfigPath"
    }

    foreach ($required in @("server_url", "api_key", "device_id", "device_label")) {
        if (-not $config.$required) {
            throw "Missing config value: $required"
        }
    }

    $baseUrl = if ($config.activitywatch_url) { $config.activitywatch_url.TrimEnd('/') } else { "http://127.0.0.1:5600/api/0" }
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME
    $lookbackMinutes = if ($config.lookback_minutes) { [int]$config.lookback_minutes } else { 10 }

    $queueOk = Flush-Queue -Config $config

    $buckets = Invoke-JsonGet -Uri "$baseUrl/buckets/"
    $windowBucket = Get-BucketId -Buckets $buckets -Prefix "aw-watcher-window" -Hostname $hostname
    $afkBucket = Get-BucketId -Buckets $buckets -Prefix "aw-watcher-afk" -Hostname $hostname
    $webBucket = Get-BucketId -Buckets $buckets -Prefix "aw-watcher-web" -Hostname $hostname

    if (-not $windowBucket -or -not $afkBucket) {
        $missing = @()
        if (-not $windowBucket) { $missing += "window" }
        if (-not $afkBucket) { $missing += "afk" }
        throw "ActivityWatch buckets not found: $($missing -join ', ')"
    }

    $state = Get-State
    if ($state.window_cursor) {
        $start = (Parse-DateUtc $state.window_cursor).AddMinutes(-2)
    } else {
        $start = [DateTime]::UtcNow.AddMinutes(-1 * $lookbackMinutes)
    }
    $end = [DateTime]::UtcNow.AddSeconds(5)

    $windowEvents = Get-BucketEvents -BaseUrl $baseUrl -BucketId $windowBucket -Start $start -End $end
    $afkEvents = Get-BucketEvents -BaseUrl $baseUrl -BucketId $afkBucket -Start $start -End $end
    $webEvents = if ($webBucket) { Get-BucketEvents -BaseUrl $baseUrl -BucketId $webBucket -Start $start -End $end } else { @() }

    $payloadEvents = Build-PayloadEvents -Config $config -Hostname $hostname -Username $username -WindowEvents $windowEvents -AfkEvents $afkEvents -WebEvents $webEvents

    if ($payloadEvents.Count -eq 0) {
        $state.window_cursor = To-IsoUtc $end
        Save-State -State $state
        Write-Log "No new events found"
        exit 0
    }

    $payload = [ordered]@{
        events = @($payloadEvents)
    }
    $latestEnd = ($payloadEvents | Select-Object -ExpandProperty timestamp_end | Sort-Object | Select-Object -Last 1)

    if (-not $queueOk) {
        Enqueue-Batch -Payload $payload
        $state.window_cursor = $latestEnd
        Save-State -State $state
        Write-Log "Queued additional batch because server is still offline events=$($payloadEvents.Count)"
        exit 1
    }

    try {
        $response = Invoke-JsonPost -Uri ("{0}/api/v1/ingest" -f $config.server_url.TrimEnd('/')) -Body $payload -Headers @{ "X-API-Key" = $config.api_key }
        $state.window_cursor = $latestEnd
        Save-State -State $state
        Write-Log "Sync success events=$($payloadEvents.Count) inserted=$($response.inserted) duplicates=$($response.duplicates)"
        exit 0
    } catch {
        Enqueue-Batch -Payload $payload
        $state.window_cursor = $latestEnd
        Save-State -State $state
        Write-Log "Sync queued offline batch events=$($payloadEvents.Count) error=$($_.Exception.Message)"
        exit 1
    }
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)"
    exit 1
} finally {
    Release-Lock
}
