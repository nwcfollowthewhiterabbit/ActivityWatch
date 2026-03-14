# Windows Client

This folder contains a semi-automated Windows client installer for the Company Monitor MVP.

## What it does

- Reads local ActivityWatch data from `http://127.0.0.1:5600/api/0`
- Matches `aw-watcher-window`, `aw-watcher-afk`, and `aw-watcher-web` when available
- Sends normalized events to the central server
- Stores local sync state in `C:\ProgramData\CompanyMonitor\state.json`
- Stores offline queue in `C:\ProgramData\CompanyMonitor\queue\`
- Writes logs to `C:\ProgramData\CompanyMonitor\agent.log`
- Uses only standard Windows tools: PowerShell + Task Scheduler

## Easiest install on a Windows PC

Double-click:

```text
install-client.cmd
```

It will:

- ask how the PC should be named in the dashboard
- ask for a technical device ID
- ask for the ingest API key
- check that ActivityWatch is running
- install and schedule the sync agent automatically

## Manual install on a Windows PC

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-client.ps1 `
  -DeviceId "laptop-001" `
  -DeviceLabel "Office - Laptop 1" `
  -ApiKey "YOUR_INGEST_API_KEY"
```

## Installed files

- `C:\ProgramData\CompanyMonitor\sync_agent.ps1`
- `C:\ProgramData\CompanyMonitor\config.json`
- `C:\ProgramData\CompanyMonitor\run-sync.ps1`
- `C:\ProgramData\CompanyMonitor\state.json`
- `C:\ProgramData\CompanyMonitor\queue\`
- `C:\ProgramData\CompanyMonitor\agent.log`

## Task Scheduler

The installer registers a task named `CompanyMonitorSync`.

Default schedule:

- every 1 minute
