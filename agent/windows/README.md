# Windows Client

This folder contains a semi-automated Windows client installer for the Company Monitor MVP.

## What it does

- Reads local ActivityWatch data from `http://127.0.0.1:5600/api/0`
- Matches:
  - `aw-watcher-window`
  - `aw-watcher-afk`
  - `aw-watcher-web` when available
- Sends normalized events to the central server
- Stores local sync state and offline queue in `C:\ProgramData\CompanyMonitor\agent.db`
- Writes logs to `C:\ProgramData\CompanyMonitor\agent.log`

## Easiest install on a Windows PC

Double-click:

```text
install-client.cmd
```

It will:

- ask how the PC should be named in the dashboard
- ask for a technical device ID
- ask for the ingest API key
- check that Python 3 is available
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

- `C:\ProgramData\CompanyMonitor\sync_agent.py`
- `C:\ProgramData\CompanyMonitor\config.json`
- `C:\ProgramData\CompanyMonitor\run-sync.ps1`
- `C:\ProgramData\CompanyMonitor\agent.db`
- `C:\ProgramData\CompanyMonitor\agent.log`

## Task Scheduler

The installer registers a task named `CompanyMonitorSync`.

Default schedule:

- every 1 minute
