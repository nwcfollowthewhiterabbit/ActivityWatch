# Windows Client

This folder contains a semi-automated Windows client installer for the Company Monitor MVP.

## What it does

- Reads local ActivityWatch data from `http://localhost:5600/api/0`
- Matches `aw-watcher-window`, `aw-watcher-afk`, and `aw-watcher-web` when available
- Sends normalized events to the central server
- Stores local sync state in `C:\ProgramData\CompanyMonitor\state.json`
- Stores offline queue in `C:\ProgramData\CompanyMonitor\queue\`
- Writes logs to `C:\ProgramData\CompanyMonitor\agent.log`
- Writes service runner logs to `C:\ProgramData\CompanyMonitor\service.log`
- Installs a real Windows service using NSSM

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
- install and start the sync service automatically

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
- `C:\ProgramData\CompanyMonitor\sync_service.ps1`
- `C:\ProgramData\CompanyMonitor\config.json`
- `C:\ProgramData\CompanyMonitor\state.json`
- `C:\ProgramData\CompanyMonitor\queue\`
- `C:\ProgramData\CompanyMonitor\nssm\`
- `C:\ProgramData\CompanyMonitor\agent.log`
- `C:\ProgramData\CompanyMonitor\service.log`

## Windows Service

The installer registers a Windows service named `CompanyMonitorSync`.

It starts automatically with Windows and runs a sync cycle every 60 seconds.

## Notes

- The installer downloads NSSM from the official site on first install.
- For Windows 10 and newer, the NSSM site recommends the `2.24-101` pre-release build to avoid service start issues.
