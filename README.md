# Company Monitor MVP

Server MVP for centralized employee activity monitoring.

## Services

- `app`: FastAPI app serving both ingest API and admin dashboard
- `db`: PostgreSQL database

## Main endpoints

- `GET /health`
- `POST /api/v1/ingest`
- `GET /login`
- `GET /`
- `GET /devices`

## Example ingest payload

```json
{
  "events": [
    {
      "device_id": "pc-014",
      "device_label": "Warehouse - PC 2",
      "hostname": "WAREHOUSE-PC-02",
      "username": "roneel",
      "timestamp_start": "2026-03-14T08:00:00Z",
      "timestamp_end": "2026-03-14T08:03:15Z",
      "app": "chrome.exe",
      "window_title": "ERPNext - Stock Entry",
      "url": "https://erp.greenleafpacific.com/app/stock-entry",
      "is_afk": false,
      "source": "aw-watcher-window"
    }
  ]
}
```

Send it with header `X-API-Key: <INGEST_API_KEY>`.

## Windows client

See [agent/windows/README.md](agent/windows/README.md) for the semi-automated Windows client installer and sync agent.
