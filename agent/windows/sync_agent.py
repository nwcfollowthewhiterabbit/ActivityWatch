#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


APP_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "CompanyMonitor"
CONFIG_PATH = APP_DIR / "config.json"
DB_PATH = APP_DIR / "agent.db"
LOG_PATH = APP_DIR / "agent.log"
LOCK_PATH = APP_DIR / "sync.lock"
AW_BASE_URL = "http://127.0.0.1:5600/api/0"

WINDOW_PREFIX = "aw-watcher-window"
AFK_PREFIX = "aw-watcher-afk"
WEB_PREFIX = "aw-watcher-web"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def log(message: str) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now().isoformat()} {message}"
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    print(line)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def parse_dt(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_data(event: dict) -> dict:
    data = event.get("data", {})
    return data if isinstance(data, dict) else {}


class LockError(RuntimeError):
    pass


@contextmanager
def file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            age = 0
        if age < 55:
            raise LockError("Another sync is already running")
        path.unlink(missing_ok=True)

    path.write_text(str(os.getpid()), encoding="utf-8")
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


class QueueStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._setup()

    def _setup(self) -> None:
        self.conn.execute(
            """
            create table if not exists state (
              key text primary key,
              value text not null
            )
            """
        )
        self.conn.execute(
            """
            create table if not exists queued_batches (
              id integer primary key autoincrement,
              payload text not null,
              created_at text not null
            )
            """
        )
        self.conn.commit()

    def get_state(self, key: str) -> str | None:
        row = self.conn.execute("select value from state where key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        self.conn.execute(
            "insert into state(key, value) values(?, ?) on conflict(key) do update set value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    def enqueue(self, payload: dict) -> None:
        self.conn.execute(
            "insert into queued_batches(payload, created_at) values(?, ?)",
            (json.dumps(payload), to_iso(utc_now())),
        )
        self.conn.commit()

    def iter_batches(self) -> list[sqlite3.Row]:
        return self.conn.execute("select id, payload from queued_batches order by id asc").fetchall()

    def delete_batch(self, batch_id: int) -> None:
        self.conn.execute("delete from queued_batches where id = ?", (batch_id,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class HttpClient:
    @staticmethod
    def get_json(url: str, timeout: int = 15) -> Any:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def post_json(url: str, payload: dict, headers: dict[str, str], timeout: int = 20) -> Any:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class ActivityWatchReader:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def get_buckets(self) -> dict:
        return HttpClient.get_json(f"{self.base_url}/buckets")

    def pick_bucket(self, prefix: str, preferred_hostname: str | None = None) -> str | None:
        buckets = self.get_buckets()
        candidates = []
        for bucket_id, meta in buckets.items():
            if bucket_id.startswith(prefix):
                score = 0
                if preferred_hostname and preferred_hostname.lower() in bucket_id.lower():
                    score += 10
                created = meta.get("created", "")
                candidates.append((score, created, bucket_id))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][2]

    def get_events(self, bucket_id: str, start: datetime, end: datetime, limit: int = -1) -> list[dict]:
        query = urllib.parse.urlencode(
            {"start": start.isoformat(), "end": end.isoformat(), "limit": str(limit)},
            quote_via=urllib.parse.quote,
        )
        url = f"{self.base_url}/buckets/{urllib.parse.quote(bucket_id, safe='')}/events?{query}"
        return HttpClient.get_json(url)


def compute_end(event: dict) -> datetime:
    start = parse_dt(event["timestamp"])
    duration = float(event.get("duration", 0) or 0)
    return start + timedelta(seconds=max(duration, 0))


def overlaps(start_a: datetime, end_a: datetime, start_b: datetime, end_b: datetime) -> bool:
    return max(start_a, start_b) < min(end_a, end_b)


def best_overlap(target_start: datetime, target_end: datetime, events: list[dict]) -> dict | None:
    best_event = None
    best_seconds = 0.0
    for event in events:
        start = parse_dt(event["timestamp"])
        end = compute_end(event)
        if not overlaps(target_start, target_end, start, end):
            continue
        overlap_seconds = (min(target_end, end) - max(target_start, start)).total_seconds()
        if overlap_seconds > best_seconds:
            best_seconds = overlap_seconds
            best_event = event
    return best_event


def build_payload(config: dict, hostname: str, username: str, window_events: list[dict], afk_events: list[dict], web_events: list[dict]) -> list[dict]:
    payload_events = []
    for event in window_events:
        start = parse_dt(event["timestamp"])
        end = compute_end(event)
        if end <= start:
            continue

        window_data = safe_data(event)
        afk_event = best_overlap(start, end, afk_events)
        web_event = best_overlap(start, end, web_events)
        web_data = safe_data(web_event) if web_event else {}
        afk_data = safe_data(afk_event) if afk_event else {}

        payload_events.append(
            {
                "device_id": config["device_id"],
                "device_label": config["device_label"],
                "hostname": hostname,
                "username": username,
                "timestamp_start": to_iso(start),
                "timestamp_end": to_iso(end),
                "app": window_data.get("app"),
                "window_title": window_data.get("title"),
                "url": web_data.get("url"),
                "is_afk": afk_data.get("status") == "afk",
                "source": WINDOW_PREFIX,
            }
        )
    return payload_events


def discover_username() -> str:
    return os.getenv("USERNAME") or os.getenv("USER") or "unknown"


def discover_hostname() -> str:
    return socket.gethostname()


def validate_config(config: dict) -> None:
    required = ["server_url", "api_key", "device_id", "device_label"]
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise RuntimeError(f"Missing config values: {', '.join(missing)}")


def flush_queue(store: QueueStore, config: dict) -> bool:
    for row in store.iter_batches():
        payload = json.loads(row["payload"])
        try:
            response = HttpClient.post_json(
                f"{config['server_url'].rstrip('/')}/api/v1/ingest",
                payload,
                headers={"Content-Type": "application/json", "X-API-Key": config["api_key"]},
            )
            log(f"Flushed queued batch {row['id']}: inserted={response.get('inserted')} duplicates={response.get('duplicates')}")
            store.delete_batch(row["id"])
        except Exception as exc:  # noqa: BLE001
            log(f"Queue flush paused on batch {row['id']}: {exc}")
            return False
    return True


def run_once(config_path: Path) -> int:
    config = load_json(config_path)
    validate_config(config)
    hostname = discover_hostname()
    username = discover_username()
    reader = ActivityWatchReader(config.get("activitywatch_url", AW_BASE_URL))
    store = QueueStore(DB_PATH)
    lookback_minutes = int(config.get("lookback_minutes", 10))

    try:
        queue_ok = flush_queue(store, config)

        window_bucket = reader.pick_bucket(WINDOW_PREFIX, preferred_hostname=hostname)
        afk_bucket = reader.pick_bucket(AFK_PREFIX, preferred_hostname=hostname)
        web_bucket = reader.pick_bucket(WEB_PREFIX, preferred_hostname=hostname)

        if not window_bucket or not afk_bucket:
            missing = []
            if not window_bucket:
                missing.append("window")
            if not afk_bucket:
                missing.append("afk")
            raise RuntimeError(f"ActivityWatch buckets not found: {', '.join(missing)}")

        cursor_raw = store.get_state("window_cursor")
        start = parse_dt(cursor_raw) - timedelta(minutes=2) if cursor_raw else utc_now() - timedelta(minutes=lookback_minutes)
        end = utc_now() + timedelta(seconds=5)

        window_events = reader.get_events(window_bucket, start, end)
        afk_events = reader.get_events(afk_bucket, start, end)
        web_events = reader.get_events(web_bucket, start, end) if web_bucket else []

        payload_events = build_payload(config, hostname, username, window_events, afk_events, web_events)
        if not payload_events:
            log("No new events found")
            store.set_state("window_cursor", to_iso(end))
            return 0

        payload = {"events": payload_events}
        latest_end = max(event["timestamp_end"] for event in payload_events)
        if not queue_ok:
            store.enqueue(payload)
            store.set_state("window_cursor", latest_end)
            log(f"Queued additional batch because server is still offline events={len(payload_events)}")
            return 1
        try:
            response = HttpClient.post_json(
                f"{config['server_url'].rstrip('/')}/api/v1/ingest",
                payload,
                headers={"Content-Type": "application/json", "X-API-Key": config["api_key"]},
            )
            store.set_state("window_cursor", latest_end)
            log(
                "Sync success "
                f"events={len(payload_events)} inserted={response.get('inserted')} duplicates={response.get('duplicates')}"
            )
            return 0
        except Exception as exc:  # noqa: BLE001
            store.enqueue(payload)
            store.set_state("window_cursor", latest_end)
            log(f"Sync queued offline batch events={len(payload_events)} error={exc}")
            return 1
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Company Monitor ActivityWatch sync agent")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.json")
    args = parser.parse_args()

    try:
        with file_lock(LOCK_PATH):
            return run_once(Path(args.config))
    except LockError as exc:
        log(str(exc))
        return 0
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        log(f"HTTP error {exc.code}: {body}")
        return 1
    except Exception as exc:  # noqa: BLE001
        log(f"Fatal error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
