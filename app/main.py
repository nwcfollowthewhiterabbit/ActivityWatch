import hashlib
import hmac
import json
import logging
import os
import secrets
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import Generator
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Date, DateTime, Integer, String, UniqueConstraint, create_engine, delete, func, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://monitor:monitor@db:5432/monitor")
API_KEY = os.getenv("INGEST_API_KEY", "change-me")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-too")
SESSION_SECRET = os.getenv("SESSION_SECRET", "replace-session-secret")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
templates = Jinja2Templates(directory="app/templates")
FIJI_TZ = ZoneInfo("Pacific/Fiji")
logger = logging.getLogger("company_monitor")
CORPORATE_DOMAINS = {
    "cloud.greenleafpacific.com",
    "erp.greenleafpacific.com",
}
DEFAULT_RULES = {
    "max_single_afk_minutes": 20,
    "max_daily_afk_minutes": 120,
    "max_afk_sessions_per_day": 10,
    "min_corporate_minutes_per_day": 0,
    "anomaly_pct_threshold": 35,
}
AFK_SESSION_GAP = timedelta(seconds=5)


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    device_label: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_username: Mapped[str | None] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DeviceAlias(Base):
    __tablename__ = "device_aliases"

    old_device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    target_device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ActivityEvent(Base):
    __tablename__ = "activity_events"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_activity_events_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), index=True)
    device_label: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(255), index=True)
    timestamp_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    timestamp_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_date: Mapped[date] = mapped_column(Date, index=True)
    app: Mapped[str | None] = mapped_column(String(255))
    window_title: Mapped[str | None] = mapped_column(String(2000))
    url: Mapped[str | None] = mapped_column(String(2000))
    is_afk: Mapped[bool] = mapped_column(default=False, index=True)
    source: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AdminUser(Base):
    __tablename__ = "admin_users"

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )


class UserMonitoringRule(Base):
    __tablename__ = "user_monitoring_rules"

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    max_single_afk_minutes: Mapped[int | None] = mapped_column(Integer)
    max_daily_afk_minutes: Mapped[int | None] = mapped_column(Integer)
    max_afk_sessions_per_day: Mapped[int | None] = mapped_column(Integer)
    min_corporate_minutes_per_day: Mapped[int | None] = mapped_column(Integer)
    anomaly_pct_threshold: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def require_admin(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, salt, expected = stored_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    calculated = hash_password(password, salt).split("$", 2)[2]
    return hmac.compare_digest(calculated, expected)


def ensure_admin_user(db: Session, username: str, password: str) -> None:
    user = db.get(AdminUser, username)
    if user:
        return
    db.add(AdminUser(username=username, password_hash=hash_password(password)))
    db.commit()


def sync_device_labels(db: Session) -> None:
    devices = db.execute(select(Device)).scalars().all()
    for device in devices:
        db.execute(
            update(ActivityEvent)
            .where(ActivityEvent.device_id == device.device_id, ActivityEvent.device_label != device.device_label)
            .values(device_label=device.device_label)
        )
    db.commit()


def sync_device_last_seen(db: Session) -> None:
    rows = db.execute(select(ActivityEvent.device_id, func.max(ActivityEvent.timestamp_end)).group_by(ActivityEvent.device_id))
    for device_id, last_seen_at in rows:
        device = db.get(Device, device_id)
        if device and last_seen_at and (not device.last_seen_at or last_seen_at > device.last_seen_at):
            device.last_seen_at = last_seen_at
            db.add(device)
    db.commit()


def parse_dt(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def event_fingerprint(payload: dict) -> str:
    raw = "|".join(
        [
            payload.get("device_id", ""),
            payload.get("username", ""),
            payload.get("timestamp_start", ""),
            payload.get("timestamp_end", ""),
            payload.get("app", "") or "",
            payload.get("window_title", "") or "",
            payload.get("url", "") or "",
            payload.get("source", "") or "",
            str(payload.get("is_afk", False)),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def matching_event_id(db: Session, event: ActivityEvent) -> int | None:
    return db.execute(
        select(ActivityEvent.id)
        .where(
            ActivityEvent.device_id == event.device_id,
            ActivityEvent.username == event.username,
            ActivityEvent.timestamp_start == event.timestamp_start,
            ActivityEvent.timestamp_end == event.timestamp_end,
            ActivityEvent.app == event.app,
            ActivityEvent.window_title == event.window_title,
            ActivityEvent.url == event.url,
            ActivityEvent.source == event.source,
            ActivityEvent.is_afk == event.is_afk,
        )
        .limit(1)
    ).scalar_one_or_none()


def normalize_device_identity(raw_event: dict) -> dict:
    normalized = dict(raw_event)
    device_id = (normalized.get("device_id") or normalized.get("device_label") or "").strip()
    device_label = (normalized.get("device_label") or device_id).strip()
    normalized["device_id"] = device_id
    normalized["device_label"] = device_label
    return normalized


def canonicalize_ingest_device(db: Session, raw_event: dict) -> dict:
    alias = db.get(DeviceAlias, raw_event["device_id"])
    if not alias:
        return raw_event

    target = db.get(Device, alias.target_device_id)
    if not target:
        return raw_event

    canonical_event = dict(raw_event)
    canonical_event["device_id"] = target.device_id
    canonical_event["device_label"] = target.device_label
    canonical_event["hostname"] = canonical_event.get("hostname") or target.hostname
    return canonical_event


def merge_device_events(db: Session, source: Device, target: Device) -> None:
    source_events = db.execute(select(ActivityEvent).where(ActivityEvent.device_id == source.device_id)).scalars().all()
    for event in source_events:
        fingerprint_payload = {
            "device_id": target.device_id,
            "username": event.username,
            "timestamp_start": event.timestamp_start.isoformat(),
            "timestamp_end": event.timestamp_end.isoformat(),
            "app": event.app,
            "window_title": event.window_title,
            "url": event.url,
            "source": event.source,
            "is_afk": event.is_afk,
        }
        new_fingerprint = event_fingerprint(fingerprint_payload)
        event.device_id = target.device_id
        event.device_label = target.device_label
        event.fingerprint = new_fingerprint
        duplicate_event_id = db.execute(
            select(ActivityEvent.id).where(ActivityEvent.fingerprint == new_fingerprint, ActivityEvent.id != event.id)
        ).scalar_one_or_none()
        if not duplicate_event_id:
            duplicate_event_id = matching_event_id(db, event)
            if duplicate_event_id == event.id:
                duplicate_event_id = None
        if duplicate_event_id:
            db.delete(event)
            continue

        db.add(event)


def looks_like_event(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {str(key).lower() for key in value.keys()}
    markers = {"device_id", "timestamp_start", "timestamp_end", "hostname", "username"}
    return len(keys & markers) >= 3


def extract_events(payload: object) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    lower_key_map = {str(key).lower(): key for key in payload.keys()}
    for candidate_key in ("events", "items", "value", "values", "data"):
        if candidate_key in lower_key_map:
            value = payload[lower_key_map[candidate_key]]
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = extract_events(value)
                if nested:
                    return nested
                if looks_like_event(value):
                    return [value]

    if looks_like_event(payload):
        return [payload]

    dict_values = list(payload.values())
    if dict_values and all(isinstance(item, dict) for item in dict_values):
        event_like_values = [item for item in dict_values if looks_like_event(item)]
        if event_like_values:
            return event_like_values

    return []


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_admin_user(db, ADMIN_USERNAME, ADMIN_PASSWORD)
        sync_device_labels(db)
        sync_device_last_seen(db)
    yield


app = FastAPI(title="Company Monitor", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def format_fiji_dt(value: datetime | None) -> str:
    if not value:
        return "-"
    return value.astimezone(FIJI_TZ).strftime("%Y-%m-%d %H:%M")


def format_fiji_time(value: datetime | None) -> str:
    if not value:
        return "-"
    return value.astimezone(FIJI_TZ).strftime("%H:%M")


def previous_closed_workday(reference_dt: datetime | None = None) -> date:
    current_local_date = (reference_dt or datetime.now(FIJI_TZ)).astimezone(FIJI_TZ).date()
    candidate = current_local_date - timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate -= timedelta(days=1)
    return candidate


def local_day_bounds_utc(day_value: date) -> tuple[datetime, datetime]:
    local_start = datetime.combine(day_value, datetime.min.time(), tzinfo=FIJI_TZ)
    local_end = local_start + timedelta(days=1)
    return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)


def hours_label(seconds: float) -> str:
    return f"{seconds / 3600:.2f}"


def minutes_label(seconds: float) -> str:
    return f"{seconds / 60:.0f}"


def pct_label(value: float) -> str:
    return f"{value:.0f}%"


def event_seconds(event: ActivityEvent) -> float:
    return max((event.timestamp_end - event.timestamp_start).total_seconds(), 0)


def normalized_domain(value: str | None) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    domain = (parsed.netloc or value).lower()
    return domain.split("@")[-1].split(":")[0]


def is_corporate_url(value: str | None) -> bool:
    return normalized_domain(value) in CORPORATE_DOMAINS


def is_machine_username(value: str | None) -> bool:
    if not value:
        return True
    normalized = value.strip().lower()
    return (
        normalized.endswith("$")
        or normalized in {"system", "local system", "localsystem", "local service", "network service"}
        or normalized.startswith("desktop-")
        or normalized.startswith("laptop-")
    )


def preferred_person_label(raw_username: str | None, preferred_device_label: str | None = None) -> str:
    if preferred_device_label:
        return preferred_device_label
    return (raw_username or "Unknown").strip() or "Unknown"


def build_device_label_map(devices: list[Device]) -> dict[str, str]:
    return {device.device_id: device.device_label for device in devices}


def canonical_device_label(device_id: str | None, fallback_label: str | None, device_label_map: dict[str, str]) -> str:
    if device_id and device_id in device_label_map:
        return device_label_map[device_id]
    return (fallback_label or device_id or "Unknown").strip() or "Unknown"


def summarize_rule_values(rule: UserMonitoringRule | None) -> dict[str, int]:
    return {
        key: int(getattr(rule, key)) if rule and getattr(rule, key) is not None else default
        for key, default in DEFAULT_RULES.items()
    }


def build_daily_summaries(events: list[ActivityEvent], key_getter, device_label_map: dict[str, str] | None = None) -> dict[tuple[str, date], dict]:
    summaries: dict[tuple[str, date], dict] = {}
    afk_trackers: dict[tuple[str, date], dict[str, datetime | None | float]] = {}
    device_label_map = device_label_map or {}

    for event in sorted(events, key=lambda item: (key_getter(item), item.event_date, item.timestamp_start, item.id)):
        identity = str(key_getter(event))
        summary_key = (identity, event.event_date)
        summary = summaries.setdefault(
            summary_key,
            {
                "identity": identity,
                "date": event.event_date,
                "active_seconds": 0.0,
                "afk_seconds": 0.0,
                "corporate_seconds": 0.0,
                "afk_sessions": 0,
                "longest_afk_seconds": 0.0,
                "events_count": 0,
                "devices": Counter(),
                "hostnames": Counter(),
                "usernames": Counter(),
                "apps": Counter(),
                "corporate_domains": Counter(),
            },
        )
        tracker = afk_trackers.setdefault(summary_key, {"start": None, "end": None})

        seconds = event_seconds(event)
        summary["events_count"] += 1
        resolved_device_label = canonical_device_label(event.device_id, event.device_label, device_label_map)
        if resolved_device_label:
            summary["devices"][resolved_device_label] += seconds
        if event.hostname:
            summary["hostnames"][event.hostname] += seconds
        if event.username:
            summary["usernames"][event.username] += seconds
        if event.app:
            summary["apps"][event.app] += seconds

        if event.is_afk:
            summary["afk_seconds"] += seconds
            tracker_start = tracker["start"]
            tracker_end = tracker["end"]
            if tracker_start is None or tracker_end is None:
                summary["afk_sessions"] += 1
                tracker["start"] = event.timestamp_start
                tracker["end"] = event.timestamp_end
            elif event.timestamp_start <= tracker_end + AFK_SESSION_GAP:
                tracker["end"] = max(tracker_end, event.timestamp_end)
            else:
                summary["longest_afk_seconds"] = max(
                    summary["longest_afk_seconds"],
                    (tracker_end - tracker_start).total_seconds(),
                )
                summary["afk_sessions"] += 1
                tracker["start"] = event.timestamp_start
                tracker["end"] = event.timestamp_end
        else:
            summary["active_seconds"] += seconds
            if is_corporate_url(event.url):
                domain = normalized_domain(event.url)
                summary["corporate_seconds"] += seconds
                summary["corporate_domains"][domain] += seconds
            tracker_start = tracker["start"]
            tracker_end = tracker["end"]
            if tracker_start is not None and tracker_end is not None:
                summary["longest_afk_seconds"] = max(
                    summary["longest_afk_seconds"],
                    (tracker_end - tracker_start).total_seconds(),
                )
            tracker["start"] = None
            tracker["end"] = None

    for summary_key, tracker in afk_trackers.items():
        tracker_start = tracker["start"]
        tracker_end = tracker["end"]
        if tracker_start is not None and tracker_end is not None:
            summaries[summary_key]["longest_afk_seconds"] = max(
                summaries[summary_key]["longest_afk_seconds"],
                (tracker_end - tracker_start).total_seconds(),
            )

    return summaries


def attach_anomaly_flags(daily_rows: list[dict], rule_values: dict[str, int]) -> list[dict]:
    enriched_rows: list[dict] = []
    history: list[dict] = []
    threshold = rule_values["anomaly_pct_threshold"] / 100

    for row in daily_rows:
        flags: list[str] = []
        baseline_source = history[-7:]
        baseline_active = 0.0
        baseline_afk = 0.0
        baseline_corporate = 0.0

        if baseline_source:
            baseline_active = sum(item["active_seconds"] for item in baseline_source) / len(baseline_source)
            baseline_afk = sum(item["afk_seconds"] for item in baseline_source) / len(baseline_source)
            baseline_corporate = sum(item["corporate_seconds"] for item in baseline_source) / len(baseline_source)

            if baseline_active > 0 and row["active_seconds"] < baseline_active * (1 - threshold):
                flags.append("Low active time")
            if baseline_afk > 0 and row["afk_seconds"] > baseline_afk * (1 + threshold):
                flags.append("AFK spike")
            if baseline_corporate > 0 and row["corporate_seconds"] < baseline_corporate * (1 - threshold):
                flags.append("Corporate site drop")

        if (row["longest_afk_seconds"] / 60) > rule_values["max_single_afk_minutes"]:
            flags.append("Long AFK session")
        if (row["afk_seconds"] / 60) > rule_values["max_daily_afk_minutes"]:
            flags.append("Daily AFK over limit")
        if row["afk_sessions"] > rule_values["max_afk_sessions_per_day"]:
            flags.append("Too many AFK sessions")
        if (row["corporate_seconds"] / 60) < rule_values["min_corporate_minutes_per_day"]:
            flags.append("Low corporate-site time")

        row["baseline_active_seconds"] = baseline_active
        row["baseline_afk_seconds"] = baseline_afk
        row["baseline_corporate_seconds"] = baseline_corporate
        row["flags"] = flags
        row["is_flagged"] = bool(flags)
        row["active_delta_pct"] = ((row["active_seconds"] - baseline_active) / baseline_active * 100) if baseline_active else 0.0
        row["afk_delta_pct"] = ((row["afk_seconds"] - baseline_afk) / baseline_afk * 100) if baseline_afk else 0.0
        row["corporate_delta_pct"] = (
            ((row["corporate_seconds"] - baseline_corporate) / baseline_corporate * 100) if baseline_corporate else 0.0
        )
        enriched_rows.append(row)
        history.append(row)

    return enriched_rows


def top_counter_entries(counter: Counter, limit: int = 3) -> list[tuple[str, float]]:
    return [(name, float(value)) for name, value in counter.most_common(limit)]


def percent_of(value: float, total: float) -> float:
    if total <= 0:
        return 0.0
    return round((value / total) * 100, 1)


def get_rule_values(db: Session, username: str) -> tuple[UserMonitoringRule | None, dict[str, int]]:
    rule = db.get(UserMonitoringRule, username)
    return rule, summarize_rule_values(rule)


def clamp_event(event: ActivityEvent, start_utc: datetime, end_utc: datetime) -> tuple[datetime, datetime] | None:
    start = max(event.timestamp_start, start_utc)
    end = min(event.timestamp_end, end_utc)
    if end <= start:
        return None
    return start, end


def pct_position(start: datetime, end: datetime, boundary_start: datetime, boundary_end: datetime) -> tuple[float, float]:
    total = max((boundary_end - boundary_start).total_seconds(), 1)
    left = ((start - boundary_start).total_seconds() / total) * 100
    width = max(((end - start).total_seconds() / total) * 100, 0.15)
    return left, width


def compact_segments(segments: list[dict], key_name: str) -> list[dict]:
    if not segments:
        return []
    merged = [segments[0].copy()]
    for segment in segments[1:]:
        prev = merged[-1]
        if (
            prev[key_name] == segment[key_name]
            and abs(prev["end_pct"] - segment["left_pct"]) < 0.05
        ):
            prev["end_pct"] = segment["left_pct"] + segment["width_pct"]
            prev["width_pct"] = prev["end_pct"] - prev["left_pct"]
            prev["end_label"] = segment["end_label"]
        else:
            merged.append(segment.copy())
    return merged


def short_domain(value: str | None) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    return parsed.netloc or value


def timeline_tooltip(title: str, start: datetime, end: datetime, details: list[str] | None = None) -> str:
    parts = [
        f"<strong>{title}</strong>",
        f"{format_fiji_dt(start)} - {format_fiji_dt(end)}",
    ]
    if details:
        parts.extend(details)
    return "<br>".join(parts)


def merge_timeline_items(items: list[dict], merge_gap: timedelta = timedelta(seconds=5)) -> list[dict]:
    if not items:
        return []

    sorted_items = sorted(items, key=lambda item: item["start_dt"])
    merged = [sorted_items[0].copy()]

    for item in sorted_items[1:]:
        prev = merged[-1]
        same_item = (
            prev["group"] == item["group"]
            and prev["content"] == item["content"]
            and prev["className"] == item["className"]
            and prev.get("merge_key") == item.get("merge_key")
        )
        close_enough = item["start_dt"] <= prev["end_dt"] + merge_gap
        if same_item and close_enough:
            prev["end_dt"] = max(prev["end_dt"], item["end_dt"])
            prev["title"] = timeline_tooltip(
                prev["content"],
                prev["start_dt"],
                prev["end_dt"],
                prev.get("details"),
            )
            continue
        merged.append(item.copy())

    return merged


templates.env.filters["fiji_dt"] = format_fiji_dt
templates.env.filters["fiji_time"] = format_fiji_time
templates.env.filters["hours"] = hours_label
templates.env.filters["minutes"] = minutes_label
templates.env.filters["pct"] = pct_label


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    db.execute(select(1))
    return {"status": "ok", "utc": datetime.now(timezone.utc).isoformat()}


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    from_date: str | None = None,
    to_date: str | None = None,
    device_id: str | None = None,
    username: str | None = None,
    db: Session = Depends(get_db),
):
    require_admin(request)

    closed_workday = previous_closed_workday()
    use_default_closed_day = not from_date and not to_date
    date_from = datetime.fromisoformat(from_date).date() if from_date else closed_workday
    date_to = datetime.fromisoformat(to_date).date() if to_date else closed_workday

    if use_default_closed_day:
        latest_closed_with_data = None
        probe_day = closed_workday
        for _ in range(14):
            probe_start_utc, probe_end_utc = local_day_bounds_utc(probe_day)
            has_data = db.execute(
                select(ActivityEvent.id)
                .where(ActivityEvent.timestamp_end > probe_start_utc, ActivityEvent.timestamp_start < probe_end_utc)
                .limit(1)
            ).scalar_one_or_none()
            if has_data:
                latest_closed_with_data = probe_day
                break
            probe_day -= timedelta(days=1)
            while probe_day.weekday() >= 5:
                probe_day -= timedelta(days=1)
        if latest_closed_with_data:
            date_from = latest_closed_with_data
            date_to = latest_closed_with_data

    range_start_utc, _ = local_day_bounds_utc(date_from)
    _, range_end_utc = local_day_bounds_utc(date_to)

    base_query = select(ActivityEvent).where(ActivityEvent.timestamp_end > range_start_utc, ActivityEvent.timestamp_start < range_end_utc)
    if device_id:
        base_query = base_query.where(ActivityEvent.device_id == device_id)
    if username:
        base_query = base_query.where(ActivityEvent.username == username)

    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    device_label_map = build_device_label_map(devices)
    events = db.execute(base_query.order_by(ActivityEvent.timestamp_start.asc()).limit(20000)).scalars().all()
    for event in events:
        event.device_label = canonical_device_label(event.device_id, event.device_label, device_label_map)
    daily_by_user = build_daily_summaries(events, lambda event: event.device_id, device_label_map=device_label_map)

    total_seconds = 0.0
    afk_seconds = 0.0
    corporate_seconds = 0.0
    apps: dict[str, float] = defaultdict(float)
    sites: dict[str, float] = defaultdict(float)
    daily: dict[str, dict[str, float]] = defaultdict(lambda: {"active": 0.0, "afk": 0.0, "corporate": 0.0})
    user_rollups: dict[str, dict] = defaultdict(
        lambda: {
            "device_id": "",
            "display_name": "",
            "active_seconds": 0.0,
            "afk_seconds": 0.0,
            "corporate_seconds": 0.0,
            "afk_sessions": 0,
            "longest_afk_seconds": 0.0,
            "days": [],
            "devices": Counter(),
            "status_flags": [],
        }
    )

    for event in events:
        seconds = event_seconds(event)
        total_seconds += seconds
        if event.is_afk:
            afk_seconds += seconds
            daily[str(event.event_date)]["afk"] += seconds
        else:
            apps[event.app or "Unknown"] += seconds
            if event.url:
                sites[event.url] += seconds
            daily[str(event.event_date)]["active"] += seconds
            if is_corporate_url(event.url):
                corporate_seconds += seconds
                daily[str(event.event_date)]["corporate"] += seconds

    device_to_username: dict[str, str] = {}
    for event in events:
        if event.device_id not in device_to_username and not is_machine_username(event.username):
            device_to_username[event.device_id] = event.username
        elif event.device_id not in device_to_username:
            device_to_username[event.device_id] = event.username

    for (summary_device_id, _), summary in daily_by_user.items():
        rule_owner = device_to_username.get(summary_device_id, summary_device_id)
        rule, rule_values = get_rule_values(db, rule_owner)
        user_rollup = user_rollups[summary_device_id]
        user_rollup["device_id"] = summary_device_id
        user_rollup["active_seconds"] += summary["active_seconds"]
        user_rollup["afk_seconds"] += summary["afk_seconds"]
        user_rollup["corporate_seconds"] += summary["corporate_seconds"]
        user_rollup["afk_sessions"] += summary["afk_sessions"]
        user_rollup["longest_afk_seconds"] = max(user_rollup["longest_afk_seconds"], summary["longest_afk_seconds"])
        user_rollup["devices"].update(summary["devices"])
        day_row = {
            "date": summary["date"],
            "active_seconds": summary["active_seconds"],
            "afk_seconds": summary["afk_seconds"],
            "corporate_seconds": summary["corporate_seconds"],
            "afk_sessions": summary["afk_sessions"],
            "longest_afk_seconds": summary["longest_afk_seconds"],
        }
        user_rollup["days"].append(day_row)
        flagged_day = attach_anomaly_flags([day_row.copy()], rule_values)[0]
        if flagged_day["flags"]:
            user_rollup["status_flags"].extend(flagged_day["flags"])
        user_rollup["rule"] = rule
        user_rollup["rule_values"] = rule_values
        user_rollup["display_name"] = canonical_device_label(summary_device_id, None, device_label_map)

    operator_rows = []
    for row in user_rollups.values():
        day_rows = attach_anomaly_flags(sorted(row["days"], key=lambda item: item["date"]), row["rule_values"])
        latest_day = day_rows[-1] if day_rows else None
        total_active = row["active_seconds"]
        total_afk = row["afk_seconds"]
        total_combined = total_active + total_afk
        operator_rows.append(
            {
                "device_id": row["device_id"],
                "display_name": row["display_name"] or row["device_id"],
                "active_seconds": total_active,
                "afk_seconds": total_afk,
                "corporate_seconds": row["corporate_seconds"],
                "afk_sessions": row["afk_sessions"],
                "longest_afk_seconds": row["longest_afk_seconds"],
                "afk_ratio": percent_of(total_afk, total_combined),
                "corporate_ratio": percent_of(row["corporate_seconds"], total_active),
                "latest_day": latest_day,
                "flags": latest_day["flags"] if latest_day else [],
                "rule_values": row["rule_values"],
            }
        )

    operator_rows.sort(key=lambda item: (len(item["flags"]), item["afk_seconds"]), reverse=True)
    active_seconds = total_seconds - afk_seconds
    daily_rows = []
    max_daily_total = max((values["active"] + values["afk"] for values in daily.values()), default=0.0)
    for day_key, values in sorted(daily.items()):
        total_day = values["active"] + values["afk"]
        daily_rows.append(
            {
                "date": day_key,
                "active_seconds": values["active"],
                "afk_seconds": values["afk"],
                "corporate_seconds": values["corporate"],
                "active_pct": percent_of(values["active"], total_day),
                "afk_pct": percent_of(values["afk"], total_day),
                "corporate_pct": percent_of(values["corporate"], values["active"]),
                "bar_pct": percent_of(total_day, max_daily_total) if max_daily_total else 0.0,
            }
        )

    latest_by_device: dict[str, ActivityEvent] = {}
    for event in reversed(events):
        latest_by_device.setdefault(event.device_id, event)
    recent_statuses = sorted(latest_by_device.values(), key=lambda item: item.timestamp_start, reverse=True)[:20]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "devices": devices,
            "display_timezone": "Pacific/Fiji",
            "selected_device_id": device_id or "",
            "selected_username": username or "",
            "from_date": str(date_from),
            "to_date": str(date_to),
            "metrics": {
                "total_hours": round(total_seconds / 3600, 2),
                "active_hours": round(active_seconds / 3600, 2),
                "afk_hours": round(afk_seconds / 3600, 2),
                "corporate_hours": round(corporate_seconds / 3600, 2),
                "events_count": len(events),
                "tracked_users": len(operator_rows),
            },
            "top_apps": sorted(apps.items(), key=lambda item: item[1], reverse=True)[:15],
            "top_sites": sorted(sites.items(), key=lambda item: item[1], reverse=True)[:15],
            "daily_rows": daily_rows,
            "operator_rows": operator_rows,
            "flagged_rows": [row for row in operator_rows if row["flags"]][:6],
            "corporate_domains": sorted(CORPORATE_DOMAINS),
            "recent_statuses": recent_statuses,
        },
    )


@app.get("/timeline", response_class=HTMLResponse)
def timeline_page(
    request: Request,
    device_id: str | None = None,
    day: str | None = None,
    db: Session = Depends(get_db),
):
    require_admin(request)

    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    if not devices:
        return templates.TemplateResponse(
            request,
            "timeline.html",
            {
                "request": request,
                "devices": [],
                "selected_device_id": "",
                "selected_day": day or str(datetime.now(FIJI_TZ).date()),
                "display_timezone": "Pacific/Fiji",
                "timeline_rows": [],
                "hour_markers": [],
                "selected_device": None,
            },
        )

    selected_device_id = device_id or devices[0].device_id
    selected_day = datetime.fromisoformat(day).date() if day else datetime.now(FIJI_TZ).date()
    selected_device = db.get(Device, selected_device_id)

    local_start = datetime.combine(selected_day, datetime.min.time(), tzinfo=FIJI_TZ)
    local_end = local_start + timedelta(days=1)
    start_utc = local_start.astimezone(timezone.utc)
    end_utc = local_end.astimezone(timezone.utc)

    events = (
        db.execute(
            select(ActivityEvent)
            .where(
                ActivityEvent.device_id == selected_device_id,
                ActivityEvent.timestamp_end > start_utc,
                ActivityEvent.timestamp_start < end_utc,
            )
            .order_by(ActivityEvent.timestamp_start)
        )
        .scalars()
        .all()
    )

    activity_segments = []
    site_segments = []
    app_segments = []

    for event in events:
        bounded = clamp_event(event, start_utc, end_utc)
        if not bounded:
            continue
        clipped_start, clipped_end = bounded
        local_clipped_start = clipped_start.astimezone(FIJI_TZ)
        local_clipped_end = clipped_end.astimezone(FIJI_TZ)
        left_pct, width_pct = pct_position(local_clipped_start, local_clipped_end, local_start, local_end)

        activity_segments.append(
            {
                "label": "afk" if event.is_afk else "not-afk",
                "left_pct": left_pct,
                "width_pct": width_pct,
                "end_pct": left_pct + width_pct,
                "start_label": local_clipped_start.strftime("%H:%M"),
                "end_label": local_clipped_end.strftime("%H:%M"),
                "title": f"{'AFK' if event.is_afk else 'Active'} {local_clipped_start.strftime('%H:%M')} - {local_clipped_end.strftime('%H:%M')}",
                "css_class": "afk" if event.is_afk else "active",
            }
        )

        if event.url:
            site_segments.append(
                {
                    "label": short_domain(event.url),
                    "left_pct": left_pct,
                    "width_pct": width_pct,
                    "title": f"{event.url}\n{local_clipped_start.strftime('%H:%M')} - {local_clipped_end.strftime('%H:%M')}",
                    "css_class": "site",
                }
            )

        app_label = (event.window_title or event.app or "Unknown").strip()
        app_segments.append(
            {
                "label": app_label[:48],
                "left_pct": left_pct,
                "width_pct": width_pct,
                "title": f"{event.app or 'Unknown'} | {app_label}\n{local_clipped_start.strftime('%H:%M')} - {local_clipped_end.strftime('%H:%M')}",
                "css_class": "app",
            }
        )

    activity_segments = compact_segments(activity_segments, "label")
    hour_markers = [
        {"label": (local_start + timedelta(hours=hour)).strftime("%H:%M"), "left_pct": (hour / 24) * 100}
        for hour in range(25)
    ]

    timeline_rows = [
        {"label": "Activity", "segments": activity_segments, "row_class": "activity-row"},
        {"label": "Sites", "segments": site_segments, "row_class": "sites-row"},
        {"label": "Apps", "segments": app_segments, "row_class": "apps-row"},
    ]

    return templates.TemplateResponse(
        request,
        "timeline.html",
        {
            "request": request,
            "devices": devices,
            "selected_device_id": selected_device_id,
            "selected_day": str(selected_day),
            "display_timezone": "Pacific/Fiji",
            "selected_device": selected_device,
            "timeline_rows": timeline_rows,
            "hour_markers": hour_markers,
        },
    )


@app.get("/api/v1/timeline")
def timeline_data(
    request: Request,
    device_id: str,
    day: str | None = None,
    db: Session = Depends(get_db),
):
    require_admin(request)

    selected_day = datetime.fromisoformat(day).date() if day else datetime.now(FIJI_TZ).date()
    local_start = datetime.combine(selected_day, datetime.min.time(), tzinfo=FIJI_TZ)
    local_end = local_start + timedelta(days=1)
    start_utc = local_start.astimezone(timezone.utc)
    end_utc = local_end.astimezone(timezone.utc)

    events = (
        db.execute(
            select(ActivityEvent)
            .where(
                ActivityEvent.device_id == device_id,
                ActivityEvent.timestamp_end > start_utc,
                ActivityEvent.timestamp_start < end_utc,
            )
            .order_by(ActivityEvent.timestamp_start)
        )
        .scalars()
        .all()
    )

    groups = [
        {"id": "activity", "content": "Activity"},
        {"id": "sites", "content": "Sites"},
        {"id": "apps", "content": "Apps"},
    ]
    items: list[dict] = []
    activity_items: list[dict] = []
    site_items: list[dict] = []
    app_items: list[dict] = []
    first_event_start: datetime | None = None
    last_event_end: datetime | None = None

    for index, event in enumerate(events):
        bounded = clamp_event(event, start_utc, end_utc)
        if not bounded:
            continue
        clipped_start, clipped_end = bounded
        if first_event_start is None or clipped_start < first_event_start:
            first_event_start = clipped_start
        if last_event_end is None or clipped_end > last_event_end:
            last_event_end = clipped_end
        start_iso = clipped_start.astimezone(FIJI_TZ).isoformat()
        end_iso = clipped_end.astimezone(FIJI_TZ).isoformat()

        activity_items.append(
            {
                "id": f"e{index}-activity",
                "group": "activity",
                "content": "afk" if event.is_afk else "not-afk",
                "start_dt": clipped_start.astimezone(FIJI_TZ),
                "end_dt": clipped_end.astimezone(FIJI_TZ),
                "title": timeline_tooltip(
                    "AFK" if event.is_afk else "Active",
                    clipped_start,
                    clipped_end,
                    [f"User: {event.username}", f"Source: {event.source or '-'}"],
                ),
                "details": [f"User: {event.username}", f"Source: {event.source or '-'}"],
                "merge_key": "afk" if event.is_afk else "not-afk",
                "className": "aw-item aw-activity-afk" if event.is_afk else "aw-item aw-activity-active",
            }
        )

        if event.url:
            domain = short_domain(event.url)
            site_items.append(
                {
                    "id": f"e{index}-site",
                    "group": "sites",
                    "content": domain,
                    "start_dt": clipped_start.astimezone(FIJI_TZ),
                    "end_dt": clipped_end.astimezone(FIJI_TZ),
                    "title": timeline_tooltip(
                        domain,
                        clipped_start,
                        clipped_end,
                        [event.url],
                    ),
                    "details": [event.url],
                    "merge_key": domain.lower(),
                    "className": "aw-item aw-site",
                }
            )

        app_name = (event.app or event.window_title or "Unknown").strip()
        app_display = app_name.removesuffix(".exe")[:90]
        window_label = (event.window_title or app_display or "Unknown").strip()
        app_items.append(
            {
                "id": f"e{index}-app",
                "group": "apps",
                "content": app_display,
                "start_dt": clipped_start.astimezone(FIJI_TZ),
                "end_dt": clipped_end.astimezone(FIJI_TZ),
                "title": timeline_tooltip(
                    app_display or "Unknown",
                    clipped_start,
                    clipped_end,
                    [window_label, f"User: {event.username}"],
                ),
                "details": [window_label, f"User: {event.username}"],
                "merge_key": app_display.lower(),
                "className": "aw-item aw-app",
            }
        )

    for merged_index, activity_item in enumerate(merge_timeline_items(activity_items)):
        items.append(
            {
                "id": f"merged-activity-{merged_index}",
                "group": "activity",
                "content": activity_item["content"],
                "start": activity_item["start_dt"].isoformat(),
                "end": activity_item["end_dt"].isoformat(),
                "title": activity_item["title"],
                "className": activity_item["className"],
            }
        )

    for merged_index, site_item in enumerate(merge_timeline_items(site_items)):
        items.append(
            {
                "id": f"merged-site-{merged_index}",
                "group": "sites",
                "content": site_item["content"],
                "start": site_item["start_dt"].isoformat(),
                "end": site_item["end_dt"].isoformat(),
                "title": site_item["title"],
                "className": site_item["className"],
            }
        )

    for merged_index, app_item in enumerate(merge_timeline_items(app_items)):
        items.append(
            {
                "id": f"merged-app-{merged_index}",
                "group": "apps",
                "content": app_item["content"],
                "start": app_item["start_dt"].isoformat(),
                "end": app_item["end_dt"].isoformat(),
                "title": app_item["title"],
                "className": app_item["className"],
            }
        )

    focus_start = local_start
    focus_end = local_end
    if first_event_start and last_event_end:
        first_local = first_event_start.astimezone(FIJI_TZ)
        last_local = last_event_end.astimezone(FIJI_TZ)
        event_span = max(last_local - first_local, timedelta(minutes=10))
        padding = min(max(event_span * 0.2, timedelta(minutes=10)), timedelta(minutes=45))
        focus_start = max(local_start, first_local - padding)
        focus_end = min(local_end, last_local + padding)

        # Keep at least a narrow readable range so item labels have room to render.
        minimum_focus_span = timedelta(minutes=45)
        if focus_end - focus_start < minimum_focus_span:
            midpoint = focus_start + ((focus_end - focus_start) / 2)
            half_span = minimum_focus_span / 2
            focus_start = max(local_start, midpoint - half_span)
            focus_end = min(local_end, midpoint + half_span)

    return {
        "groups": groups,
        "items": items,
        "window": {
            "start": local_start.isoformat(),
            "end": local_end.isoformat(),
        },
        "focus_window": {
            "start": focus_start.isoformat(),
            "end": focus_end.isoformat(),
        },
        "has_items": bool(items),
        "display_timezone": "Pacific/Fiji",
    }


@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    event_counts = {
        row.device_id: row.events_count
        for row in db.execute(
            select(ActivityEvent.device_id, func.count(ActivityEvent.id).label("events_count")).group_by(ActivityEvent.device_id)
        )
    }
    devices_by_hostname: dict[str, list[Device]] = defaultdict(list)
    for device in devices:
        if device.hostname:
            devices_by_hostname[device.hostname].append(device)
    duplicate_groups = [group for group in devices_by_hostname.values() if len(group) > 1]
    duplicate_groups.sort(key=lambda group: group[0].hostname or "")
    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "request": request,
            "devices": devices,
            "event_counts": event_counts,
            "duplicate_groups": duplicate_groups,
            "display_timezone": "Pacific/Fiji",
        },
    )


@app.get("/users/{username}", response_class=HTMLResponse)
def user_detail_page(
    username: str,
    request: Request,
    from_date: str | None = None,
    to_date: str | None = None,
    device_id: str | None = None,
    db: Session = Depends(get_db),
):
    require_admin(request)

    today = datetime.now(timezone.utc).date()
    date_from = datetime.fromisoformat(from_date).date() if from_date else today - timedelta(days=13)
    date_to = datetime.fromisoformat(to_date).date() if to_date else today

    query = select(ActivityEvent).where(
        ActivityEvent.username == username,
        ActivityEvent.event_date >= date_from,
        ActivityEvent.event_date <= date_to,
    )
    if device_id:
        query = query.where(ActivityEvent.device_id == device_id)

    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    device_label_map = build_device_label_map(devices)
    events = db.execute(query.order_by(ActivityEvent.timestamp_start.asc()).limit(25000)).scalars().all()
    for event in events:
        event.device_label = canonical_device_label(event.device_id, event.device_label, device_label_map)
    daily_map = build_daily_summaries(events, lambda event: event.username, device_label_map=device_label_map)
    day_rows = [
        {
            "date": summary["date"],
            "active_seconds": summary["active_seconds"],
            "afk_seconds": summary["afk_seconds"],
            "corporate_seconds": summary["corporate_seconds"],
            "afk_sessions": summary["afk_sessions"],
            "longest_afk_seconds": summary["longest_afk_seconds"],
            "top_corporate_domains": top_counter_entries(summary["corporate_domains"], limit=2),
            "top_apps": top_counter_entries(summary["apps"], limit=2),
            "top_devices": top_counter_entries(summary["devices"], limit=1),
        }
        for (_, _), summary in sorted(daily_map.items(), key=lambda item: item[1]["date"])
    ]

    rule, rule_values = get_rule_values(db, username)
    day_rows = attach_anomaly_flags(day_rows, rule_values)
    max_active = max((row["active_seconds"] for row in day_rows), default=0.0)
    max_afk = max((row["afk_seconds"] for row in day_rows), default=0.0)
    max_corporate = max((row["corporate_seconds"] for row in day_rows), default=0.0)

    for row in day_rows:
        row["active_bar_pct"] = percent_of(row["active_seconds"], max_active) if max_active else 0.0
        row["afk_bar_pct"] = percent_of(row["afk_seconds"], max_afk) if max_afk else 0.0
        row["corporate_bar_pct"] = percent_of(row["corporate_seconds"], max_corporate) if max_corporate else 0.0

    total_active = sum(row["active_seconds"] for row in day_rows)
    total_afk = sum(row["afk_seconds"] for row in day_rows)
    total_corporate = sum(row["corporate_seconds"] for row in day_rows)
    total_sessions = sum(row["afk_sessions"] for row in day_rows)
    latest_row = day_rows[-1] if day_rows else None
    user_devices = sorted({event.device_id: event.device_label for event in events}.items(), key=lambda item: item[1].lower())
    recent_events = list(reversed(events[-60:]))
    display_name = user_devices[0][1] if user_devices else preferred_person_label(username)

    return templates.TemplateResponse(
        request,
        "user_detail.html",
        {
            "request": request,
            "username": username,
            "display_name": display_name,
            "display_timezone": "Pacific/Fiji",
            "from_date": str(date_from),
            "to_date": str(date_to),
            "selected_device_id": device_id or "",
            "user_devices": user_devices,
            "day_rows": list(reversed(day_rows)),
            "latest_row": latest_row,
            "recent_events": recent_events,
            "rule": rule,
            "rule_values": rule_values,
            "metrics": {
                "active_seconds": total_active,
                "afk_seconds": total_afk,
                "corporate_seconds": total_corporate,
                "afk_sessions": total_sessions,
                "longest_afk_seconds": max((row["longest_afk_seconds"] for row in day_rows), default=0.0),
                "flagged_days": sum(1 for row in day_rows if row["is_flagged"]),
            },
            "corporate_domains": sorted(CORPORATE_DOMAINS),
        },
    )


@app.post("/users/{username}/rules")
def save_user_rules(
    username: str,
    request: Request,
    max_single_afk_minutes: int = Form(...),
    max_daily_afk_minutes: int = Form(...),
    max_afk_sessions_per_day: int = Form(...),
    min_corporate_minutes_per_day: int = Form(...),
    anomaly_pct_threshold: int = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    rule = db.get(UserMonitoringRule, username)
    if not rule:
        rule = UserMonitoringRule(username=username)
    rule.max_single_afk_minutes = max(1, max_single_afk_minutes)
    rule.max_daily_afk_minutes = max(1, max_daily_afk_minutes)
    rule.max_afk_sessions_per_day = max(1, max_afk_sessions_per_day)
    rule.min_corporate_minutes_per_day = max(0, min_corporate_minutes_per_day)
    rule.anomaly_pct_threshold = max(5, anomaly_pct_threshold)
    db.add(rule)
    db.commit()
    return RedirectResponse(url=f"/users/{username}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/devices/{device_id}/detail", response_class=HTMLResponse)
def device_detail_page(
    device_id: str,
    request: Request,
    from_date: str | None = None,
    to_date: str | None = None,
    db: Session = Depends(get_db),
):
    require_admin(request)

    today = datetime.now(timezone.utc).date()
    date_from = datetime.fromisoformat(from_date).date() if from_date else today - timedelta(days=13)
    date_to = datetime.fromisoformat(to_date).date() if to_date else today
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    device_label_map = build_device_label_map(devices)
    events = (
        db.execute(
            select(ActivityEvent)
            .where(
                ActivityEvent.device_id == device_id,
                ActivityEvent.event_date >= date_from,
                ActivityEvent.event_date <= date_to,
            )
            .order_by(ActivityEvent.timestamp_start.asc())
            .limit(25000)
        )
        .scalars()
        .all()
    )
    for event in events:
        event.device_label = canonical_device_label(event.device_id, event.device_label, device_label_map)

    daily_map = build_daily_summaries(events, lambda event: event.device_id, device_label_map=device_label_map)
    day_rows = []
    for (_, _), summary in sorted(daily_map.items(), key=lambda item: item[1]["date"]):
        total_seconds = summary["active_seconds"] + summary["afk_seconds"]
        day_rows.append(
            {
                "date": summary["date"],
                "active_seconds": summary["active_seconds"],
                "afk_seconds": summary["afk_seconds"],
                "corporate_seconds": summary["corporate_seconds"],
                "afk_sessions": summary["afk_sessions"],
                "longest_afk_seconds": summary["longest_afk_seconds"],
                "primary_user": preferred_person_label(
                    summary["usernames"].most_common(1)[0][0] if summary["usernames"] else None,
                    summary["devices"].most_common(1)[0][0] if summary["devices"] else None,
                ),
                "afk_ratio": percent_of(summary["afk_seconds"], total_seconds),
            }
        )

    max_total = max((row["active_seconds"] + row["afk_seconds"] for row in day_rows), default=0.0)
    for row in day_rows:
        row["bar_pct"] = percent_of(row["active_seconds"] + row["afk_seconds"], max_total) if max_total else 0.0

    recent_events = list(reversed(events[-60:]))
    user_totals = Counter()
    user_display_names: dict[str, str] = {}
    for event in events:
        user_totals[event.username] += event_seconds(event)
        user_display_names[event.username] = preferred_person_label(event.username, event.device_label)

    return templates.TemplateResponse(
        request,
        "device_detail.html",
        {
            "request": request,
            "device": device,
            "display_timezone": "Pacific/Fiji",
            "from_date": str(date_from),
            "to_date": str(date_to),
            "day_rows": list(reversed(day_rows)),
            "recent_events": recent_events,
            "top_users": [(name, float(seconds)) for name, seconds in user_totals.most_common(5)],
            "user_display_names": user_display_names,
            "metrics": {
                "active_seconds": sum(row["active_seconds"] for row in day_rows),
                "afk_seconds": sum(row["afk_seconds"] for row in day_rows),
                "corporate_seconds": sum(row["corporate_seconds"] for row in day_rows),
                "afk_sessions": sum(row["afk_sessions"] for row in day_rows),
            },
        },
    )


@app.post("/devices/{device_id}/label")
def update_device_label(device_id: str, request: Request, device_label: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    new_label = device_label.strip() or device.device_id
    device.device_label = new_label
    db.add(device)
    db.execute(update(ActivityEvent).where(ActivityEvent.device_id == device.device_id).values(device_label=new_label))
    db.commit()
    return RedirectResponse(url="/devices", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/devices/{device_id}/delete")
def delete_device(device_id: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    db.execute(delete(ActivityEvent).where(ActivityEvent.device_id == device.device_id))
    db.execute(delete(DeviceAlias).where(DeviceAlias.old_device_id == device.device_id))
    db.execute(delete(DeviceAlias).where(DeviceAlias.target_device_id == device.device_id))
    db.execute(delete(Device).where(Device.device_id == device.device_id))
    db.commit()
    return RedirectResponse(url="/devices", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/devices/{device_id}/merge")
def merge_device(
    device_id: str,
    request: Request,
    target_device_id: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    source = db.get(Device, device_id)
    target = db.get(Device, target_device_id)
    if not source or not target:
        raise HTTPException(status_code=404, detail="Device not found")
    if source.device_id == target.device_id:
        raise HTTPException(status_code=400, detail="Source and target devices must be different")

    if source.last_seen_at and (not target.last_seen_at or source.last_seen_at > target.last_seen_at):
        target.last_seen_at = source.last_seen_at
    if source.last_username and not target.last_username:
        target.last_username = source.last_username
    if source.hostname and not target.hostname:
        target.hostname = source.hostname

    db.merge(DeviceAlias(old_device_id=source.device_id, target_device_id=target.device_id))
    merge_device_events(db, source, target)
    db.add(target)
    db.execute(delete(Device).where(Device.device_id == source.device_id))
    db.commit()
    return RedirectResponse(url="/devices", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.get(AdminUser, username)
    if user and verify_password(password, user.password_hash):
        request.session["authenticated"] = True
        request.session["username"] = username
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid credentials"}, status_code=401)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/v1/ingest")
async def ingest_events(request: Request, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    raw_body = await request.body()
    decoded_body = None
    last_error = None
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            decoded_body = raw_body.decode(encoding)
            payload = json.loads(decoded_body)
            break
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
            continue
    else:
        detail = "Invalid JSON payload"
        if last_error:
            detail = f"{detail}: {last_error}"
        logger.warning("Ingest rejected: %s", detail)
        raise HTTPException(status_code=400, detail=detail) from last_error

    events = extract_events(payload)
    if not isinstance(events, list) or not events:
        payload_keys = sorted(payload.keys()) if isinstance(payload, dict) else []
        logger.warning(
            "Ingest rejected: payload missing non-empty events array payload_type=%s keys=%s preview=%r",
            type(payload).__name__,
            payload_keys,
            decoded_body[:500],
        )
        raise HTTPException(status_code=400, detail="Payload must contain non-empty 'events' array")

    inserted = 0
    duplicated = 0
    touched_devices: dict[str, Device] = {}
    seen_fingerprints: set[str] = set()

    for raw_event in events:
        raw_event = normalize_device_identity(raw_event)
        required = [
            "device_id",
            "hostname",
            "username",
            "timestamp_start",
            "timestamp_end",
            "is_afk",
            "source",
        ]
        missing = [field for field in required if field not in raw_event or raw_event.get(field) in (None, "")]
        if missing:
            logger.warning("Ingest rejected: missing fields %s in event keys=%s", missing, sorted(raw_event.keys()))
            raise HTTPException(status_code=422, detail=f"Missing fields: {', '.join(missing)}")
        raw_event = canonicalize_ingest_device(db, raw_event)

        try:
            ts_start = parse_dt(str(raw_event["timestamp_start"]))
            ts_end = parse_dt(str(raw_event["timestamp_end"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ingest rejected: invalid timestamps start=%r end=%r error=%s", raw_event.get("timestamp_start"), raw_event.get("timestamp_end"), exc)
            raise HTTPException(status_code=422, detail="Invalid timestamp format") from exc
        if ts_end < ts_start:
            logger.warning("Ingest rejected: timestamp_end before timestamp_start for device_id=%s", raw_event.get("device_id"))
            raise HTTPException(status_code=422, detail="timestamp_end must be greater than or equal to timestamp_start")

        fingerprint = event_fingerprint(raw_event)
        if fingerprint in seen_fingerprints:
            duplicated += 1
            continue
        seen_fingerprints.add(fingerprint)
        exists = db.execute(select(ActivityEvent.id).where(ActivityEvent.fingerprint == fingerprint)).scalar_one_or_none()
        if exists:
            duplicated += 1
            continue

        event = ActivityEvent(
            fingerprint=fingerprint,
            device_id=raw_event["device_id"],
            device_label=raw_event["device_label"],
            hostname=raw_event["hostname"],
            username=raw_event["username"],
            timestamp_start=ts_start,
            timestamp_end=ts_end,
            event_date=ts_start.date(),
            app=raw_event.get("app"),
            window_title=raw_event.get("window_title"),
            url=raw_event.get("url"),
            is_afk=bool(raw_event["is_afk"]),
            source=raw_event.get("source"),
        )
        if matching_event_id(db, event):
            duplicated += 1
            continue

        db.add(event)
        inserted += 1

        device = touched_devices.get(raw_event["device_id"]) or db.get(Device, raw_event["device_id"])
        if not device:
            device = Device(
                device_id=raw_event["device_id"],
                device_label=raw_event["device_label"],
                hostname=raw_event["hostname"],
                last_seen_at=ts_end,
                last_username=raw_event["username"],
            )
        else:
            device.device_label = raw_event["device_label"] or device.device_label
            device.hostname = raw_event["hostname"] or device.hostname
            if not device.last_seen_at or ts_end > device.last_seen_at:
                device.last_seen_at = ts_end
            device.last_username = raw_event["username"]
        touched_devices[device.device_id] = device
        db.add(device)

    db.commit()
    return {"status": "ok", "inserted": inserted, "duplicates": duplicated}
