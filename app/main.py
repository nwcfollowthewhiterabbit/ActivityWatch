import hashlib
import hmac
import json
import logging
import os
import secrets
from collections import defaultdict
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


def normalize_device_identity(raw_event: dict) -> dict:
    normalized = dict(raw_event)
    device_id = (normalized.get("device_id") or normalized.get("device_label") or "").strip()
    device_label = (normalized.get("device_label") or device_id).strip()
    normalized["device_id"] = device_id
    normalized["device_label"] = device_label
    return normalized


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

    today = datetime.now(timezone.utc).date()
    date_from = datetime.fromisoformat(from_date).date() if from_date else today - timedelta(days=6)
    date_to = datetime.fromisoformat(to_date).date() if to_date else today

    base_query = select(ActivityEvent).where(ActivityEvent.event_date >= date_from, ActivityEvent.event_date <= date_to)
    if device_id:
        base_query = base_query.where(ActivityEvent.device_id == device_id)
    if username:
        base_query = base_query.where(ActivityEvent.username == username)

    events = db.execute(base_query.order_by(ActivityEvent.timestamp_start.desc()).limit(5000)).scalars().all()

    total_seconds = 0
    afk_seconds = 0
    apps: dict[str, float] = defaultdict(float)
    sites: dict[str, float] = defaultdict(float)
    daily: dict[str, dict[str, float]] = defaultdict(lambda: {"active": 0, "afk": 0})
    recent_events = []

    for event in events:
        seconds = max((event.timestamp_end - event.timestamp_start).total_seconds(), 0)
        total_seconds += seconds
        if event.is_afk:
            afk_seconds += seconds
            daily[str(event.event_date)]["afk"] += seconds
        else:
            apps[event.app or "Unknown"] += seconds
            if event.url:
                sites[event.url] += seconds
            daily[str(event.event_date)]["active"] += seconds
        recent_events.append(event)

    active_seconds = total_seconds - afk_seconds

    devices = db.execute(select(Device).order_by(Device.device_label)).scalars().all()
    usernames = db.execute(select(ActivityEvent.username).distinct().order_by(ActivityEvent.username)).scalars().all()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "devices": devices,
            "usernames": usernames,
            "display_timezone": "Pacific/Fiji",
            "selected_device_id": device_id or "",
            "selected_username": username or "",
            "from_date": str(date_from),
            "to_date": str(date_to),
            "metrics": {
                "total_hours": round(total_seconds / 3600, 2),
                "active_hours": round(active_seconds / 3600, 2),
                "afk_hours": round(afk_seconds / 3600, 2),
                "events_count": len(events),
            },
            "top_apps": sorted(apps.items(), key=lambda item: item[1], reverse=True)[:15],
            "top_sites": sorted(sites.items(), key=lambda item: item[1], reverse=True)[:15],
            "daily": sorted(daily.items()),
            "recent_events": recent_events[:50],
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


@app.post("/devices/{device_id}/label")
def update_device_label(device_id: str, request: Request, device_label: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.device_label = device_label.strip() or device.device_id
    db.add(device)
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

    db.execute(
        update(ActivityEvent)
        .where(ActivityEvent.device_id == source.device_id)
        .values(device_id=target.device_id, device_label=target.device_label)
    )

    if source.last_seen_at and (not target.last_seen_at or source.last_seen_at > target.last_seen_at):
        target.last_seen_at = source.last_seen_at
    if source.last_username and not target.last_username:
        target.last_username = source.last_username
    if source.hostname and not target.hostname:
        target.hostname = source.hostname

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
            device.last_seen_at = ts_end
            device.last_username = raw_event["username"]
        touched_devices[device.device_id] = device
        db.add(device)

    db.commit()
    return {"status": "ok", "inserted": inserted, "duplicates": duplicated}
