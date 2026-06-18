"""
Events API — dashboard data endpoints.

GET /api/events          — paginated event list with filters
GET /api/events/stats    — aggregate stats for dashboard cards + charts
GET /api/events/stream   — Server-Sent Events for live feed
GET /api/events/{id}     — single event detail
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, Query, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from database import get_db
from models import HoneypotEvent, ServiceType, EventSeverity
from services.geoip import enrich_event

logger = logging.getLogger("honeywatch.api")

router = APIRouter(prefix="/api/events", tags=["events"])


# ── Helper ────────────────────────────────────────────────────────────────────

def _event_to_dict(event: HoneypotEvent) -> dict:
    """Serialize a HoneypotEvent to a JSON-safe dict."""
    return {
        "id":           event.id,
        "timestamp":    event.timestamp.isoformat() if event.timestamp else None,
        "service":      event.service.value if event.service else None,
        "source_ip":    event.source_ip,
        "source_port":  event.source_port,
        "username":     event.username,
        "password":     event.password,
        "raw_payload":  event.raw_payload,
        "country":      event.country,
        "country_code": event.country_code,
        "city":         event.city,
        "severity":     event.severity.value if event.severity else None,
    }


# ── GET /api/events ───────────────────────────────────────────────────────────

@router.get("")
def list_events(
    page:         int      = Query(default=1, ge=1),
    per_page:     int      = Query(default=50, ge=1, le=200),
    service:      str|None = Query(default=None),
    severity:     str|None = Query(default=None),
    country_code: str|None = Query(default=None),
    ip:           str|None = Query(default=None),
    db: Session = Depends(get_db),
):
    """
    Paginated list of honeypot events, newest first.
    Filter by: service (SSH/HTTP/FTP), severity (Low/Medium/High),
               country_code (e.g. CN), source ip.
    """
    query = db.query(HoneypotEvent)

    if service:
        try:
            query = query.filter(HoneypotEvent.service == ServiceType(service))
        except ValueError:
            pass

    if severity:
        try:
            query = query.filter(HoneypotEvent.severity == EventSeverity(severity))
        except ValueError:
            pass

    if country_code:
        query = query.filter(HoneypotEvent.country_code == country_code.upper())

    if ip:
        query = query.filter(HoneypotEvent.source_ip == ip)

    total  = query.count()
    events = (
        query
        .order_by(desc(HoneypotEvent.timestamp))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "events":   [_event_to_dict(e) for e in events],
    }


# ── GET /api/events/stats ─────────────────────────────────────────────────────

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Aggregate stats for the dashboard cards and charts."""
    total      = db.query(func.count(HoneypotEvent.id)).scalar() or 0
    unique_ips = db.query(func.count(func.distinct(HoneypotEvent.source_ip))).scalar() or 0

    # Count per service
    service_rows = (
        db.query(HoneypotEvent.service, func.count(HoneypotEvent.id))
        .group_by(HoneypotEvent.service)
        .all()
    )
    by_service = {row[0].value: row[1] for row in service_rows if row[0]}

    # Count per severity
    severity_rows = (
        db.query(HoneypotEvent.severity, func.count(HoneypotEvent.id))
        .group_by(HoneypotEvent.severity)
        .all()
    )
    by_severity = {row[0].value: row[1] for row in severity_rows if row[0]}

    # Top 10 attacker IPs
    top_ips = (
        db.query(
            HoneypotEvent.source_ip,
            func.count(HoneypotEvent.id).label("count"),
        )
        .group_by(HoneypotEvent.source_ip)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Top 10 countries
    top_countries = (
        db.query(
            HoneypotEvent.country,
            HoneypotEvent.country_code,
            func.count(HoneypotEvent.id).label("count"),
        )
        .filter(HoneypotEvent.country.isnot(None))
        .group_by(HoneypotEvent.country, HoneypotEvent.country_code)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Top 10 usernames tried
    top_usernames = (
        db.query(
            HoneypotEvent.username,
            func.count(HoneypotEvent.id).label("count"),
        )
        .filter(HoneypotEvent.username.isnot(None))
        .group_by(HoneypotEvent.username)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Top 10 passwords tried
    top_passwords = (
        db.query(
            HoneypotEvent.password,
            func.count(HoneypotEvent.id).label("count"),
        )
        .filter(HoneypotEvent.password.isnot(None))
        .group_by(HoneypotEvent.password)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    return {
        "total":         total,
        "unique_ips":    unique_ips,
        "by_service":    by_service,
        "by_severity":   by_severity,
        "top_ips":       [{"ip": r[0], "count": r[1]} for r in top_ips],
        "top_countries": [{"country": r[0], "country_code": r[1], "count": r[2]} for r in top_countries],
        "top_usernames": [{"username": r[0], "count": r[1]} for r in top_usernames],
        "top_passwords": [{"password": r[0], "count": r[1]} for r in top_passwords],
    }


# ── GET /api/events/stream ────────────────────────────────────────────────────

@router.get("/stream")
async def stream_events(db: Session = Depends(get_db)):
    """
    Server-Sent Events stream for the live dashboard feed.
    Polls DB every 2 seconds and pushes new events to the client.

    Usage in React:
        const es = new EventSource('/api/events/stream');
        es.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    async def event_generator():
        # Start from the latest event so we only stream NEW ones
        last_id = db.query(func.max(HoneypotEvent.id)).scalar() or 0

        # Immediate heartbeat so browser knows connection is alive
        yield ": heartbeat\n\n"

        while True:
            await asyncio.sleep(2)
            try:
                new_events = (
                    db.query(HoneypotEvent)
                    .filter(HoneypotEvent.id > last_id)
                    .order_by(HoneypotEvent.id)
                    .all()
                )
                for event in new_events:
                    last_id = event.id
                    data = json.dumps(_event_to_dict(event))
                    yield f"data: {data}\n\n"

                # Keep-alive heartbeat every cycle
                yield ": heartbeat\n\n"

            except Exception as exc:
                logger.error("SSE stream error: %s", exc)
                yield ": error\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── GET /api/events/{id} ──────────────────────────────────────────────────────

@router.get("/{event_id}")
def get_event(
    event_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Single event detail with full raw_payload.
    Triggers GeoIP enrichment in background if not yet enriched.
    """
    event = db.query(HoneypotEvent).filter(HoneypotEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Enrich with GeoIP if not done yet
    if event.country is None:
        background_tasks.add_task(enrich_event, event_id)

    return _event_to_dict(event)