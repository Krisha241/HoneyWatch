"""
GeoIP enrichment service using ip-api.com (free, no API key needed).

Docs: http://ip-api.com/docs/api:json
Limit: 45 requests/minute on the free tier.

Private/loopback IPs are skipped — they have no GeoIP record.
"""

import ipaddress
import logging
import threading
import time
import urllib.request
import urllib.error
import json

logger = logging.getLogger("honeywatch.geoip")

# ip-api.com free endpoint — HTTP only on free tier
GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,query"

# Simple rate limiter — ip-api allows 45 req/min = ~1.3s between requests
_lock = threading.Lock()
_last_request_time: float = 0.0
MIN_REQUEST_INTERVAL = 1.4  # seconds between requests to stay under limit


def _is_private(ip: str) -> bool:
    """Return True if the IP is private, loopback, or link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _rate_limit() -> None:
    """Block until we're safe to make another request."""
    global _last_request_time
    with _lock:
        now = time.time()
        elapsed = now - _last_request_time
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)
        _last_request_time = time.time()


def lookup(ip: str) -> dict[str, str | None]:
    """
    Look up GeoIP data for an IP address using ip-api.com.

    Returns a dict with keys: country, country_code, city.
    All values are None if lookup fails or IP is private.
    """
    result = {"country": None, "country_code": None, "city": None}

    if not ip or ip == "unknown" or _is_private(ip):
        logger.debug("GeoIP | %s | skipped (private/loopback)", ip)
        return result

    _rate_limit()

    try:
        url = GEOIP_URL.format(ip=ip)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "HoneyWatch/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        if data.get("status") == "success":
            result["country"]      = data.get("country")
            result["country_code"] = data.get("countryCode")  # e.g. "CN", "RU"
            result["city"]         = data.get("city")
            logger.info(
                "GeoIP | %s | %s, %s (%s)",
                ip,
                data.get("city", "?"),
                data.get("country", "?"),
                data.get("isp", "?"),
            )
        else:
            logger.debug("GeoIP | %s | api returned status: %s", ip, data.get("status"))

    except urllib.error.URLError as exc:
        logger.warning("GeoIP | %s | network error: %s", ip, exc)
    except Exception as exc:
        logger.warning("GeoIP | %s | lookup error: %s", ip, exc)

    return result


def enrich_event(event_id: int) -> None:
    """
    Fetch GeoIP data for an event and update it in the database.
    Designed to run in a background thread after each event is saved.
    """
    from database import SessionLocal
    from models import HoneypotEvent

    db = SessionLocal()
    try:
        event = db.query(HoneypotEvent).filter(HoneypotEvent.id == event_id).first()
        if not event:
            return

        geo = lookup(event.source_ip)

        event.country      = geo["country"]
        event.country_code = geo["country_code"]
        event.city         = geo["city"]

        db.commit()
        logger.info(
            "GeoIP | event %s | %s → %s, %s",
            event_id,
            event.source_ip,
            geo["city"] or "unknown city",
            geo["country"] or "unknown country",
        )
    except Exception as exc:
        db.rollback()
        logger.error("GeoIP | enrich_event(%s) error: %s", event_id, exc)
    finally:
        db.close()