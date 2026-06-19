"""
HTTP Honeypot — port 8080

Serves a convincing admin login page over raw TCP.
Captures:
  - Every GET  → which paths attackers probe (/admin, /wp-login, etc.)
  - Every POST → credential stuffing attempts (username + password)
  - User-Agent → reveals the attack tool (hydra, sqlmap, curl, etc.)
  - Full raw request → stored as evidence
"""

import asyncio
import logging
from urllib.parse import unquote_plus

from config import settings
from database import SessionLocal
from models import HoneypotEvent, ServiceType, EventSeverity

logger = logging.getLogger("honeywatch.http")

READ_TIMEOUT = 15
MAX_REQUEST_BYTES = 8192

LOGIN_PAGE_HTML = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nServer: Apache/2.4.62 (Ubuntu)\r\nX-Powered-By: PHP/8.2.0\r\nConnection: close\r\n\r\n<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Panel - Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; background: #1a1a2e;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 8px; padding: 2rem; width: 340px; }
  h2 { font-size: 20px; margin-bottom: 1.5rem; color: #333; text-align: center; }
  label { font-size: 13px; color: #555; display: block; margin-bottom: 4px; }
  input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;
          margin-bottom: 1rem; font-size: 14px; }
  button { width: 100%; padding: 10px; background: #4f46e5; color: #fff;
           border: none; border-radius: 4px; font-size: 14px; cursor: pointer; }
  .logo { text-align: center; font-size: 28px; margin-bottom: 1rem; color: #4f46e5; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">&#9670;</div>
  <h2>Administrator Login</h2>
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter username" autofocus>
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password">
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>"""

LOGIN_FAIL_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Server: Apache/2.4.62 (Ubuntu)\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><body><p style='color:red'>Invalid username or password.</p></body></html>"
)

METHOD_NOT_ALLOWED = b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"


def _parse_http_request(raw: bytes) -> dict:
    """Minimal HTTP/1.x parser — returns method, path, headers, body."""
    result = {"method": "", "path": "/", "headers": {}, "body": ""}
    try:
        if b"\r\n\r\n" in raw:
            header_section, body_bytes = raw.split(b"\r\n\r\n", 1)
        else:
            header_section, body_bytes = raw, b""

        lines = header_section.decode(errors="replace").splitlines()
        if not lines:
            return result

        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            result["method"] = parts[0].upper()
            result["path"] = parts[1]

        for line in lines[1:]:
            if ": " in line:
                key, _, value = line.partition(": ")
                result["headers"][key.lower()] = value.strip()

        result["body"] = body_bytes.decode(errors="replace")
    except Exception:
        pass
    return result


def _parse_form_body(body: str) -> tuple[str | None, str | None]:
    """Parse application/x-www-form-urlencoded — returns (username, password)."""
    username = None
    password = None
    try:
        for pair in body.split("&"):
            if "=" in pair:
                key, _, value = pair.partition("=")
                key = unquote_plus(key.strip().lower())
                value = unquote_plus(value.strip())
                if key in ("username", "user", "login", "email", "uname"):
                    username = value
                elif key in ("password", "pass", "pwd", "passwd"):
                    password = value
    except Exception:
        pass
    return username, password


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    source_port = peer[1] if peer else None

    username = None
    password = None
    raw_payload = None
    severity = EventSeverity.LOW
    response = METHOD_NOT_ALLOWED

    try:
        raw_bytes = await asyncio.wait_for(
            reader.read(MAX_REQUEST_BYTES), timeout=READ_TIMEOUT
        )
        if not raw_bytes:
            return

        raw_payload = raw_bytes.decode(errors="replace")
        req = _parse_http_request(raw_bytes)
        method = req["method"]
        user_agent = req["headers"].get("user-agent", "")

        logger.info(
            "HTTP | %s | %s %s | UA: %s",
            source_ip, method, req["path"], user_agent[:80]
        )

        if method == "GET":
            response = LOGIN_PAGE_HTML
            severity = EventSeverity.LOW

        elif method == "POST":
            username, password = _parse_form_body(req["body"])
            response = LOGIN_FAIL_RESPONSE
            severity = EventSeverity.HIGH if (username or password) else EventSeverity.MEDIUM
            logger.info(
                "HTTP | %s | credentials — user: %s | pass: %s",
                source_ip, username or "(none)", password or "(none)"
            )
        else:
            severity = EventSeverity.LOW

        writer.write(response)
        await writer.drain()

    except asyncio.TimeoutError:
        logger.debug("HTTP | %s | read timeout", source_ip)
    except (ConnectionResetError, BrokenPipeError):
        logger.debug("HTTP | %s | connection reset", source_ip)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if raw_payload:
            _save_event(source_ip, source_port, username, password, raw_payload, severity)


def _save_event(
    source_ip: str,
    source_port: int | None,
    username: str | None,
    password: str | None,
    raw_payload: str | None,
    severity: EventSeverity,
) -> None:
    db = SessionLocal()
    try:
        event = HoneypotEvent(
            service=ServiceType.HTTP,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            password=password,
            raw_payload=raw_payload,
            severity=severity,
        )
        db.add(event)
        db.commit()
        logger.info("HTTP | %s | event saved (severity=%s)", source_ip, severity.value)
    except Exception as exc:
        db.rollback()
        logger.error("HTTP | %s | DB error: %s", source_ip, exc)
    finally:
        db.close()


async def start_http_honeypot() -> asyncio.Server:
    """Start the HTTP honeypot. Called from main.py lifespan."""
    server = await asyncio.start_server(
        _handle_connection,
        host="0.0.0.0",
        port=settings.http_trap_port,
    )
    addr = server.sockets[0].getsockname()
    logger.info("HTTP honeypot listening on %s:%s", addr[0], addr[1])
    return server