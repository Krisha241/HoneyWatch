"""
FTP Honeypot — port 2121

Implements just enough FTP (RFC 959) to look real to automated scanners.

Auth flow we emulate:
  1. Server → 220 welcome banner
  2. Client → USER <username>
  3. Server → 331 Password required
  4. Client → PASS <password>
  5. Server → 530 Login incorrect   (we always reject)
  6. Client → QUIT
"""

import asyncio
import logging

from config import settings
from database import SessionLocal
from models import HoneypotEvent, ServiceType, EventSeverity

logger = logging.getLogger("honeywatch.ftp")

READ_TIMEOUT = 30

FTP_BANNER   = b"220 (vsFTPd 3.0.5)\r\n"
R_PASSWORD   = b"331 Please specify the password.\r\n"
R_REJECTED   = b"530 Login incorrect.\r\n"
R_GOODBYE    = b"221 Goodbye.\r\n"
R_SYST       = b"215 UNIX Type: L8\r\n"
R_UNKNOWN    = b"502 Command not implemented.\r\n"


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    source_port = peer[1] if peer else None

    username = None
    password = None
    severity = EventSeverity.LOW
    raw_lines: list[str] = []

    try:
        # Send welcome banner
        writer.write(FTP_BANNER)
        await writer.drain()

        # FTP command loop
        while True:
            try:
                line_bytes = await asyncio.wait_for(
                    reader.readline(), timeout=READ_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.debug("FTP | %s | session timeout", source_ip)
                break

            if not line_bytes:
                break

            line = line_bytes.decode(errors="replace").strip()
            if not line:
                continue

            raw_lines.append(line)
            cmd = line.split(" ", 1)[0].upper()
            arg = line[len(cmd):].strip() if " " in line else ""

            if cmd == "USER":
                username = arg or None
                severity = EventSeverity.MEDIUM
                writer.write(R_PASSWORD)
                await writer.drain()

            elif cmd == "PASS":
                password = arg or None
                severity = EventSeverity.HIGH
                logger.info(
                    "FTP | %s | credentials — user: %s | pass: %s",
                    source_ip, username or "(none)", password or "(none)"
                )
                writer.write(R_REJECTED)
                await writer.drain()
                break  # most scanners disconnect after failed auth

            elif cmd == "SYST":
                writer.write(R_SYST)
                await writer.drain()

            elif cmd == "QUIT":
                writer.write(R_GOODBYE)
                await writer.drain()
                break

            else:
                writer.write(R_UNKNOWN)
                await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        logger.debug("FTP | %s | connection reset", source_ip)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if raw_lines:
            _save_event(source_ip, source_port, username, password,
                        "\n".join(raw_lines), severity)


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
            service=ServiceType.FTP,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            password=password,
            raw_payload=raw_payload,
            severity=severity,
        )
        db.add(event)
        db.commit()
        logger.info("FTP | %s | event saved (severity=%s)", source_ip, severity.value)
    except Exception as exc:
        db.rollback()
        logger.error("FTP | %s | DB error: %s", source_ip, exc)
    finally:
        db.close()


async def start_ftp_honeypot() -> asyncio.Server:
    """Start the FTP honeypot. Called from main.py lifespan."""
    server = await asyncio.start_server(
        _handle_connection,
        host="0.0.0.0",
        port=settings.ftp_trap_port,
    )
    addr = server.sockets[0].getsockname()
    logger.info("FTP honeypot listening on %s:%s", addr[0], addr[1])
    return server