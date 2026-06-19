"""
SSH Honeypot — port 2222

Mimics an OpenSSH server banner, reads the client's SSH identification
string, then waits for any credential data before logging and closing.

How real SSH auth works (simplified):
  1. Server sends:  SSH-2.0-OpenSSH_9.6\r\n
  2. Client sends:  SSH-2.0-<client_version>\r\n
  3. Key exchange + auth negotiation (binary packets)
  4. Client sends username/password in encrypted packets

Since we don't implement real SSH crypto, we capture:
  - The client version string (step 2) — reveals the attack tool
  - Any raw bytes sent after the banner (step 3+) — the payload
  - We classify severity based on whether a payload was sent
"""

import asyncio
import logging

from config import settings
from database import SessionLocal
from models import HoneypotEvent, ServiceType, EventSeverity

logger = logging.getLogger("honeywatch.ssh")

# Realistic OpenSSH banner — must end with \r\n per RFC 4253
SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"

READ_TIMEOUT = 10
MAX_READ_BYTES = 4096


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    source_port = peer[1] if peer else None

    raw_payload = None
    username = None
    severity = EventSeverity.LOW

    try:
        # Step 1 — send our fake banner
        writer.write(SSH_BANNER)
        await writer.drain()

        # Step 2 — read client identification string
        try:
            client_banner = await asyncio.wait_for(
                reader.readline(), timeout=READ_TIMEOUT
            )
            client_version = client_banner.decode(errors="replace").strip()
            logger.info("SSH | %s | client version: %s", source_ip, client_version)
        except asyncio.TimeoutError:
            logger.debug("SSH | %s | timeout waiting for client banner", source_ip)
            return

        # Step 3 — read key exchange / auth payload
        try:
            payload_bytes = await asyncio.wait_for(
                reader.read(MAX_READ_BYTES), timeout=READ_TIMEOUT
            )
            if payload_bytes:
                raw_payload = payload_bytes.decode(errors="replace")
                username = _extract_ssh_username(payload_bytes)
                severity = EventSeverity.HIGH if username else EventSeverity.MEDIUM
                logger.info(
                    "SSH | %s | payload %d bytes | username: %s",
                    source_ip, len(payload_bytes), username or "unknown"
                )
        except asyncio.TimeoutError:
            logger.debug("SSH | %s | timeout waiting for payload", source_ip)

    except (ConnectionResetError, BrokenPipeError):
        logger.debug("SSH | %s | connection reset by client", source_ip)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        _save_event(
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            raw_payload=raw_payload,
            severity=severity,
        )


def _extract_ssh_username(data: bytes) -> str | None:
    """
    Best-effort extraction of username from SSH userauth packet.

    SSH_MSG_USERAUTH_REQUEST (type=50) structure:
      1 byte  — message type (50 = 0x32)
      4 bytes — username length
      N bytes — username string
    """
    try:
        idx = data.find(b"\x32")  # SSH_MSG_USERAUTH_REQUEST
        if idx == -1:
            return None
        if idx + 5 >= len(data):
            return None
        uname_len = int.from_bytes(data[idx + 1:idx + 5], "big")
        if uname_len <= 0 or uname_len > 64:
            return None
        uname_start = idx + 5
        uname_end = uname_start + uname_len
        if uname_end > len(data):
            return None
        return data[uname_start:uname_end].decode(errors="replace")
    except Exception:
        return None


def _save_event(
    source_ip: str,
    source_port: int | None,
    username: str | None,
    raw_payload: str | None,
    severity: EventSeverity,
) -> None:
    db = SessionLocal()
    try:
        event = HoneypotEvent(
            service=ServiceType.SSH,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            raw_payload=raw_payload,
            severity=severity,
        )
        db.add(event)
        db.commit()
        logger.info("SSH | %s | event saved (severity=%s)", source_ip, severity.value)
    except Exception as exc:
        db.rollback()
        logger.error("SSH | %s | DB error: %s", source_ip, exc)
    finally:
        db.close()


async def start_ssh_honeypot() -> asyncio.Server:
    """Start the SSH honeypot. Called from main.py lifespan."""
    server = await asyncio.start_server(
        _handle_connection,
        host="0.0.0.0",
        port=settings.ssh_trap_port,
    )
    addr = server.sockets[0].getsockname()
    logger.info("SSH honeypot listening on %s:%s", addr[0], addr[1])
    return server