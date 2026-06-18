import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import engine, Base
import models  # noqa: F401 — registers models with Base

from honeypot.ssh import start_ssh_honeypot
from honeypot.http_trap import start_http_honeypot
from honeypot.ftp import start_ftp_honeypot
from api.events import router as events_router  # ← added

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)
logger = logging.getLogger("honeywatch")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────
    Base.metadata.create_all(bind=engine)

    # Start honeypot listeners
    ssh_server  = await start_ssh_honeypot()
    http_server = await start_http_honeypot()
    ftp_server  = await start_ftp_honeypot()

    logger.info("HoneyWatch is live — all honeypots running")
    logger.info("SSH  trap → port %s", settings.ssh_trap_port)
    logger.info("HTTP trap → port %s", settings.http_trap_port)
    logger.info("FTP  trap → port %s", settings.ftp_trap_port)

    yield

    # ── Shutdown ──────────────────────────────────────────────
    ssh_server.close()
    http_server.close()
    ftp_server.close()

    await asyncio.gather(
        ssh_server.wait_closed(),
        http_server.wait_closed(),
        ftp_server.wait_closed(),
    )
    logger.info("HoneyWatch shut down cleanly")


app = FastAPI(
    title="HoneyWatch",
    description="Low-interaction honeypot with live attack dashboard.",
    version="0.3.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        ["*"] if settings.is_development
        else ["http://localhost:5173"]
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(events_router)  # ← added


@app.get("/health", tags=["system"])
def health_check():
    return {
        "status": "ok",
        "environment": settings.environment,
        "version": "0.3.0",
        "honeypots": {
            "ssh":  f"port {settings.ssh_trap_port}",
            "http": f"port {settings.http_trap_port}",
            "ftp":  f"port {settings.ftp_trap_port}",
        },
    }