from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import engine, Base

# Import models so SQLAlchemy registers them with Base before create_all
import models  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────
    # Create all DB tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # Honeypot listeners will be started here in Phase 2
    print("HoneyWatch API started")
    print(f"Environment : {settings.environment}")
    print(f"SSH trap    : port {settings.ssh_trap_port}")
    print(f"HTTP trap   : port {settings.http_trap_port}")
    print(f"FTP trap    : port {settings.ftp_trap_port}")

    yield

    # ── Shutdown ─────────────────────────────────────────────
    # Honeypot listeners will be stopped here in Phase 2
    print("HoneyWatch API shutting down")


app = FastAPI(
    title="HoneyWatch",
    description="Low-interaction honeypot with live attack dashboard.",
    version="0.1.0",
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


@app.get("/health", tags=["system"])
def health_check():
    """Liveness probe — used by Docker and monitoring tools."""
    return {
        "status": "ok",
        "environment": settings.environment,
        "version": "0.1.0",
    }