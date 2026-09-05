"""
FastAPI Application Entry Point
================================
- Creates database tables on startup (no Alembic needed for demo)
- Mounts the API router under /api/v1
- Provides a /health endpoint that pings the database
- Configures CORS for development
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.database import Base, engine
from app.router import router

APP_VERSION = "1.0.0"


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all tables on startup; dispose engine on shutdown."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


# ── Application ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Mini NCM Application (Cisco IOS Compliance)",
    description=(
        "## Cisco IOS Network Configuration Compliance API\n\n"
        "This service accepts raw Cisco IOS configuration text and:\n"
        "- **Parses** it into structured data "
        "(hostname, interfaces, ACLs, SNMP, AAA, NTP…)\n"
        "- **Evaluates** 8 security compliance rules (SEC-001 → SEC-008)\n"
        "- **Stores** both the parsed config and compliance report in PostgreSQL\n"
        "- **Returns** the full result via REST API\n\n"
        "### Quick Start\n"
        "Use `POST /api/v1/parse` with a raw IOS config to get started.\n"
        "Browse stored data with `GET /api/v1/configs` and `GET /api/v1/reports`."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "Cisco IOS Compliance",
            "description": "Parse configs, run compliance checks, manage results",
        },
        {
            "name": "System",
            "description": "Health checks and system status",
        },
    ],
)


# ── Middleware ───────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ───────────────────────────────────────────────────────────────────

app.include_router(router)


@app.get(
    "/health",
    tags=["System"],
    summary="Health check — verifies API and DB connectivity",
)
async def health_check():
    """Return service health and DB connectivity status."""
    db_status = "unknown"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as exc:
        db_status = f"error: {exc}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "version": APP_VERSION,
        "db": db_status,
        "timestamp": time.time(),
    }
