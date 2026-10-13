"""
SIEM/SOAR AI Backend - Main Application Entry Point

FastAPI application with:
- Structured JSON logging (structlog)
- Prometheus metrics instrumentation
- CORS middleware
- JWT authentication
- Async database connections
- WebSocket support for real-time events
"""
import contextlib
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from core.config import settings
from core.database import engine, Base

# Import routers from api modules
from api.events import router as events_router
from api.alerts import router as alerts_router
from api.incidents import router as incidents_router
from api.playbooks import router as playbooks_router
from api.analytics import router as analytics_router
from api.auth import router as auth_router

# Setup structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if settings.DEBUG else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger(__name__)

# --- Connected WebSocket clients (for real-time events) ---
_ws_clients: list[WebSocket] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info("startup", service="siem-soar-backend", version=app.version)

    # Create database tables (use Alembic migrations in production)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("database_tables_created")
    yield

    logger.info("shutdown", service="siem-soar-backend")
    await engine.dispose()


# --- FastAPI Application ---
app = FastAPI(
    title="SIEM/SOAR AI Backend",
    description="""
## AI-Powered SIEM and SOAR Platform

This API powers the SIEM/SOAR platform with:
- 🔍 **Security Event Management** - Ingest, normalize, and analyze security events
- 🚨 **Alert Management** - Automated alert creation and correlation
- ⚡ **Incident Response** - AI-driven incident management
- 🤖 **SOAR Automation** - Automated playbook execution
- 📊 **Analytics** - Real-time security dashboards
- 🧠 **AI Integration** - Gemini-powered threat analysis
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Prometheus Metrics ---
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics")
except ImportError:
    logger.warning("prometheus_instrumentator_not_installed")


# --- Global Exception Handlers ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# --- WebSocket for Real-time Events ---
@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time security event streaming."""
    await websocket.accept()
    _ws_clients.append(websocket)
    logger.info("websocket_client_connected", total_clients=len(_ws_clients))
    try:
        while True:
            # Keep connection alive, data is pushed from event processor
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)
        logger.info("websocket_client_disconnected", total_clients=len(_ws_clients))


async def broadcast_event(event_data: dict[str, Any]) -> None:
    """Broadcast a new security event to all connected WebSocket clients."""
    import json
    disconnected = []
    for client in _ws_clients:
        try:
            await client.send_text(json.dumps(event_data))
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        _ws_clients.remove(client)


# --- Health Check ---
@app.get("/health", tags=["Health"], summary="System health check")
async def health_check() -> dict[str, Any]:
    """Returns system health status."""
    return {
        "status": "ok",
        "service": "siem-soar-backend",
        "version": app.version,
    }


# --- Include API Routers ---
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(events_router, prefix="/api/v1/events", tags=["Security Events"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(incidents_router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(playbooks_router, prefix="/api/v1/playbooks", tags=["SOAR Playbooks"])
app.include_router(analytics_router, prefix="/api/v1/analytics", tags=["Analytics"])
