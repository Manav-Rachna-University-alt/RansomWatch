"""FastAPI application entry point for RansomWatch.

Provides REST API endpoints for monitoring events, detection windows, security alerts,
threat intelligence indicators, and automated response actions.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import APIRouter, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import config
from database import (
    Alert,
    DatabaseManager,
    DatabaseStats,
    DetectionWindow,
    FileEvent,
    ResponseLog,
    ThreatIndicator,
    get_db,
)

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
def configure_logging() -> None:
    """Initialize structured logging to console and rotating log file."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = config.LOG_DIR / "ransomwatch.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(log_file), encoding="utf-8"),
        ],
    )


logger = logging.getLogger("ransomwatch.main")


# -----------------------------------------------------------------------------
# Application Lifespan (Startup / Shutdown)
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle: startup initialization and graceful shutdown."""
    # Startup
    configure_logging()
    logger.info("Starting RansomWatch Service...")
    logger.info("Simulation Mode: %s", config.SIMULATION_MODE)
    logger.info("Real Containment Enabled: %s", config.REAL_CONTAINMENT_ENABLED)

    # Ensure all required project directories exist
    config.ensure_directories()
    logger.info("Verified required data directories.")

    # Initialize SQLite database and migrations
    db = get_db(config.DATABASE_PATH)
    logger.info("Database initialized at %s", config.DATABASE_PATH)

    # Seed baseline threat indicators if database is empty
    seeded_count = db.seed_threat_indicators()
    if seeded_count > 0:
        logger.info("Seeded %d demo threat indicators into database.", seeded_count)

    # Initialize modular API routes
    try:
        from api.routes import initialize as init_api_routes
        init_api_routes(config=config, db=db)
        logger.info("Modular API routes initialized with config and database.")
    except Exception as exc:
        logger.warning("Could not initialize modular API routes: %s", exc)

    yield

    # Shutdown
    logger.info("Shutting down RansomWatch Service...")
    try:
        db.close()
        logger.info("Database connection pool closed successfully.")
    except Exception as exc:
        logger.error("Error closing database connection pool: %s", exc)


# -----------------------------------------------------------------------------
# FastAPI Application & Middleware
# -----------------------------------------------------------------------------
app = FastAPI(
    title="RansomWatch API",
    description="Real-Time Ransomware Detection, Canary Monitoring, and Automated Containment System",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for Streamlit and external dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class HealthResponse(BaseModel):
    """System health check payload."""

    status: str
    timestamp: str
    version: str
    simulation_mode: bool
    real_containment_enabled: bool
    monitored_directory: Optional[str]
    database_connected: bool


class AlertStatusUpdate(BaseModel):
    """Request payload for updating alert status."""

    status: str = Field(..., description="Target status: active, investigating, resolved, false_positive")
    response_action: Optional[str] = Field(default=None, description="Optional description of containment or review action")


# -----------------------------------------------------------------------------
# API Router Definitions
# -----------------------------------------------------------------------------
api_router = APIRouter(prefix="/api")


# --- System & Health Endpoints ---
@app.get("/health", response_model=HealthResponse, tags=["Health"])
@api_router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """Perform health and operational status verification."""
    db_connected = False
    try:
        db = get_db()
        stats = db.get_database_stats()
        db_connected = True
    except Exception as err:
        logger.warning("Health check database query failed: %s", err)

    return HealthResponse(
        status="healthy" if db_connected else "degraded",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="0.1.0",
        simulation_mode=config.SIMULATION_MODE,
        real_containment_enabled=config.REAL_CONTAINMENT_ENABLED,
        monitored_directory=str(config.DEFAULT_MONITOR_DIR) if config.DEFAULT_MONITOR_DIR else None,
        database_connected=db_connected,
    )


@api_router.get("/stats", response_model=DatabaseStats, tags=["System"])
def get_system_stats() -> DatabaseStats:
    """Retrieve database metrics, event tallies, and active alert counts."""
    db = get_db()
    return db.get_database_stats()


@api_router.get("/config", response_model=Dict[str, Any], tags=["System"])
def get_system_configuration() -> Dict[str, Any]:
    """Retrieve non-sensitive active configuration parameters."""
    return config.to_dict()


# --- File Events Endpoints ---
@api_router.get("/events", response_model=List[FileEvent], tags=["Events"])
def list_file_events(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None),
    is_canary: Optional[bool] = Query(default=None),
    directory: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
) -> List[FileEvent]:
    """Retrieve file system events filtered by type, canary flag, or time range."""
    db = get_db()
    return db.get_file_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        is_canary=is_canary,
        directory=directory,
        start_time=start_time,
        end_time=end_time,
    )


@api_router.post("/events", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Events"])
def record_file_event(event: FileEvent) -> Dict[str, Any]:
    """Record a newly observed file activity event."""
    db = get_db()
    event_id = db.insert_file_event(event)
    return {"id": event_id, "status": "recorded"}


# --- Alerts Endpoints ---
@api_router.get("/alerts", response_model=List[Alert], tags=["Alerts"])
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Alert]:
    """List detection alerts with optional severity and status filters."""
    db = get_db()
    return db.get_alerts(limit=limit, offset=offset, status=status, severity=severity)


@api_router.get("/alerts/{alert_id}", response_model=Alert, tags=["Alerts"])
def get_alert_details(alert_id: int) -> Alert:
    """Retrieve details for a specific alert by ID."""
    db = get_db()
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert with id {alert_id} not found")
    return alert


@api_router.post("/alerts", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Alerts"])
def create_alert(alert: Alert) -> Dict[str, Any]:
    """Create a new detection alert."""
    db = get_db()
    alert_id = db.insert_alert(alert)
    return {"id": alert_id, "status": "created"}


@api_router.patch("/alerts/{alert_id}/status", response_model=Dict[str, Any], tags=["Alerts"])
def update_alert_status(alert_id: int, update: AlertStatusUpdate) -> Dict[str, Any]:
    """Update status (e.g. resolve or acknowledge) and action notes for an alert."""
    db = get_db()
    existing = db.get_alert_by_id(alert_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert with id {alert_id} not found")

    success = db.update_alert_status(
        alert_id=alert_id,
        status=update.status,
        response_action=update.response_action,
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update alert")
    return {"id": alert_id, "status": update.status, "updated": True}


# --- Threat Intelligence Endpoints ---
@api_router.get("/threat-intel", response_model=List[ThreatIndicator], tags=["Threat Intel"])
def list_threat_indicators(
    limit: int = Query(default=100, ge=1, le=1000),
    indicator_type: Optional[str] = Query(default=None),
    is_demo_data: Optional[bool] = Query(default=None),
) -> List[ThreatIndicator]:
    """List registered threat intelligence indicators (hashes, extensions, IPs)."""
    db = get_db()
    return db.get_threat_indicators(limit=limit, indicator_type=indicator_type, is_demo_data=is_demo_data)


@api_router.post("/threat-intel", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Threat Intel"])
def add_threat_indicator(indicator: ThreatIndicator) -> Dict[str, Any]:
    """Add or update a threat intelligence indicator."""
    db = get_db()
    indicator_id = db.insert_threat_indicator(indicator)
    return {"id": indicator_id, "status": "saved"}


@api_router.get("/threat-intel/lookup/{value}", response_model=Dict[str, Any], tags=["Threat Intel"])
def lookup_threat_indicator(value: str) -> Dict[str, Any]:
    """Check if a file hash or extension matches any registered threat indicator."""
    db = get_db()
    match = db.find_threat_indicator(value)
    if match:
        return {"matched": True, "indicator": match.model_dump()}
    return {"matched": False, "indicator": None}


@api_router.delete("/threat-intel/{indicator_id}", response_model=Dict[str, Any], tags=["Threat Intel"])
def delete_threat_indicator(indicator_id: int) -> Dict[str, Any]:
    """Delete a threat indicator from the database."""
    db = get_db()
    success = db.delete_threat_indicator(indicator_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Indicator {indicator_id} not found")
    return {"id": indicator_id, "deleted": True}


# --- Detection Windows & Response Logs ---
@api_router.get("/detection/windows", response_model=List[DetectionWindow], tags=["Detection"])
def list_detection_windows(
    limit: int = Query(default=50, ge=1, le=500),
    only_anomalies: bool = Query(default=False),
) -> List[DetectionWindow]:
    """List sliding detection windows and computed anomaly scores."""
    db = get_db()
    return db.get_detection_windows(limit=limit, only_anomalies=only_anomalies)


@api_router.get("/response/logs", response_model=List[ResponseLog], tags=["Response"])
def list_response_logs(
    alert_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> List[ResponseLog]:
    """Retrieve audit history of automated containment actions."""
    db = get_db()
    return db.get_response_logs(alert_id=alert_id, limit=limit)


# Mount the API router
app.include_router(api_router)

# Mount modular API router from api/routes.py
try:
    from api.routes import router as modular_routes_router
    app.include_router(modular_routes_router)
except Exception as exc:
    logger.warning("Could not include modular_routes_router: %s", exc)



# Root path redirect / info
@app.get("/", tags=["General"])
def root_info() -> Dict[str, Any]:
    """Root info endpoint providing service descriptor and links."""
    return {
        "service": "RansomWatch",
        "description": "Real-Time Ransomware Detection and Automated Containment System",
        "docs_url": "/docs",
        "health_url": "/health",
        "api_prefix": "/api",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=config.API_HOST, port=config.API_PORT, reload=False)
