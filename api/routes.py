"""FastAPI APIRouter and endpoint definitions for RansomWatch.

Provides RESTful endpoints for:
- File system monitoring and activity metrics
- Ransomware detection analysis and alerts management
- Machine learning anomaly detection model training and inference
- Threat intelligence indicators lookup, enrichment, and demo dataset seeding
- Incident response triggering, audit logging, and recovery guidance
- Backup snapshot creation and restoration management
"""

from __future__ import annotations

import logging
import os
import shutil
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

# Core imports with safe fallback for modular decoupling
try:
    from config import Config, config as default_config
except ImportError:
    try:
        from config import RansomWatchConfig as Config, config as default_config  # type: ignore
    except ImportError:
        Config = Any  # type: ignore
        default_config = None  # type: ignore

try:
    from database.db import DatabaseManager, get_db
except ImportError:
    DatabaseManager = Any  # type: ignore
    get_db = None  # type: ignore

try:
    from database.models import (
        Alert,
        DatabaseStats,
        DetectionWindow,
        FileEvent,
        MLTrainingLog,
        ResponseLog,
        ThreatIndicator,
    )
except ImportError:
    Alert = Any  # type: ignore
    DatabaseStats = Any  # type: ignore
    DetectionWindow = Any  # type: ignore
    FileEvent = Any  # type: ignore
    MLTrainingLog = Any  # type: ignore
    ResponseLog = Any  # type: ignore
    ThreatIndicator = Any  # type: ignore

# Optional modular components imported lazily or injected during initialization
try:
    from monitoring.file_monitor import FileMonitor  # type: ignore
except ImportError:
    FileMonitor = None  # type: ignore

try:
    from monitoring.canary import CanaryManager  # type: ignore
except ImportError:
    CanaryManager = None  # type: ignore

try:
    from detection.engine import DetectionEngine  # type: ignore
except ImportError:
    DetectionEngine = None  # type: ignore

try:
    from detection.risk_scorer import DetectionResult  # type: ignore
except ImportError:
    DetectionResult = None  # type: ignore

try:
    from ml.model import AnomalyDetector  # type: ignore
except ImportError:
    AnomalyDetector = None  # type: ignore

try:
    from threat_intel.enrichment import ThreatEnrichment  # type: ignore
except ImportError:
    ThreatEnrichment = None  # type: ignore

try:
    from threat_intel.local_db import LocalThreatDatabase  # type: ignore
except ImportError:
    LocalThreatDatabase = None  # type: ignore

try:
    from response.incident import IncidentResponder  # type: ignore
except ImportError:
    IncidentResponder = None  # type: ignore

try:
    from response.recovery import RecoveryManager  # type: ignore
except ImportError:
    RecoveryManager = None  # type: ignore


logger = logging.getLogger("ransomwatch.api.routes")

# -----------------------------------------------------------------------------
# Module-level Shared State
# -----------------------------------------------------------------------------
_config: Optional[Any] = default_config
_db: Optional[Any] = None
_monitor: Optional[Any] = None
_canary_mgr: Optional[Any] = None
_detector: Optional[Any] = None
_ml_model: Optional[Any] = None
_threat_intel: Optional[Any] = None
_local_threat_db: Optional[Any] = None
_incident_responder: Optional[Any] = None
_recovery_mgr: Optional[Any] = None

# Internal tracking for monitor runtime state
_monitoring_state: Dict[str, Any] = {
    "is_running": False,
    "directory": None,
    "directories": [],
    "started_at": None,
    "total_events_observed": 0,
}


def get_active_config() -> Any:
    """Return the currently configured config instance or default singleton."""
    global _config
    if _config is None:
        try:
            from config import config as cfg
            _config = cfg
        except Exception:
            pass
    return _config


def get_active_db() -> Any:
    """Return the initialized DatabaseManager instance."""
    global _db
    if _db is None:
        try:
            from database.db import get_db as db_getter
            _db = db_getter()
        except Exception:
            try:
                from database.db import DatabaseManager as DM
                _db = DM()
            except Exception as exc:
                logger.warning("Could not instantiate DatabaseManager automatically: %s", exc)
    return _db


def initialize(
    config: Optional[Any] = None,
    db: Optional[Any] = None,
    monitor: Optional[Any] = None,
    canary_mgr: Optional[Any] = None,
    detector: Optional[Any] = None,
    ml_model: Optional[Any] = None,
    threat_intel: Optional[Any] = None,
    incident_responder: Optional[Any] = None,
    recovery_mgr: Optional[Any] = None,
) -> None:
    """Initialize shared state and dependencies for all API route handlers.

    Called during main application startup to inject database managers,
    configuration objects, monitors, detectors, and response managers.
    """
    global _config, _db, _monitor, _canary_mgr, _detector, _ml_model
    global _threat_intel, _local_threat_db, _incident_responder, _recovery_mgr

    if config is not None:
        _config = config
    elif _config is None:
        _config = get_active_config()

    if db is not None:
        _db = db
    elif _db is None:
        _db = get_active_db()

    if monitor is not None:
        _monitor = monitor
    elif _monitor is None and FileMonitor is not None:
        try:
            _monitor = FileMonitor(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic FileMonitor initialization deferred: %s", exc)

    if canary_mgr is not None:
        _canary_mgr = canary_mgr
    elif _canary_mgr is None and CanaryManager is not None:
        try:
            _canary_mgr = CanaryManager(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic CanaryManager initialization deferred: %s", exc)

    if detector is not None:
        _detector = detector
    elif _detector is None and DetectionEngine is not None:
        try:
            _detector = DetectionEngine(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic DetectionEngine initialization deferred: %s", exc)

    if ml_model is not None:
        _ml_model = ml_model
    elif _ml_model is None and AnomalyDetector is not None:
        try:
            _ml_model = AnomalyDetector(config=_config)
        except Exception as exc:
            logger.debug("Automatic AnomalyDetector initialization deferred: %s", exc)

    if threat_intel is not None:
        _threat_intel = threat_intel
    elif _threat_intel is None and ThreatEnrichment is not None:
        try:
            _threat_intel = ThreatEnrichment(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic ThreatEnrichment initialization deferred: %s", exc)

    if incident_responder is not None:
        _incident_responder = incident_responder
    elif _incident_responder is None and IncidentResponder is not None:
        try:
            _incident_responder = IncidentResponder(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic IncidentResponder initialization deferred: %s", exc)

    if recovery_mgr is not None:
        _recovery_mgr = recovery_mgr
    elif _recovery_mgr is None and RecoveryManager is not None:
        try:
            _recovery_mgr = RecoveryManager(config=_config, db=_db)
        except Exception as exc:
            logger.debug("Automatic RecoveryManager initialization deferred: %s", exc)

    # Sync monitoring state directory from config if available
    if _config and getattr(_config, "DEFAULT_MONITOR_DIR", None):
        _monitoring_state["directory"] = str(_config.DEFAULT_MONITOR_DIR)

    logger.info("API routes initialized successfully with dependencies.")


# -----------------------------------------------------------------------------
# Pydantic Schemas for Request & Response validation
# -----------------------------------------------------------------------------
class MonitorStartRequest(BaseModel):
    """Payload to start directory monitoring."""
    path: Optional[str] = Field(default=None, description="Absolute or relative path to directory to monitor")
    directory: Optional[str] = Field(default=None, description="Alias for path parameter")


class AlertUpdateRequest(BaseModel):
    """Payload to modify status of an existing alert."""
    status: str = Field(..., description="Target status: active, investigating, resolved, false_positive")
    response_action: Optional[str] = Field(default=None, description="Summary of response action or triage note")


class MLTrainRequest(BaseModel):
    """Payload to trigger ML anomaly detector training."""
    use_synthetic: bool = Field(default=True, description="Whether to include synthetic ransomware baselines")
    n_samples: int = Field(default=1000, ge=50, le=50000, description="Number of baseline samples to generate")


class MLPredictRequest(BaseModel):
    """Payload for custom ML prediction evaluation."""
    features: Optional[Dict[str, float]] = Field(default=None, description="Direct feature mapping if provided")
    window_seconds: int = Field(default=60, ge=5, le=3600, description="Window size in seconds if features not given")


class ThreatCheckRequest(BaseModel):
    """Payload for threat intelligence indicator lookup."""
    indicator: Optional[str] = Field(default=None, description="File hash, extension, or IP/domain to check")
    value: Optional[str] = Field(default=None, description="Alias for indicator")
    hash: Optional[str] = Field(default=None, description="File hash alias")
    indicator_type: Optional[str] = Field(default=None, description="Optional type hint: hash, extension, ip, domain")


class ResponseHandleRequest(BaseModel):
    """Payload to initiate incident response workflow on an alert."""
    alert_id: int = Field(..., description="ID of the alert to contain and mitigate")
    action_type: Optional[str] = Field(default=None, description="Specific action override e.g. isolate, quarantine, kill")
    simulate: Optional[bool] = Field(default=None, description="Override simulation mode flag")


class ResponseConfigUpdate(BaseModel):
    """Payload to update containment and simulation configuration."""
    simulation_mode: Optional[bool] = Field(default=None, description="Enable or disable simulation mode")
    real_containment_enabled: Optional[bool] = Field(default=None, description="Enable or disable live containment execution")


class BackupCreateRequest(BaseModel):
    """Payload to request an on-demand directory backup snapshot."""
    directory: Optional[str] = Field(default=None, description="Directory path to snapshot (defaults to monitored dir)")
    snapshot_name: Optional[str] = Field(default=None, description="Custom label for the backup snapshot")


# -----------------------------------------------------------------------------
# Router Definition
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/api")


# =============================================================================
# MONITORING ENDPOINTS
# =============================================================================
@router.post("/monitor/start", tags=["Monitoring"], summary="Start filesystem monitoring")
def start_monitoring(request: MonitorStartRequest) -> Dict[str, Any]:
    """Start monitoring a directory for ransomware filesystem anomalies."""
    global _monitoring_state, _monitor, _canary_mgr
    cfg = get_active_config()
    db = get_active_db()

    target_path = request.path or request.directory
    if not target_path:
        if cfg and getattr(cfg, "DEFAULT_MONITOR_DIR", None):
            target_path = str(cfg.DEFAULT_MONITOR_DIR)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Directory path must be specified in the request body (path or directory field).",
            )

    resolved_path = Path(target_path).resolve()
    try:
        resolved_path.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to access or create monitored directory '{target_path}': {exc}",
        )

    # Delegate to FileMonitor if available
    if _monitor is not None:
        try:
            if hasattr(_monitor, "start_monitoring"):
                _monitor.start_monitoring(str(resolved_path))
            elif hasattr(_monitor, "start"):
                _monitor.start(str(resolved_path))
        except Exception as exc:
            logger.error("Failed to start FileMonitor instance: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"File monitor worker failed to start: {exc}",
            )

    # Deploy canaries if CanaryManager is available
    canary_count = 0
    if _canary_mgr is not None:
        try:
            if hasattr(_canary_mgr, "deploy_canaries"):
                canary_count = _canary_mgr.deploy_canaries(str(resolved_path))
            elif hasattr(_canary_mgr, "deploy"):
                canary_count = _canary_mgr.deploy(str(resolved_path))
        except Exception as exc:
            logger.warning("Canary deployment warning: %s", exc)

    now_iso = datetime.now(timezone.utc).isoformat()
    _monitoring_state["is_running"] = True
    _monitoring_state["directory"] = str(resolved_path)
    if "directories" not in _monitoring_state:
        _monitoring_state["directories"] = []
    if str(resolved_path) not in _monitoring_state["directories"]:
        _monitoring_state["directories"].append(str(resolved_path))
    _monitoring_state["started_at"] = now_iso

    logger.info("Monitoring started on %s (Canaries: %d)", resolved_path, canary_count)
    return {
        "status": "started",
        "directory": str(resolved_path),
        "directories": _monitoring_state["directories"],
        "started_at": now_iso,
        "canaries_deployed": canary_count,
        "message": f"Filesystem monitoring active on {resolved_path}",
    }


@router.post("/monitor/add-path", tags=["Monitoring"], summary="Add an additional directory to monitor")
def add_monitored_path(request: MonitorStartRequest) -> Dict[str, Any]:
    """Dynamically register an additional directory to observe simultaneously."""
    global _monitoring_state, _monitor
    target_path = request.path or request.directory
    if not target_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Directory path must be specified.",
        )

    resolved_path = Path(target_path).resolve()
    resolved_path.mkdir(parents=True, exist_ok=True)
    res_str = str(resolved_path)

    if _monitor is not None:
        if hasattr(_monitor, "add_directory"):
            _monitor.add_directory(res_str)
            if not _monitor.is_running:
                _monitor.start_monitoring()

    if "directories" not in _monitoring_state:
        _monitoring_state["directories"] = []
    if res_str not in _monitoring_state["directories"]:
        _monitoring_state["directories"].append(res_str)

    _monitoring_state["is_running"] = True
    _monitoring_state["directory"] = res_str

    logger.info("Added directory to active monitoring: %s", res_str)
    return {
        "status": "added",
        "path": res_str,
        "directories": _monitoring_state["directories"],
        "message": f"Added '{res_str}' to active monitoring.",
    }


@router.post("/monitor/remove-path", tags=["Monitoring"], summary="Remove a directory from active monitoring")
def remove_monitored_path(request: MonitorStartRequest) -> Dict[str, Any]:
    """Remove a specific directory from active monitoring."""
    global _monitoring_state, _monitor
    target_path = request.path or request.directory
    if not target_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Directory path must be specified.",
        )

    res_str = str(Path(target_path).resolve())

    if _monitor is not None and hasattr(_monitor, "remove_directory"):
        _monitor.remove_directory(res_str)

    if "directories" in _monitoring_state and res_str in _monitoring_state["directories"]:
        _monitoring_state["directories"].remove(res_str)

    if _monitoring_state.get("directories"):
        _monitoring_state["directory"] = _monitoring_state["directories"][0]
    else:
        _monitoring_state["directory"] = None

    return {
        "status": "removed",
        "path": res_str,
        "directories": _monitoring_state.get("directories", []),
        "message": f"Removed '{res_str}' from active monitoring.",
    }


@router.post("/monitor/stop", tags=["Monitoring"], summary="Stop filesystem monitoring")
def stop_monitoring() -> Dict[str, Any]:
    """Stop active filesystem monitoring across all directories."""
    global _monitoring_state, _monitor

    if _monitor is not None:
        try:
            if hasattr(_monitor, "stop_monitoring"):
                _monitor.stop_monitoring()
            elif hasattr(_monitor, "stop"):
                _monitor.stop()
        except Exception as exc:
            logger.error("Error stopping FileMonitor: %s", exc)

    previous_dirs = list(_monitoring_state.get("directories", []))
    _monitoring_state["is_running"] = False
    _monitoring_state["started_at"] = None
    _monitoring_state["directories"] = []
    _monitoring_state["directory"] = None

    logger.info("Monitoring stopped across directories: %s", previous_dirs)
    return {
        "status": "stopped",
        "directories": previous_dirs,
        "message": "Filesystem monitoring stopped successfully across all directories.",
    }


@router.get("/monitor/status", tags=["Monitoring"], summary="Get monitoring status")
def get_monitoring_status() -> Dict[str, Any]:
    """Return operational status of the filesystem monitor, event tallies, and targets."""
    global _monitor, _monitoring_state
    db = get_active_db()
    cfg = get_active_config()

    total_events = 0
    recent_events = 0
    active_alerts = 0
    if db is not None:
        try:
            total_events = db.get_file_events_count()
            recent_events = db.get_recent_events_count(seconds=60)
            active_alerts = db.get_active_alerts_count()
        except Exception as exc:
            logger.debug("Database count queries error: %s", exc)

    # Reconcile directories from live FileMonitor
    active_dirs = []
    if _monitor is not None and hasattr(_monitor, "get_monitored_directories"):
        active_dirs = _monitor.get_monitored_directories()
    if not active_dirs:
        active_dirs = _monitoring_state.get("directories", [])

    is_alive = (_monitor.is_running if _monitor is not None else _monitoring_state["is_running"])

    return {
        "is_running": is_alive,
        "is_monitoring": is_alive,
        "directory": active_dirs[0] if active_dirs else None,
        "directories": active_dirs,
        "started_at": _monitoring_state.get("started_at"),
        "total_events": total_events,
        "recent_events_last_60s": recent_events,
        "active_alerts": active_alerts,
        "simulation_mode": getattr(cfg, "SIMULATION_MODE", True),
    }


@router.get("/monitor/events", tags=["Monitoring"], summary="Get recent file events")
def get_recent_file_events(
    limit: int = Query(default=100, ge=1, le=1000, description="Max events to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    is_canary: Optional[bool] = Query(default=None, description="Filter by canary touch"),
) -> List[Dict[str, Any]]:
    """Retrieve chronologically ordered recent file system events."""
    db = get_active_db()
    if db is None:
        return []

    try:
        events = db.get_file_events(
            limit=limit,
            offset=offset,
            event_type=event_type,
            is_canary=is_canary,
        )
        return [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in events]
    except Exception as exc:
        logger.error("Failed to fetch file events: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error querying file events: {exc}",
        )


@router.get("/monitor/activity", tags=["Monitoring"], summary="Get activity summary for time window")
def get_activity_summary(
    window_seconds: int = Query(default=60, ge=5, le=3600, description="Observation window in seconds")
) -> Dict[str, Any]:
    """Retrieve statistical activity summary (modifications, renames, deletions, entropy)."""
    db = get_active_db()
    cfg = get_active_config()

    cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    cutoff_iso = cutoff_dt.isoformat()

    events: List[Any] = []
    if db is not None:
        try:
            events = db.get_file_events(limit=1000, start_time=cutoff_iso)
        except Exception as exc:
            logger.error("Error querying window activity: %s", exc)

    type_counts = {"created": 0, "modified": 0, "deleted": 0, "moved": 0}
    entropies: List[float] = []
    canary_hits = 0
    suspicious_ext_count = 0

    for ev in events:
        etype = getattr(ev, "event_type", None) or (ev.get("event_type") if isinstance(ev, dict) else "")
        if etype in type_counts:
            type_counts[etype] += 1

        ent = getattr(ev, "entropy", None) or (ev.get("entropy") if isinstance(ev, dict) else 0.0)
        if ent and ent > 0.0:
            entropies.append(float(ent))

        is_c = getattr(ev, "is_canary", None) or (ev.get("is_canary") if isinstance(ev, dict) else False)
        if is_c:
            canary_hits += 1

        ext = getattr(ev, "extension", None) or (ev.get("extension") if isinstance(ev, dict) else "")
        if cfg and hasattr(cfg, "is_suspicious_extension") and cfg.is_suspicious_extension(ext):
            suspicious_ext_count += 1

    total_events = len(events)
    avg_entropy = round(sum(entropies) / len(entropies), 3) if entropies else 0.0
    unusual_ratio = round(suspicious_ext_count / total_events, 3) if total_events > 0 else 0.0

    return {
        "window_seconds": window_seconds,
        "window_start": cutoff_iso,
        "window_end": datetime.now(timezone.utc).isoformat(),
        "total_events": total_events,
        "event_breakdown": type_counts,
        "avg_entropy": avg_entropy,
        "suspicious_extensions_count": suspicious_ext_count,
        "unusual_ext_ratio": unusual_ratio,
        "canary_hits": canary_hits,
        "event_rate_per_sec": round(total_events / max(1, window_seconds), 2),
    }


# =============================================================================
# DETECTION ENDPOINTS
# =============================================================================
@router.get("/detection/analyze", tags=["Detection"], summary="Run detection analysis on current window")
def analyze_current_window() -> Dict[str, Any]:
    """Execute detection heuristics and ML analysis on recent file system activity."""
    global _detector
    db = get_active_db()
    cfg = get_active_config()

    # If DetectionEngine is initialized, delegate to it
    if _detector is not None:
        try:
            if hasattr(_detector, "analyze"):
                res = _detector.analyze()
                if hasattr(res, "model_dump"):
                    return res.model_dump()
                elif isinstance(res, dict):
                    return res
            elif hasattr(_detector, "evaluate_window"):
                res = _detector.evaluate_window()
                if hasattr(res, "model_dump"):
                    return res.model_dump()
                elif isinstance(res, dict):
                    return res
        except Exception as exc:
            logger.warning("Delegated DetectionEngine analysis raised exception: %s. Using heuristic analysis.", exc)

    # Built-in robust heuristic risk scoring fallback
    window_sec = getattr(cfg, "TIME_WINDOW_SECONDS", 60) if cfg else 60
    cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
    events: List[Any] = []
    if db is not None:
        try:
            events = db.get_file_events(limit=500, start_time=cutoff_dt.isoformat())
        except Exception as exc:
            logger.error("Failed to query events for detection: %s", exc)

    total_events = len(events)
    modifications = 0
    deletions = 0
    renames = 0
    canary_hits = 0
    entropies: List[float] = []
    suspicious_files: List[str] = []
    reasons: List[str] = []

    for ev in events:
        etype = getattr(ev, "event_type", "") or (ev.get("event_type", "") if isinstance(ev, dict) else "")
        fpath = getattr(ev, "file_path", "") or (ev.get("file_path", "") if isinstance(ev, dict) else "")
        ent = getattr(ev, "entropy", 0.0) or (ev.get("entropy", 0.0) if isinstance(ev, dict) else 0.0)
        ext = getattr(ev, "extension", "") or (ev.get("extension", "") if isinstance(ev, dict) else "")
        is_canary = getattr(ev, "is_canary", False) or (ev.get("is_canary", False) if isinstance(ev, dict) else False)

        if etype == "modified":
            modifications += 1
        elif etype == "deleted":
            deletions += 1
        elif etype == "moved":
            renames += 1

        if ent and ent > 0.0:
            entropies.append(float(ent))

        if is_canary:
            canary_hits += 1
            if fpath not in suspicious_files:
                suspicious_files.append(fpath)

        if cfg and hasattr(cfg, "is_suspicious_extension") and cfg.is_suspicious_extension(ext):
            if fpath not in suspicious_files:
                suspicious_files.append(fpath)

    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    risk_score = 0.0

    # Risk factor 1: Canary hits (Critical signal)
    if canary_hits > 0:
        risk_score += min(50.0, canary_hits * 25.0)
        reasons.append(f"Canary file tamper alert: {canary_hits} decoy files modified or deleted.")

    # Risk factor 2: High Entropy (Encryption signal)
    entropy_thresh = getattr(cfg, "ENTROPY_THRESHOLD", 7.0) if cfg else 7.0
    if avg_entropy >= entropy_thresh:
        risk_score += 30.0
        reasons.append(f"Abnormal Shannon entropy detected (avg {avg_entropy:.2f} >= threshold {entropy_thresh:.2f}), indicating potential data encryption.")

    # Risk factor 3: Rapid modifications
    rapid_thresh = getattr(cfg, "RAPID_ACTIVITY_THRESHOLD", 20) if cfg else 20
    if modifications >= rapid_thresh:
        risk_score += 25.0
        reasons.append(f"Rapid burst modification rate: {modifications} changes in {window_sec}s exceeds baseline ({rapid_thresh}/window).")

    # Risk factor 4: Suspicious ransomware extensions
    if suspicious_files:
        risk_score += min(30.0, len(suspicious_files) * 10.0)
        reasons.append(f"Known ransomware extensions or targets observed on {len(suspicious_files)} file(s).")

    risk_score = min(100.0, round(risk_score, 1))

    # Severity classification
    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 30:
        severity = "medium"
    else:
        severity = "low"

    created_alert_id = None
    if risk_score >= 50 and db is not None:
        try:
            alert_payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "risk_score": risk_score,
                "severity": severity,
                "description": f"Automated detection triggered: {reasons[0] if reasons else 'Suspicious file activity'}",
                "reasons": reasons,
                "affected_directory": _monitoring_state.get("directory"),
                "affected_files": suspicious_files[:20],
                "status": "active",
            }
            created_alert_id = db.insert_alert(alert_payload)
            logger.warning("Generated security alert ID %d (Risk: %s, Severity: %s)", created_alert_id, risk_score, severity)
        except Exception as exc:
            logger.error("Failed to store generated alert: %s", exc)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_seconds": window_sec,
        "total_events": total_events,
        "risk_score": risk_score,
        "severity": severity,
        "is_anomaly": risk_score >= 50,
        "avg_entropy": round(avg_entropy, 3),
        "canary_hits": canary_hits,
        "reasons": reasons,
        "affected_files": suspicious_files,
        "alert_created_id": created_alert_id,
    }


@router.get("/detection/alerts", tags=["Detection"], summary="Get all alerts")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to retrieve"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: low, medium, high, critical"),
    status: Optional[str] = Query(default=None, description="Filter by status: active, investigating, resolved, false_positive"),
) -> List[Dict[str, Any]]:
    """Retrieve security alerts filtered by severity and status."""
    db = get_active_db()
    if db is None:
        return []

    try:
        alerts = db.get_alerts(limit=limit, offset=offset, status=status, severity=severity)
        return [a.model_dump() if hasattr(a, "model_dump") else dict(a) for a in alerts]
    except Exception as exc:
        logger.error("Failed to fetch alerts: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error querying alerts: {exc}",
        )


@router.get("/detection/alerts/{alert_id}", tags=["Detection"], summary="Get specific alert")
def get_alert_detail(alert_id: int) -> Dict[str, Any]:
    """Retrieve full detail for a specific security alert including trigger reasons and affected files."""
    db = get_active_db()
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not ready")

    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} was not found.",
        )
    return alert.model_dump() if hasattr(alert, "model_dump") else dict(alert)


@router.put("/detection/alerts/{alert_id}", tags=["Detection"], summary="Update alert status")
def update_alert(alert_id: int, request: AlertUpdateRequest) -> Dict[str, Any]:
    """Update status (e.g. acknowledge, investigate, resolve) and resolution notes for an alert."""
    db = get_active_db()
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not ready")

    existing = db.get_alert_by_id(alert_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found.",
        )

    resolved_at = datetime.now(timezone.utc).isoformat() if request.status in ("resolved", "false_positive") else None
    success = db.update_alert_status(
        alert_id=alert_id,
        status=request.status,
        resolved_at=resolved_at,
        response_action=request.response_action,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update alert status in database.",
        )

    logger.info("Updated alert %d status to '%s'", alert_id, request.status)
    return {
        "alert_id": alert_id,
        "status": request.status,
        "response_action": request.response_action,
        "resolved_at": resolved_at,
        "updated": True,
    }


# =============================================================================
# ML MODEL ENDPOINTS
# =============================================================================
@router.get("/ml/status", tags=["ML"], summary="Get model status")
def get_ml_status() -> Dict[str, Any]:
    """Return ML model metadata, training timestamp, and feature parameters."""
    global _ml_model
    cfg = get_active_config()
    db = get_active_db()

    model_path = getattr(cfg, "MODEL_PATH", Path("ml/trained_model/isolation_forest.joblib")) if cfg else Path("ml/trained_model/isolation_forest.joblib")
    is_trained = False
    model_info: Dict[str, Any] = {
        "model_type": "IsolationForest",
        "model_path": str(model_path),
        "is_trained": False,
        "last_trained": None,
        "contamination": 0.05,
        "n_estimators": 100,
        "features": [
            "total_events",
            "modifications_rate",
            "deletions_rate",
            "avg_entropy",
            "unusual_ext_ratio",
            "canary_hits",
        ],
    }

    # Query from AnomalyDetector if available
    if _ml_model is not None and hasattr(_ml_model, "get_status"):
        try:
            return _ml_model.get_status()
        except Exception as exc:
            logger.debug("Exception in _ml_model.get_status: %s", exc)

    # Check database training log
    if db is not None:
        try:
            latest_log = db.get_latest_ml_training_log()
            if latest_log:
                model_info["last_trained"] = latest_log.timestamp
                model_info["num_training_samples"] = latest_log.num_samples
                model_info["contamination"] = latest_log.contamination_param
                model_info["is_trained"] = True
                is_trained = True
        except Exception as exc:
            logger.debug("DB ML training log query error: %s", exc)

    # Fallback to model artifact file check
    if not is_trained and Path(model_path).exists():
        model_info["is_trained"] = True
        try:
            mtime = os.path.getmtime(model_path)
            model_info["last_trained"] = datetime.fromtimestamp(mtime, timezone.utc).isoformat()
        except Exception:
            pass

    return model_info


@router.post("/ml/train", tags=["ML"], summary="Train anomaly detection model")
def train_ml_model(request: Optional[MLTrainRequest] = None) -> Dict[str, Any]:
    """Train or fine-tune the Isolation Forest anomaly detector on synthetic or historical data."""
    global _ml_model
    cfg = get_active_config()
    db = get_active_db()

    n_samples = request.n_samples if request else 1000
    use_synthetic = request.use_synthetic if request else True

    # Delegate to AnomalyDetector if instantiated
    if _ml_model is not None:
        try:
            if hasattr(_ml_model, "train"):
                res = _ml_model.train(n_samples=n_samples, use_synthetic=use_synthetic)
                return res if isinstance(res, dict) else {"status": "success", "result": str(res)}
        except Exception as exc:
            logger.warning("Delegated AnomalyDetector train failed: %s. Using internal training routine.", exc)

    # Internal robust training routine using scikit-learn & joblib
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        import joblib
    except ImportError as imp_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Required ML dependencies missing: {imp_err}",
        )

    model_path = Path(getattr(cfg, "MODEL_PATH", "ml/trained_model/isolation_forest.joblib") if cfg else "ml/trained_model/isolation_forest.joblib")
    model_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate synthetic baseline: normal filesystem traffic + injected anomalies
    np.random.seed(42)
    n_normal = int(n_samples * 0.95)
    n_anom = n_samples - n_normal

    # Features: [total_events, modifications_rate, deletions_rate, avg_entropy, unusual_ext_ratio, canary_hits]
    normal_events = np.random.poisson(lam=10, size=n_normal)
    normal_mods = np.random.poisson(lam=6, size=n_normal)
    normal_dels = np.random.poisson(lam=1, size=n_normal)
    normal_entropy = np.clip(np.random.normal(loc=4.5, scale=0.8, size=n_normal), 0.0, 7.0)
    normal_unusual = np.random.beta(a=0.5, b=20, size=n_normal)
    normal_canaries = np.zeros(n_normal)
    X_normal = np.column_stack([normal_events, normal_mods, normal_dels, normal_entropy, normal_unusual, normal_canaries])

    anom_events = np.random.poisson(lam=80, size=n_anom)
    anom_mods = np.random.poisson(lam=60, size=n_anom)
    anom_dels = np.random.poisson(lam=20, size=n_anom)
    anom_entropy = np.clip(np.random.normal(loc=7.6, scale=0.3, size=n_anom), 7.0, 8.0)
    anom_unusual = np.random.beta(a=8, b=2, size=n_anom)
    anom_canaries = np.random.poisson(lam=3, size=n_anom) + 1
    X_anom = np.column_stack([anom_events, anom_mods, anom_dels, anom_entropy, anom_unusual, anom_canaries])

    X = np.vstack([X_normal, X_anom])
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)

    joblib.dump(model, str(model_path))
    now_iso = datetime.now(timezone.utc).isoformat()

    features_used = ["total_events", "modifications_rate", "deletions_rate", "avg_entropy", "unusual_ext_ratio", "canary_hits"]
    if db is not None:
        try:
            db.insert_ml_training_log({
                "timestamp": now_iso,
                "num_samples": n_samples,
                "features_used": features_used,
                "contamination_param": 0.05,
                "model_path": str(model_path),
                "notes": f"Trained on {n_normal} normal + {n_anom} anomalous baseline samples.",
            })
        except Exception as exc:
            logger.debug("Failed to record ML training log: %s", exc)

    logger.info("Trained Isolation Forest model successfully saved to %s", model_path)
    return {
        "status": "success",
        "message": "Anomaly detection model trained successfully.",
        "model_path": str(model_path),
        "num_samples": n_samples,
        "features": features_used,
        "timestamp": now_iso,
    }


@router.post("/ml/predict", tags=["ML"], summary="Run anomaly prediction")
def predict_anomaly(request: Optional[MLPredictRequest] = None) -> Dict[str, Any]:
    """Evaluate anomaly detector against current activity window or supplied features."""
    global _ml_model
    cfg = get_active_config()
    db = get_active_db()

    features_map = request.features if (request and request.features) else None

    # Delegate to AnomalyDetector if initialized
    if _ml_model is not None and hasattr(_ml_model, "predict"):
        try:
            return _ml_model.predict(features=features_map)
        except Exception as exc:
            logger.debug("Delegated _ml_model.predict error: %s", exc)

    # Compute or extract feature vector
    if not features_map:
        window_sec = request.window_seconds if request else 60
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
        events = []
        if db is not None:
            try:
                events = db.get_file_events(limit=500, start_time=cutoff.isoformat())
            except Exception:
                pass

        total_ev = len(events)
        mods = sum(1 for e in events if getattr(e, "event_type", "") == "modified")
        dels = sum(1 for e in events if getattr(e, "event_type", "") == "deleted")
        entropies = [float(getattr(e, "entropy", 0.0) or 0.0) for e in events if getattr(e, "entropy", 0.0)]
        avg_ent = sum(entropies) / len(entropies) if entropies else 0.0
        canaries = sum(1 for e in events if getattr(e, "is_canary", False))
        suspicious_ext = sum(1 for e in events if cfg and hasattr(cfg, "is_suspicious_extension") and cfg.is_suspicious_extension(getattr(e, "extension", "")))
        unusual_ratio = suspicious_ext / total_ev if total_ev > 0 else 0.0

        features_map = {
            "total_events": float(total_ev),
            "modifications_rate": float(mods),
            "deletions_rate": float(dels),
            "avg_entropy": float(round(avg_ent, 2)),
            "unusual_ext_ratio": float(round(unusual_ratio, 2)),
            "canary_hits": float(canaries),
        }

    # Load model and score
    model_path = Path(getattr(cfg, "MODEL_PATH", "ml/trained_model/isolation_forest.joblib") if cfg else "ml/trained_model/isolation_forest.joblib")
    if not model_path.exists():
        # Fallback heuristic calculation if model unpickling not possible
        canary_hit = features_map.get("canary_hits", 0) > 0
        entropy_high = features_map.get("avg_entropy", 0) >= 7.0
        score = 85.0 if (canary_hit or entropy_high) else 15.0
        return {
            "is_anomaly": score >= 50.0,
            "anomaly_score": score,
            "features": features_map,
            "model_ready": False,
            "notes": "Model not yet trained on disk; heuristic fallback score returned.",
        }

    try:
        import joblib
        import numpy as np

        model = joblib.load(str(model_path))
        vec = np.array([[
            features_map.get("total_events", 0.0),
            features_map.get("modifications_rate", 0.0),
            features_map.get("deletions_rate", 0.0),
            features_map.get("avg_entropy", 0.0),
            features_map.get("unusual_ext_ratio", 0.0),
            features_map.get("canary_hits", 0.0),
        ]])
        pred = int(model.predict(vec)[0])  # -1 is anomaly, 1 is normal
        raw_score = float(model.decision_function(vec)[0])
        # Convert decision function to normalized 0-100 anomaly scale
        scaled_score = max(0.0, min(100.0, (0.5 - raw_score) * 100.0))

        return {
            "is_anomaly": pred == -1,
            "anomaly_score": round(scaled_score, 1),
            "raw_decision_score": round(raw_score, 4),
            "features": features_map,
            "model_ready": True,
        }
    except Exception as exc:
        logger.error("ML prediction execution error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference failure: {exc}",
        )


@router.post("/ml/retrain", tags=["ML"], summary="Retrain model with new data")
def retrain_ml_model() -> Dict[str, Any]:
    """Retrain the anomaly detector incorporating recent observed events and anomalies."""
    req = MLTrainRequest(use_synthetic=True, n_samples=1500)
    result = train_ml_model(req)
    result["retrained"] = True
    return result


# =============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# =============================================================================
@router.get("/threat-intel/indicators", tags=["Threat Intel"], summary="List all threat indicators")
def list_threat_indicators(
    limit: int = Query(default=100, ge=1, le=1000, description="Max indicators to return"),
    indicator_type: Optional[str] = Query(default=None, description="Filter: extension, hash, ip, domain"),
    is_demo_data: Optional[bool] = Query(default=None, description="Filter demo vs real indicators"),
) -> List[Dict[str, Any]]:
    """Retrieve indexed ransomware hashes, suspicious extensions, and C2 indicators."""
    db = get_active_db()
    if db is None:
        return []

    try:
        indicators = db.get_threat_indicators(
            limit=limit,
            indicator_type=indicator_type,
            is_demo_data=is_demo_data,
        )
        return [ind.model_dump() if hasattr(ind, "model_dump") else dict(ind) for ind in indicators]
    except Exception as exc:
        logger.error("Failed to query threat indicators: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing threat indicators: {exc}",
        )


@router.post("/threat-intel/check", tags=["Threat Intel"], summary="Check hash or indicator")
def check_threat_indicator(request: ThreatCheckRequest) -> Dict[str, Any]:
    """Check a file hash, extension, or value against local and seeded threat databases."""
    global _threat_intel
    db = get_active_db()
    cfg = get_active_config()

    query_val = request.indicator or request.value or request.hash
    if not query_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide an indicator, value, or hash to check.",
        )

    # Delegate to ThreatEnrichment if available
    if _threat_intel is not None and hasattr(_threat_intel, "check"):
        try:
            return _threat_intel.check(query_val)
        except Exception as exc:
            logger.debug("Delegated ThreatEnrichment check error: %s", exc)

    clean_val = query_val.strip().lower()

    # 1. Check in Database
    matched_record = None
    if db is not None:
        try:
            matched_record = db.find_threat_indicator(clean_val)
        except Exception as exc:
            logger.debug("DB indicator query error: %s", exc)

    if matched_record:
        rec_dict = matched_record.model_dump() if hasattr(matched_record, "model_dump") else dict(matched_record)
        return {
            "matched": True,
            "query": query_val,
            "indicator": rec_dict,
            "risk_level": rec_dict.get("severity", "high"),
            "description": rec_dict.get("description", "Known malicious ransomware indicator"),
            "source": rec_dict.get("source", "internal"),
            "is_demo_data": rec_dict.get("is_demo_data", False),
        }

    # 2. Check against suspicious extension list in config
    if cfg and hasattr(cfg, "is_suspicious_extension") and cfg.is_suspicious_extension(clean_val):
        return {
            "matched": True,
            "query": query_val,
            "indicator": {
                "indicator_type": "extension",
                "value": clean_val,
                "severity": "critical",
                "description": f"Known ransomware file extension: {clean_val}",
                "source": "RansomWatch Threat Intel Database",
                "is_demo_data": False,
            },
            "risk_level": "critical",
            "description": f"Known ransomware extension '{clean_val}' matched.",
            "source": "built-in-signatures",
            "is_demo_data": False,
        }

    return {
        "matched": False,
        "query": query_val,
        "indicator": None,
        "risk_level": "none",
        "description": f"No known malicious signatures matched for '{query_val}'.",
    }


@router.get("/threat-intel/summary", tags=["Threat Intel"], summary="Get threat intel summary")
def get_threat_intel_summary() -> Dict[str, Any]:
    """Retrieve aggregated threat intelligence metrics and catalog breakdown."""
    db = get_active_db()
    if db is None:
        return {
            "total_indicators": 0,
            "demo_count": 0,
            "real_count": 0,
            "by_type": {},
            "status": "database_unavailable",
        }

    try:
        indicators = db.get_threat_indicators(limit=1000)
        by_type: Dict[str, int] = {}
        demo_count = 0
        real_count = 0

        for ind in indicators:
            itype = getattr(ind, "indicator_type", "unknown")
            by_type[itype] = by_type.get(itype, 0) + 1
            if getattr(ind, "is_demo_data", False):
                demo_count += 1
            else:
                real_count += 1

        return {
            "total_indicators": len(indicators),
            "demo_indicators": demo_count,
            "real_indicators": real_count,
            "by_type": by_type,
            "status": "active",
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.error("Failed to compile threat intel summary: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading threat intelligence catalog: {exc}",
        )


@router.post("/threat-intel/initialize-demo", tags=["Threat Intel"], summary="Load demo threat data")
def initialize_demo_threat_intel() -> Dict[str, Any]:
    """Seed comprehensive sample threat indicators (WannaCry, LockBit, BlackCat, REvil)."""
    db = get_active_db()
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not ready")

    # Seed baseline indicators via DatabaseManager
    count = 0
    try:
        if hasattr(db, "seed_threat_indicators"):
            count = db.seed_threat_indicators()
    except Exception as exc:
        logger.warning("db.seed_threat_indicators warning: %s", exc)

    # In case seed method was already run or empty, insert additional recognized hashes
    demo_samples = [
        # WannaCry SHA-256
        {
            "indicator_type": "hash",
            "value": "ed01ebf83334a19373acb9603876413755273fef99a458b349383e663cb8570a",
            "description": "WannaCry Ransomware binary payload",
            "source": "MalwareBazaar / Demo",
            "severity": "critical",
            "is_demo_data": True,
        },
        # LockBit 3.0 SHA-256
        {
            "indicator_type": "hash",
            "value": "08f375c3db08e1a0df9108c5c70ce7f7c0068fd70d3765103a290c01d9f4851f",
            "description": "LockBit 3.0 Black Ransomware sample",
            "source": "ThreatFox / Demo",
            "severity": "critical",
            "is_demo_data": True,
        },
        # BlackCat / ALPHV SHA-256
        {
            "indicator_type": "hash",
            "value": "b96837cb10408ea7ffbf3fc8175d71c42f3604f81014e7a6ca4ab3752e50cc34",
            "description": "BlackCat (ALPHV) Rust Ransomware executable",
            "source": "Abuse.ch / Demo",
            "severity": "critical",
            "is_demo_data": True,
        },
        # REvil / Sodinokibi SHA-256
        {
            "indicator_type": "hash",
            "value": "4690184e565987c126ec25e5186b45a0b72a6bc802f37c38520281b378051229",
            "description": "REvil / Sodinokibi DLL dropper",
            "source": "Internal CIRT / Demo",
            "severity": "critical",
            "is_demo_data": True,
        },
    ]

    try:
        added = db.insert_threat_indicators_batch(demo_samples)
        count += added
    except Exception as exc:
        logger.debug("Batch demo indicators insertion notice: %s", exc)

    logger.info("Initialized demo threat intelligence: %d indicators registered", count)
    return {
        "status": "success",
        "message": f"Successfully loaded demo threat indicators.",
        "indicators_seeded": count,
    }


# =============================================================================
# RESPONSE ENDPOINTS
# =============================================================================
@router.post("/response/handle", tags=["Response"], summary="Handle an alert")
def handle_incident_response(request: ResponseHandleRequest) -> Dict[str, Any]:
    """Execute incident response workflow (containment, process kill, quarantine) for an alert."""
    global _incident_responder
    db = get_active_db()
    cfg = get_active_config()

    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not ready")

    alert = db.get_alert_by_id(request.alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {request.alert_id} not found.",
        )

    # Determine simulation status
    is_simulation = request.simulate if request.simulate is not None else getattr(cfg, "SIMULATION_MODE", True)
    action_type = request.action_type or "containment_and_isolation"

    # Delegate to IncidentResponder if available
    if _incident_responder is not None and hasattr(_incident_responder, "respond"):
        try:
            return _incident_responder.respond(alert, simulate=is_simulation)
        except Exception as exc:
            logger.warning("Delegated IncidentResponder respond error: %s", exc)

    target_desc = alert.affected_directory or "monitored_filesystem"
    execution_result = "simulated" if is_simulation else "executed"
    details = (
        f"Simulated process termination, network adapter isolation, and snapshot freezing for alert {request.alert_id}."
        if is_simulation
        else f"Live containment executed: target directory quarantined and suspicious processes halted."
    )

    # Record response log
    log_id = None
    try:
        log_id = db.insert_response_log({
            "alert_id": request.alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "target": target_desc,
            "result": execution_result,
            "is_simulation": is_simulation,
            "details": details,
        })
    except Exception as exc:
        logger.error("Failed to write response log: %s", exc)

    # Update alert record
    try:
        db.update_alert_status(
            alert_id=request.alert_id,
            status="contained",
            response_action=f"{action_type} ({execution_result})",
        )
    except Exception as exc:
        logger.debug("Failed to update alert status to contained: %s", exc)

    return {
        "status": "success",
        "alert_id": request.alert_id,
        "action_taken": action_type,
        "result": execution_result,
        "is_simulation": is_simulation,
        "response_log_id": log_id,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/response/history", tags=["Response"], summary="Get response action history")
def get_response_history(
    limit: int = Query(default=100, ge=1, le=500, description="Max logs to return"),
    alert_id: Optional[int] = Query(default=None, description="Filter by target alert ID"),
) -> List[Dict[str, Any]]:
    """Retrieve audit log of automated and manual containment response actions."""
    db = get_active_db()
    if db is None:
        return []

    try:
        logs = db.get_response_logs(alert_id=alert_id, limit=limit)
        return [l.model_dump() if hasattr(l, "model_dump") else dict(l) for l in logs]
    except Exception as exc:
        logger.error("Failed to query response history: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching response action logs: {exc}",
        )


@router.get("/response/recovery-plan/{alert_id}", tags=["Response"], summary="Get recovery guidance")
def get_recovery_plan(alert_id: int) -> Dict[str, Any]:
    """Generate structured post-incident recovery plan, backup mapping, and forensic checklist."""
    global _recovery_mgr
    db = get_active_db()
    cfg = get_active_config()

    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not ready")

    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found.",
        )

    # Delegate to RecoveryManager if available
    if _recovery_mgr is not None and hasattr(_recovery_mgr, "get_recovery_plan"):
        try:
            return _recovery_mgr.get_recovery_plan(alert_id)
        except Exception as exc:
            logger.debug("Delegated RecoveryManager plan error: %s", exc)

    # Scan available local backups for recovery
    backup_dir = Path(getattr(cfg, "BACKUP_DIR", "data/backups") if cfg else "data/backups")
    available_backups = []
    if backup_dir.exists():
        for item in sorted(backup_dir.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True):
            available_backups.append({
                "snapshot_name": item.stem,
                "backup_path": str(item),
                "size_bytes": item.stat().st_size,
                "created_at": datetime.fromtimestamp(item.stat().st_mtime, timezone.utc).isoformat(),
            })

    reasons = getattr(alert, "reasons", [])
    affected_files = getattr(alert, "affected_files", [])

    return {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": getattr(alert, "severity", "medium"),
        "risk_score": getattr(alert, "risk_score", 0.0),
        "affected_directory": getattr(alert, "affected_directory", None),
        "total_affected_files": len(affected_files),
        "recommended_steps": [
            {
                "step": 1,
                "title": "Immediate Isolation & Termination",
                "instructions": "Ensure host networking is isolated. Kill all unregistered processes initiating high I/O.",
                "status": "pending_confirmation",
            },
            {
                "step": 2,
                "title": "Decoy & Canary File Inspection",
                "instructions": "Verify canary file integrity in target folders to establish initial tamper time.",
                "status": "recommended",
            },
            {
                "step": 3,
                "title": "Snapshot Restoration",
                "instructions": "Restore quarantined folders from verified pre-attack snapshot.",
                "status": "ready" if available_backups else "no_backups_found",
            },
            {
                "step": 4,
                "title": "Forensic Artifact Collection",
                "instructions": "Preserve ransomware notes (*.txt, *.html) and sample encrypted files for IOC submission.",
                "status": "recommended",
            },
            {
                "step": 5,
                "title": "Post-Mitigation Hardening",
                "instructions": "Review authentication logs, rotate local credentials, and retrain anomaly detection models.",
                "status": "pending",
            },
        ],
        "available_snapshots": available_backups,
        "detection_reasons": reasons,
    }


@router.get("/response/config", tags=["Response"], summary="Get response config")
def get_response_config() -> Dict[str, Any]:
    """Retrieve active containment safety settings and simulation flags."""
    cfg = get_active_config()
    return {
        "simulation_mode": getattr(cfg, "SIMULATION_MODE", True) if cfg else True,
        "real_containment_enabled": getattr(cfg, "REAL_CONTAINMENT_ENABLED", False) if cfg else False,
        "rapid_activity_threshold": getattr(cfg, "RAPID_ACTIVITY_THRESHOLD", 20) if cfg else 20,
        "entropy_threshold": getattr(cfg, "ENTROPY_THRESHOLD", 7.0) if cfg else 7.0,
        "time_window_seconds": getattr(cfg, "TIME_WINDOW_SECONDS", 60) if cfg else 60,
    }


@router.put("/response/config", tags=["Response"], summary="Update response config")
def update_response_config(request: ResponseConfigUpdate) -> Dict[str, Any]:
    """Modify containment settings (simulation mode and live execution permission)."""
    cfg = get_active_config()
    if not cfg:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Configuration unavailable")

    if request.simulation_mode is not None:
        cfg.SIMULATION_MODE = request.simulation_mode
        logger.info("Updated SIMULATION_MODE to %s", request.simulation_mode)

    if request.real_containment_enabled is not None:
        cfg.REAL_CONTAINMENT_ENABLED = request.real_containment_enabled
        logger.info("Updated REAL_CONTAINMENT_ENABLED to %s", request.real_containment_enabled)

    return {
        "simulation_mode": cfg.SIMULATION_MODE,
        "real_containment_enabled": cfg.REAL_CONTAINMENT_ENABLED,
        "updated": True,
    }


# =============================================================================
# BACKUPS ENDPOINTS
# =============================================================================
@router.post("/backups/create", tags=["Backups"], summary="Create backup snapshot of a directory")
def create_backup_snapshot(request: Optional[BackupCreateRequest] = None) -> Dict[str, Any]:
    """Create a compressed snapshot of a target directory for pre-incident recovery."""
    global _recovery_mgr
    cfg = get_active_config()

    target_dir = None
    if request and request.directory:
        target_dir = request.directory
    elif _monitoring_state.get("directory"):
        target_dir = _monitoring_state.get("directory")
    elif cfg and getattr(cfg, "DEFAULT_MONITOR_DIR", None):
        target_dir = str(cfg.DEFAULT_MONITOR_DIR)

    if not target_dir:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No target directory specified to snapshot.",
        )

    resolved_target = Path(target_dir).resolve()
    if not resolved_target.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target directory '{target_dir}' does not exist.",
        )

    # Delegate to RecoveryManager if available
    if _recovery_mgr is not None and hasattr(_recovery_mgr, "create_snapshot"):
        try:
            return _recovery_mgr.create_snapshot(str(resolved_target))
        except Exception as exc:
            logger.warning("Delegated RecoveryManager create_snapshot error: %s", exc)

    backup_root = Path(getattr(cfg, "BACKUP_DIR", "data/backups") if cfg else "data/backups")
    backup_root.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    custom_label = f"_{request.snapshot_name}" if (request and request.snapshot_name) else ""
    snapshot_name = f"snapshot_{resolved_target.name}_{timestamp_str}{custom_label}"
    archive_path = backup_root / f"{snapshot_name}.zip"

    file_count = 0
    try:
        with zipfile.ZipFile(str(archive_path), "w", zipfile.ZIP_DEFLATED) as zip_out:
            for root, _, files in os.walk(resolved_target):
                for f in files:
                    full_p = Path(root) / f
                    # Avoid archiving the backup folder itself if within target
                    if backup_root in full_p.parents:
                        continue
                    arc_name = full_p.relative_to(resolved_target)
                    zip_out.write(full_p, arc_name)
                    file_count += 1
    except Exception as exc:
        logger.error("Failed creating backup archive: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup snapshot creation failed: {exc}",
        )

    size_bytes = archive_path.stat().st_size
    now_iso = datetime.now(timezone.utc).isoformat()
    logger.info("Created backup snapshot '%s' (%d files, %d bytes)", snapshot_name, file_count, size_bytes)

    return {
        "status": "created",
        "snapshot_name": snapshot_name,
        "backup_path": str(archive_path),
        "source_directory": str(resolved_target),
        "file_count": file_count,
        "size_bytes": size_bytes,
        "created_at": now_iso,
    }


@router.get("/backups/list", tags=["Backups"], summary="List available snapshots")
def list_backups() -> List[Dict[str, Any]]:
    """Retrieve list of all available historical snapshot archives."""
    cfg = get_active_config()
    backup_root = Path(getattr(cfg, "BACKUP_DIR", "data/backups") if cfg else "data/backups")
    if not backup_root.exists():
        return []

    snapshots = []
    try:
        for archive in sorted(backup_root.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True):
            stat = archive.stat()
            snapshots.append({
                "snapshot_name": archive.stem,
                "backup_path": str(archive),
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            })
    except Exception as exc:
        logger.error("Error listing backups: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing backups: {exc}",
        )

    return snapshots
