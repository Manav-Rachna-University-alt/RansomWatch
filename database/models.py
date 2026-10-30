"""Database models and data structures for RansomWatch.

Defines Pydantic data schemas representing file monitoring events, detection windows,
threat indicators, security alerts, automated response logs, and ML model training logs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class FileEvent(BaseModel):
    """Represents a single filesystem event captured by the file system watcher."""

    id: Optional[int] = Field(default=None, description="Primary key")
    timestamp: str = Field(default_factory=_utc_now_iso, description="ISO 8601 timestamp of event")
    event_type: str = Field(..., description="Type of event: created, modified, deleted, moved")
    file_path: str = Field(..., description="Absolute path of the file")
    file_hash: Optional[str] = Field(default=None, description="SHA256 hash of file content if computed")
    file_size: Optional[int] = Field(default=0, description="File size in bytes")
    entropy: Optional[float] = Field(default=0.0, description="Calculated Shannon entropy (0.0 - 8.0)")
    extension: Optional[str] = Field(default="", description="Current file extension (e.g., '.txt')")
    old_extension: Optional[str] = Field(default=None, description="Previous extension if moved/renamed")
    is_canary: bool = Field(default=False, description="Whether the targeted file is a canary/decoy file")
    directory: Optional[str] = Field(default=None, description="Parent directory of the file")

    @classmethod
    def from_row(cls, row: Any) -> FileEvent:
        """Construct model from a sqlite3.Row or mapping."""
        data = dict(row)
        data["is_canary"] = bool(data.get("is_canary", 0))
        return cls(**data)


class DetectionWindow(BaseModel):
    """Represents aggregated metrics calculated over a sliding observation window."""

    id: Optional[int] = Field(default=None, description="Primary key")
    window_start: str = Field(..., description="ISO 8601 start timestamp of time window")
    window_end: str = Field(..., description="ISO 8601 end timestamp of time window")
    total_events: int = Field(default=0, description="Total events in window")
    modifications: int = Field(default=0, description="Number of modification events")
    renames: int = Field(default=0, description="Number of rename/move events")
    deletions: int = Field(default=0, description="Number of deletion events")
    creations: int = Field(default=0, description="Number of creation events")
    avg_entropy: float = Field(default=0.0, description="Average Shannon entropy across modified/created files")
    unusual_ext_ratio: float = Field(default=0.0, description="Ratio of events involving suspicious extensions (0.0 - 1.0)")
    canary_hits: int = Field(default=0, description="Number of canary/decoy files touched")
    anomaly_score: float = Field(default=0.0, description="Calculated heuristic or ML anomaly score (0 - 100)")
    is_anomaly: bool = Field(default=False, description="Flag indicating if the window met anomaly criteria")

    @classmethod
    def from_row(cls, row: Any) -> DetectionWindow:
        """Construct model from a sqlite3.Row or mapping."""
        data = dict(row)
        data["is_anomaly"] = bool(data.get("is_anomaly", 0))
        return cls(**data)


class Alert(BaseModel):
    """Represents a security alert raised by the detection engine."""

    id: Optional[int] = Field(default=None, description="Primary key")
    timestamp: str = Field(default_factory=_utc_now_iso, description="ISO 8601 timestamp of alert")
    risk_score: float = Field(..., description="Computed risk score from 0.0 to 100.0")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    description: str = Field(..., description="Human-readable description of the threat")
    reasons: List[str] = Field(default_factory=list, description="List of detection signals/reasons")
    affected_directory: Optional[str] = Field(default=None, description="Target directory under attack")
    affected_files: List[str] = Field(default_factory=list, description="List of file paths involved in alert")
    status: str = Field(default="active", description="Alert status: active, investigating, resolved, false_positive")
    response_action: Optional[str] = Field(default=None, description="Summary of response action taken")
    resolved_at: Optional[str] = Field(default=None, description="ISO 8601 timestamp when resolved")

    @field_validator("reasons", mode="before")
    @classmethod
    def parse_reasons(cls, v: Union[str, List[Any], None]) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
        return [str(item) for item in v]

    @field_validator("affected_files", mode="before")
    @classmethod
    def parse_affected_files(cls, v: Union[str, List[Any], None]) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
        return [str(item) for item in v]

    @classmethod
    def from_row(cls, row: Any) -> Alert:
        """Construct model from a sqlite3.Row or mapping."""
        return cls(**dict(row))


class ThreatIndicator(BaseModel):
    """Represents a known threat indicator (hash, extension, pattern, or C2 IP/domain)."""

    id: Optional[int] = Field(default=None, description="Primary key")
    indicator_type: str = Field(..., description="Type of indicator: extension, hash, ip, domain, yara_rule")
    value: str = Field(..., description="Indicator value, e.g. '.locked' or sha256 string")
    description: Optional[str] = Field(default="", description="Contextual description of the threat")
    source: Optional[str] = Field(default="internal", description="Source of indicator: internal, abuse.ch, virustotal, demo")
    severity: str = Field(default="high", description="Severity: low, medium, high, critical")
    last_updated: str = Field(default_factory=_utc_now_iso, description="ISO 8601 timestamp")
    is_demo_data: bool = Field(default=False, description="Whether this indicator is pre-populated demo data")

    @classmethod
    def from_row(cls, row: Any) -> ThreatIndicator:
        """Construct model from a sqlite3.Row or mapping."""
        data = dict(row)
        data["is_demo_data"] = bool(data.get("is_demo_data", 0))
        return cls(**data)


class ResponseLog(BaseModel):
    """Represents an audit entry for an automated or manual containment response."""

    id: Optional[int] = Field(default=None, description="Primary key")
    alert_id: Optional[int] = Field(default=None, description="Foreign key referencing alerts(id)")
    timestamp: str = Field(default_factory=_utc_now_iso, description="ISO 8601 timestamp of action")
    action_type: str = Field(..., description="Action taken: kill_process, isolate_network, quarantine_file, alert_admin")
    target: str = Field(..., description="Target affected (e.g. PID, file path, host)")
    result: str = Field(..., description="Outcome: success, failed, simulated")
    is_simulation: bool = Field(default=True, description="Whether this action was simulated")
    details: Optional[str] = Field(default=None, description="Additional contextual details or execution trace")

    @classmethod
    def from_row(cls, row: Any) -> ResponseLog:
        """Construct model from a sqlite3.Row or mapping."""
        data = dict(row)
        data["is_simulation"] = bool(data.get("is_simulation", 0))
        return cls(**data)


class MLTrainingLog(BaseModel):
    """Represents a record of an ML model training or fine-tuning run."""

    model_config = {"protected_namespaces": ()}

    id: Optional[int] = Field(default=None, description="Primary key")
    timestamp: str = Field(default_factory=_utc_now_iso, description="ISO 8601 timestamp of training")
    num_samples: int = Field(..., description="Number of baseline training samples")
    features_used: List[str] = Field(default_factory=list, description="List of feature column names")
    contamination_param: float = Field(..., description="Contamination factor for IsolationForest")
    model_path: str = Field(..., description="Filesystem location where model was saved")
    notes: Optional[str] = Field(default=None, description="Observations, metrics, or notes")

    @field_validator("features_used", mode="before")
    @classmethod
    def parse_features_used(cls, v: Union[str, List[Any], None]) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
        return [str(item) for item in v]

    @classmethod
    def from_row(cls, row: Any) -> MLTrainingLog:
        """Construct model from a sqlite3.Row or mapping."""
        return cls(**dict(row))


class DatabaseStats(BaseModel):
    """Summary statistics for the RansomWatch database."""

    total_events: int = 0
    total_alerts: int = 0
    active_alerts: int = 0
    total_threat_indicators: int = 0
    total_detection_windows: int = 0
    total_response_logs: int = 0
    database_size_bytes: int = 0
    last_event_timestamp: Optional[str] = None
