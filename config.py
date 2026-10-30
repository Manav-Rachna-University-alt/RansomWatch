"""Configuration module for the RansomWatch ransomware detection and response system.

Provides centralized configuration management with sensible security defaults,
path resolution, risk threshold definitions, and directory structure maintenance.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


# Base project directory
BASE_DIR: Path = Path(__file__).resolve().parent

# Default suspicious ransomware extensions to flag
DEFAULT_SUSPICIOUS_EXTENSIONS: List[str] = [
    ".encrypted",
    ".locked",
    ".crypto",
    ".crypt",
    ".enc",
    ".ransom",
    ".crypted",
    ".locky",
    ".wannacry",
    ".wncry",
    ".wcry",
    ".cerber",
    ".zepto",
    ".lockbit",
    ".darkside",
    ".revil",
    ".blackcat",
    ".clop",
    ".stop",
    ".djvu",
    ".mallox",
    ".ryuk",
    ".phobos",
    ".dharma",
    ".makop",
    ".aes",
    ".encr",
    ".sage",
    ".jaff",
    ".arena",
]

# Risk score brackets (score range inclusive)
DEFAULT_RISK_THRESHOLDS: Dict[str, Tuple[int, int]] = {
    "low": (0, 29),
    "medium": (30, 59),
    "high": (60, 79),
    "critical": (80, 100),
}


class RansomWatchConfig(BaseModel):
    """Central configuration model for RansomWatch."""

    model_config = {"protected_namespaces": ()}

    # Project paths
    BASE_DIR: Path = Field(default=BASE_DIR, description="Root directory of the RansomWatch project")
    DEFAULT_MONITOR_DIR: Optional[Path] = Field(
        default=None,
        description="Path to directory monitored for ransomware activity (must be configured by user)",
    )
    DATABASE_PATH: Path = Field(
        default_factory=lambda: BASE_DIR / "data" / "ransomwatch.db",
        description="Path to SQLite database file",
    )
    MODEL_PATH: Path = Field(
        default_factory=lambda: BASE_DIR / "ml" / "trained_model" / "isolation_forest.joblib",
        description="Path to trained ML anomaly detection model artifact",
    )
    CANARY_DIR: Path = Field(
        default_factory=lambda: BASE_DIR / "data" / "canary_files",
        description="Directory for deployed decoy/canary files",
    )
    LOG_DIR: Path = Field(
        default_factory=lambda: BASE_DIR / "data" / "logs",
        description="Directory for application and response log files",
    )
    BACKUP_DIR: Path = Field(
        default_factory=lambda: BASE_DIR / "data" / "backups",
        description="Directory for automated pre-threat file backups",
    )

    # Detection & Analysis settings
    TIME_WINDOW_SECONDS: int = Field(
        default=60,
        description="Duration of sliding time window for event aggregation in seconds",
    )
    RISK_THRESHOLDS: Dict[str, Tuple[int, int]] = Field(
        default=DEFAULT_RISK_THRESHOLDS,
        description="Mapping of severity level to (min_score, max_score) tuple",
    )
    MAX_EVENTS_BUFFER: int = Field(
        default=10000,
        description="Maximum number of in-memory buffered file events before rotation",
    )
    ENTROPY_THRESHOLD: float = Field(
        default=7.0,
        description="Shannon entropy threshold above which file content is considered encrypted/compressed (0.0 to 8.0)",
    )
    RAPID_ACTIVITY_THRESHOLD: int = Field(
        default=20,
        description="Maximum acceptable file modification events per minute before triggering rapid activity alert",
    )
    SUSPICIOUS_EXTENSIONS: List[str] = Field(
        default_factory=lambda: list(DEFAULT_SUSPICIOUS_EXTENSIONS),
        description="File extensions associated with known ransomware families",
    )

    # Response & Containment settings
    SIMULATION_MODE: bool = Field(
        default=True,
        description="When True, response actions (kill, isolate, quarantine) are simulated without impacting system state",
    )
    REAL_CONTAINMENT_ENABLED: bool = Field(
        default=False,
        description="Safety flag; must be explicitly True along with SIMULATION_MODE=False for actual process termination or isolation",
    )

    # Threat Intelligence integrations
    THREAT_INTEL_API_URL: Optional[str] = Field(
        default=None,
        description="Optional URL endpoint for threat intelligence API lookup",
    )
    THREAT_INTEL_API_KEY: Optional[str] = Field(
        default=None,
        description="Optional API key for threat intelligence service",
    )

    # Server settings
    API_HOST: str = Field(default="127.0.0.1", description="FastAPI host address")
    API_PORT: int = Field(default=8000, description="FastAPI port")

    def ensure_directories(self) -> None:
        """Create all required data and log directories if they do not exist."""
        directories = [
            self.DATABASE_PATH.parent,
            self.MODEL_PATH.parent,
            self.CANARY_DIR,
            self.LOG_DIR,
            self.BACKUP_DIR,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def get_risk_level(self, risk_score: float) -> str:
        """Classify a numeric risk score (0-100) into low, medium, high, or critical."""
        clamped_score = max(0.0, min(100.0, float(risk_score)))
        for level, (low, high) in self.RISK_THRESHOLDS.items():
            if low <= clamped_score <= high:
                return level
        if clamped_score >= 80:
            return "critical"
        return "low"

    def is_suspicious_extension(self, extension: str) -> bool:
        """Check whether a given file extension is in the suspicious ransomware list."""
        if not extension:
            return False
        normalized = extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        return normalized in [ext.lower() for ext in self.SUSPICIOUS_EXTENSIONS]

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to serializable dictionary, masking sensitive keys."""
        data = self.model_dump()
        # Convert Path objects to strings
        for k, v in data.items():
            if isinstance(v, Path):
                data[k] = str(v)
        if data.get("THREAT_INTEL_API_KEY"):
            data["THREAT_INTEL_API_KEY"] = "***REDACTED***"
        return data


Config = RansomWatchConfig



# Instantiate global singleton config with environment variable overrides
_env_monitor_dir = os.environ.get("RANSOMWATCH_MONITOR_DIR")
_env_sim_mode = os.environ.get("RANSOMWATCH_SIMULATION_MODE")
_env_real_containment = os.environ.get("RANSOMWATCH_REAL_CONTAINMENT")

config = RansomWatchConfig(
    DEFAULT_MONITOR_DIR=Path(_env_monitor_dir) if _env_monitor_dir else None,
    SIMULATION_MODE=_env_sim_mode.lower() not in ("0", "false", "no") if _env_sim_mode is not None else True,
    REAL_CONTAINMENT_ENABLED=_env_real_containment.lower() in ("1", "true", "yes") if _env_real_containment is not None else False,
)

# Export individual constants for convenient imports
Config = RansomWatchConfig
DEFAULT_MONITOR_DIR = config.DEFAULT_MONITOR_DIR
DATABASE_PATH = config.DATABASE_PATH
MODEL_PATH = config.MODEL_PATH
CANARY_DIR = config.CANARY_DIR
LOG_DIR = config.LOG_DIR
BACKUP_DIR = config.BACKUP_DIR
TIME_WINDOW_SECONDS = config.TIME_WINDOW_SECONDS
RISK_THRESHOLDS = config.RISK_THRESHOLDS
SIMULATION_MODE = config.SIMULATION_MODE
REAL_CONTAINMENT_ENABLED = config.REAL_CONTAINMENT_ENABLED
MAX_EVENTS_BUFFER = config.MAX_EVENTS_BUFFER
ENTROPY_THRESHOLD = config.ENTROPY_THRESHOLD
RAPID_ACTIVITY_THRESHOLD = config.RAPID_ACTIVITY_THRESHOLD
SUSPICIOUS_EXTENSIONS = config.SUSPICIOUS_EXTENSIONS
THREAT_INTEL_API_URL = config.THREAT_INTEL_API_URL
THREAT_INTEL_API_KEY = config.THREAT_INTEL_API_KEY

# Alias Config to RansomWatchConfig for standard import compatibility
Config = RansomWatchConfig

Config = RansomWatchConfig
