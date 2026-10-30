"""RansomWatch database package.

Provides SQLite persistence, connection pooling, and data models for file events,
threat indicators, alerts, detection windows, response logs, and ML training logs.
"""

from database.db import DatabaseConnectionPool, DatabaseManager, get_db
from database.models import (
    Alert,
    DatabaseStats,
    DetectionWindow,
    FileEvent,
    MLTrainingLog,
    ResponseLog,
    ThreatIndicator,
)

__all__ = [
    "DatabaseConnectionPool",
    "DatabaseManager",
    "get_db",
    "FileEvent",
    "DetectionWindow",
    "Alert",
    "ThreatIndicator",
    "ResponseLog",
    "MLTrainingLog",
    "DatabaseStats",
]
