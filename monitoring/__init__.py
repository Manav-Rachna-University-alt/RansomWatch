"""Monitoring package for RansomWatch.

Provides filesystem activity tracking via Watchdog, Shannon entropy calculation,
and canary/decoy file deployment and tripwire detection.
"""

from __future__ import annotations

from monitoring.canary import CanaryManager
from monitoring.entropy import (
    calculate_data_entropy,
    calculate_file_entropy,
    is_high_entropy,
)
from monitoring.file_monitor import FileMonitor

__all__ = [
    "calculate_file_entropy",
    "calculate_data_entropy",
    "is_high_entropy",
    "CanaryManager",
    "FileMonitor",
]
