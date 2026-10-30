"""Detection package for RansomWatch.

Provides multi-signal heuristic analysis, risk scoring, threat indicator aggregation,
and alerting logic for ransomware detection.
"""

from __future__ import annotations

from detection.engine import DetectionEngine
from detection.risk_scorer import (
    DetectionResult,
    format_alert_message,
    should_trigger_alert,
)

__all__ = [
    "DetectionEngine",
    "DetectionResult",
    "format_alert_message",
    "should_trigger_alert",
]
