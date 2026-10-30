"""Risk scoring schemas, formatting, and alert threshold evaluation for RansomWatch.

Provides the DetectionResult data structure encapsulating heuristic signals and ML metrics,
along with alert message formatters and alert triggering rules.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ransomwatch.detection.risk_scorer")


@dataclass
class DetectionResult:
    """Dataclass holding detection analysis results, composite risk score, and signal breakdown."""

    risk_score: float
    severity: str
    reasons: List[str]
    indicators: Dict[str, Any]
    timestamp: datetime
    window_start: datetime
    window_end: datetime
    is_anomaly: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert the DetectionResult to a serializable dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["window_start"] = self.window_start.isoformat()
        data["window_end"] = self.window_end.isoformat()
        return data

    def to_alert_payload(
        self,
        affected_directory: Optional[str] = None,
        affected_files: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Convert DetectionResult into an Alert dictionary suitable for database insertion."""
        description = format_alert_message(self)
        return {
            "timestamp": self.timestamp.isoformat(),
            "risk_score": self.risk_score,
            "severity": self.severity,
            "description": description,
            "reasons": list(self.reasons),
            "affected_directory": affected_directory,
            "affected_files": affected_files or [],
            "status": "active",
        }


def format_alert_message(result: DetectionResult) -> str:
    """Generate a structured, human-readable alert message from a DetectionResult.

    Args:
        result: DetectionResult instance to format.

    Returns:
        Multi-line formatted alert message string.
    """
    severity_tag = result.severity.upper()
    lines = [
        f"[{severity_tag}] Ransomware Threat Alert - Risk Score: {result.risk_score:.1f}/100",
        f"Window: {result.window_start.strftime('%Y-%m-%d %H:%M:%S UTC')} to {result.window_end.strftime('%H:%M:%S UTC')}",
    ]

    if result.is_anomaly:
        lines.append("ML Engine: Unsupervised Anomaly Flagged")

    if result.reasons:
        lines.append("Triggered Heuristic Indicators:")
        for reason in result.reasons:
            lines.append(f"  * {reason}")
    else:
        lines.append("No heuristic threat indicators triggered.")

    # Include key indicators if present
    ind = result.indicators
    metrics_summary = []
    if "total_events" in ind:
        metrics_summary.append(f"Events: {ind.get('total_events', 0)}")
    if "canary_hits" in ind and ind["canary_hits"] > 0:
        metrics_summary.append(f"Canary Decoy Hits: {ind['canary_hits']}")
    if "suspicious_extensions_count" in ind and ind["suspicious_extensions_count"] > 0:
        metrics_summary.append(f"Suspicious Extension Changes: {ind['suspicious_extensions_count']}")
    if "avg_entropy" in ind and ind["avg_entropy"] > 0:
        metrics_summary.append(f"Avg Entropy: {ind['avg_entropy']:.2f}")

    if metrics_summary:
        lines.append(f"Metrics Summary: {', '.join(metrics_summary)}")

    return "\n".join(lines)


def should_trigger_alert(result: DetectionResult, min_score: float = 30.0) -> bool:
    """Determine whether a DetectionResult warrants raising an active security alert.

    An alert triggers if the composite risk score meets or exceeds the minimum score threshold,
    if the severity is marked as 'high' or 'critical', or if the ML model flagged an anomaly.

    Args:
        result: Evaluated DetectionResult.
        min_score: Minimum risk score threshold required to trigger (default 30.0).

    Returns:
        True if an alert should be raised, False otherwise.
    """
    if result.risk_score >= min_score:
        return True
    if result.severity in ("high", "critical"):
        return True
    if result.is_anomaly and result.risk_score >= 15.0:
        return True
    return False
