"""Heuristic threat detection engine for RansomWatch.

Aggregates filesystem events across sliding observation windows and analyzes
burst modifications, rename waves, suspicious ransomware file extensions,
Shannon entropy spikes, event velocity, and canary tripwire violations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from config import Config, DEFAULT_RISK_THRESHOLDS, DEFAULT_SUSPICIOUS_EXTENSIONS, RansomWatchConfig
from database.db import DatabaseManager
from database.models import DetectionWindow, FileEvent
from detection.risk_scorer import DetectionResult

logger = logging.getLogger("ransomwatch.detection.engine")


class DetectionEngine:
    """Multi-signal heuristic detection engine for ransomware behavior analysis."""

    def __init__(
        self,
        db: DatabaseManager,
        config: Union[Config, RansomWatchConfig, Any],
    ) -> None:
        """Initialize DetectionEngine with database access and system configuration.

        Args:
            db: DatabaseManager instance for event querying and detection logging.
            config: Configuration object containing thresholds and indicators.
        """
        self.db = db
        self.config = config

        # Retrieve thresholds from config or fallback to secure defaults
        self.entropy_threshold: float = float(getattr(self.config, "ENTROPY_THRESHOLD", 7.0))
        self.rapid_activity_threshold: int = int(getattr(self.config, "RAPID_ACTIVITY_THRESHOLD", 20))
        self.risk_thresholds: Dict[str, Tuple[int, int]] = getattr(
            self.config, "RISK_THRESHOLDS", DEFAULT_RISK_THRESHOLDS
        )

        # Build normalized suspicious extensions set
        raw_suspicious: List[str] = getattr(self.config, "SUSPICIOUS_EXTENSIONS", DEFAULT_SUSPICIOUS_EXTENSIONS)
        self.suspicious_extensions: Set[str] = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in raw_suspicious
        }

    def analyze_window(
        self,
        window_start: datetime,
        window_end: datetime,
        record_detection_window: bool = True,
    ) -> DetectionResult:
        """Analyze all filesystem events occurring within the specified time window.

        Args:
            window_start: Start timestamp of the observation window.
            window_end: End timestamp of the observation window.
            record_detection_window: Whether to persist the aggregated window to the database.

        Returns:
            DetectionResult containing risk score, severity, reasons, and raw indicators.
        """
        # Fetch events from database within time window
        raw_events = self.db.get_events_in_window(window_start, window_end)
        events = [self._normalize_event(ev) for ev in raw_events]

        # Execute heuristic signal checks
        score_mod, reason_mod = self._check_modification_burst(events)
        score_ren, reason_ren = self._check_rename_burst(events)
        score_ext, reason_ext = self._check_extension_changes(events)
        score_ent, reason_ent = self._check_entropy_spike(events)
        score_rap, reason_rap = self._check_rapid_operations(events)
        score_can, reason_can = self._check_canary_access(events)

        # Aggregate counts
        total_events = len(events)
        mod_count = sum(1 for e in events if e.get("event_type") == "modified")
        ren_count = sum(1 for e in events if e.get("event_type") == "moved")
        del_count = sum(1 for e in events if e.get("event_type") == "deleted")
        cre_count = sum(1 for e in events if e.get("event_type") == "created")
        canary_hits = sum(1 for e in events if e.get("is_canary"))

        entropy_vals = [
            float(e["entropy"]) for e in events
            if e.get("entropy") is not None and float(e.get("entropy", -1.0)) >= 0.0
        ]
        avg_entropy = round(sum(entropy_vals) / len(entropy_vals), 4) if entropy_vals else 0.0

        suspicious_ext_count = sum(
            1 for e in events if self._is_suspicious_ext(e.get("extension"))
        )
        unusual_ext_ratio = round(suspicious_ext_count / total_events, 4) if total_events > 0 else 0.0

        # Construct comprehensive indicator metrics
        indicators: Dict[str, Any] = {
            "total_events": total_events,
            "modifications": mod_count,
            "renames": ren_count,
            "deletions": del_count,
            "creations": cre_count,
            "canary_hits": canary_hits,
            "avg_entropy": avg_entropy,
            "unusual_ext_ratio": unusual_ext_ratio,
            "suspicious_extensions_count": suspicious_ext_count,
            "modification_burst_score": score_mod,
            "rename_burst_score": score_ren,
            "extension_changes_score": score_ext,
            "entropy_spike_score": score_ent,
            "rapid_operations_score": score_rap,
            "canary_access_score": score_can,
            "signal_reasons": [
                r for r in [reason_mod, reason_ren, reason_ext, reason_ent, reason_rap, reason_can]
                if r is not None
            ],
        }

        # Calculate composite risk score
        risk_score, severity, reasons = self.calculate_risk_score(indicators)

        result = DetectionResult(
            risk_score=risk_score,
            severity=severity,
            reasons=reasons,
            indicators=indicators,
            timestamp=datetime.now(timezone.utc),
            window_start=window_start,
            window_end=window_end,
            is_anomaly=False,
        )

        if record_detection_window:
            try:
                window_record = {
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "total_events": total_events,
                    "modifications": mod_count,
                    "renames": ren_count,
                    "deletions": del_count,
                    "creations": cre_count,
                    "avg_entropy": avg_entropy,
                    "unusual_ext_ratio": unusual_ext_ratio,
                    "canary_hits": canary_hits,
                    "anomaly_score": risk_score,
                    "is_anomaly": 1 if severity in ("high", "critical") else 0,
                }
                self.db.insert_detection_window(window_record)
            except Exception as db_exc:
                logger.warning("Failed to record detection window: %s", db_exc)

        return result

    def calculate_risk_score(self, indicators: Dict[str, Any]) -> Tuple[float, str, List[str]]:
        """Calculate composite risk score, severity category, and contributing reasons.

        Args:
            indicators: Dictionary containing heuristic signal scores and metadata.

        Returns:
            Tuple of (clamped_risk_score, severity_string, reasons_list).
        """
        signal_keys = [
            "modification_burst_score",
            "rename_burst_score",
            "extension_changes_score",
            "entropy_spike_score",
            "rapid_operations_score",
            "canary_access_score",
        ]
        raw_sum = sum(float(indicators.get(k, 0.0)) for k in signal_keys)
        final_score = round(min(100.0, max(0.0, raw_sum)), 2)

        severity = self.get_severity(final_score)
        reasons = list(indicators.get("signal_reasons", []))

        return final_score, severity, reasons

    def get_severity(self, score: float) -> str:
        """Classify a numeric risk score into low, medium, high, or critical severity.

        Args:
            score: Risk score between 0.0 and 100.0.

        Returns:
            One of 'low', 'medium', 'high', 'critical'.
        """
        # If config provides get_risk_level, delegate
        if hasattr(self.config, "get_risk_level"):
            try:
                return self.config.get_risk_level(score)
            except Exception:
                pass

        clamped = max(0.0, min(100.0, float(score)))
        for level, (low, high) in self.risk_thresholds.items():
            if low <= clamped <= high:
                return level

        if clamped >= 80.0:
            return "critical"
        return "low"

    # -------------------------------------------------------------------------
    # Heuristic Signal Evaluation Methods (0.0 to 20.0 each)
    # -------------------------------------------------------------------------

    def _check_modification_burst(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate rapid modification bursts indicative of mass file tampering.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        mod_events = [e for e in events if e.get("event_type") == "modified"]
        count = len(mod_events)

        if count >= self.rapid_activity_threshold:
            return 20.0, f"Critical modification burst: {count} files modified (threshold: {self.rapid_activity_threshold})"
        elif count >= max(1, self.rapid_activity_threshold // 2):
            return 12.0, f"Elevated file modification rate: {count} files modified in window"
        elif count >= max(1, self.rapid_activity_threshold // 4):
            return 6.0, f"Moderate file modifications: {count} files modified"
        return 0.0, None

    def _check_rename_burst(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate mass file renames typical of ransomware appending extensions.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        ren_events = [e for e in events if e.get("event_type") == "moved"]
        count = len(ren_events)

        if count >= 15:
            return 20.0, f"Critical file rename burst: {count} files renamed in window"
        elif count >= 8:
            return 14.0, f"Elevated file renames observed: {count} files renamed"
        elif count >= 3:
            return 7.0, f"Multiple file renames detected: {count} files renamed"
        return 0.0, None

    def _check_extension_changes(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate occurrences of known ransomware or suspicious encrypted extensions.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        suspicious_matches: List[str] = []
        for ev in events:
            ext = ev.get("extension")
            if ext and self._is_suspicious_ext(ext):
                suspicious_matches.append(ext.lower())

        count = len(suspicious_matches)
        if count == 0:
            return 0.0, None

        unique_exts = sorted(set(suspicious_matches))
        ext_sample = ", ".join(unique_exts[:5])

        if count >= 5:
            return 20.0, f"Mass ransomware extensions detected ({count} files with {ext_sample})"
        elif count >= 2:
            return 16.0, f"Suspicious ransomware file extensions observed on {count} files ({ext_sample})"
        else:
            return 10.0, f"Known ransomware extension detected on file ({ext_sample})"

    def _check_entropy_spike(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate Shannon entropy spikes indicative of ciphertext encryption.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        high_entropy_events = [
            e for e in events
            if e.get("entropy") is not None and float(e.get("entropy", 0.0)) >= self.entropy_threshold
        ]
        count = len(high_entropy_events)

        if count >= 5:
            return 20.0, f"Severe Shannon entropy spike: {count} files exhibiting high entropy (>= {self.entropy_threshold})"
        elif count >= 2:
            return 14.0, f"Elevated entropy detected across {count} files (>= {self.entropy_threshold})"
        elif count == 1:
            return 8.0, f"High entropy file modification observed (>= {self.entropy_threshold})"
        return 0.0, None

    def _check_rapid_operations(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate aggregate filesystem operation velocity.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        total = len(events)
        burst_threshold = self.rapid_activity_threshold * 2

        if total >= burst_threshold:
            return 20.0, f"Extreme filesystem velocity: {total} total operations (threshold: {burst_threshold})"
        elif total >= self.rapid_activity_threshold:
            return 14.0, f"High filesystem activity rate: {total} total operations in window"
        elif total >= max(1, self.rapid_activity_threshold // 2):
            return 7.0, f"Elevated filesystem activity: {total} operations"
        return 0.0, None

    def _check_canary_access(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Evaluate unauthorized modification or deletion of decoy canary files.

        Returns:
            (score_contribution 0-20, human-readable reason or None)
        """
        canary_events = [e for e in events if e.get("is_canary")]
        count = len(canary_events)

        if count == 0:
            return 0.0, None

        touched_files = sorted({Path(e.get("file_path", "")).name for e in canary_events if e.get("file_path")})
        sample_str = ", ".join(touched_files[:3])

        if count >= 2:
            return 20.0, f"CRITICAL CANARY TRIPWIRE: Multiple decoy files tampered with ({count} hits: {sample_str})"
        else:
            return 20.0, f"CRITICAL CANARY TRIPWIRE: Decoy file tampered with ({sample_str})"

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _is_suspicious_ext(self, ext: Optional[str]) -> bool:
        """Check if an extension is in the suspicious ransomware extension list."""
        if not ext:
            return False
        normalized = ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        return normalized in self.suspicious_extensions

    @staticmethod
    def _normalize_event(event: Union[FileEvent, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert a FileEvent model or dictionary into a normalized dictionary."""
        if hasattr(event, "model_dump"):
            return event.model_dump()
        elif hasattr(event, "__dict__"):
            return dict(event.__dict__)
        return dict(event)
