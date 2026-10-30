"""Feature extraction module for RansomWatch file system events.

Transforms raw file system events within sliding time windows into normalized
numerical feature vectors suitable for anomaly detection models.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Union
import numpy as np

logger = logging.getLogger("ransomwatch.ml.features")

# Default known ransomware extensions if config is unavailable
DEFAULT_SUSPICIOUS_EXTENSIONS: Set[str] = {
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
}

FEATURE_NAMES: List[str] = [
    "files_modified",
    "files_renamed",
    "files_created",
    "files_deleted",
    "total_operations",
    "operation_frequency",
    "unusual_ext_ratio",
    "avg_entropy",
    "max_entropy",
    "entropy_std",
    "canary_interactions",
    "unique_extensions",
    "ext_change_count",
]


class FeatureExtractor:
    """Extracts, validates, and transforms file monitoring events into ML feature vectors."""

    def __init__(
        self,
        suspicious_extensions: Optional[Iterable[str]] = None,
        time_window_seconds: float = 60.0,
    ) -> None:
        """Initialize FeatureExtractor with optional custom suspicious extensions and window.

        Args:
            suspicious_extensions: Optional iterable of file extensions (.ext format) to flag as suspicious.
            time_window_seconds: Default window duration in seconds for frequency calculation.
        """
        if suspicious_extensions is not None:
            self.suspicious_extensions = {
                ext.lower() if ext.startswith(".") else f".{ext.lower()}"
                for ext in suspicious_extensions
            }
        else:
            try:
                from config import config  # type: ignore
                self.suspicious_extensions = {
                    ext.lower() if ext.startswith(".") else f".{ext.lower()}"
                    for ext in getattr(config, "SUSPICIOUS_EXTENSIONS", DEFAULT_SUSPICIOUS_EXTENSIONS)
                }
            except Exception:
                self.suspicious_extensions = set(DEFAULT_SUSPICIOUS_EXTENSIONS)

        self.time_window_seconds = float(time_window_seconds)

    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Return the ordered list of feature names.

        Returns:
            List of feature name strings.
        """
        return list(FEATURE_NAMES)

    def extract_features(
        self,
        events: List[Union[Dict[str, Any], Any]],
        window_seconds: Optional[float] = None,
    ) -> Dict[str, float]:
        """Extract statistical and behavioral features from a list of file events in a time window.

        Args:
            events: List of event dictionaries or objects containing event attributes.
            window_seconds: Optional duration of the observation window in seconds.
                            Defaults to self.time_window_seconds.

        Returns:
            Dictionary mapping feature names to their extracted numerical values.
        """
        duration = float(window_seconds if window_seconds and window_seconds > 0 else self.time_window_seconds)
        total_ops = len(events)

        if total_ops == 0:
            return {name: 0.0 for name in FEATURE_NAMES}

        files_modified = 0
        files_renamed = 0
        files_created = 0
        files_deleted = 0
        canary_interactions = 0
        suspicious_ext_events = 0
        ext_change_count = 0

        valid_entropies: List[float] = []
        unique_extensions: Set[str] = set()
        timestamps: List[float] = []

        for item in events:
            # Support both dict and object (e.g. Pydantic FileEvent)
            ev: Dict[str, Any] = item if isinstance(item, dict) else (
                item.model_dump() if hasattr(item, "model_dump") else getattr(item, "__dict__", {})
            )

            # Event type classification
            ev_type = str(ev.get("event_type", "")).strip().lower()
            if ev_type in ("modified", "modification"):
                files_modified += 1
            elif ev_type in ("renamed", "moved", "rename", "move"):
                files_renamed += 1
            elif ev_type in ("created", "creation"):
                files_created += 1
            elif ev_type in ("deleted", "deletion"):
                files_deleted += 1

            # Canary interactions
            is_canary = ev.get("is_canary", False)
            file_path = str(ev.get("file_path", "") or ev.get("src_path", ""))
            dest_path = str(ev.get("dest_path", ""))
            
            if is_canary or "canary" in file_path.lower() or "canary" in dest_path.lower():
                canary_interactions += 1

            # Extensions and extension change detection
            ext = str(ev.get("extension", "")).strip().lower()
            if not ext and file_path:
                ext = Path(file_path).suffix.lower()

            old_ext = str(ev.get("old_extension", "")).strip().lower()
            if not old_ext and dest_path:
                # If moved: file_path is source, dest_path is target
                source_ext = Path(file_path).suffix.lower()
                target_ext = Path(dest_path).suffix.lower()
                if source_ext and target_ext and source_ext != target_ext:
                    old_ext = source_ext
                    ext = target_ext

            if ext:
                unique_extensions.add(ext)
            if old_ext:
                unique_extensions.add(old_ext)

            # Check if event involved extension change
            if old_ext and ext and old_ext != ext:
                ext_change_count += 1

            # Check for suspicious extensions
            is_suspicious = False
            if ext and ext in self.suspicious_extensions:
                is_suspicious = True
            elif old_ext and old_ext in self.suspicious_extensions:
                is_suspicious = True
            elif any(s in file_path.lower() for s in self.suspicious_extensions):
                is_suspicious = True

            if is_suspicious:
                suspicious_ext_events += 1

            # Entropy calculation (skip negative or -1.0 sentinel values)
            entropy_val = ev.get("entropy")
            if entropy_val is not None:
                try:
                    f_ent = float(entropy_val)
                    if not math.isnan(f_ent) and not math.isinf(f_ent) and f_ent >= 0.0:
                        # Values strictly >= 0 (skips -1.0)
                        valid_entropies.append(f_ent)
                except (ValueError, TypeError):
                    pass

            # Timestamp parsing for potential frequency resolution
            ts = ev.get("timestamp")
            if ts is not None:
                try:
                    if isinstance(ts, (int, float)):
                        timestamps.append(float(ts))
                except (ValueError, TypeError):
                    pass

        # Operation frequency calculation (operations per second)
        operation_frequency = float(total_ops) / duration

        # Suspicious extension ratio
        unusual_ext_ratio = float(suspicious_ext_events) / float(total_ops) if total_ops > 0 else 0.0

        # Entropy statistics
        if valid_entropies:
            avg_entropy = float(np.mean(valid_entropies))
            max_entropy = float(np.max(valid_entropies))
            entropy_std = float(np.std(valid_entropies)) if len(valid_entropies) > 1 else 0.0
        else:
            avg_entropy = 0.0
            max_entropy = 0.0
            entropy_std = 0.0

        features = {
            "files_modified": float(files_modified),
            "files_renamed": float(files_renamed),
            "files_created": float(files_created),
            "files_deleted": float(files_deleted),
            "total_operations": float(total_ops),
            "operation_frequency": float(operation_frequency),
            "unusual_ext_ratio": float(unusual_ext_ratio),
            "avg_entropy": float(avg_entropy),
            "max_entropy": float(max_entropy),
            "entropy_std": float(entropy_std),
            "canary_interactions": float(canary_interactions),
            "unique_extensions": float(len(unique_extensions)),
            "ext_change_count": float(ext_change_count),
        }

        return self.validate_features(features)

    def validate_features(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Validate feature dictionary: replace NaN/None with 0.0, clip extreme values.

        Ensures all expected feature keys are present and conform to realistic bounds.

        Args:
            features: Dictionary containing feature values.

        Returns:
            Sanitized dictionary with guaranteed keys and valid numerical ranges.
        """
        validated: Dict[str, float] = {}
        for name in FEATURE_NAMES:
            raw_val = features.get(name, 0.0)
            if raw_val is None:
                val = 0.0
            else:
                try:
                    val = float(raw_val)
                    if math.isnan(val) or math.isinf(val):
                        val = 0.0
                except (ValueError, TypeError):
                    val = 0.0

            # Apply domain-specific clipping
            if name in (
                "files_modified",
                "files_renamed",
                "files_created",
                "files_deleted",
                "total_operations",
                "canary_interactions",
                "unique_extensions",
                "ext_change_count",
            ):
                val = float(max(0.0, min(1_000_000.0, val)))
            elif name == "unusual_ext_ratio":
                val = float(max(0.0, min(1.0, val)))
            elif name in ("avg_entropy", "max_entropy", "entropy_std"):
                val = float(max(0.0, min(8.0, val)))
            elif name == "operation_frequency":
                val = float(max(0.0, min(100_000.0, val)))
            else:
                val = float(max(0.0, val))

            validated[name] = val

        return validated

    def features_to_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert a feature dictionary into a 1D numpy array in deterministic feature order.

        Args:
            features: Dictionary containing feature values.

        Returns:
            1D numpy ndarray of shape (13,) with dtype float64.
        """
        validated = self.validate_features(features)
        ordered_values = [validated[name] for name in FEATURE_NAMES]
        return np.array(ordered_values, dtype=np.float64)
