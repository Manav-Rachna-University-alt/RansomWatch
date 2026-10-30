"""Unit and integration tests for RansomWatch monitoring and detection modules.

Tests:
- monitoring.entropy: Shannon entropy calculations, thresholds, error handling.
- monitoring.canary: Decoy deployment, tripwire lookups, cleanup.
- monitoring.file_monitor: Watchdog file monitoring, hashing, entropy analysis, event buffer.
- detection.risk_scorer: DetectionResult dataclass, alert formatters, threshold triggers.
- detection.engine: Multi-signal heuristic detection engine, score calculation, severity.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import Config, RansomWatchConfig
from database.db import DatabaseManager
from detection.engine import DetectionEngine
from detection.risk_scorer import (
    DetectionResult,
    format_alert_message,
    should_trigger_alert,
)
from monitoring.canary import CanaryManager
from monitoring.entropy import (
    calculate_data_entropy,
    calculate_file_entropy,
    is_high_entropy,
)
from monitoring.file_monitor import FileMonitor


@pytest.fixture
def temp_db(tmp_path: Path):
    """Provide an isolated temporary DatabaseManager."""
    db_file = tmp_path / "test_detect.db"
    manager = DatabaseManager(db_path=db_file, max_connections=5)
    yield manager
    manager.close()


@pytest.fixture
def test_config(tmp_path: Path) -> RansomWatchConfig:
    """Provide a customized RansomWatchConfig pointing to tmp_path."""
    return RansomWatchConfig(
        BASE_DIR=tmp_path,
        DATABASE_PATH=tmp_path / "data" / "rw_test.db",
        CANARY_DIR=tmp_path / "data" / "canaries",
        ENTROPY_THRESHOLD=7.0,
        RAPID_ACTIVITY_THRESHOLD=20,
    )


# =============================================================================
# 1. Tests for monitoring/entropy.py
# =============================================================================
class TestEntropyModule:
    """Test Shannon entropy calculation routines."""

    def test_calculate_data_entropy_empty(self):
        assert calculate_data_entropy(b"") == 0.0

    def test_calculate_data_entropy_uniform_distribution(self):
        # 256 unique bytes evenly distributed has theoretical entropy of 8.0 bits
        data = bytes(range(256)) * 10
        entropy = calculate_data_entropy(data)
        assert 7.99 <= entropy <= 8.0

    def test_calculate_data_entropy_monotonous(self):
        # Single repeated byte has zero entropy
        data = b"A" * 5000
        assert calculate_data_entropy(data) == 0.0

    def test_calculate_file_entropy_missing_file(self, tmp_path: Path):
        missing_file = tmp_path / "does_not_exist.bin"
        assert calculate_file_entropy(missing_file) == -1.0

    def test_calculate_file_entropy_empty_file(self, tmp_path: Path):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        assert calculate_file_entropy(empty_file) == 0.0

    def test_calculate_file_entropy_plaintext(self, tmp_path: Path):
        text_file = tmp_path / "sample.txt"
        text_file.write_text("The quick brown fox jumps over the lazy dog. " * 50, encoding="utf-8")
        entropy = calculate_file_entropy(text_file)
        # Plain English text typically has entropy between 3.5 and 4.8
        assert 3.0 <= entropy <= 5.2
        assert is_high_entropy(entropy, threshold=7.0) is False

    def test_calculate_file_entropy_pseudorandom(self, tmp_path: Path):
        rand_file = tmp_path / "random.enc"
        # Pseudorandom data resembles encrypted payload
        rand_file.write_bytes(os.urandom(16384))
        entropy = calculate_file_entropy(rand_file)
        assert entropy >= 7.8
        assert is_high_entropy(entropy, threshold=7.0) is True

    def test_is_high_entropy_negative_value(self):
        # Error return (-1.0) must not be flagged as high entropy
        assert is_high_entropy(-1.0, threshold=7.0) is False


# =============================================================================
# 2. Tests for monitoring/canary.py
# =============================================================================
class TestCanaryManager:
    """Test CanaryManager decoy generation, lookup, and cleanup."""

    def test_setup_and_lookup_canary_files(self, tmp_path: Path):
        canary_dir = tmp_path / "canary_zone"
        manager = CanaryManager(canary_dir=canary_dir)

        deployed = manager.setup_canary_files()
        assert len(deployed) >= 3

        # Verify files were actually written to disk
        for path_str in deployed:
            path = Path(path_str)
            assert path.exists()
            assert path.stat().st_size > 0
            assert manager.is_canary_file(path_str) is True

        # Verify untracked file is not flagged as canary
        regular_file = canary_dir / "regular_notes.txt"
        regular_file.write_text("Regular content", encoding="utf-8")
        assert manager.is_canary_file(str(regular_file)) is False

    def test_get_canary_paths(self, tmp_path: Path):
        canary_dir = tmp_path / "canaries"
        manager = CanaryManager(canary_dir=canary_dir)
        paths = manager.setup_canary_files()

        retrieved = manager.get_canary_paths()
        assert len(retrieved) == len(paths)
        assert sorted(paths) == sorted(retrieved)

    def test_remove_canary_files(self, tmp_path: Path):
        canary_dir = tmp_path / "canaries"
        manager = CanaryManager(canary_dir=canary_dir)
        paths = manager.setup_canary_files()
        assert len(paths) > 0

        removed_count = manager.remove_canary_files()
        assert removed_count == len(paths)

        # Confirm files are deleted and paths cleared
        for path_str in paths:
            assert Path(path_str).exists() is False
            assert manager.is_canary_file(path_str) is False
        assert len(manager.get_canary_paths()) == 0


# =============================================================================
# 3. Tests for monitoring/file_monitor.py
# =============================================================================
class TestFileMonitor:
    """Test Watchdog integration and event processing in FileMonitor."""

    def test_monitor_lifecycle(self, temp_db: DatabaseManager, test_config: RansomWatchConfig, tmp_path: Path):
        watch_dir = tmp_path / "watch_target"
        monitor = FileMonitor(db=temp_db, config=test_config)

        assert monitor.is_running is False
        assert monitor.get_monitored_directory() is None

        monitor.start_monitoring(watch_dir)
        assert monitor.is_running is True
        assert monitor.get_monitored_directory() == str(watch_dir.resolve())

        monitor.stop_monitoring()
        assert monitor.is_running is False

    def test_handler_process_event_created_and_modified(
        self, temp_db: DatabaseManager, test_config: RansomWatchConfig, tmp_path: Path
    ):
        recorded_events: List[dict] = []

        def callback(ev: dict):
            recorded_events.append(ev)

        monitor = FileMonitor(db=temp_db, config=test_config, event_callback=callback)
        handler = monitor.RansomWatchHandler(monitor)

        # Create a sample file
        test_file = tmp_path / "document.docx"
        test_file.write_text("Sensitive executive document", encoding="utf-8")

        # Process creation event directly through handler
        handler._process_event("created", str(test_file))

        assert len(recorded_events) == 1
        ev = recorded_events[0]
        assert ev["event_type"] == "created"
        assert ev["extension"] == ".docx"
        assert ev["file_hash"] is not None
        assert ev["entropy"] >= 0.0
        assert ev["is_canary"] is False

        # Verify event was persisted to SQLite
        db_events = temp_db.get_file_events(limit=10)
        assert len(db_events) == 1
        assert db_events[0].file_path == str(test_file.resolve())

    def test_handler_ignores_temp_files(
        self, temp_db: DatabaseManager, test_config: RansomWatchConfig, tmp_path: Path
    ):
        monitor = FileMonitor(db=temp_db, config=test_config)
        handler = monitor.RansomWatchHandler(monitor)

        temp_file = tmp_path / "~$document.docx"
        dot_file = tmp_path / ".git_config"

        handler._process_event("created", str(temp_file))
        handler._process_event("created", str(dot_file))

        assert len(monitor.events_buffer) == 0
        assert temp_db.get_file_events_count() == 0

    def test_handler_moved_event_extension_tracking(
        self, temp_db: DatabaseManager, test_config: RansomWatchConfig, tmp_path: Path
    ):
        monitor = FileMonitor(db=temp_db, config=test_config)
        handler = monitor.RansomWatchHandler(monitor)

        old_file = str(tmp_path / "finance.xlsx")
        new_file = str(tmp_path / "finance.xlsx.locked")

        handler._process_event("moved", new_file, old_path=old_file)

        assert len(monitor.events_buffer) == 1
        event = monitor.events_buffer[0]
        assert event["event_type"] == "moved"
        assert event["old_extension"] == ".xlsx"
        assert event["extension"] == ".locked"

    def test_get_recent_activity(
        self, temp_db: DatabaseManager, test_config: RansomWatchConfig, tmp_path: Path
    ):
        monitor = FileMonitor(db=temp_db, config=test_config)
        handler = monitor.RansomWatchHandler(monitor)

        for i in range(5):
            fpath = tmp_path / f"test_{i}.txt"
            fpath.write_text(f"content {i}", encoding="utf-8")
            handler._process_event("created", str(fpath))

        stats = monitor.get_recent_activity(seconds=60)
        assert stats["total_events"] == 5
        assert stats["created"] == 5
        assert stats["modified"] == 0
        assert stats["canary_hits"] == 0


# =============================================================================
# 4. Tests for detection/risk_scorer.py
# =============================================================================
class TestRiskScorer:
    """Test DetectionResult, formatting, and alert triggers."""

    def test_detection_result_to_dict_and_payload(self):
        now = datetime.now(timezone.utc)
        result = DetectionResult(
            risk_score=75.0,
            severity="high",
            reasons=["High file entropy spike observed", "Suspicious extension .locked detected"],
            indicators={"total_events": 40, "canary_hits": 0, "avg_entropy": 7.4},
            timestamp=now,
            window_start=now - timedelta(seconds=60),
            window_end=now,
            is_anomaly=False,
        )

        d = result.to_dict()
        assert d["risk_score"] == 75.0
        assert d["severity"] == "high"
        assert len(d["reasons"]) == 2

        payload = result.to_alert_payload(affected_directory="C:/Data")
        assert payload["risk_score"] == 75.0
        assert payload["affected_directory"] == "C:/Data"
        assert payload["status"] == "active"

    def test_format_alert_message(self):
        now = datetime.now(timezone.utc)
        result = DetectionResult(
            risk_score=85.0,
            severity="critical",
            reasons=["Critical canary tripwire triggered", "Mass file encryption burst"],
            indicators={"total_events": 100, "canary_hits": 2, "avg_entropy": 7.8},
            timestamp=now,
            window_start=now - timedelta(seconds=60),
            window_end=now,
            is_anomaly=True,
        )

        message = format_alert_message(result)
        assert "[CRITICAL]" in message
        assert "85.0/100" in message
        assert "Canary Decoy Hits: 2" in message
        assert "Critical canary tripwire triggered" in message
        assert "ML Engine: Unsupervised Anomaly Flagged" in message

    def test_should_trigger_alert(self):
        now = datetime.now(timezone.utc)
        low_res = DetectionResult(
            risk_score=10.0,
            severity="low",
            reasons=[],
            indicators={},
            timestamp=now,
            window_start=now,
            window_end=now,
            is_anomaly=False,
        )
        assert should_trigger_alert(low_res, min_score=30.0) is False

        medium_res = DetectionResult(
            risk_score=45.0,
            severity="medium",
            reasons=["Rapid file modifications"],
            indicators={},
            timestamp=now,
            window_start=now,
            window_end=now,
            is_anomaly=False,
        )
        assert should_trigger_alert(medium_res, min_score=30.0) is True

        crit_res = DetectionResult(
            risk_score=20.0,
            severity="critical",
            reasons=["Canary tripwire hit"],
            indicators={},
            timestamp=now,
            window_start=now,
            window_end=now,
            is_anomaly=False,
        )
        # Critical severity triggers regardless of min_score
        assert should_trigger_alert(crit_res, min_score=30.0) is True


# =============================================================================
# 5. Tests for detection/engine.py
# =============================================================================
class TestDetectionEngine:
    """Test DetectionEngine heuristic rules and window analysis."""

    def test_individual_signal_burst_checks(self, temp_db: DatabaseManager, test_config: RansomWatchConfig):
        engine = DetectionEngine(db=temp_db, config=test_config)

        # 1. Modification burst
        mod_events = [{"event_type": "modified"} for _ in range(25)]
        score_mod, reason_mod = engine._check_modification_burst(mod_events)
        assert score_mod == 20.0
        assert "Critical modification burst" in reason_mod

        # 2. Rename burst
        ren_events = [{"event_type": "moved"} for _ in range(16)]
        score_ren, reason_ren = engine._check_rename_burst(ren_events)
        assert score_ren == 20.0
        assert "Critical file rename burst" in reason_ren

        # 3. Extension changes
        ext_events = [
            {"extension": ".locked"},
            {"extension": ".crypto"},
            {"extension": ".pdf"},
        ]
        score_ext, reason_ext = engine._check_extension_changes(ext_events)
        assert score_ext == 16.0
        assert "Suspicious ransomware file extensions" in reason_ext

        # 4. Entropy spike
        ent_events = [
            {"entropy": 7.8},
            {"entropy": 7.9},
            {"entropy": 7.7},
            {"entropy": 7.5},
            {"entropy": 7.6},
        ]
        score_ent, reason_ent = engine._check_entropy_spike(ent_events)
        assert score_ent == 20.0
        assert "Severe Shannon entropy spike" in reason_ent

        # 5. Rapid operations
        rap_events = [{"event_type": "modified"} for _ in range(45)]
        score_rap, reason_rap = engine._check_rapid_operations(rap_events)
        assert score_rap == 20.0
        assert "Extreme filesystem velocity" in reason_rap

        # 6. Canary access
        can_events = [
            {"is_canary": True, "file_path": "/data/!_00_passwords.docx"},
            {"is_canary": True, "file_path": "/data/!_01_payroll.xlsx"},
        ]
        score_can, reason_can = engine._check_canary_access(can_events)
        assert score_can == 20.0
        assert "CRITICAL CANARY TRIPWIRE" in reason_can

    def test_calculate_risk_score_capped_at_100(self, temp_db: DatabaseManager, test_config: RansomWatchConfig):
        engine = DetectionEngine(db=temp_db, config=test_config)

        # Max out all 6 signals (6 * 20 = 120) -> should clamp to 100
        indicators = {
            "modification_burst_score": 20.0,
            "rename_burst_score": 20.0,
            "extension_changes_score": 20.0,
            "entropy_spike_score": 20.0,
            "rapid_operations_score": 20.0,
            "canary_access_score": 20.0,
            "signal_reasons": ["Reason 1", "Reason 2"],
        }
        score, severity, reasons = engine.calculate_risk_score(indicators)
        assert score == 100.0
        assert severity == "critical"
        assert len(reasons) == 2

    def test_analyze_window_simulated_ransomware_attack(
        self, temp_db: DatabaseManager, test_config: RansomWatchConfig
    ):
        engine = DetectionEngine(db=temp_db, config=test_config)
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=60)
        window_end = now

        # Insert simulated ransomware attack events into SQLite
        events_batch = []
        for i in range(25):
            events_batch.append({
                "timestamp": (window_start + timedelta(seconds=i)).isoformat(),
                "event_type": "modified",
                "file_path": f"C:/UserData/document_{i}.docx.locked",
                "file_hash": "a" * 32,
                "file_size": 2048,
                "entropy": 7.6,
                "extension": ".locked",
                "old_extension": ".docx",
                "is_canary": i == 0,  # One canary touched
                "directory": "C:/UserData",
            })
        temp_db.insert_file_events_batch(events_batch)

        result = engine.analyze_window(window_start, window_end, record_detection_window=True)

        assert result.risk_score >= 70.0
        assert result.severity in ("high", "critical")
        assert len(result.reasons) >= 3
        assert result.indicators["total_events"] == 25
        assert result.indicators["canary_hits"] == 1
        assert result.indicators["suspicious_extensions_count"] == 25

        # Verify detection window was recorded in DB
        windows = temp_db.get_detection_windows(limit=5)
        assert len(windows) == 1
        assert windows[0].total_events == 25
        assert windows[0].canary_hits == 1
