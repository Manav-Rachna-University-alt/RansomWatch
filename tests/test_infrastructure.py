"""Unit and integration tests for RansomWatch core infrastructure.

Tests config.py, database models, SQLite DatabaseManager with connection pooling,
and FastAPI main endpoints using TestClient.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import RansomWatchConfig, config
from database.db import DatabaseManager
from database.models import (
    Alert,
    DatabaseStats,
    DetectionWindow,
    FileEvent,
    MLTrainingLog,
    ResponseLog,
    ThreatIndicator,
)
from main import app


@pytest.fixture
def temp_db_manager(tmp_path: Path):
    """Fixture to provide a clean isolated SQLite database manager."""
    db_file = tmp_path / "test_ransomwatch.db"
    manager = DatabaseManager(db_path=db_file, max_connections=5)
    yield manager
    manager.close()


class TestConfig:
    """Test configuration module."""

    def test_default_config_values(self):
        cfg = RansomWatchConfig()
        assert cfg.DEFAULT_MONITOR_DIR is None
        assert cfg.TIME_WINDOW_SECONDS == 60
        assert cfg.ENTROPY_THRESHOLD == 7.0
        assert cfg.RAPID_ACTIVITY_THRESHOLD == 20
        assert cfg.SIMULATION_MODE is True
        assert cfg.REAL_CONTAINMENT_ENABLED is False
        assert cfg.MAX_EVENTS_BUFFER == 10000
        assert ".encrypted" in cfg.SUSPICIOUS_EXTENSIONS
        assert ".locked" in cfg.SUSPICIOUS_EXTENSIONS

    def test_risk_level_mapping(self):
        cfg = RansomWatchConfig()
        assert cfg.get_risk_level(10) == "low"
        assert cfg.get_risk_level(29) == "low"
        assert cfg.get_risk_level(30) == "medium"
        assert cfg.get_risk_level(50) == "medium"
        assert cfg.get_risk_level(65) == "high"
        assert cfg.get_risk_level(85) == "critical"
        assert cfg.get_risk_level(100) == "critical"

    def test_is_suspicious_extension(self):
        cfg = RansomWatchConfig()
        assert cfg.is_suspicious_extension(".locked") is True
        assert cfg.is_suspicious_extension("locked") is True
        assert cfg.is_suspicious_extension(".Wannacry") is True
        assert cfg.is_suspicious_extension(".txt") is False
        assert cfg.is_suspicious_extension("") is False

    def test_ensure_directories(self, tmp_path: Path):
        test_base = tmp_path / "test_ransom"
        cfg = RansomWatchConfig(
            BASE_DIR=test_base,
            DATABASE_PATH=test_base / "data" / "rw.db",
            MODEL_PATH=test_base / "ml" / "model.joblib",
            CANARY_DIR=test_base / "data" / "canaries",
            LOG_DIR=test_base / "data" / "logs",
            BACKUP_DIR=test_base / "data" / "backups",
        )
        cfg.ensure_directories()
        assert (test_base / "data").exists()
        assert (test_base / "ml").exists()
        assert (test_base / "data" / "canaries").exists()
        assert (test_base / "data" / "logs").exists()
        assert (test_base / "data" / "backups").exists()


class TestDatabaseOperations:
    """Test SQLite DatabaseManager CRUD operations."""

    def test_file_events_crud(self, temp_db_manager: DatabaseManager):
        event = FileEvent(
            event_type="modified",
            file_path="C:/test/file1.docx",
            file_hash="abc123hash",
            file_size=2048,
            entropy=7.4,
            extension=".docx",
            is_canary=False,
            directory="C:/test",
        )
        event_id = temp_db_manager.insert_file_event(event)
        assert event_id > 0

        events = temp_db_manager.get_file_events(limit=10)
        assert len(events) == 1
        assert events[0].id == event_id
        assert events[0].file_path == "C:/test/file1.docx"
        assert events[0].entropy == 7.4
        assert events[0].is_canary is False

        # Batch insert
        batch = [
            FileEvent(event_type="created", file_path="C:/test/file2.txt", extension=".txt"),
            FileEvent(event_type="deleted", file_path="C:/test/canary.pdf", extension=".pdf", is_canary=True),
        ]
        count = temp_db_manager.insert_file_events_batch(batch)
        assert count == 2

        all_events = temp_db_manager.get_file_events(limit=10)
        assert len(all_events) == 3

        canary_events = temp_db_manager.get_file_events(is_canary=True)
        assert len(canary_events) == 1
        assert canary_events[0].is_canary is True

    def test_alerts_crud(self, temp_db_manager: DatabaseManager):
        alert = Alert(
            risk_score=85.0,
            severity="critical",
            description="Mass encryption detected in documents directory",
            reasons=["High entropy burst", "Canary file touched"],
            affected_directory="C:/Users/test/Documents",
            affected_files=["C:/Users/test/Documents/report.docx.locked"],
            status="active",
        )
        alert_id = temp_db_manager.insert_alert(alert)
        assert alert_id > 0

        fetched = temp_db_manager.get_alert_by_id(alert_id)
        assert fetched is not None
        assert fetched.id == alert_id
        assert fetched.risk_score == 85.0
        assert fetched.severity == "critical"
        assert "Canary file touched" in fetched.reasons
        assert len(fetched.affected_files) == 1

        # Update status
        updated = temp_db_manager.update_alert_status(
            alert_id=alert_id,
            status="resolved",
            response_action="Quarantined suspicious process and restored backups",
        )
        assert updated is True

        resolved_alert = temp_db_manager.get_alert_by_id(alert_id)
        assert resolved_alert.status == "resolved"
        assert resolved_alert.resolved_at is not None
        assert resolved_alert.response_action == "Quarantined suspicious process and restored backups"

    def test_threat_indicators(self, temp_db_manager: DatabaseManager):
        # Seed demo indicators
        seeded = temp_db_manager.seed_threat_indicators()
        assert seeded > 0

        indicators = temp_db_manager.get_threat_indicators()
        assert len(indicators) >= seeded

        # Lookup
        found = temp_db_manager.find_threat_indicator(".locked")
        assert found is not None
        assert found.indicator_type == "extension"

        # Lookup case insensitive
        found_upper = temp_db_manager.find_threat_indicator(".LOCKED")
        assert found_upper is not None

        # Insert new indicator
        new_ind = ThreatIndicator(
            indicator_type="hash",
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            description="Empty file SHA256 test",
            severity="low",
        )
        new_id = temp_db_manager.insert_threat_indicator(new_ind)
        assert new_id > 0

        # Delete indicator
        deleted = temp_db_manager.delete_threat_indicator(new_id)
        assert deleted is True

    def test_detection_windows_crud(self, temp_db_manager: DatabaseManager):
        window = DetectionWindow(
            window_start="2026-10-28T00:00:00Z",
            window_end="2026-10-28T00:01:00Z",
            total_events=45,
            modifications=30,
            renames=10,
            deletions=5,
            creations=0,
            avg_entropy=7.85,
            unusual_ext_ratio=0.8,
            canary_hits=2,
            anomaly_score=92.5,
            is_anomaly=True,
        )
        win_id = temp_db_manager.insert_detection_window(window)
        assert win_id > 0

        windows = temp_db_manager.get_detection_windows(only_anomalies=True)
        assert len(windows) == 1
        assert windows[0].anomaly_score == 92.5
        assert windows[0].is_anomaly is True

    def test_response_logs_crud(self, temp_db_manager: DatabaseManager):
        # Insert prerequisite alert for foreign key constraint
        alert = Alert(
            risk_score=75.0,
            severity="high",
            description="Suspicious activity triggering response",
            reasons=["Entropy threshold exceeded"],
        )
        alert_id = temp_db_manager.insert_alert(alert)

        log = ResponseLog(
            alert_id=alert_id,
            action_type="kill_process",
            target="PID 4392 (simulated_ransomware.exe)",
            result="simulated",
            is_simulation=True,
            details="Simulation mode active: kill command suppressed",
        )
        log_id = temp_db_manager.insert_response_log(log)
        assert log_id > 0

        logs = temp_db_manager.get_response_logs(alert_id=alert_id)
        assert len(logs) == 1
        assert logs[0].action_type == "kill_process"
        assert logs[0].is_simulation is True

        # Test log with alert_id=None
        log_no_alert = ResponseLog(
            alert_id=None,
            action_type="isolate_network",
            target="Network Adapter",
            result="simulated",
        )
        log_id2 = temp_db_manager.insert_response_log(log_no_alert)
        assert log_id2 > 0

    def test_ml_training_log_crud(self, temp_db_manager: DatabaseManager):
        ml_log = MLTrainingLog(
            num_samples=5000,
            features_used=["modifications", "renames", "avg_entropy", "unusual_ext_ratio"],
            contamination_param=0.03,
            model_path="ml/trained_model/isolation_forest.joblib",
            notes="Baseline model trained on clean system activities",
        )
        log_id = temp_db_manager.insert_ml_training_log(ml_log)
        assert log_id > 0

        latest = temp_db_manager.get_latest_ml_training_log()
        assert latest is not None
        assert latest.num_samples == 5000
        assert "avg_entropy" in latest.features_used

    def test_database_stats(self, temp_db_manager: DatabaseManager):
        stats = temp_db_manager.get_database_stats()
        assert isinstance(stats, DatabaseStats)
        assert stats.total_events == 0

        temp_db_manager.insert_file_event(FileEvent(event_type="created", file_path="C:/foo.bar"))
        new_stats = temp_db_manager.get_database_stats()
        assert new_stats.total_events == 1
        assert new_stats.last_event_timestamp is not None


class TestFastAPIEndpoints:
    """Test FastAPI application endpoints."""

    @pytest.fixture(autouse=True)
    def setup_client(self):
        client = TestClient(app)
        self.client = client

    def test_root_endpoint(self):
        response = self.client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "RansomWatch"
        assert data["docs_url"] == "/docs"

    def test_health_endpoints(self):
        resp1 = self.client.get("/health")
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["status"] in ("healthy", "degraded")
        assert data1["simulation_mode"] is True

        resp2 = self.client.get("/api/health")
        assert resp2.status_code == 200
        assert resp2.json()["version"] == "0.1.0"

    def test_config_endpoint(self):
        resp = self.client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["TIME_WINDOW_SECONDS"] == 60
        assert data["SIMULATION_MODE"] is True
        assert "SUSPICIOUS_EXTENSIONS" in data

    def test_record_and_get_events(self):
        event_payload = {
            "event_type": "modified",
            "file_path": "C:/data/important_plan.pdf",
            "file_size": 4096,
            "entropy": 7.82,
            "extension": ".pdf",
            "is_canary": False,
            "directory": "C:/data",
        }
        post_resp = self.client.post("/api/events", json=event_payload)
        assert post_resp.status_code == 201
        assert post_resp.json()["status"] == "recorded"

        get_resp = self.client.get("/api/events?limit=5")
        assert get_resp.status_code == 200
        events = get_resp.json()
        assert len(events) >= 1

    def test_create_and_manage_alert(self):
        alert_payload = {
            "risk_score": 90.0,
            "severity": "critical",
            "description": "Rapid file modification with high entropy",
            "reasons": ["Rapid modifications", "High entropy"],
            "affected_directory": "C:/data",
            "affected_files": ["C:/data/f1.enc", "C:/data/f2.enc"],
            "status": "active",
        }
        post_resp = self.client.post("/api/alerts", json=alert_payload)
        assert post_resp.status_code == 201
        alert_id = post_resp.json()["id"]

        get_resp = self.client.get(f"/api/alerts/{alert_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["risk_score"] == 90.0

        patch_resp = self.client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "resolved", "response_action": "Admin acknowledged and dismissed"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["updated"] is True

    def test_threat_intel_endpoints(self):
        lookup_resp = self.client.get("/api/threat-intel/lookup/.locked")
        assert lookup_resp.status_code == 200
        assert "matched" in lookup_resp.json()
