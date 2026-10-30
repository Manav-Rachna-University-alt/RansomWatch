"""Tests for the RansomWatch Response and Recovery Module."""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest

from config import Config
from database.db import DatabaseManager
from database.models import Alert
from response.containment import ContainmentAdapter
from response.incident import IncidentResponder
from response.recovery import RecoveryManager


@pytest.fixture
def temp_env():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "test_ransomwatch.db"
        backup_dir = root / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)

        config = Config()
        config.DATABASE_PATH = str(db_path)
        config.BACKUP_DIR = str(backup_dir)
        config.SIMULATION_MODE = True
        config.REAL_CONTAINMENT_ENABLED = False

        db = DatabaseManager(db_path=str(db_path))

        yield {
            "root": root,
            "config": config,
            "db": db,
            "backup_dir": backup_dir,
        }
        db.close()


def test_containment_adapter_safety_defaults(temp_env):
    config = temp_env["config"]
    adapter = ContainmentAdapter(config)

    assert not adapter.is_enabled

    # Should not enable without config permission
    assert not adapter.enable("CONFIRM_CONTAINMENT")
    assert not adapter.is_enabled

    # Enable simulation action
    sim_res = adapter.simulate_action("log_only", "C:/test")
    assert sim_res["success"] is True
    assert sim_res["simulated"] is True

    # Simulation of prohibited action clearly warns it would be blocked
    sim_block = adapter.simulate_action("kill_process", "PID_1234")
    assert "BLOCKED in real mode" in sim_block["message"]

    # Prohibited action in execute mode is unconditionally rejected
    res_block = adapter.execute_action("kill_process", "PID_1234")
    assert res_block["success"] is False
    assert "strictly prohibited" in res_block["message"]


def test_containment_adapter_authorized_enablement(temp_env):
    config = temp_env["config"]
    config.REAL_CONTAINMENT_ENABLED = True
    adapter = ContainmentAdapter(config)

    # Wrong passphrase fails
    assert not adapter.enable("WRONG_CODE")
    assert not adapter.is_enabled

    # Correct passphrase succeeds
    assert adapter.enable("CONFIRM_CONTAINMENT")
    assert adapter.is_enabled

    # Execute safe action
    res = adapter.execute_action("log_only", "C:/test/file")
    assert res["success"] is True
    assert res["simulated"] is False

    # Prohibited action is STILL rejected even when enabled
    res_blocked = adapter.execute_action("delete_files", "C:/test/file")
    assert res_blocked["success"] is False

    adapter.disable()
    assert not adapter.is_enabled


def test_incident_responder_workflow(temp_env):
    config = temp_env["config"]
    db = temp_env["db"]

    responder = IncidentResponder(config=config, db=db)

    alert_id = db.insert_alert(
        Alert(
            risk_score=85.0,
            severity="critical",
            description="Mass file encryption activity",
            reasons=["High entropy burst", "Canary file modified"],
            affected_directory="C:/test/dir",
            affected_files=["C:/test/dir/doc1.locked", "C:/test/dir/doc2.locked"],
        )
    )

    alert = db.get_alert_by_id(alert_id)
    assert alert is not None

    result = responder.handle_alert(alert, simulate=True)

    assert result["status"] == "success"
    assert result["workflow"] == "DETECT -> ASSESS -> CONTAIN -> ALERT -> RECOVER"
    assert result["is_simulation"] is True

    # Stages verification
    stages = result["stages"]
    assert stages["detect"]["status"] == "completed"
    assert stages["assess"]["assessment"]["severity"] == "critical"
    assert stages["contain"]["status"] == "completed"
    assert stages["alert"]["status"] == "completed"
    assert stages["recover"]["status"] == "ready"

    # Verify audit log was created in DB
    history = responder.get_response_history()
    assert len(history) >= 1
    assert history[0]["alert_id"] == alert_id
    assert history[0]["is_simulation"] is True


def test_recovery_manager_snapshot_and_plan(temp_env):
    config = temp_env["config"]
    db = temp_env["db"]
    root = temp_env["root"]

    # Create dummy data directory to snapshot
    data_dir = root / "user_data"
    data_dir.mkdir()
    (data_dir / "file1.txt").write_text("Hello World", encoding="utf-8")
    (data_dir / "file2.txt").write_text("Secret document", encoding="utf-8")

    rec_mgr = RecoveryManager(config=config, db=db)

    status = rec_mgr.check_backup_status()
    assert status["healthy"] is True
    assert status["snapshot_count"] == 0

    # Create snapshot
    snap_result = rec_mgr.create_snapshot(str(data_dir))
    assert snap_result["success"] is True
    assert snap_result["file_count"] == 2
    assert Path(snap_result["archive_path"]).exists()

    # List snapshots
    snaps = rec_mgr.list_snapshots()
    assert len(snaps) == 1
    assert snaps[0]["file_count"] == 2

    # Verify zip integrity
    with zipfile.ZipFile(snap_result["archive_path"], "r") as zf:
        assert "file1.txt" in zf.namelist()
        assert "manifest.json" in zf.namelist()

    # Recovery plan for alert
    alert_id = db.insert_alert(
        Alert(
            risk_score=75.0,
            severity="high",
            description="Suspicious activity in user_data",
            reasons=["Unusual extension change"],
            affected_directory=str(data_dir),
            affected_files=[str(data_dir / "file1.txt")],
        )
    )

    plan = rec_mgr.get_recovery_plan(alert_id)
    assert plan["threat_severity"] == "high"
    assert plan["recommended_snapshot"] is not None
    assert plan["restoration_completed"] is False
    assert len(plan["recovery_steps"]) == 6
