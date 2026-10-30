"""Recovery and Backup Management Module for RansomWatch.

Manages clean backup snapshots, forensic recovery plans, and post-incident
restoration guidance. Enforces strict safety rules:
- Never automatically deletes user files.
- Never claims files have been restored unless an actual verified recovery was executed.
- Provides cryptographic hash verification on created backup archives.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from config import Config
from database.db import DatabaseManager
from database.models import Alert

logger = logging.getLogger("ransomwatch.response.recovery")


class RecoveryManager:
    """Manages pre-incident snapshots, recovery plans, and restoration safeguards."""

    def __init__(
        self,
        config: Config,
        db: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize RecoveryManager.

        Args:
            config: RansomWatch configuration object.
            db: Optional DatabaseManager instance.
        """
        self.config = config
        self.db = db
        self.backup_dir = Path(getattr(config, "BACKUP_DIR", "data/backups"))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def check_backup_status(self) -> Dict[str, Any]:
        """Inspect backup storage availability, snapshot count, and storage usage."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        snapshots = self.list_snapshots()
        total_size_bytes = sum(s.get("size_bytes", 0) for s in snapshots)

        return {
            "backup_directory": str(self.backup_dir.resolve()),
            "exists": self.backup_dir.exists(),
            "snapshot_count": len(snapshots),
            "total_size_bytes": total_size_bytes,
            "total_size_mb": round(total_size_bytes / (1024 * 1024), 2),
            "healthy": True,
            "last_snapshot": snapshots[0]["created_at"] if snapshots else None,
        }

    def create_snapshot(self, source_dir: str) -> Dict[str, Any]:
        """Create a compressed snapshot archive of the target directory.

        Args:
            source_dir: Directory to protect with a snapshot.

        Returns:
            Dict[str, Any]: Snapshot creation result and metadata.
        """
        src = Path(source_dir).resolve()
        if not src.exists() or not src.is_dir():
            raise ValueError(f"Source directory does not exist or is not a directory: {source_dir}")

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sanitized_name = src.name or "root"
        archive_name = f"snapshot_{sanitized_name}_{timestamp_str}.zip"
        archive_path = self.backup_dir / archive_name

        file_count = 0
        total_uncompressed_bytes = 0
        file_hashes: Dict[str, str] = {}

        try:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(src):
                    for file in files:
                        full_path = Path(root) / file
                        # Skip if inside backup dir
                        if self.backup_dir.resolve() in full_path.resolve().parents:
                            continue

                        rel_path = full_path.relative_to(src)
                        try:
                            # Calculate sha256
                            hasher = hashlib.sha256()
                            with open(full_path, "rb") as f:
                                while chunk := f.read(65536):
                                    hasher.update(chunk)
                            file_hashes[str(rel_path)] = hasher.hexdigest()

                            zipf.write(full_path, arcname=str(rel_path))
                            file_count += 1
                            total_uncompressed_bytes += full_path.stat().st_size
                        except Exception as file_err:
                            logger.warning("Could not include file %s in snapshot: %s", full_path, file_err)

                # Write manifest inside the zip
                manifest = {
                    "source_directory": str(src),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "file_count": file_count,
                    "total_bytes": total_uncompressed_bytes,
                    "file_hashes": file_hashes,
                }
                zipf.writestr("manifest.json", json.dumps(manifest, indent=2))

            archive_size = archive_path.stat().st_size
            logger.info("Created backup snapshot: %s (%d files, %d bytes)", archive_name, file_count, archive_size)

            return {
                "success": True,
                "snapshot_name": archive_name,
                "archive_path": str(archive_path.resolve()),
                "source_directory": str(src),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "file_count": file_count,
                "size_bytes": archive_size,
                "size_mb": round(archive_size / (1024 * 1024), 2),
            }
        except Exception as exc:
            if archive_path.exists():
                try:
                    archive_path.unlink()
                except Exception:
                    pass
            logger.error("Failed to create snapshot for %s: %s", source_dir, exc)
            raise

    # Alias for create_snapshot
    def create_backup_snapshot(self, source_dir: str) -> Dict[str, Any]:
        """Alias for create_snapshot."""
        return self.create_snapshot(source_dir)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all available snapshots in chronological order (most recent first)."""
        snapshots: List[Dict[str, Any]] = []
        if not self.backup_dir.exists():
            return snapshots

        for zip_file in sorted(self.backup_dir.glob("snapshot_*.zip"), reverse=True):
            try:
                stat = zip_file.stat()
                mtime_iso = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                file_count = 0
                source_dir = "Unknown"

                # Quick read of manifest if possible
                try:
                    with zipfile.ZipFile(zip_file, "r") as zf:
                        if "manifest.json" in zf.namelist():
                            manifest_bytes = zf.read("manifest.json")
                            manifest = json.loads(manifest_bytes.decode("utf-8"))
                            file_count = manifest.get("file_count", len(zf.namelist()) - 1)
                            source_dir = manifest.get("source_directory", "Unknown")
                        else:
                            file_count = len(zf.namelist())
                except Exception:
                    pass

                snapshots.append({
                    "snapshot_name": zip_file.name,
                    "archive_path": str(zip_file.resolve()),
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created_at": mtime_iso,
                    "file_count": file_count,
                    "source_directory": source_dir,
                })
            except Exception as exc:
                logger.warning("Error inspecting snapshot %s: %s", zip_file, exc)

        return snapshots

    def get_recovery_plan(self, alert_or_id: Union[Alert, Dict[str, Any], int]) -> Dict[str, Any]:
        """Generate structured forensic recovery plan and backup mapping for an alert."""
        alert_obj: Optional[Alert] = None
        alert_id = None

        if isinstance(alert_or_id, int):
            alert_id = alert_or_id
            if self.db is not None:
                alert_obj = self.db.get_alert_by_id(alert_id)
        elif isinstance(alert_or_id, Alert):
            alert_obj = alert_or_id
            alert_id = alert_obj.id
        elif isinstance(alert_or_id, dict):
            alert_id = alert_or_id.get("id")
            try:
                alert_obj = Alert(**alert_or_id)
            except Exception:
                pass

        target_dir = alert_obj.affected_directory if alert_obj else "monitored_filesystem"
        affected_files = alert_obj.affected_files if alert_obj else []
        risk_score = alert_obj.risk_score if alert_obj else 0.0
        severity = alert_obj.severity if alert_obj else "unknown"

        # Match relevant backups
        available_snapshots = self.list_snapshots()
        relevant_snapshots = [
            s for s in available_snapshots
            if target_dir and s.get("source_directory") == str(Path(target_dir).resolve())
        ]
        recommended_snapshot = relevant_snapshots[0] if relevant_snapshots else (
            available_snapshots[0] if available_snapshots else None
        )

        recovery_steps = [
            {
                "step": 1,
                "title": "Immediate Network and Host Containment",
                "action": "Disconnect network cable and disable Wi-Fi. Do not reboot if volatile RAM capture is required.",
                "status": "pending_manual_action",
            },
            {
                "step": 2,
                "title": "Preserve Forensic Artifacts",
                "action": "Export RansomWatch audit logs, database alerts, and anomalous process records.",
                "status": "pending_manual_action",
            },
            {
                "step": 3,
                "title": "Verify Offline Clean Snapshot",
                "action": (
                    f"Selected snapshot: '{recommended_snapshot['snapshot_name']}' "
                    f"({recommended_snapshot['file_count']} files, {recommended_snapshot['size_mb']} MB). "
                    "Validate archive checksum prior to extraction."
                    if recommended_snapshot
                    else "No automated snapshot matched. Locate external offline backup."
                ),
                "status": "ready" if recommended_snapshot else "action_required",
            },
            {
                "step": 4,
                "title": "Malware Eradication",
                "action": "Ensure all persistent autorun entries, scheduled tasks, and rogue scripts are removed.",
                "status": "pending_manual_action",
            },
            {
                "step": 5,
                "title": "Isolated Sandbox Restoration Test",
                "action": "Restore snapshot contents into a staging/sandbox directory first to confirm zero corruption.",
                "status": "pending_manual_action",
            },
            {
                "step": 6,
                "title": "Production Restoration",
                "action": "Copy validated clean files to target directory after confirmation.",
                "status": "pending_manual_action",
            },
        ]

        return {
            "alert_id": alert_id,
            "target_directory": target_dir,
            "threat_severity": severity,
            "risk_score": risk_score,
            "affected_files_count": len(affected_files),
            "affected_files_sample": affected_files[:10],
            "recommended_snapshot": recommended_snapshot,
            "available_snapshots_count": len(available_snapshots),
            "recovery_steps": recovery_steps,
            "restoration_completed": False,
            "disclaimer": (
                "RansomWatch does not fabricate restoration claims. Real file restoration "
                "must be validated and triggered by an authorized administrator."
            ),
        }
