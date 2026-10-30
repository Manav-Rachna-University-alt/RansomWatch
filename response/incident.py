"""Incident Response Workflow Orchestrator for RansomWatch.

Implements the five-stage incident response lifecycle:
DETECT -> ASSESS -> CONTAIN -> ALERT -> RECOVER

Safety Guarantees:
- Never terminates arbitrary system processes.
- Never deletes or modifies user documents.
- Operates in simulation mode by default.
- Real containment requires explicit configuration enablement AND operator passphrase confirmation.
- Full audit logging of all containment actions in the database.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from config import Config
from database.db import DatabaseManager
from database.models import Alert, ResponseLog
from response.containment import ContainmentAdapter

logger = logging.getLogger("ransomwatch.response.incident")


class IncidentResponder:
    """Orchestrates detection-to-recovery incident response lifecycle."""

    def __init__(
        self,
        config: Config,
        db: Optional[DatabaseManager] = None,
        containment_adapter: Optional[ContainmentAdapter] = None,
    ) -> None:
        """Initialize IncidentResponder.

        Args:
            config: Configuration instance.
            db: DatabaseManager instance for persistent auditing.
            containment_adapter: Optional custom ContainmentAdapter.
        """
        self.config = config
        self.db = db
        self.containment = containment_adapter or ContainmentAdapter(config)
        self.simulation_mode = getattr(config, "SIMULATION_MODE", True)

    def assess_threat(self, alert_or_dict: Union[Alert, Dict[str, Any]]) -> Dict[str, Any]:
        """Assess the severity and containment urgency of an alert.

        Args:
            alert_or_dict: Alert object or dictionary.

        Returns:
            Dict[str, Any] with assessment details and recommended actions.
        """
        if isinstance(alert_or_dict, Alert):
            risk_score = alert_or_dict.risk_score
            severity = alert_or_dict.severity
            reasons = alert_or_dict.reasons
            target_dir = alert_or_dict.affected_directory
            affected_files = alert_or_dict.affected_files
        else:
            risk_score = float(alert_or_dict.get("risk_score", 0.0))
            severity = str(alert_or_dict.get("severity", "low")).lower()
            reasons = alert_or_dict.get("reasons", [])
            target_dir = alert_or_dict.get("affected_directory")
            affected_files = alert_or_dict.get("affected_files", [])

        # Map risk score to containment recommendation
        if risk_score >= 80 or severity == "critical":
            recommended_action = "alert_admin"
            containment_level = "immediate_containment"
            containment_summary = "Critical threat detected: Immediate containment notification and admin dispatch."
        elif risk_score >= 60 or severity == "high":
            recommended_action = "alert_admin"
            containment_level = "elevated_containment"
            containment_summary = "High threat level: Admin security alert recommended."
        elif risk_score >= 30 or severity == "medium":
            recommended_action = "log_only"
            containment_level = "monitoring_only"
            containment_summary = "Medium anomaly: Enhanced logging and behavioural audit active."
        else:
            recommended_action = "log_only"
            containment_level = "informational"
            containment_summary = "Low threat level: Standard auditing."

        return {
            "risk_score": risk_score,
            "severity": severity,
            "containment_level": containment_level,
            "recommended_action": recommended_action,
            "containment_summary": containment_summary,
            "target_directory": target_dir,
            "file_count": len(affected_files),
            "reasons": reasons,
        }

    def handle_alert(
        self,
        alert_or_dict: Union[Alert, Dict[str, Any]],
        simulate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Execute full incident response lifecycle: DETECT -> ASSESS -> CONTAIN -> ALERT -> RECOVER.

        Args:
            alert_or_dict: Alert instance or dictionary representation.
            simulate: Optional override for simulation mode. If None, uses config.

        Returns:
            Dict[str, Any] detailing execution across all 5 stages.
        """
        alert_id = getattr(alert_or_dict, "id", None) or (
            alert_or_dict.get("id") if isinstance(alert_or_dict, dict) else None
        )
        is_simulation = self.simulation_mode if simulate is None else simulate

        # 1. DETECT
        detect_stage = {
            "status": "completed",
            "alert_id": alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 2. ASSESS
        assessment = self.assess_threat(alert_or_dict)
        assess_stage = {
            "status": "completed",
            "assessment": assessment,
        }

        # 3. CONTAIN
        action_type = assessment["recommended_action"]
        target = assessment["target_directory"] or "monitored_filesystem"

        if is_simulation:
            containment_result = self.containment.simulate_action(action_type, target)
        else:
            containment_result = self.containment.execute_action(action_type, target)

        # Record audit log in database if DB is configured
        log_id = None
        if self.db is not None:
            try:
                log_model = ResponseLog(
                    alert_id=alert_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    action_type=action_type,
                    target=target,
                    result=containment_result.get("action", "executed")
                    if containment_result.get("success")
                    else "failed",
                    is_simulation=is_simulation,
                    details=containment_result.get("message"),
                )
                log_id = self.db.insert_response_log(log_model)

                # Update alert status and action summary
                if alert_id is not None:
                    self.db.update_alert(
                        alert_id,
                        {
                            "status": "investigating",
                            "response_action": f"{'[SIMULATED] ' if is_simulation else ''}{action_type}: {containment_result.get('message')}",
                        },
                    )
            except Exception as exc:
                logger.warning("Failed to persist response log in database: %s", exc)

        contain_stage = {
            "status": "completed" if containment_result.get("success") else "blocked",
            "action": action_type,
            "target": target,
            "simulated": is_simulation,
            "result": containment_result,
            "log_id": log_id,
        }

        # 4. ALERT
        alert_stage = {
            "status": "completed",
            "notification": (
                f"[{'SIMULATION' if is_simulation else 'ACTIVE'}] "
                f"Severity: {assessment['severity'].upper()} | Risk Score: {assessment['risk_score']} | "
                f"Action: {action_type} on {target}"
            ),
        }

        # 5. RECOVER
        recovery_guidance = self.get_recovery_guidance(alert_or_dict)
        recover_stage = {
            "status": "ready",
            "guidance": recovery_guidance,
        }

        logger.info(
            "Incident response completed for alert %s (Simulation: %s, Result: %s)",
            alert_id,
            is_simulation,
            containment_result.get("success"),
        )

        return {
            "workflow": "DETECT -> ASSESS -> CONTAIN -> ALERT -> RECOVER",
            "alert_id": alert_id,
            "is_simulation": is_simulation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stages": {
                "detect": detect_stage,
                "assess": assess_stage,
                "contain": contain_stage,
                "alert": alert_stage,
                "recover": recover_stage,
            },
            "status": "success" if containment_result.get("success") else "blocked",
        }

    # Compatibility alias expected by api/routes.py
    def respond(
        self,
        alert: Union[Alert, Dict[str, Any]],
        simulate: bool = True,
    ) -> Dict[str, Any]:
        """Alias for handle_alert to satisfy route contracts."""
        return self.handle_alert(alert, simulate=simulate)

    def get_recovery_guidance(self, alert_or_dict: Union[Alert, Dict[str, Any]]) -> Dict[str, Any]:
        """Provide detailed, safe recovery guidance without taking destructive actions.

        Never claims files are restored unless an actual restore operation was performed.
        """
        if isinstance(alert_or_dict, Alert):
            target_dir = alert_or_dict.affected_directory
            affected_files = alert_or_dict.affected_files
            risk_score = alert_or_dict.risk_score
        else:
            target_dir = alert_or_dict.get("affected_directory")
            affected_files = alert_or_dict.get("affected_files", [])
            risk_score = float(alert_or_dict.get("risk_score", 0.0))

        steps = [
            "1. Isolate the affected host or network segment immediately to contain spread.",
            "2. Preserve volatile forensic evidence (memory snapshot, audit logs).",
            "3. Identify the initial infection vector and terminate unauthorized remote sessions.",
            f"4. Verify the integrity of snapshots in the backup repository ({getattr(self.config, 'BACKUP_DIR', 'data/backups')}).",
            f"5. Cross-reference {len(affected_files)} identified suspicious files against offline clean backups.",
            "6. Perform malware eradication before restoring user data.",
            "7. Restore verified clean backups to a sandboxed environment first to test integrity.",
            "8. Never pay ransom demands as payment does not guarantee file recovery.",
        ]

        return {
            "target_directory": target_dir,
            "affected_files_count": len(affected_files),
            "threat_severity_score": risk_score,
            "recovery_steps": steps,
            "restoration_performed": False,
            "notice": (
                "RansomWatch does not claim files are restored automatically. "
                "Manual or tested backup restoration must be conducted following the incident recovery plan."
            ),
        }

    def get_response_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve audit history of containment responses.

        Args:
            limit: Maximum records to return.

        Returns:
            List of response log dictionaries.
        """
        if self.db is None:
            return []
        try:
            logs = self.db.get_response_logs(limit=limit)
            return [log.model_dump() for log in logs]
        except Exception as exc:
            logger.warning("Error fetching response logs: %s", exc)
            return []
