"""Containment Adapter for RansomWatch Incident Response.

Enforces strict safety controls around containment actions. Real destructive
operations (process termination, firewall tampering, file deletion) are strictly
disallowed. Only safe actions (log_only, alert_admin) are supported and require
explicit configuration authorization and two-step confirmation codes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, FrozenSet

from config import Config

logger = logging.getLogger("ransomwatch.response.containment")


class ContainmentAdapter:
    """Safe containment adapter controlling automated response actions.

    Default state is always disabled. Enabling requires explicit confirmation
    string AND configuration approval (REAL_CONTAINMENT_ENABLED=True).
    Destructive actions are strictly prohibited to prevent data loss or outage.
    """

    CONFIRMATION_PHRASES: FrozenSet[str] = frozenset([
        "CONFIRM_CONTAINMENT",
        "CONFIRM_CONTAINMENT_EXECUTION",
        "CONFIRM_CONTAINMENT_SAFETY_PROTOCOL",
    ])

    SUPPORTED_ACTIONS: FrozenSet[str] = frozenset([
        "log_only",
        "alert_admin",
    ])

    PROHIBITED_ACTIONS: FrozenSet[str] = frozenset([
        "kill_process",
        "modify_firewall",
        "delete_files",
        "terminate_pid",
        "quarantine_file",
        "block_port",
        "drop_connection",
        "disable_interface",
    ])

    def __init__(self, config: Config) -> None:
        """Initialize ContainmentAdapter in a strictly disabled state.

        Args:
            config: RansomWatch configuration object.
        """
        self.config = config
        self._enabled: bool = False

    @property
    def is_enabled(self) -> bool:
        """Return True if containment execution is currently authorized and enabled."""
        return self._enabled

    def enable(self, confirmation_code: str) -> bool:
        """Enable real containment actions using a confirmed passphrase.

        Requires both a valid operator confirmation passphrase and configuration
        flag REAL_CONTAINMENT_ENABLED = True.

        Args:
            confirmation_code: Authorization string provided by operator.

        Returns:
            bool: True if containment was successfully enabled, False otherwise.
        """
        # Guard 1: Configuration must allow real containment
        config_allowed = getattr(self.config, "REAL_CONTAINMENT_ENABLED", False)
        if not config_allowed:
            logger.warning(
                "ContainmentAdapter enable rejected: REAL_CONTAINMENT_ENABLED is False in configuration."
            )
            self._enabled = False
            return False

        # Guard 2: Passphrase must match accepted confirmation codes
        normalized_code = str(confirmation_code or "").strip()
        if normalized_code not in self.CONFIRMATION_PHRASES:
            logger.warning(
                "ContainmentAdapter enable rejected: Invalid confirmation code provided."
            )
            self._enabled = False
            return False

        self._enabled = True
        logger.info("ContainmentAdapter successfully ENABLED by authorized operator.")
        return True

    def disable(self) -> None:
        """Disable containment actions, returning adapter to safe dormant state."""
        self._enabled = False
        logger.info("ContainmentAdapter DISABLED.")

    def simulate_action(self, action_type: str, target: str) -> Dict[str, Any]:
        """Simulate an action and describe what would happen without executing anything.

        Args:
            action_type: Name of containment action (e.g. 'log_only', 'alert_admin', 'kill_process').
            target: Target identifier (e.g. file path, directory, PID, IP).

        Returns:
            Dict[str, Any]: Simulation result report.
        """
        norm_action = str(action_type or "").strip().lower()
        norm_target = str(target or "").strip()

        logger.info("Simulating containment action '%s' against target '%s'", norm_action, norm_target)

        # Note if the requested action is prohibited in real execution
        is_prohibited = norm_action in self.PROHIBITED_ACTIONS

        if is_prohibited:
            message = (
                f"SIMULATION ONLY: Action '{norm_action}' on target '{norm_target}' would be "
                "BLOCKED in real mode (destructive actions are prohibited by RansomWatch safety policies)."
            )
        else:
            message = (
                f"SIMULATION: Would execute non-destructive containment '{norm_action}' "
                f"against target '{norm_target}'. No system changes performed."
            )

        return {
            "success": True,
            "action": norm_action,
            "target": norm_target,
            "simulated": True,
            "message": message,
        }

    def execute_action(self, action_type: str, target: str) -> Dict[str, Any]:
        """Execute a safe containment action if enabled and validated.

        Destructive actions ('kill_process', 'modify_firewall', 'delete_files')
        are unconditionally blocked regardless of enablement state.

        Args:
            action_type: Action to perform. Supported: 'log_only', 'alert_admin'.
            target: The target entity (file path, process name, host).

        Returns:
            Dict[str, Any]: {
                "success": bool,
                "action": str,
                "target": str,
                "simulated": bool,
                "message": str
            }
        """
        norm_action = str(action_type or "").strip().lower()
        norm_target = str(target or "").strip()

        # Check 1: Strict rejection of prohibited/destructive actions
        if norm_action in self.PROHIBITED_ACTIONS:
            logger.critical(
                "CONTAINMENT POLICY VIOLATION: Blocked attempt to execute destructive action '%s' on '%s'",
                norm_action,
                norm_target,
            )
            return {
                "success": False,
                "action": norm_action,
                "target": norm_target,
                "simulated": False,
                "message": (
                    f"Action blocked: Destructive action '{norm_action}' is strictly prohibited. "
                    "RansomWatch forbids arbitrary process termination, firewall modification, "
                    "and file deletion."
                ),
            }

        # Check 2: Target validation
        if not norm_target:
            logger.warning("Containment action '%s' rejected: Target cannot be empty.", norm_action)
            return {
                "success": False,
                "action": norm_action,
                "target": "",
                "simulated": False,
                "message": "Containment rejected: Invalid or empty target identifier.",
            }

        # Check 3: Adapter must be explicitly enabled
        if not self.is_enabled:
            logger.warning(
                "Containment execution of '%s' rejected: ContainmentAdapter is currently disabled.",
                norm_action,
            )
            return {
                "success": False,
                "action": norm_action,
                "target": norm_target,
                "simulated": False,
                "message": (
                    "ContainmentAdapter is disabled. Enable with a valid confirmation "
                    "code before executing real containment actions."
                ),
            }

        # Check 4: Must be an authorized supported action
        if norm_action not in self.SUPPORTED_ACTIONS:
            logger.warning("Unsupported containment action '%s' requested.", norm_action)
            return {
                "success": False,
                "action": norm_action,
                "target": norm_target,
                "simulated": False,
                "message": (
                    f"Unsupported containment action '{norm_action}'. "
                    f"Supported safe actions: {sorted(list(self.SUPPORTED_ACTIONS))}"
                ),
            }

        # Execution of safe actions
        if norm_action == "log_only":
            logger.info("CONTAINMENT [LOG_ONLY]: Security event logged for target '%s'", norm_target)
            return {
                "success": True,
                "action": norm_action,
                "target": norm_target,
                "simulated": False,
                "message": f"Containment audit entry recorded for target '{norm_target}'.",
            }

        elif norm_action == "alert_admin":
            logger.warning("CONTAINMENT [ALERT_ADMIN]: Administrator alert triggered for '%s'", norm_target)
            return {
                "success": True,
                "action": norm_action,
                "target": norm_target,
                "simulated": False,
                "message": f"High-priority security notification dispatched for target '{norm_target}'.",
            }

        # Fallback safeguard
        return {
            "success": False,
            "action": norm_action,
            "target": norm_target,
            "simulated": False,
            "message": "Action could not be executed.",
        }
