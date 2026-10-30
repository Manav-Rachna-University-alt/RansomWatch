"""RansomWatch Incident Response and Recovery Module.

Provides:
- ContainmentAdapter: Safe containment guard preventing destructive actions
- IncidentResponder: Orchestrator for the DETECT -> ASSESS -> CONTAIN -> ALERT -> RECOVER lifecycle
- RecoveryManager: Backup snapshot manager, integrity verification, and recovery guidance
"""

from response.containment import ContainmentAdapter
from response.incident import IncidentResponder
from response.recovery import RecoveryManager

__all__ = [
    "ContainmentAdapter",
    "IncidentResponder",
    "RecoveryManager",
]
