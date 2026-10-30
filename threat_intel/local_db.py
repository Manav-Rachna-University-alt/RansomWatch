"""Local Threat Intelligence Database module for RansomWatch.

Provides indicator lookups, demo dataset initialization with known ransomware
family signatures (hashes, domains, and IPs), and custom indicator registration.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.db import DatabaseManager

logger = logging.getLogger("ransomwatch.threat_intel.local_db")


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class LocalThreatDatabase:
    """Manages local threat indicators within SQLite via DatabaseManager.

    Supports demo indicator seeding, hash and indicator lookups,
    and runtime threat intelligence updates.
    """

    DEMO_INDICATORS: List[Dict[str, Any]] = [
        # Ransomware File Hashes (MD5 format, clearly identified demo hashes)
        {
            "indicator_type": "hash",
            "value": "84c82835a5d21bbcf75a61706d8ab549",
            "description": "WannaCry ransomware dropper payload demo hash (WannaCry family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "d0cf11e1f13b10b001a479eb46d0a7d5",
            "description": "LockBit 3.0 encryptor component demo hash (LockBit family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "e2c865db4162bed963bcf94f4da7e474",
            "description": "REvil / Sodinokibi affiliate binary demo hash (REvil family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "fa06f654b0a483e582813134e6dd5143",
            "description": "Conti ransomware v3 locker binary demo hash (Conti family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "9a35e80d46d0ef0694ef0066d9c6e3b5",
            "description": "BlackCat / ALPHV Rust loader demo hash (BlackCat family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "6b3a55e0261b0304143f805a24924d0c",
            "description": "Ryuk enterprise ransomware payload demo hash (Ryuk family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "3f1a94e82c5f94d1b8c0a221469e5d80",
            "description": "DarkSide ransomware pipeline artifact demo hash (DarkSide family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "7d54e12e84a203f191b7d52a13f044bb",
            "description": "Hive ransomware encryptor demo hash (Hive family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "b1a2c3d4e5f60718293a4b5c6d7e8f90",
            "description": "Babuk locker builder demo hash (Babuk family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "hash",
            "value": "5a4b3c2d1e0f987654321fedcba09876",
            "description": "Black Basta secondary payload demo hash (Black Basta family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        # Suspicious Domains (example-malware.com style)
        {
            "indicator_type": "domain",
            "value": "c2-sync.example-malware.com",
            "description": "LockBit command and control coordination endpoint (LockBit family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "domain",
            "value": "payment-decrypt.example-malware.com",
            "description": "WannaCry simulated payment portal domain (WannaCry family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "domain",
            "value": "exfil-gateway.example-malware.com",
            "description": "REvil affiliate data staging and exfiltration portal (REvil family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "domain",
            "value": "leak-bulletin.example-malware.com",
            "description": "Conti public leak blog communication domain (Conti family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "domain",
            "value": "negotiate-portal.example-malware.com",
            "description": "BlackCat / ALPHV extortion communication portal (BlackCat family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "domain",
            "value": "c2-beacon.example-malware.com",
            "description": "Ryuk lateral movement beacon rendezvous domain (Ryuk family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        # Suspicious IPs (Documentation ranges RFC 5737: 192.0.2.x, 198.51.100.x)
        {
            "indicator_type": "ip",
            "value": "192.0.2.15",
            "description": "WannaCry SMB relay and secondary beacon test IP (WannaCry family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "ip",
            "value": "192.0.2.44",
            "description": "LockBit affiliate management listener IP (LockBit family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "ip",
            "value": "192.0.2.108",
            "description": "REvil staging proxy node test IP (REvil family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "ip",
            "value": "198.51.100.22",
            "description": "Conti ransom note callback listener IP (Conti family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
        {
            "indicator_type": "ip",
            "value": "198.51.100.77",
            "description": "BlackCat / ALPHV command dispatch endpoint IP (BlackCat family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "critical",
            "is_demo_data": True,
        },
        {
            "indicator_type": "ip",
            "value": "198.51.100.150",
            "description": "DarkSide egress gateway mock IP (DarkSide family)",
            "source": "RansomWatch Demo Dataset",
            "severity": "high",
            "is_demo_data": True,
        },
    ]

    def __init__(self, db: DatabaseManager) -> None:
        """Initialize the local threat database with a DatabaseManager instance.

        Args:
            db: Active DatabaseManager instance for SQLite operations.
        """
        self.db = db

    def initialize_demo_data(self) -> int:
        """Populate the database with sample threat indicators.

        Seeds ~20 sample threat indicators spanning known ransomware families
        (WannaCry, LockBit, REvil, Conti, BlackCat, Ryuk, etc.) including MD5
        hashes, example-malware.com domains, and RFC 5737 documentation IPs.

        Returns:
            int: The number of indicators inserted or updated.
        """
        inserted_count = 0
        now = _utc_now_iso()

        for item in self.DEMO_INDICATORS:
            indicator_dict = dict(item)
            indicator_dict["last_updated"] = now
            try:
                self.db.insert_threat_indicator(indicator_dict)
                inserted_count += 1
            except Exception as e:
                logger.error("Failed to insert demo indicator '%s': %s", indicator_dict.get("value"), e)

        logger.info("Initialized %d demo threat indicators in local database", inserted_count)
        return inserted_count

    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Search for a specific file hash in known threat indicators.

        Performs a case-insensitive lookup.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash string to search.

        Returns:
            Optional[Dict[str, Any]]: Indicator dict if found, None otherwise.
        """
        if not file_hash or not isinstance(file_hash, str):
            return None

        clean_hash = file_hash.strip().lower()
        if not clean_hash:
            return None

        try:
            indicator = self.db.search_threat_indicator(clean_hash)
            if indicator is not None:
                return indicator.model_dump() if hasattr(indicator, "model_dump") else dict(indicator)
        except Exception as e:
            logger.error("Error looking up hash '%s': %s", clean_hash, e)

        return None

    def lookup_indicator(self, value: str) -> Optional[Dict[str, Any]]:
        """Generic lookup for any threat indicator by value (hash, domain, or IP).

        Args:
            value: The indicator value to match.

        Returns:
            Optional[Dict[str, Any]]: Indicator dict if found, None otherwise.
        """
        if not value or not isinstance(value, str):
            return None

        clean_val = value.strip()
        if not clean_val:
            return None

        try:
            indicator = self.db.search_threat_indicator(clean_val)
            if indicator is not None:
                return indicator.model_dump() if hasattr(indicator, "model_dump") else dict(indicator)
        except Exception as e:
            logger.error("Error looking up indicator '%s': %s", clean_val, e)

        return None

    def get_all_indicators(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieve all registered threat indicators.

        Args:
            limit: Maximum number of indicators to return (default: 500).

        Returns:
            List[Dict[str, Any]]: List of threat indicator dictionaries.
        """
        try:
            indicators = self.db.get_threat_indicators(limit=limit)
            return [
                ind.model_dump() if hasattr(ind, "model_dump") else dict(ind)
                for ind in indicators
            ]
        except Exception as e:
            logger.error("Error retrieving threat indicators: %s", e)
            return []

    def add_indicator(self, indicator: Dict[str, Any]) -> bool:
        """Add or update a custom threat indicator.

        Args:
            indicator: Dictionary containing indicator data:
                - indicator_type (str): 'hash', 'domain', 'ip', 'extension'
                - value (str): The indicator string
                - description (str, optional): Contextual description
                - severity (str, optional): 'low', 'medium', 'high', 'critical'
                - source (str, optional): Source of indicator

        Returns:
            bool: True if indicator was successfully added/updated, False otherwise.
        """
        if not isinstance(indicator, dict):
            logger.warning("add_indicator rejected: payload must be a dictionary")
            return False

        indicator_type = indicator.get("indicator_type")
        value = indicator.get("value")

        if not indicator_type or not value:
            logger.warning("add_indicator rejected: missing required fields 'indicator_type' or 'value'")
            return False

        payload = {
            "indicator_type": str(indicator_type).strip().lower(),
            "value": str(value).strip(),
            "description": str(indicator.get("description", "Custom analyst indicator")),
            "source": str(indicator.get("source", "manual")),
            "severity": str(indicator.get("severity", "high")).lower(),
            "last_updated": indicator.get("last_updated") or _utc_now_iso(),
            "is_demo_data": bool(indicator.get("is_demo_data", False)),
        }

        try:
            row_id = self.db.insert_threat_indicator(payload)
            logger.info("Threat indicator '%s' (%s) saved with ID %s", payload["value"], payload["indicator_type"], row_id)
            return True
        except Exception as e:
            logger.error("Failed to add indicator '%s': %s", payload.get("value"), e)
            return False
