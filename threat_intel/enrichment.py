"""Threat Intelligence Enrichment module for RansomWatch.

Provides alert correlation against local threat signatures (known ransomware hashes,
malicious domains, C2 IPs) and optional external threat intel endpoints, enhancing
security alert triage without destructive or data-leaking operations.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from config import Config
from database.db import DatabaseManager
from threat_intel.local_db import LocalThreatDatabase

logger = logging.getLogger("ransomwatch.threat_intel.enrichment")


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class ThreatEnrichment:
    """Enriches alerts and suspicious artifacts with known threat intelligence.

    Correlates filesystem events and security alerts against the local
    threat intelligence repository and optional secure external threat feeds.
    """

    def __init__(self, db: DatabaseManager, config: Config) -> None:
        """Initialize the enrichment engine with database and configuration.

        Args:
            db: DatabaseManager instance for SQLite access.
            config: RansomWatch configuration instance.
        """
        self.db = db
        self.config = config
        self.local_db = LocalThreatDatabase(db)

    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check a single hash against local DB and optional external threat feed.

        Never uploads file contents; performs lookup strictly by cryptographic hash.

        Args:
            file_hash: MD5, SHA1, or SHA256 string to inspect.

        Returns:
            Dict[str, Any]: {
                "found": bool,
                "indicator": Optional[dict],
                "source": str ("local_db", "external_api", or "none")
            }
        """
        if not file_hash or not isinstance(file_hash, str):
            return {"found": False, "indicator": None, "source": "none"}

        clean_hash = file_hash.strip().lower()
        if not clean_hash:
            return {"found": False, "indicator": None, "source": "none"}

        # 1. First priority: Check local database
        local_match = self.local_db.lookup_hash(clean_hash)
        if local_match:
            logger.debug("Threat Intel hit in local database for hash %s", clean_hash)
            return {"found": True, "indicator": local_match, "source": "local_db"}

        # 2. Second priority: Query external threat intelligence API if configured
        if getattr(self.config, "THREAT_INTEL_API_URL", None):
            ext_match = self.check_external_service(clean_hash)
            if ext_match and ext_match.get("found"):
                logger.info("Threat Intel hit in external service for hash %s", clean_hash)
                return {
                    "found": True,
                    "indicator": ext_match.get("indicator", ext_match),
                    "source": "external_api",
                }

        return {"found": False, "indicator": None, "source": "none"}

    def check_external_service(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query an external threat intelligence API if configured.

        Safety Assurance: Never uploads file contents or binary data. Queries
        are executed strictly using the cryptographic hash string as a parameter.

        Args:
            file_hash: Hash string to query.

        Returns:
            Optional[Dict[str, Any]]: Response data if found/configured, or None.
        """
        api_url = getattr(self.config, "THREAT_INTEL_API_URL", None)
        if not api_url or not str(api_url).strip():
            logger.debug("Threat Intel external service check skipped: No API URL configured.")
            return None

        clean_hash = file_hash.strip().lower()
        api_key = getattr(self.config, "THREAT_INTEL_API_KEY", None)

        try:
            # Build target URL safely (support placeholder or query param)
            if "{hash}" in api_url:
                target_url = api_url.replace("{hash}", urllib.parse.quote(clean_hash))
            else:
                sep = "&" if "?" in api_url else "?"
                target_url = f"{api_url}{sep}hash={urllib.parse.quote(clean_hash)}"

            headers = {
                "User-Agent": "RansomWatch-ThreatIntel/1.0",
                "Accept": "application/json",
            }
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
                headers["x-api-key"] = api_key

            req = urllib.request.Request(target_url, headers=headers, method="GET")

            # 5-second timeout to avoid blocking detection pipelines
            with urllib.request.urlopen(req, timeout=5.0) as response:
                status_code = response.getcode()
                if status_code == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    return {
                        "found": True,
                        "indicator": payload,
                        "status_code": status_code,
                    }
                elif status_code == 404:
                    return {"found": False, "indicator": None, "status_code": 404}
                else:
                    logger.warning("External threat intel returned status %s for hash %s", status_code, clean_hash)
                    return None

        except urllib.error.HTTPError as he:
            if he.code == 404:
                return {"found": False, "indicator": None, "status_code": 404}
            logger.warning("External threat intel HTTP error %s for hash %s: %s", he.code, clean_hash, he.reason)
            return None
        except urllib.error.URLError as ue:
            logger.warning("External threat intel network unreachable for %s: %s", clean_hash, ue.reason)
            return None
        except Exception as ex:
            logger.error("Unexpected error in external threat intel check for %s: %s", clean_hash, ex)
            return None

    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate alert indicators with threat intelligence and return enriched alert.

        Extracts file hashes, domains, and IPs from the alert, checks against the
        threat intelligence store, and appends matched threat indicators and risk
        adjustments.

        Args:
            alert: Raw alert dictionary.

        Returns:
            Dict[str, Any]: A copy of the alert enriched with threat intelligence attributes:
                - threat_intel_match (bool): True if any indicator matched
                - matched_indicators (List[dict]): Details of all matched indicators
                - enrichment_sources (List[str]): Sources providing matches
                - enrichment_timestamp (str): ISO 8601 timestamp of enrichment
        """
        enriched: Dict[str, Any] = dict(alert)
        matched_indicators: List[Dict[str, Any]] = []
        sources: Set[str] = set()

        # 1. Collect candidate hashes from alert fields
        candidate_hashes: Set[str] = set()

        # Direct file_hash field
        if alert.get("file_hash"):
            candidate_hashes.add(str(alert["file_hash"]).strip().lower())

        # List of hashes
        for key in ("file_hashes", "hashes"):
            raw_hashes = alert.get(key)
            if isinstance(raw_hashes, list):
                for h in raw_hashes:
                    if h:
                        candidate_hashes.add(str(h).strip().lower())
            elif isinstance(raw_hashes, str):
                for part in raw_hashes.split(","):
                    if part.strip():
                        candidate_hashes.add(part.strip().lower())

        # Nested details dictionary
        details = alert.get("details")
        if isinstance(details, dict):
            if details.get("file_hash"):
                candidate_hashes.add(str(details["file_hash"]).strip().lower())
            if isinstance(details.get("hashes"), list):
                for h in details["hashes"]:
                    if h:
                        candidate_hashes.add(str(h).strip().lower())

        # 2. Query each candidate hash
        for h in candidate_hashes:
            res = self.check_file_hash(h)
            if res.get("found") and res.get("indicator"):
                matched_indicators.append(res["indicator"])
                sources.add(res.get("source", "local_db"))

        # 3. Check domain and IP indicators if present
        raw_indicators = alert.get("indicators", [])
        if isinstance(raw_indicators, list):
            for ind_val in raw_indicators:
                if isinstance(ind_val, str) and ind_val.strip():
                    clean_val = ind_val.strip()
                    match = self.local_db.lookup_indicator(clean_val)
                    if match:
                        matched_indicators.append(match)
                        sources.add("local_db")

        # 4. Synthesize enrichment metadata
        has_match = len(matched_indicators) > 0
        enriched["threat_intel_match"] = has_match
        enriched["matched_indicators"] = matched_indicators
        enriched["enrichment_sources"] = sorted(list(sources))
        enriched["enrichment_timestamp"] = _utc_now_iso()

        # If threat intel matches exist, augment alert reasons and risk score if helpful
        if has_match:
            reasons = list(enriched.get("reasons", []))
            for match in matched_indicators:
                desc = match.get("description", "Known malicious signature")
                val = match.get("value", "")
                family_notice = f"Threat Intel Match [{match.get('source', 'demo')}]: {val} ({desc})"
                if family_notice not in reasons:
                    reasons.append(family_notice)
            enriched["reasons"] = reasons

            # Boost risk score if known critical threat indicator matches
            current_score = float(enriched.get("risk_score", 0.0))
            max_severity = max(
                (m.get("severity", "medium").lower() for m in matched_indicators),
                key=lambda s: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
                default="medium",
            )
            if max_severity == "critical" and current_score < 90.0:
                enriched["risk_score"] = max(current_score, 90.0)
                enriched["severity"] = "critical"
            elif max_severity == "high" and current_score < 75.0:
                enriched["risk_score"] = max(current_score, 75.0)
                if enriched.get("severity") in ("low", "medium"):
                    enriched["severity"] = "high"

        return enriched

    def get_enrichment_summary(self) -> Dict[str, Any]:
        """Generate statistical summary of local and external threat intelligence capabilities.

        Returns:
            Dict[str, Any]: Summary metrics covering indicator counts, category breakdowns,
            severity distributions, and external service configuration state.
        """
        all_indicators = self.local_db.get_all_indicators(limit=1000)

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        last_updated: Optional[str] = None
        demo_count = 0

        for ind in all_indicators:
            itype = str(ind.get("indicator_type", "unknown")).lower()
            by_type[itype] = by_type.get(itype, 0) + 1

            sev = str(ind.get("severity", "unknown")).lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

            if ind.get("is_demo_data"):
                demo_count += 1

            ind_ts = ind.get("last_updated")
            if ind_ts:
                if last_updated is None or ind_ts > last_updated:
                    last_updated = ind_ts

        api_url = getattr(self.config, "THREAT_INTEL_API_URL", None)
        external_configured = bool(api_url and str(api_url).strip())

        return {
            "total_indicators": len(all_indicators),
            "by_type": by_type,
            "by_severity": by_severity,
            "demo_indicators_count": demo_count,
            "last_updated": last_updated or _utc_now_iso(),
            "external_service_configured": external_configured,
            "external_service_endpoint": "***CONFIGURED***" if external_configured else "none",
        }
