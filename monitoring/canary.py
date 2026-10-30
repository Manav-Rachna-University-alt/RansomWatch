"""Canary decoy file manager for RansomWatch.

Deploys strategic decoy/canary files with typical high-value document extensions
(.docx, .xlsx, .pdf) in monitored directories. Any creation, modification,
rename, or deletion of these files acts as a high-fidelity tripwire for ransomware.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

logger = logging.getLogger("ransomwatch.monitoring.canary")

# Marker embedded in decoy payloads for tripwire verification
CANARY_SIGNATURE: bytes = b"RANSOMWATCH_CANARY_TRIPWIRE_TOKEN_5A8E"

# Decoy templates: Strategic filenames starting with punctuation/numbers so they appear
# first in alphabetical filesystem traversals typical of automated ransomware encryption loops.
CANARY_TEMPLATES: Dict[str, bytes] = {
    "!_00_system_passwords_confidential.docx": (
        b"PK\x03\x04\x14\x00\x06\x00\x08\x00"
        b"\x00\x00!\x00RansomWatch_Tripwire_Docx_Decoy\x00\x00"
        + CANARY_SIGNATURE
        + b"\nCONFIDENTIAL PASSWORDS AND CREDENTIALS REPOSITORY\n"
        b"DO NOT MODIFY - MONITORED BY RANSOMWATCH CANARY TRACE\n"
    ),
    "!_01_corporate_payroll_2026.xlsx": (
        b"PK\x03\x04\x14\x00\x06\x00\x08\x00"
        b"\x00\x00!\x00RansomWatch_Tripwire_Xlsx_Decoy\x00\x00"
        + CANARY_SIGNATURE
        + b"\nEXECUTIVE COMPENSATION AND PAYROLL SCHEDULE 2026\n"
        b"DO NOT MODIFY - MONITORED BY RANSOMWATCH CANARY TRACE\n"
    ),
    "!_02_financial_audit_q4.pdf": (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Title (Q4 Financial Audit) /Author (Finance Dept) "
        b"/Subject (RansomWatch Decoy) /Keywords (Canary) >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Length 120 >>\nstream\n"
        + CANARY_SIGNATURE
        + b"\nINTERNAL AUDIT REPORT AND FINANCIAL STATEMENT\n"
        b"endstream\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    ),
    "_canary_backup_manifest.docx": (
        b"PK\x03\x04\x14\x00\x06\x00\x08\x00"
        b"\x00\x00!\x00RansomWatch_Tripwire_Backup_Decoy\x00\x00"
        + CANARY_SIGNATURE
        + b"\nENTERPRISE SERVER BACKUP MANIFEST & VAULT KEYS\n"
    ),
    "_canary_customer_records.xlsx": (
        b"PK\x03\x04\x14\x00\x06\x00\x08\x00"
        b"\x00\x00!\x00RansomWatch_Tripwire_Records_Decoy\x00\x00"
        + CANARY_SIGNATURE
        + b"\nCUSTOMER PII AND TRANSACTION ARCHIVE 2026\n"
    ),
}


class CanaryManager:
    """Manages deployment, tracking, identification, and cleanup of canary decoy files."""

    def __init__(self, canary_dir: Optional[Union[str, Path]] = None) -> None:
        """Initialize the CanaryManager.

        Args:
            canary_dir: Optional default directory where canary files are deployed.
        """
        self.default_canary_dir: Optional[Path] = Path(canary_dir).resolve() if canary_dir else None
        # Normalized absolute path strings stored for fast O(1) set membership lookups
        self._canary_paths: Set[str] = set()
        # Original casing path mappings for friendly output
        self._canary_path_map: Dict[str, str] = {}

    def setup_canary_files(self, directory: Optional[Union[str, Path]] = None) -> List[str]:
        """Deploy canary decoy files into the specified directory.

        Creates docx, xlsx, and pdf files with realistic names and canary markers.
        Files are added to the in-memory tracking set for immediate lookup.

        Args:
            directory: Directory to plant canaries in. Defaults to default_canary_dir.

        Returns:
            List of absolute paths to created canary files.

        Raises:
            ValueError: If no directory was provided and no default was set.
            OSError: If directory creation or file writing fails.
        """
        target_dir = Path(directory) if directory else self.default_canary_dir
        if not target_dir:
            raise ValueError("No directory specified for setting up canary files.")

        target_dir = target_dir.resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        created_paths: List[str] = []

        for filename, content in CANARY_TEMPLATES.items():
            file_path = target_dir / filename
            try:
                # Write or overwrite canary file
                file_path.write_bytes(content)
                resolved_str = str(file_path.resolve())
                norm_key = self._normalize_path(resolved_str)

                self._canary_paths.add(norm_key)
                self._canary_path_map[norm_key] = resolved_str
                created_paths.append(resolved_str)
                logger.debug("Deployed canary file: %s", resolved_str)
            except OSError as err:
                logger.error("Failed to write canary file '%s': %s", file_path, err)
                raise

        logger.info("Successfully deployed %d canary files in %s", len(created_paths), target_dir)
        return created_paths

    def is_canary_file(self, file_path: Union[str, Path]) -> bool:
        """Check whether a given file path corresponds to an active canary file.

        Performs an O(1) set lookup on normalized paths. Also checks filename templates
        if path belongs to known canary directory.

        Args:
            file_path: Path of the file to inspect.

        Returns:
            True if the file is an active canary decoy, False otherwise.
        """
        if not file_path:
            return False

        try:
            norm_key = self._normalize_path(file_path)
            if norm_key in self._canary_paths:
                return True

            # Also check if filename matches template in active canary directory
            resolved = Path(file_path).resolve()
            if resolved.name in CANARY_TEMPLATES and norm_key in self._canary_paths:
                return True

            return False
        except Exception as exc:
            logger.debug("Error checking canary path '%s': %s", file_path, exc)
            return False

    def get_canary_paths(self) -> List[str]:
        """Return the list of all currently tracked canary file paths.

        Returns:
            List of absolute path strings to active canary files.
        """
        return sorted(self._canary_path_map.values())

    def remove_canary_files(self) -> int:
        """Remove all tracked canary files from disk and clear in-memory registry.

        Returns:
            Number of canary files successfully removed from disk.
        """
        removed_count = 0
        for norm_key, path_str in list(self._canary_path_map.items()):
            path = Path(path_str)
            try:
                if path.exists():
                    path.unlink()
                    removed_count += 1
                    logger.debug("Deleted canary file: %s", path_str)
            except OSError as err:
                logger.warning("Failed to delete canary file '%s': %s", path_str, err)

        self._canary_paths.clear()
        self._canary_path_map.clear()
        logger.info("Canary cleanup finished: removed %d files", removed_count)
        return removed_count

    @staticmethod
    def _normalize_path(path: Union[str, Path]) -> str:
        """Normalize path for cross-platform case-insensitive comparisons on Windows.

        Args:
            path: Path string or Path object.

        Returns:
            Canonical normalized lowercase string representation.
        """
        return os.path.normcase(os.path.abspath(str(path)))
