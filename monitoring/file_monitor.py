"""Filesystem monitoring service using Watchdog for RansomWatch.

Tracks file creation, modification, deletion, and rename operations in real time.
Calculates MD5 hashes, Shannon entropy spikes, detects suspicious extension alterations,
and triggers canary tripwires. Stores events in SQLite and an in-memory ring buffer.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Union

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from config import Config, RansomWatchConfig
from database.db import DatabaseManager
from monitoring.canary import CanaryManager
from monitoring.entropy import calculate_file_entropy

logger = logging.getLogger("ransomwatch.monitoring.file_monitor")


def _utc_now_iso() -> str:
    """Return current UTC timestamp formatted as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


class FileMonitor:
    """Real-time directory monitor tracking file modifications and ransomware indicators."""

    def __init__(
        self,
        db: DatabaseManager,
        config: Union[Config, RansomWatchConfig, Any],
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        canary_manager: Optional[CanaryManager] = None,
    ) -> None:
        """Initialize the FileMonitor.

        Args:
            db: DatabaseManager instance for persistent event storage.
            config: Application configuration instance or class.
            event_callback: Optional callback invoked whenever a new event is recorded.
            canary_manager: Optional CanaryManager instance; if None, a new one is created.
        """
        self.db = db
        self.config = config

        # Determine buffer size from config
        max_buffer = getattr(self.config, "MAX_EVENTS_BUFFER", 10000)
        self.events_buffer: Deque[Dict[str, Any]] = deque(maxlen=int(max_buffer))

        self.event_callback = event_callback
        canary_dir = getattr(self.config, "CANARY_DIR", None)
        self.canary_manager = canary_manager or CanaryManager(canary_dir=canary_dir)

        self._observer: Optional[Observer] = None
        self._monitored_directories: Dict[str, Any] = {}
        self._handler = self.RansomWatchHandler(self)

    @property
    def is_running(self) -> bool:
        """Return True if the Watchdog observer is currently running."""
        return self._observer is not None and self._observer.is_alive()

    def get_monitored_directory(self) -> Optional[str]:
        """Return the primary monitored directory, or None."""
        if self._monitored_directories:
            return next(iter(self._monitored_directories.keys()))
        return None

    def get_monitored_directories(self) -> List[str]:
        """Return a list of all currently registered monitored directories."""
        return list(self._monitored_directories.keys())

    def add_directory(self, directory: Union[str, Path]) -> str:
        """Add an additional directory to active monitoring.

        Args:
            directory: Directory path to monitor.

        Returns:
            Resolved absolute path string.
        """
        target_path = Path(directory).resolve()
        target_path.mkdir(parents=True, exist_ok=True)
        path_str = str(target_path)

        if path_str in self._monitored_directories and self._monitored_directories[path_str] is not None:
            return path_str

        watch = None
        if self.is_running and self._observer is not None:
            try:
                watch = self._observer.schedule(self._handler, path=path_str, recursive=True)
                logger.info("Dynamically scheduled watch on %s", path_str)
            except Exception as exc:
                logger.error("Failed to dynamically schedule watch on %s: %s", path_str, exc)
                raise

        self._monitored_directories[path_str] = watch
        return path_str

    def remove_directory(self, directory: Union[str, Path]) -> bool:
        """Remove a directory from active monitoring."""
        path_str = str(Path(directory).resolve())
        if path_str not in self._monitored_directories:
            return False

        watch = self._monitored_directories.pop(path_str, None)
        if watch is not None and self.is_running and self._observer is not None:
            try:
                self._observer.unschedule(watch)
                logger.info("Unscheduled watch on %s", path_str)
            except Exception as exc:
                logger.warning("Error unscheduling watch on %s: %s", path_str, exc)

        return True

    def start_monitoring(self, directory: Optional[Union[str, Path, List[Union[str, Path]]]] = None) -> None:
        """Start monitoring directories for filesystem changes."""
        if directory is not None:
            if isinstance(directory, list):
                for d in directory:
                    self.add_directory(d)
            else:
                self.add_directory(directory)

        if not self._monitored_directories:
            raise ValueError("No directories configured to monitor.")

        if self.is_running:
            if self._observer is not None:
                for path_str, watch in list(self._monitored_directories.items()):
                    if watch is None:
                        try:
                            self._monitored_directories[path_str] = self._observer.schedule(
                                self._handler, path=path_str, recursive=True
                            )
                        except Exception as exc:
                            logger.error("Error scheduling path %s: %s", path_str, exc)
            return

        self._observer = Observer()
        for path_str in list(self._monitored_directories.keys()):
            try:
                watch = self._observer.schedule(self._handler, path=path_str, recursive=True)
                self._monitored_directories[path_str] = watch
                logger.info("Scheduled watch on %s", path_str)
            except Exception as exc:
                logger.error("Error scheduling watch on %s: %s", path_str, exc)

        self._observer.start()
        logger.info(
            "Watchdog observer active and monitoring %d directories: %s",
            len(self._monitored_directories),
            list(self._monitored_directories.keys()),
        )

    def stop_monitoring(self) -> None:
        """Stop and join the Watchdog observer thread."""
        if self._observer is not None:
            logger.info("Stopping Watchdog observer across %d directories", len(self._monitored_directories))
            try:
                self._observer.stop()
                self._observer.join(timeout=5.0)
            except Exception as exc:
                logger.warning("Error stopping observer: %s", exc)
            finally:
                self._observer = None
                for path_str in self._monitored_directories:
                    self._monitored_directories[path_str] = None
        logger.info("File monitoring stopped.")

    def get_recent_activity(self, seconds: int = 60) -> Dict[str, Any]:
        """Compute aggregated statistics of filesystem events within the last N seconds.

        Args:
            seconds: Time window duration in seconds (default 60).

        Returns:
            Dictionary containing event counts by type, canary hits, and average entropy.
        """
        cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        cutoff_iso = cutoff_dt.isoformat()

        # Extract snapshot from in-memory ring buffer
        events_snapshot = list(self.events_buffer)
        window_events = [ev for ev in events_snapshot if ev.get("timestamp", "") >= cutoff_iso]

        total = len(window_events)
        created = sum(1 for e in window_events if e.get("event_type") == "created")
        modified = sum(1 for e in window_events if e.get("event_type") == "modified")
        deleted = sum(1 for e in window_events if e.get("event_type") == "deleted")
        moved = sum(1 for e in window_events if e.get("event_type") == "moved")
        canary_hits = sum(1 for e in window_events if e.get("is_canary"))

        entropy_vals = [
            float(e["entropy"]) for e in window_events
            if e.get("entropy") is not None and float(e.get("entropy", -1.0)) >= 0.0
        ]
        avg_entropy = round(sum(entropy_vals) / len(entropy_vals), 4) if entropy_vals else 0.0

        unique_files = len({e.get("file_path") for e in window_events if e.get("file_path")})

        return {
            "window_seconds": seconds,
            "total_events": total,
            "created": created,
            "modified": modified,
            "deleted": deleted,
            "moved": moved,
            "canary_hits": canary_hits,
            "avg_entropy": avg_entropy,
            "unique_files": unique_files,
        }

    # -------------------------------------------------------------------------
    # Inner Watchdog Event Handler
    # -------------------------------------------------------------------------

    class RansomWatchHandler(FileSystemEventHandler):
        """Internal Watchdog event handler converting filesystem events to RansomWatch records."""

        def __init__(self, monitor: FileMonitor) -> None:
            super().__init__()
            self.monitor = monitor

        def _is_ignored(self, file_path: str) -> bool:
            """Check if a file should be ignored (system, hidden, or temp files)."""
            filename = os.path.basename(file_path)
            # Ignore hidden files, temporary office locks (~$), swap, or vim temporary files
            if filename.startswith((".", "~")):
                return True
            if filename.endswith((".tmp", ".swp", ".part", ".crdownload")):
                return True
            if filename.lower() in ("desktop.ini", "thumbs.db", "icon\r"):
                return True
            return False

        def _calculate_md5(self, file_path: str) -> Optional[str]:
            """Compute MD5 hash of file in streaming chunks, returning None if unreadable."""
            try:
                if not os.path.isfile(file_path):
                    return None
                hasher = hashlib.md5()
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        hasher.update(chunk)
                return hasher.hexdigest()
            except (OSError, PermissionError):
                return None
            except Exception as exc:
                logger.debug("Failed computing MD5 for %s: %s", file_path, exc)
                return None

        def _process_event(
            self,
            event_type: str,
            file_path: str,
            old_path: Optional[str] = None,
        ) -> None:
            """Process, enrich, persist, and dispatch a single filesystem event."""
            if self._is_ignored(file_path):
                return

            timestamp = _utc_now_iso()
            path_obj = Path(file_path)
            directory = str(path_obj.parent)

            # Determine extension
            extension = path_obj.suffix.lower()
            old_extension = Path(old_path).suffix.lower() if old_path else None

            # Canary check
            is_canary = self.monitor.canary_manager.is_canary_file(file_path)
            if not is_canary and old_path:
                is_canary = self.monitor.canary_manager.is_canary_file(old_path)

            file_hash: Optional[str] = None
            entropy: float = 0.0
            file_size: int = 0

            # Calculate content metrics for created or modified events
            if event_type in ("created", "modified"):
                file_hash = self._calculate_md5(file_path)
                calc_entropy = calculate_file_entropy(file_path)
                entropy = max(0.0, calc_entropy) if calc_entropy >= 0 else 0.0
                try:
                    file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                except (OSError, PermissionError):
                    file_size = 0

            event_dict: Dict[str, Any] = {
                "timestamp": timestamp,
                "event_type": event_type,
                "file_path": str(path_obj.resolve()),
                "file_hash": file_hash,
                "file_size": file_size,
                "entropy": entropy,
                "extension": extension,
                "old_extension": old_extension,
                "is_canary": is_canary,
                "directory": directory,
            }

            # Persist to database
            try:
                event_id = self.monitor.db.insert_file_event(event_dict)
                event_dict["id"] = event_id
            except Exception as exc:
                logger.error("Failed to insert file event into database: %s", exc)

            # Append to in-memory buffer
            self.monitor.events_buffer.append(event_dict)

            # Invoke callback if provided
            if self.monitor.event_callback is not None:
                try:
                    self.monitor.event_callback(event_dict)
                except Exception as cb_exc:
                    logger.error("Error executing file event callback: %s", cb_exc)

        def on_created(self, event: FileSystemEvent) -> None:
            """Handle file creation events."""
            if event.is_directory:
                return
            self._process_event("created", event.src_path)

        def on_modified(self, event: FileSystemEvent) -> None:
            """Handle file modification events."""
            if event.is_directory:
                return
            self._process_event("modified", event.src_path)

        def on_deleted(self, event: FileSystemEvent) -> None:
            """Handle file deletion events."""
            if event.is_directory:
                return
            self._process_event("deleted", event.src_path)

        def on_moved(self, event: FileMovedEvent) -> None:
            """Handle file moved or renamed events."""
            if event.is_directory:
                return
            self._process_event("moved", event.dest_path, old_path=event.src_path)
