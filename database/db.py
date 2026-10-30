"""Database manager and connection pooling for RansomWatch SQLite storage.

Provides connection pooling, schema migrations, and CRUD operations for file events,
threat indicators, detection windows, alerts, automated response logs, and ML logs.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from config import DATABASE_PATH, RansomWatchConfig
from database.models import (
    Alert,
    DatabaseStats,
    DetectionWindow,
    FileEvent,
    MLTrainingLog,
    ResponseLog,
    ThreatIndicator,
)

logger = logging.getLogger("ransomwatch.database")


class DatabaseConnectionPool:
    """Thread-safe SQLite connection pool with WAL mode and foreign key enforcement."""

    def __init__(self, db_path: Path, max_connections: int = 10, timeout: float = 10.0) -> None:
        self.db_path = Path(db_path)
        self.max_connections = max_connections
        self.timeout = timeout
        self._pool: queue.Queue[sqlite3.Connection] = queue.Queue(maxsize=max_connections)
        self._allocated_count = 0
        self._lock = threading.Lock()
        self._closed = False

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _create_connection(self) -> sqlite3.Connection:
        """Create and initialize a configured SQLite connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.timeout,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; transactions handled explicitly
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def acquire(self, timeout: Optional[float] = None) -> sqlite3.Connection:
        """Acquire a connection from the pool or create a new one if below max limit."""
        if self._closed:
            raise RuntimeError("DatabaseConnectionPool is closed.")

        wait_time = self.timeout if timeout is None else timeout

        # Fast non-blocking check
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            pass

        # Try to allocate a new connection if under max capacity
        with self._lock:
            if self._allocated_count < self.max_connections:
                conn = self._create_connection()
                self._allocated_count += 1
                return conn

        # Wait on pool queue
        try:
            return self._pool.get(timeout=wait_time)
        except queue.Empty:
            raise TimeoutError(f"Database connection pool exhausted (timeout after {wait_time}s).")

    def release(self, conn: sqlite3.Connection) -> None:
        """Return a connection to the pool or close it if the pool is closed."""
        if self._closed:
            try:
                conn.close()
            except Exception:
                pass
            return

        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            # Should not happen under normal accounting, but close if overflow occurs
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                self._allocated_count = max(0, self._allocated_count - 1)

    def close_all(self) -> None:
        """Close all pooled connections and reject subsequent acquisitions."""
        with self._lock:
            self._closed = True
            while not self._pool.empty():
                try:
                    conn = self._pool.get_nowait()
                    conn.close()
                except Exception:
                    pass
            self._allocated_count = 0


class DatabaseManager:
    """Manages SQLite migrations and transactional CRUD operations for RansomWatch."""

    def __init__(self, db_path: Optional[Union[Path, str]] = None, max_connections: int = 10) -> None:
        self.db_path = Path(db_path) if db_path else DATABASE_PATH
        self.pool = DatabaseConnectionPool(self.db_path, max_connections=max_connections)
        self.initialize_database()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager to borrow a pooled connection with transaction management."""
        conn = self.pool.acquire()
        try:
            if not conn.in_transaction:
                conn.execute("BEGIN;")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT;")
        except Exception:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
            except Exception as rollback_err:
                logger.error("Failed to rollback transaction: %s", rollback_err)
            raise
        finally:
            self.pool.release(conn)

    @contextmanager
    def get_cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager yielding a cursor from a pooled connection."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
            finally:
                cursor.close()

    def initialize_database(self) -> None:
        """Execute database migrations to ensure all required tables and indexes exist."""
        with self.get_connection() as conn:
            # Migration tracking table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )

            # Check if migration version 1 has been applied
            cursor = conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 1;")
            if cursor.fetchone()[0] == 0:
                logger.info("Applying schema migration v1 to %s", self.db_path)
                self._apply_migration_v1(conn)
                now_str = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                    (1, now_str),
                )
                logger.info("Schema migration v1 applied successfully.")

    def _apply_migration_v1(self, conn: sqlite3.Connection) -> None:
        """Create tables and indexes for schema version 1."""
        conn.executescript(
            """
            -- File Events Table
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER DEFAULT 0,
                entropy REAL DEFAULT 0.0,
                extension TEXT,
                old_extension TEXT,
                is_canary INTEGER DEFAULT 0,
                directory TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(file_path);
            CREATE INDEX IF NOT EXISTS idx_file_events_directory ON file_events(directory);
            CREATE INDEX IF NOT EXISTS idx_file_events_is_canary ON file_events(is_canary);

            -- Alerts Table
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                reasons TEXT NOT NULL,
                affected_directory TEXT,
                affected_files TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                response_action TEXT,
                resolved_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

            -- Threat Indicators Table
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                description TEXT,
                source TEXT DEFAULT 'internal',
                severity TEXT DEFAULT 'high',
                last_updated TEXT NOT NULL,
                is_demo_data INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type);
            CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value);

            -- Detection Windows Table
            CREATE TABLE IF NOT EXISTS detection_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                total_events INTEGER DEFAULT 0,
                modifications INTEGER DEFAULT 0,
                renames INTEGER DEFAULT 0,
                deletions INTEGER DEFAULT 0,
                creations INTEGER DEFAULT 0,
                avg_entropy REAL DEFAULT 0.0,
                unusual_ext_ratio REAL DEFAULT 0.0,
                canary_hits INTEGER DEFAULT 0,
                anomaly_score REAL DEFAULT 0.0,
                is_anomaly INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_detection_windows_start ON detection_windows(window_start);
            CREATE INDEX IF NOT EXISTS idx_detection_windows_anomaly ON detection_windows(is_anomaly);

            -- Response Logs Table
            CREATE TABLE IF NOT EXISTS response_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                is_simulation INTEGER DEFAULT 1,
                details TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_response_logs_alert_id ON response_logs(alert_id);
            CREATE INDEX IF NOT EXISTS idx_response_logs_timestamp ON response_logs(timestamp);

            -- ML Training Log Table
            CREATE TABLE IF NOT EXISTS ml_training_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                num_samples INTEGER NOT NULL,
                features_used TEXT NOT NULL,
                contamination_param REAL NOT NULL,
                model_path TEXT NOT NULL,
                notes TEXT
            );
            """
        )

    # -------------------------------------------------------------------------
    # File Events CRUD
    # -------------------------------------------------------------------------

    def insert_file_event(self, event: Union[FileEvent, Dict[str, Any]]) -> int:
        """Insert a single filesystem event and return inserted ID."""
        data = event.model_dump() if isinstance(event, FileEvent) else dict(event)
        query = """
            INSERT INTO file_events (
                timestamp, event_type, file_path, file_hash, file_size,
                entropy, extension, old_extension, is_canary, directory
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data.get("event_type"),
            data.get("file_path"),
            data.get("file_hash"),
            data.get("file_size", 0),
            data.get("entropy", 0.0),
            data.get("extension", ""),
            data.get("old_extension"),
            1 if data.get("is_canary") else 0,
            data.get("directory"),
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def insert_file_events_batch(self, events: List[Union[FileEvent, Dict[str, Any]]]) -> int:
        """Insert multiple filesystem events in a single transaction."""
        if not events:
            return 0
        rows = []
        for ev in events:
            d = ev.model_dump() if isinstance(ev, FileEvent) else dict(ev)
            rows.append((
                d.get("timestamp", datetime.now(timezone.utc).isoformat()),
                d.get("event_type"),
                d.get("file_path"),
                d.get("file_hash"),
                d.get("file_size", 0),
                d.get("entropy", 0.0),
                d.get("extension", ""),
                d.get("old_extension"),
                1 if d.get("is_canary") else 0,
                d.get("directory"),
            ))
        query = """
            INSERT INTO file_events (
                timestamp, event_type, file_path, file_hash, file_size,
                entropy, extension, old_extension, is_canary, directory
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.get_connection() as conn:
            conn.executemany(query, rows)
        return len(rows)

    def get_file_events(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[str] = None,
        is_canary: Optional[bool] = None,
        directory: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[FileEvent]:
        """Retrieve filtered file events ordered by latest first."""
        conditions = []
        params: List[Any] = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if is_canary is not None:
            conditions.append("is_canary = ?")
            params.append(1 if is_canary else 0)
        if directory:
            conditions.append("directory LIKE ?")
            params.append(f"%{directory}%")
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM file_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [FileEvent.from_row(row) for row in cursor.fetchall()]

    def get_recent_events_count(self, seconds: int = 60) -> int:
        """Count file events recorded in the last N seconds."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        query = "SELECT COUNT(*) FROM file_events WHERE timestamp >= ?;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (cutoff,))
            row = cursor.fetchone()
            return row[0] if row else 0

    def get_file_events_count(self) -> int:
        """Get total count of all file events recorded."""
        query = "SELECT COUNT(*) FROM file_events;"
        with self.get_connection() as conn:
            cursor = conn.execute(query)
            row = cursor.fetchone()
            return row[0] if row else 0

    def get_events_in_window(
        self,
        start: Union[str, datetime],
        end: Union[str, datetime],
        limit: int = 10000,
    ) -> List[FileEvent]:
        """Retrieve all file events recorded within a given time window."""
        start_str = start.isoformat() if isinstance(start, datetime) else str(start)
        end_str = end.isoformat() if isinstance(end, datetime) else str(end)
        return self.get_file_events(limit=limit, start_time=start_str, end_time=end_str)

    def get_recent_events(self, limit: int = 100) -> List[FileEvent]:
        """Retrieve the most recent file events up to the specified limit."""
        return self.get_file_events(limit=limit)


    # -------------------------------------------------------------------------
    # Alerts CRUD
    # -------------------------------------------------------------------------

    def insert_alert(self, alert: Union[Alert, Dict[str, Any]]) -> int:
        """Insert a security alert and return inserted ID."""
        data = alert.model_dump() if isinstance(alert, Alert) else dict(alert)
        reasons_raw = data.get("reasons", [])
        reasons_json = json.dumps(reasons_raw if isinstance(reasons_raw, list) else [str(reasons_raw)])
        affected_files_raw = data.get("affected_files", [])
        affected_files_json = json.dumps(
            affected_files_raw if isinstance(affected_files_raw, list) else [str(affected_files_raw)]
        )

        query = """
            INSERT INTO alerts (
                timestamp, risk_score, severity, description, reasons,
                affected_directory, affected_files, status, response_action, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            float(data.get("risk_score", 0.0)),
            str(data.get("severity", "medium")),
            str(data.get("description", "")),
            reasons_json,
            data.get("affected_directory"),
            affected_files_json,
            str(data.get("status", "active")),
            data.get("response_action"),
            data.get("resolved_at"),
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def get_alert_by_id(self, alert_id: int) -> Optional[Alert]:
        """Retrieve a specific alert by its primary key ID."""
        query = "SELECT * FROM alerts WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (alert_id,))
            row = cursor.fetchone()
            return Alert.from_row(row) if row else None

    get_alert = get_alert_by_id

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieve alerts ordered by timestamp descending."""
        conditions = []
        params: List[Any] = []

        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [Alert.from_row(row) for row in cursor.fetchall()]

    def update_alert_status(
        self,
        alert_id: int,
        status: str,
        resolved_at: Optional[str] = None,
        response_action: Optional[str] = None,
    ) -> bool:
        """Update the status, resolution timestamp, or response action of an alert."""
        updates = ["status = ?"]
        params: List[Any] = [status]

        if resolved_at is not None:
            updates.append("resolved_at = ?")
            params.append(resolved_at)
        elif status in ("resolved", "false_positive"):
            updates.append("resolved_at = ?")
            params.append(datetime.now(timezone.utc).isoformat())

        if response_action is not None:
            updates.append("response_action = ?")
            params.append(response_action)

        params.append(alert_id)
        query = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?;"

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    def update_alert(self, alert_id: int, updates: Dict[str, Any]) -> bool:
        """Update arbitrary columns of an alert by ID."""
        if not updates:
            return True
        allowed_cols = {
            "risk_score", "severity", "description", "reasons",
            "affected_directory", "affected_files", "status",
            "response_action", "resolved_at"
        }
        set_clauses = []
        params: List[Any] = []
        for k, v in updates.items():
            if k in allowed_cols:
                set_clauses.append(f"{k} = ?")
                if k in ("reasons", "affected_files") and isinstance(v, (list, dict)):
                    params.append(json.dumps(v))
                else:
                    params.append(v)
        if not set_clauses:
            return False
        params.append(alert_id)
        query = f"UPDATE alerts SET {', '.join(set_clauses)} WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    def get_active_alerts_count(self) -> int:
        """Count alerts currently active or under investigation."""
        query = "SELECT COUNT(*) FROM alerts WHERE status IN ('active', 'investigating');"
        with self.get_connection() as conn:
            cursor = conn.execute(query)
            row = cursor.fetchone()
            return row[0] if row else 0

    # -------------------------------------------------------------------------
    # Threat Indicators CRUD
    # -------------------------------------------------------------------------

    def insert_threat_indicator(self, indicator: Union[ThreatIndicator, Dict[str, Any]]) -> int:
        """Insert or replace a threat indicator record."""
        data = indicator.model_dump() if isinstance(indicator, ThreatIndicator) else dict(indicator)
        query = """
            INSERT INTO threat_indicators (
                indicator_type, value, description, source, severity, last_updated, is_demo_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
                indicator_type = excluded.indicator_type,
                description = excluded.description,
                source = excluded.source,
                severity = excluded.severity,
                last_updated = excluded.last_updated,
                is_demo_data = excluded.is_demo_data;
        """
        params = (
            data.get("indicator_type"),
            data.get("value"),
            data.get("description", ""),
            data.get("source", "internal"),
            data.get("severity", "high"),
            data.get("last_updated", datetime.now(timezone.utc).isoformat()),
            1 if data.get("is_demo_data") else 0,
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def insert_threat_indicators_batch(self, indicators: List[Union[ThreatIndicator, Dict[str, Any]]]) -> int:
        """Insert or replace multiple threat indicators."""
        if not indicators:
            return 0
        rows = []
        for ind in indicators:
            d = ind.model_dump() if isinstance(ind, ThreatIndicator) else dict(ind)
            rows.append((
                d.get("indicator_type"),
                d.get("value"),
                d.get("description", ""),
                d.get("source", "internal"),
                d.get("severity", "high"),
                d.get("last_updated", datetime.now(timezone.utc).isoformat()),
                1 if d.get("is_demo_data") else 0,
            ))
        query = """
            INSERT INTO threat_indicators (
                indicator_type, value, description, source, severity, last_updated, is_demo_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
                indicator_type = excluded.indicator_type,
                description = excluded.description,
                source = excluded.source,
                severity = excluded.severity,
                last_updated = excluded.last_updated,
                is_demo_data = excluded.is_demo_data;
        """
        with self.get_connection() as conn:
            conn.executemany(query, rows)
        return len(rows)

    def get_threat_indicators(
        self,
        limit: int = 100,
        indicator_type: Optional[str] = None,
        is_demo_data: Optional[bool] = None,
    ) -> List[ThreatIndicator]:
        """Retrieve threat indicators with optional type and demo filter."""
        conditions = []
        params: List[Any] = []

        if indicator_type:
            conditions.append("indicator_type = ?")
            params.append(indicator_type)
        if is_demo_data is not None:
            conditions.append("is_demo_data = ?")
            params.append(1 if is_demo_data else 0)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM threat_indicators
            {where_clause}
            ORDER BY last_updated DESC
            LIMIT ?
        """
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [ThreatIndicator.from_row(row) for row in cursor.fetchall()]

    def find_threat_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Find an indicator by exact value (case-insensitive for extensions/hashes)."""
        query = "SELECT * FROM threat_indicators WHERE LOWER(value) = LOWER(?) LIMIT 1;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (value.strip(),))
            row = cursor.fetchone()
            return ThreatIndicator.from_row(row) if row else None

    search_threat_indicator = find_threat_indicator

    def delete_threat_indicator(self, indicator_id: int) -> bool:
        """Delete an indicator by ID."""
        query = "DELETE FROM threat_indicators WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (indicator_id,))
            return cursor.rowcount > 0

    def seed_threat_indicators(self) -> int:
        """Seed demo threat indicators if table is currently empty."""
        count_query = "SELECT COUNT(*) FROM threat_indicators;"
        with self.get_connection() as conn:
            cursor = conn.execute(count_query)
            if cursor.fetchone()[0] > 0:
                return 0

        demo_indicators = [
            # Extensions
            ThreatIndicator(indicator_type="extension", value=".locked", description="Generic ransomware encrypted extension", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".crypto", description="CryptXXX ransomware extension", source="demo", severity="high", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".locky", description="Locky ransomware family extension", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".wncry", description="WannaCry ransomware extension", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".blackcat", description="ALPHV/BlackCat ransomware extension", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".revil", description="REvil/Sodinokibi ransomware extension", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="extension", value=".encrypted", description="Common generic ransomware extension", source="demo", severity="high", is_demo_data=True),
            # Hashes (known demo/test hashes)
            ThreatIndicator(indicator_type="hash", value="84c82835a5d21bbcf75a61706d8ab549", description="WannaCry sample MD5 demo hash", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="hash", value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", description="WannaCry sample SHA256 demo hash", source="demo", severity="critical", is_demo_data=True),
            ThreatIndicator(indicator_type="hash", value="a8d3e913a69a4e2ba96a3099cd3e82d56c8ff541c8f13f179c2980fa54005aa2", description="LockBit 3.0 test payload hash", source="demo", severity="critical", is_demo_data=True),
            # C2 Domains & IPs
            ThreatIndicator(indicator_type="domain", value="ransom-payment-portal-test.onion", description="Simulated Tor payment portal", source="demo", severity="medium", is_demo_data=True),
            ThreatIndicator(indicator_type="ip", value="198.51.100.42", description="Simulated C2 beacon endpoint", source="demo", severity="medium", is_demo_data=True),
        ]
        return self.insert_threat_indicators_batch(demo_indicators)

    # -------------------------------------------------------------------------
    # Detection Windows CRUD
    # -------------------------------------------------------------------------

    def insert_detection_window(self, window: Union[DetectionWindow, Dict[str, Any]]) -> int:
        """Record an aggregated detection window metrics row."""
        data = window.model_dump() if isinstance(window, DetectionWindow) else dict(window)
        query = """
            INSERT INTO detection_windows (
                window_start, window_end, total_events, modifications, renames,
                deletions, creations, avg_entropy, unusual_ext_ratio, canary_hits,
                anomaly_score, is_anomaly
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            data.get("window_start"),
            data.get("window_end"),
            data.get("total_events", 0),
            data.get("modifications", 0),
            data.get("renames", 0),
            data.get("deletions", 0),
            data.get("creations", 0),
            float(data.get("avg_entropy", 0.0)),
            float(data.get("unusual_ext_ratio", 0.0)),
            data.get("canary_hits", 0),
            float(data.get("anomaly_score", 0.0)),
            1 if data.get("is_anomaly") else 0,
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def get_detection_windows(self, limit: int = 100, only_anomalies: bool = False) -> List[DetectionWindow]:
        """Fetch detection windows sorted newest first."""
        query = """
            SELECT * FROM detection_windows
            WHERE (? = 0 OR is_anomaly = 1)
            ORDER BY window_start DESC
            LIMIT ?
        """
        with self.get_connection() as conn:
            cursor = conn.execute(query, (1 if only_anomalies else 0, limit))
            return [DetectionWindow.from_row(row) for row in cursor.fetchall()]

    def get_latest_detection_window(self) -> Optional[DetectionWindow]:
        """Get the most recent detection window."""
        windows = self.get_detection_windows(limit=1)
        return windows[0] if windows else None

    # -------------------------------------------------------------------------
    # Response Logs CRUD
    # -------------------------------------------------------------------------

    def insert_response_log(self, log: Union[ResponseLog, Dict[str, Any]]) -> int:
        """Insert an audit log entry for containment responses."""
        data = log.model_dump() if isinstance(log, ResponseLog) else dict(log)
        query = """
            INSERT INTO response_logs (
                alert_id, timestamp, action_type, target, result, is_simulation, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            data.get("alert_id"),
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data.get("action_type"),
            data.get("target"),
            data.get("result"),
            1 if data.get("is_simulation", True) else 0,
            data.get("details"),
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def get_response_logs(self, alert_id: Optional[int] = None, limit: int = 100) -> List[ResponseLog]:
        """Fetch response logs with optional alert_id filter."""
        if alert_id is not None:
            query = "SELECT * FROM response_logs WHERE alert_id = ? ORDER BY timestamp DESC LIMIT ?;"
            params: Tuple[Any, ...] = (alert_id, limit)
        else:
            query = "SELECT * FROM response_logs ORDER BY timestamp DESC LIMIT ?;"
            params = (limit,)

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [ResponseLog.from_row(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # ML Training Log CRUD
    # -------------------------------------------------------------------------

    def insert_ml_training_log(self, log: Union[MLTrainingLog, Dict[str, Any]]) -> int:
        """Record an ML training run."""
        data = log.model_dump() if isinstance(log, MLTrainingLog) else dict(log)
        features_raw = data.get("features_used", [])
        features_json = json.dumps(features_raw if isinstance(features_raw, list) else [str(features_raw)])

        query = """
            INSERT INTO ml_training_log (
                timestamp, num_samples, features_used, contamination_param, model_path, notes
            ) VALUES (?, ?, ?, ?, ?, ?)
        """
        params = (
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data.get("num_samples"),
            features_json,
            float(data.get("contamination_param", 0.05)),
            str(data.get("model_path")),
            data.get("notes"),
        )
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    insert_training_log = insert_ml_training_log

    def get_ml_training_logs(self, limit: int = 50) -> List[MLTrainingLog]:
        """Fetch historical model training logs."""
        query = "SELECT * FROM ml_training_log ORDER BY timestamp DESC LIMIT ?;"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (limit,))
            return [MLTrainingLog.from_row(row) for row in cursor.fetchall()]

    def get_latest_ml_training_log(self) -> Optional[MLTrainingLog]:
        """Get the most recent training run record."""
        logs = self.get_ml_training_logs(limit=1)
        return logs[0] if logs else None

    # -------------------------------------------------------------------------
    # Database Statistics & Maintenance
    # -------------------------------------------------------------------------

    def get_database_stats(self) -> DatabaseStats:
        """Compute aggregated counts and storage metrics for database tables."""
        stats = DatabaseStats()
        with self.get_connection() as conn:
            # Table counts
            stats.total_events = conn.execute("SELECT COUNT(*) FROM file_events;").fetchone()[0]
            stats.total_alerts = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
            stats.active_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status IN ('active', 'investigating');"
            ).fetchone()[0]
            stats.total_threat_indicators = conn.execute("SELECT COUNT(*) FROM threat_indicators;").fetchone()[0]
            stats.total_detection_windows = conn.execute("SELECT COUNT(*) FROM detection_windows;").fetchone()[0]
            stats.total_response_logs = conn.execute("SELECT COUNT(*) FROM response_logs;").fetchone()[0]

            # Last event timestamp
            last_event_row = conn.execute(
                "SELECT timestamp FROM file_events ORDER BY id DESC LIMIT 1;"
            ).fetchone()
            if last_event_row:
                stats.last_event_timestamp = last_event_row[0]

        # File size on disk
        if self.db_path.exists():
            stats.database_size_bytes = self.db_path.stat().st_size

        return stats

    def clear_table(self, table_name: str) -> int:
        """Delete all rows from a specified table. Useful for testing and resets."""
        allowed_tables = {
            "file_events",
            "alerts",
            "threat_indicators",
            "detection_windows",
            "response_logs",
            "ml_training_log",
        }
        if table_name not in allowed_tables:
            raise ValueError(f"Table {table_name} is not allowed to be cleared.")
        with self.get_connection() as conn:
            cursor = conn.execute(f"DELETE FROM {table_name};")  # nosec
            return cursor.rowcount

    def close(self) -> None:
        """Close connection pool."""
        self.pool.close_all()


# Singleton database instance and accessor
_db_manager_instance: Optional[DatabaseManager] = None
_db_manager_lock = threading.Lock()


def get_db(db_path: Optional[Union[Path, str]] = None) -> DatabaseManager:
    """Return singleton DatabaseManager instance, creating it if needed."""
    global _db_manager_instance
    with _db_manager_lock:
        if _db_manager_instance is None or (db_path and Path(db_path) != _db_manager_instance.db_path):
            _db_manager_instance = DatabaseManager(db_path=db_path)
        return _db_manager_instance
