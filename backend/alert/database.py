"""SQLite persistence layer for NIDS detection alerts.

Provides thread-safe connection management, schema initialization, parameterized queries,
and index creation for fast dashboard lookups and alert filtering.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Allowed columns for GROUP BY aggregation queries to prevent SQL injection
ALLOWED_GROUP_COLUMNS = {"severity", "alert_type", "status", "protocol", "src_ip"}


class AlertDatabase:
    """Manages SQLite storage, table creation, and queries for security alerts."""

    def __init__(self, db_path: str | Path = "nids_events.db") -> None:
        """Initialize database with the specified SQLite path.

        Automatically ensures parent directories exist and runs schema initialization.
        """
        self.db_path_str: str = str(db_path)
        self.is_memory: bool = self.db_path_str == ":memory:" or self.db_path_str.startswith("file:")

        if not self.is_memory:
            db_file = Path(self.db_path_str).resolve()
            db_file.parent.mkdir(parents=True, exist_ok=True)
            self.db_path: str = str(db_file)
        else:
            self.db_path = self.db_path_str

        # Shared connection for in-memory databases so state is not lost across calls
        self._shared_memory_conn: Optional[sqlite3.Connection] = None
        if self.is_memory:
            self._shared_memory_conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._shared_memory_conn.row_factory = sqlite3.Row

        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a managed SQLite connection with row_factory.

        Commits on normal exit, rolls back on error, and ensures proper closure.
        """
        if self._shared_memory_conn is not None:
            # For in-memory database, reuse shared connection so data persists within instance lifecycle
            try:
                yield self._shared_memory_conn
                self._shared_memory_conn.commit()
            except Exception:
                self._shared_memory_conn.rollback()
                raise
            return

        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize alerts table and required performance indexes.

        Safe to execute repeatedly (idempotent).
        """
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            description TEXT,
            detection_reason TEXT,
            evidence TEXT,
            status TEXT NOT NULL DEFAULT 'NEW'
        );
        """

        index_statements = [
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts (alert_type);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);",
        ]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(create_table_sql)
            for stmt in index_statements:
                cursor.execute(stmt)

        logger.debug("AlertDatabase schema initialized successfully at '%s'.", self.db_path)

    def insert_alert(
        self,
        timestamp: str,
        alert_type: str,
        severity: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        protocol: Optional[str],
        description: Optional[str],
        detection_reason: Optional[str],
        evidence: str,
        status: str = "NEW",
    ) -> int:
        """Insert a single alert record using parameterized SQL.

        Returns the auto-generated primary key ID.
        """
        sql = """
        INSERT INTO alerts (
            timestamp,
            alert_type,
            severity,
            src_ip,
            dst_ip,
            protocol,
            description,
            detection_reason,
            evidence,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            timestamp,
            alert_type,
            severity,
            src_ip,
            dst_ip,
            protocol,
            description,
            detection_reason,
            evidence,
            status,
        )

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            new_id = cursor.lastrowid

        if new_id is None:
            raise RuntimeError("Database failed to return lastrowid after inserting alert.")

        return int(new_id)

    def get_alert_by_id(self, alert_id: int) -> Optional[sqlite3.Row]:
        """Retrieve a single alert record by primary key."""
        sql = "SELECT * FROM alerts WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (alert_id,))
            return cursor.fetchone()

    def query_alerts(
        self,
        where_clauses: Optional[List[str]] = None,
        params: Optional[List[Any]] = None,
        order_by: str = "timestamp DESC, id DESC",
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[sqlite3.Row]:
        """Execute parameterized query with filtering, sorting, and pagination."""
        clauses = list(where_clauses) if where_clauses else []
        parameters = list(params) if params else []

        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM alerts{where_sql} ORDER BY {order_by}"

        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            parameters.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(parameters))
            return cursor.fetchall()

    def update_alert_status(self, alert_id: int, new_status: str) -> bool:
        """Update status for a specific alert ID.

        Returns True if a matching alert was updated, False if alert ID was not found.
        """
        sql = "UPDATE alerts SET status = ? WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (new_status, alert_id))
            return cursor.rowcount > 0

    def count_alerts(
        self,
        where_clauses: Optional[List[str]] = None,
        params: Optional[List[Any]] = None,
    ) -> int:
        """Return total count of alerts matching optional filter criteria."""
        clauses = list(where_clauses) if where_clauses else []
        parameters = list(params) if params else []

        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) as total FROM alerts{where_sql};"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(parameters))
            row = cursor.fetchone()
            return int(row["total"]) if row else 0

    def get_grouped_counts(self, column_name: str) -> Dict[str, int]:
        """Return aggregated counts grouped by a specific column (e.g., severity, alert_type).

        Validates column against ALLOWED_GROUP_COLUMNS to prevent SQL injection.
        """
        col = column_name.strip().lower()
        if col not in ALLOWED_GROUP_COLUMNS:
            raise ValueError(f"Invalid group column '{column_name}'. Allowed: {sorted(ALLOWED_GROUP_COLUMNS)}")

        sql = f"SELECT {col}, COUNT(*) as count FROM alerts GROUP BY {col};"
        counts: Dict[str, int] = {}

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            for row in cursor.fetchall():
                key = str(row[col]) if row[col] is not None else "UNKNOWN"
                counts[key] = int(row["count"])

        return counts

    def delete_alert(self, alert_id: int) -> bool:
        """Delete a single alert by ID. Returns True if deleted, False otherwise."""
        sql = "DELETE FROM alerts WHERE id = ?;"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (alert_id,))
            return cursor.rowcount > 0

    def clear_alerts(self) -> int:
        """Delete all alert records. Returns count of deleted rows."""
        sql = "DELETE FROM alerts;"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            return cursor.rowcount

    def close(self) -> None:
        """Close shared connection if applicable."""
        if self._shared_memory_conn is not None:
            try:
                self._shared_memory_conn.close()
            except Exception:
                pass
            self._shared_memory_conn = None
