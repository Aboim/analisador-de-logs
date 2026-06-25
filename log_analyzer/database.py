import sqlite3
import json
import os
from datetime import datetime
from typing import Optional


class Database:
    def __init__(self, db_path: str = "log_analyzer.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature TEXT NOT NULL UNIQUE,
                regex_pattern TEXT NOT NULL,
                category TEXT DEFAULT 'unknown',
                description TEXT DEFAULT '',
                frequency INTEGER DEFAULT 1,
                first_seen TEXT DEFAULT '',
                last_seen TEXT DEFAULT '',
                confirmed INTEGER DEFAULT 0,
                is_error INTEGER DEFAULT 0,
                sample TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS log_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                total_lines INTEGER DEFAULT 0,
                imported_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                line_number INTEGER,
                timestamp TEXT DEFAULT '',
                level TEXT DEFAULT 'INFO',
                source TEXT DEFAULT '',
                message TEXT NOT NULL,
                raw_line TEXT NOT NULL,
                pattern_id INTEGER,
                is_anomaly INTEGER DEFAULT 0,
                anomaly_score REAL DEFAULT 0.0,
                FOREIGN KEY (file_id) REFERENCES log_files(id),
                FOREIGN KEY (pattern_id) REFERENCES patterns(id)
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_entry_id INTEGER NOT NULL,
                reason TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                reviewed INTEGER DEFAULT 0,
                created_at TEXT DEFAULT '',
                FOREIGN KEY (log_entry_id) REFERENCES log_entries(id)
            );

            CREATE TABLE IF NOT EXISTS daily_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL UNIQUE,
                total_lines INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                warnings INTEGER DEFAULT 0,
                info INTEGER DEFAULT 0,
                debug INTEGER DEFAULT 0,
                anomalies INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_entries_level ON log_entries(level);
            CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON log_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_entries_pattern ON log_entries(pattern_id);
            CREATE INDEX IF NOT EXISTS idx_patterns_signature ON patterns(signature);
            CREATE INDEX IF NOT EXISTS idx_patterns_category ON patterns(category);
        """)
        self.conn.commit()

    def add_pattern(self, signature: str, regex_pattern: str, category: str = "unknown",
                    description: str = "", sample: str = "", is_error: bool = False) -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = self.conn.execute(
            """INSERT OR IGNORE INTO patterns (signature, regex_pattern, category, description, sample, is_error, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (signature, regex_pattern, category, description, sample, int(is_error), now, now)
        )
        if cursor.lastrowid and cursor.lastrowid > 0:
            self.conn.commit()
            return cursor.lastrowid
        existing = self.conn.execute(
            "UPDATE patterns SET frequency = frequency + 1, last_seen = ? WHERE signature = ?",
            (now, signature)
        )
        self.conn.commit()
        row = self.conn.execute("SELECT id FROM patterns WHERE signature = ?", (signature,)).fetchone()
        return row[0] if row else 0

    def update_pattern_frequency(self, pattern_id: int):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute(
            "UPDATE patterns SET frequency = frequency + 1, last_seen = ? WHERE id = ?",
            (now, pattern_id)
        )
        self.conn.commit()

    def update_pattern_confirm(self, pattern_id: int, confirmed: bool = True):
        self.conn.execute("UPDATE patterns SET confirmed = ? WHERE id = ?", (int(confirmed), pattern_id))
        self.conn.commit()

    def get_patterns(self, category: Optional[str] = None, limit: int = 200) -> list[dict]:
        if category:
            rows = self.conn.execute(
                "SELECT * FROM patterns WHERE category = ? ORDER BY frequency DESC LIMIT ?",
                (category, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM patterns ORDER BY frequency DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(row, self._pattern_columns()) for row in rows]

    def get_all_patterns(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM patterns ORDER BY frequency DESC").fetchall()
        return [self._row_to_dict(row, self._pattern_columns()) for row in rows]

    def get_pattern_by_id(self, pattern_id: int) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM patterns WHERE id = ?", (pattern_id,)).fetchone()
        if row:
            return self._row_to_dict(row, self._pattern_columns())
        return None

    def find_pattern_by_signature(self, signature: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM patterns WHERE signature = ?", (signature,)).fetchone()
        if row:
            return self._row_to_dict(row, self._pattern_columns())
        return None

    def add_log_file(self, filepath: str, filename: str, file_size: int = 0) -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = self.conn.execute(
            "INSERT INTO log_files (filepath, filename, file_size, imported_at) VALUES (?, ?, ?, ?)",
            (filepath, filename, file_size, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_log_file_line_count(self, file_id: int, total_lines: int):
        self.conn.execute("UPDATE log_files SET total_lines = ? WHERE id = ?", (total_lines, file_id))
        self.conn.commit()

    def insert_log_entry(self, file_id: int, line_number: int, timestamp: str, level: str,
                         source: str, message: str, raw_line: str, pattern_id: int = 0,
                         is_anomaly: bool = False, anomaly_score: float = 0.0) -> int:
        cursor = self.conn.execute(
            """INSERT INTO log_entries (file_id, line_number, timestamp, level, source, message, raw_line, pattern_id, is_anomaly, anomaly_score)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, line_number, timestamp, level, source, message, raw_line, pattern_id, int(is_anomaly), anomaly_score)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_log_entries(self, file_id: Optional[int] = None, level: Optional[str] = None,
                        is_anomaly: Optional[bool] = None, limit: int = 500, offset: int = 0) -> list[dict]:
        query = "SELECT * FROM log_entries WHERE 1=1"
        params = []
        if file_id is not None:
            query += " AND file_id = ?"
            params.append(file_id)
        if level is not None:
            query += " AND level = ?"
            params.append(level.upper())
        if is_anomaly is not None:
            query += " AND is_anomaly = ?"
            params.append(int(is_anomaly))
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self.conn.execute(query, params).fetchall()
        cols = self._entry_columns()
        return [self._row_to_dict(row, cols) for row in rows]

    def add_anomaly(self, log_entry_id: int, reason: str, severity: str = "medium") -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = self.conn.execute(
            "INSERT INTO anomalies (log_entry_id, reason, severity, created_at) VALUES (?, ?, ?, ?)",
            (log_entry_id, reason, severity, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_anomalies(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            """SELECT a.*, e.raw_line, e.timestamp, e.level
               FROM anomalies a
               JOIN log_entries e ON a.log_entry_id = e.id
               ORDER BY a.id DESC LIMIT ?""", (limit,)
        ).fetchall()
        cols = ["id", "log_entry_id", "reason", "severity", "reviewed", "created_at",
                "raw_line", "timestamp", "level"]
        return [self._row_to_dict(row, cols) for row in rows]

    def get_anomalies_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()
        return row[0] if row else 0

    def upsert_daily_stats(self, date_str: str, total_lines: int = 0, errors: int = 0,
                           warnings: int = 0, info: int = 0, debug: int = 0, anomalies: int = 0):
        self.conn.execute(
            """INSERT INTO daily_stats (date, total_lines, errors, warnings, info, debug, anomalies)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(date) DO UPDATE SET
               total_lines = total_lines + excluded.total_lines,
               errors = errors + excluded.errors,
               warnings = warnings + excluded.warnings,
               info = info + excluded.info,
               debug = debug + excluded.debug,
               anomalies = anomalies + excluded.anomalies""",
            (date_str, total_lines, errors, warnings, info, debug, anomalies)
        )
        self.conn.commit()

    def get_daily_stats(self, limit: int = 30) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM daily_stats ORDER BY date DESC LIMIT ?", (limit,)
        ).fetchall()
        cols = ["id", "date", "total_lines", "errors", "warnings", "info", "debug", "anomalies"]
        return [self._row_to_dict(row, cols) for row in rows]

    def get_stats_summary(self) -> dict:
        total_entries = self.conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
        total_patterns = self.conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        total_anomalies = self.conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
        total_files = self.conn.execute("SELECT COUNT(*) FROM log_files").fetchone()[0]
        error_count = self.conn.execute(
            "SELECT COUNT(*) FROM log_entries WHERE level='ERROR' OR level='FATAL' OR level='CRITICAL'"
        ).fetchone()[0]
        warning_count = self.conn.execute(
            "SELECT COUNT(*) FROM log_entries WHERE level='WARNING' OR level='WARN'"
        ).fetchone()[0]
        return {
            "total_entries": total_entries,
            "total_patterns": total_patterns,
            "total_anomalies": total_anomalies,
            "total_files": total_files,
            "error_count": error_count,
            "warning_count": warning_count,
        }

    def get_category_distribution(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT category, COUNT(*) as count FROM patterns GROUP BY category ORDER BY count DESC"
        ).fetchall()
        return [{"category": r[0], "count": r[1]} for r in rows]

    def get_level_distribution(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT level, COUNT(*) as count FROM log_entries GROUP BY level ORDER BY count DESC"
        ).fetchall()
        return [{"level": r[0], "count": r[1]} for r in rows]

    def delete_file_entries(self, file_id: int):
        self.conn.execute("DELETE FROM anomalies WHERE log_entry_id IN (SELECT id FROM log_entries WHERE file_id = ?)", (file_id,))
        self.conn.execute("DELETE FROM log_entries WHERE file_id = ?", (file_id,))
        self.conn.execute("DELETE FROM log_files WHERE id = ?", (file_id,))
        self.conn.commit()

    def clear_all(self):
        self.conn.executescript("""
            DELETE FROM anomalies;
            DELETE FROM log_entries;
            DELETE FROM log_files;
            DELETE FROM daily_stats;
            DELETE FROM patterns;
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    @staticmethod
    def _pattern_columns() -> list[str]:
        return ["id", "signature", "regex_pattern", "category", "description",
                "frequency", "first_seen", "last_seen", "confirmed", "is_error", "sample"]

    @staticmethod
    def _entry_columns() -> list[str]:
        return ["id", "file_id", "line_number", "timestamp", "level", "source",
                "message", "raw_line", "pattern_id", "is_anomaly", "anomaly_score"]

    @staticmethod
    def _row_to_dict(row: tuple, columns: list[str]) -> dict:
        return {columns[i]: row[i] for i in range(len(columns))}
