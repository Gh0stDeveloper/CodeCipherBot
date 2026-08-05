"""Persistencia SQLite: solo metadatos, nunca contenido de archivos."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._memory_connection: sqlite3.Connection | None = None
        if path != ":memory:":
            Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        else:
            self._memory_connection = sqlite3.connect(
                ":memory:", timeout=30, check_same_thread=False
            )
            self._memory_connection.row_factory = sqlite3.Row
            self._memory_connection.execute("PRAGMA foreign_keys = ON")
        self._initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        if self._memory_connection is not None:
            with self._lock:
                try:
                    yield self._memory_connection
                    self._memory_connection.commit()
                except Exception:
                    self._memory_connection.rollback()
                    raise
            return
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                language TEXT NOT NULL DEFAULT 'es',
                is_banned INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                method TEXT NOT NULL,
                filename TEXT,
                status TEXT NOT NULL,
                input_size INTEGER NOT NULL DEFAULT 0,
                output_size INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS methods (
                method_key TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS admin_codes (
                code_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                method_key TEXT NOT NULL,
                options_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name),
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS operations_user_idx ON operations(user_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS operations_date_idx ON operations(created_at)",
            "CREATE INDEX IF NOT EXISTS users_last_seen_idx ON users(last_seen DESC)",
        ]
        with self._lock, self.connection() as connection:
            if self.path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            for statement in statements:
                connection.execute(statement)
            connection.execute(
                """
                INSERT OR IGNORE INTO settings(key, value, updated_at)
                VALUES ('maintenance', 'false', ?)
                """,
                (utc_now(),),
            )

    def register_user(
        self,
        user_id: int,
        username: str | None,
        first_name: str | None,
    ) -> None:
        now = utc_now()
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO users(user_id, username, first_name, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    username = excluded.username,
                    first_name = excluded.first_name,
                    last_seen = excluded.last_seen
                """,
                (user_id, username, first_name, now, now),
            )

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    def is_banned(self, user_id: int) -> bool:
        user = self.get_user(user_id)
        return bool(user and user["is_banned"])

    def set_banned(self, user_id: int, banned: bool) -> None:
        now = utc_now()
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO users(user_id, created_at, last_seen, is_banned)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET is_banned = excluded.is_banned
                """,
                (user_id, now, now, int(banned)),
            )

    def set_language(self, user_id: int, language: str) -> None:
        if language not in {"es", "en"}:
            raise ValueError("Idioma no compatible.")
        with self._lock, self.connection() as connection:
            connection.execute(
                "UPDATE users SET language = ? WHERE user_id = ?",
                (language, user_id),
            )

    def get_language(self, user_id: int) -> str:
        user = self.get_user(user_id)
        return str(user["language"]) if user else "es"

    def record_operation(
        self,
        user_id: int,
        method: str,
        filename: str | None,
        status: str,
        input_size: int,
        output_size: int = 0,
        error: str | None = None,
    ) -> None:
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO operations(
                    user_id, method, filename, status,
                    input_size, output_size, error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    method,
                    filename,
                    status,
                    input_size,
                    output_size,
                    (error or "")[:300] or None,
                    utc_now(),
                ),
            )

    def recent_history(self, user_id: int, limit: int = 20) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, method, filename, status, input_size, output_size, created_at
                FROM operations
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_history(self, user_id: int) -> int:
        with self._lock, self.connection() as connection:
            cursor = connection.execute(
                "DELETE FROM operations WHERE user_id = ?", (user_id,)
            )
        return int(cursor.rowcount)

    def sync_methods(self, keys: list[str]) -> None:
        now = utc_now()
        with self._lock, self.connection() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO methods(method_key, enabled, updated_at)
                VALUES (?, 1, ?)
                """,
                [(key, now) for key in keys],
            )

    def method_enabled(self, key: str) -> bool:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT enabled FROM methods WHERE method_key = ?", (key,)
            ).fetchone()
        return bool(row["enabled"]) if row else True

    def set_method_enabled(self, key: str, enabled: bool) -> None:
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO methods(method_key, enabled, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(method_key) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (key, int(enabled), utc_now()),
            )

    def method_states(self) -> dict[str, bool]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT method_key, enabled FROM methods ORDER BY method_key"
            ).fetchall()
        return {str(row["method_key"]): bool(row["enabled"]) for row in rows}

    def get_setting(self, key: str, default: str = "") -> str:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, utc_now()),
            )

    def maintenance_enabled(self) -> bool:
        return self.get_setting("maintenance", "false").lower() == "true"

    def set_maintenance(self, enabled: bool, message: str = "") -> None:
        self.set_setting("maintenance", "true" if enabled else "false")
        self.set_setting("maintenance_message", message[:500])

    def statistics(self) -> dict[str, Any]:
        today = datetime.now(timezone.utc).date().isoformat()
        with self.connection() as connection:
            total_users = connection.execute(
                "SELECT COUNT(*) AS count FROM users"
            ).fetchone()["count"]
            active_today = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE last_seen >= ?",
                (today,),
            ).fetchone()["count"]
            total_operations = connection.execute(
                "SELECT COUNT(*) AS count FROM operations"
            ).fetchone()["count"]
            operations_today = connection.execute(
                "SELECT COUNT(*) AS count FROM operations WHERE created_at >= ?",
                (today,),
            ).fetchone()["count"]
            failures = connection.execute(
                """
                SELECT COUNT(*) AS count FROM operations
                WHERE created_at >= ? AND status != 'success'
                """,
                (today,),
            ).fetchone()["count"]
            popular = connection.execute(
                """
                SELECT method, COUNT(*) AS count
                FROM operations
                GROUP BY method
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()
        return {
            "total_users": total_users,
            "active_today": active_today,
            "total_operations": total_operations,
            "operations_today": operations_today,
            "failed_operations": failures,
            "popular_methods": [dict(row) for row in popular],
        }

    def list_users(
        self, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    u.user_id AS id,
                    u.username,
                    u.first_name,
                    u.is_banned AS banned,
                    u.last_seen,
                    COUNT(o.id) AS operations
                FROM users u
                LEFT JOIN operations o ON o.user_id = u.user_id
                GROUP BY u.user_id
                ORDER BY u.last_seen DESC
                LIMIT ? OFFSET ?
                """,
                (max(1, min(limit, 200)), max(0, offset)),
            ).fetchall()
        return [dict(row) for row in rows]

    def all_user_ids(self) -> list[int]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT user_id FROM users WHERE is_banned = 0 ORDER BY user_id"
            ).fetchall()
        return [int(row["user_id"]) for row in rows]

    def create_admin_code(self, user_id: int, minutes: int = 5) -> str:
        code = secrets.token_urlsafe(18)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        with self._lock, self.connection() as connection:
            connection.execute(
                "DELETE FROM admin_codes WHERE user_id = ? OR expires_at < ?",
                (user_id, utc_now()),
            )
            connection.execute(
                """
                INSERT INTO admin_codes(code_hash, user_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (digest, user_id, expires.isoformat(timespec="seconds")),
            )
        return code

    def consume_admin_code(self, code: str) -> int | None:
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        now = utc_now()
        with self._lock, self.connection() as connection:
            row = connection.execute(
                """
                SELECT user_id FROM admin_codes
                WHERE code_hash = ? AND used_at IS NULL AND expires_at >= ?
                """,
                (digest, now),
            ).fetchone()
            if not row:
                return None
            connection.execute(
                "UPDATE admin_codes SET used_at = ? WHERE code_hash = ?",
                (now, digest),
            )
        return int(row["user_id"])

    def audit(
        self,
        actor_id: int,
        action: str,
        target: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_logs(actor_id, action, target, details, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    actor_id,
                    action,
                    target[:200],
                    json.dumps(details or {}, ensure_ascii=False)[:2000],
                    utc_now(),
                ),
            )

    def save_preset(
        self,
        user_id: int,
        name: str,
        method_key: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                INSERT INTO presets(user_id, name, method_key, options_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id, name) DO UPDATE SET
                    method_key = excluded.method_key,
                    options_json = excluded.options_json
                """,
                (
                    user_id,
                    name[:40],
                    method_key,
                    json.dumps(options or {}, ensure_ascii=False),
                    utc_now(),
                ),
            )

    def list_presets(self, user_id: int) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT name, method_key, options_json, created_at
                FROM presets WHERE user_id = ? ORDER BY name
                """,
                (user_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["options"] = json.loads(item.pop("options_json"))
            result.append(item)
        return result

    def delete_preset(self, user_id: int, name: str) -> bool:
        with self._lock, self.connection() as connection:
            cursor = connection.execute(
                "DELETE FROM presets WHERE user_id = ? AND name = ?",
                (user_id, name),
            )
        return cursor.rowcount > 0

    def database_size(self) -> int:
        if self.path == ":memory:":
            return 0
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, actor_id, action, target, details, created_at
                FROM audit_logs ORDER BY id DESC LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item["details"] or "{}")
            except json.JSONDecodeError:
                item["details"] = {}
            result.append(item)
        return result
