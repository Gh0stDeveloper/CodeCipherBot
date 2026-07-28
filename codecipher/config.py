"""Configuración portable mediante variables de entorno."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _positive_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} debe ser un número entero.") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} debe estar entre {minimum} y {maximum}.")
    return value


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on", "si", "sí"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} debe ser true o false.")


def _ids(name: str) -> frozenset[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return frozenset()
    try:
        return frozenset(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} debe contener IDs numéricos separados por comas.") from exc


def _origins(raw: str) -> tuple[str, ...]:
    return tuple(
        item.strip().rstrip("/")
        for item in raw.split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class Settings:
    bot_token: str
    max_file_size: int
    max_batch_files: int
    max_batch_uncompressed: int
    rate_limit_per_minute: int
    worker_threads: int
    owner_ids: frozenset[int]
    admin_ids: frozenset[int]
    database_path: str
    log_level: int
    history_limit: int
    auto_delete_seconds: int
    panel_url: str
    public_api_url: str
    web_enabled: bool
    web_host: str
    web_port: int
    cors_origins: tuple[str, ...]
    session_secret: str
    run_mode: str
    webhook_base_url: str
    webhook_path_secret: str
    webhook_header_secret: str

    @property
    def all_admin_ids(self) -> frozenset[int]:
        return self.owner_ids | self.admin_ids

    def is_admin(self, user_id: int) -> bool:
        return user_id in self.all_admin_ids

    def is_owner(self, user_id: int) -> bool:
        return user_id in self.owner_ids

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.getenv("BOT_TOKEN", "").strip()
        if not token:
            raise ConfigError(
                "Falta BOT_TOKEN. Revoca el token anterior y configura uno nuevo."
            )

        log_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
        log_level = getattr(logging, log_name, None)
        if not isinstance(log_level, int):
            raise ConfigError("LOG_LEVEL no es válido.")

        run_mode = os.getenv("RUN_MODE", "polling").strip().lower()
        if run_mode not in {"polling", "webhook"}:
            raise ConfigError("RUN_MODE debe ser polling o webhook.")

        webhook_base = os.getenv("WEBHOOK_BASE_URL", "").strip().rstrip("/")
        if run_mode == "webhook" and not webhook_base.startswith("https://"):
            raise ConfigError("WEBHOOK_BASE_URL debe usar HTTPS en modo webhook.")

        max_file_mb = _positive_int("MAX_FILE_SIZE_MB", 10, 1, 20)
        max_batch_mb = _positive_int("MAX_BATCH_UNCOMPRESSED_MB", 30, 1, 100)
        session_secret = os.getenv("ADMIN_SESSION_SECRET", "").strip()
        if not session_secret:
            # La derivación evita guardar otra clave; al rotar BOT_TOKEN se invalidan sesiones.
            import hashlib

            session_secret = hashlib.sha256(
                f"codecipher-session:{token}".encode("utf-8")
            ).hexdigest()

        return cls(
            bot_token=token,
            max_file_size=max_file_mb * 1024 * 1024,
            max_batch_files=_positive_int("MAX_BATCH_FILES", 40, 1, 100),
            max_batch_uncompressed=max_batch_mb * 1024 * 1024,
            rate_limit_per_minute=_positive_int(
                "RATE_LIMIT_PER_MINUTE", 20, 1, 120
            ),
            worker_threads=_positive_int("BOT_WORKERS", 6, 1, 24),
            owner_ids=_ids("OWNER_IDS"),
            admin_ids=_ids("ADMIN_IDS"),
            database_path=os.getenv(
                "DATABASE_PATH", "./data/codecipherbot.sqlite3"
            ).strip(),
            log_level=log_level,
            history_limit=_positive_int("HISTORY_LIMIT", 20, 5, 100),
            auto_delete_seconds=_positive_int(
                "AUTO_DELETE_SECONDS", 0, 0, 86_400
            ),
            panel_url=os.getenv("PANEL_URL", "").strip().rstrip("/"),
            public_api_url=os.getenv("PUBLIC_API_URL", "").strip().rstrip("/"),
            web_enabled=_boolean("WEB_ENABLED", True),
            web_host=os.getenv("WEB_HOST", "0.0.0.0").strip(),
            web_port=_positive_int(
                "PORT", _positive_int("WEB_PORT", 8080, 1, 65_535), 1, 65_535
            ),
            cors_origins=_origins(os.getenv("CORS_ORIGINS", "")),
            session_secret=session_secret,
            run_mode=run_mode,
            webhook_base_url=webhook_base,
            webhook_path_secret=os.getenv(
                "WEBHOOK_PATH_SECRET", secrets.token_urlsafe(18)
            ).strip(),
            webhook_header_secret=os.getenv(
                "WEBHOOK_HEADER_SECRET", secrets.token_urlsafe(24)
            ).strip(),
        )
