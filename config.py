"""Configuración por variables de entorno."""

from __future__ import annotations

import logging
import os
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


def _id_allowlist(raw: str) -> frozenset[int]:
    if not raw.strip():
        return frozenset()
    try:
        return frozenset(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise ConfigError("ALLOWED_USER_IDS debe contener IDs numéricos separados por comas.") from exc


@dataclass(frozen=True)
class Settings:
    bot_token: str
    max_file_size: int
    rate_limit_per_minute: int
    worker_threads: int
    allowed_user_ids: frozenset[int]
    log_level: int

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.getenv("BOT_TOKEN", "").strip()
        if not token:
            raise ConfigError(
                "Falta BOT_TOKEN. Crea un token nuevo con BotFather y colócalo "
                "como variable de entorno."
            )

        max_file_mb = _positive_int("MAX_FILE_SIZE_MB", 5, 1, 20)
        log_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
        log_level = getattr(logging, log_name, None)
        if not isinstance(log_level, int):
            raise ConfigError("LOG_LEVEL no es válido.")

        return cls(
            bot_token=token,
            max_file_size=max_file_mb * 1024 * 1024,
            rate_limit_per_minute=_positive_int("RATE_LIMIT_PER_MINUTE", 12, 1, 120),
            worker_threads=_positive_int("BOT_WORKERS", 4, 1, 16),
            allowed_user_ids=_id_allowlist(os.getenv("ALLOWED_USER_IDS", "")),
            log_level=log_level,
        )
