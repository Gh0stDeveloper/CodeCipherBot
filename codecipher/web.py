"""API HTTP para el panel y Telegram Mini App."""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from flask import Flask, Response, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import __version__
from .config import Settings
from .registry import METHODS, public_method_payload
from .storage import Storage


LOGGER = logging.getLogger("codecipherbot.web")
SESSION_MAX_AGE = 60 * 60
TELEGRAM_AUTH_MAX_AGE = 15 * 60


class WebAuthError(ValueError):
    pass


def validate_telegram_init_data(
    init_data: str,
    bot_token: str,
    *,
    now: int | None = None,
    max_age: int = TELEGRAM_AUTH_MAX_AGE,
) -> dict[str, Any]:
    """Valida initData según el algoritmo documentado por Telegram."""

    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
    except ValueError as exc:
        raise WebAuthError("Los datos de Telegram no son válidos.") from exc
    received_hash = pairs.pop("hash", "")
    if not received_hash:
        raise WebAuthError("Falta la firma de Telegram.")
    check_string = "\n".join(f"{key}={pairs[key]}" for key in sorted(pairs))
    secret_key = hmac.new(
        b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256
    ).digest()
    expected = hmac.new(
        secret_key, check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, received_hash):
        raise WebAuthError("La firma de Telegram no coincide.")
    try:
        auth_date = int(pairs["auth_date"])
    except (KeyError, ValueError) as exc:
        raise WebAuthError("Falta la fecha de autenticación.") from exc
    current = int(time.time()) if now is None else now
    if auth_date > current + 30 or current - auth_date > max_age:
        raise WebAuthError("La autenticación de Telegram expiró.")
    try:
        user = json.loads(pairs["user"])
        user_id = int(user["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise WebAuthError("No se pudo identificar al usuario de Telegram.") from exc
    if user_id <= 0:
        raise WebAuthError("El usuario de Telegram no es válido.")
    return user


def _role(settings: Settings, user_id: int) -> str:
    if settings.is_owner(user_id):
        return "owner"
    if settings.is_admin(user_id):
        return "admin"
    return "user"


def _user_payload(
    settings: Settings,
    user_id: int,
    stored: dict[str, Any] | None,
) -> dict[str, Any]:
    item = stored or {}
    return {
        "id": user_id,
        "username": item.get("username"),
        "first_name": item.get("first_name"),
        "role": _role(settings, user_id),
        "banned": bool(item.get("is_banned", item.get("banned", False))),
        "operations": int(item.get("operations", 0)),
        "last_seen": item.get("last_seen"),
    }


def create_web_app(
    settings: Settings,
    storage: Storage,
    *,
    broadcast: Callable[[str, int], dict[str, int]] | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        JSON_AS_ASCII=False,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    serializer = URLSafeTimedSerializer(
        settings.session_secret,
        salt="codecipher-admin-session-v1",
    )

    allowed_origins = set(settings.cors_origins)
    if settings.panel_url:
        parsed = urlsplit(settings.panel_url)
        if parsed.scheme and parsed.netloc:
            allowed_origins.add(f"{parsed.scheme}://{parsed.netloc}")

    def error(message: str, status: int) -> tuple[Response, int]:
        return jsonify({"error": message}), status

    @app.after_request
    def cors(response: Response) -> Response:
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = (
                "Authorization, Content-Type"
            )
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, DELETE, OPTIONS"
            )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def issue_token(user_id: int) -> str:
        return serializer.dumps({"user_id": user_id})

    def authenticated(*, admin: bool = False, owner: bool = False):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                header = request.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    return error("Autenticación requerida.", 401)
                try:
                    payload = serializer.loads(
                        header[7:].strip(), max_age=SESSION_MAX_AGE
                    )
                    user_id = int(payload["user_id"])
                except SignatureExpired:
                    return error("La sesión expiró.", 401)
                except (BadSignature, KeyError, TypeError, ValueError):
                    return error("La sesión no es válida.", 401)
                if storage.is_banned(user_id):
                    return error("La cuenta está bloqueada.", 403)
                if admin and not settings.is_admin(user_id):
                    return error("Se requiere acceso administrativo.", 403)
                if owner and not settings.is_owner(user_id):
                    return error("Se requiere acceso del propietario.", 403)
                g.user_id = user_id
                return func(*args, **kwargs)

            return wrapper

        return decorator

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "version": __version__,
                "database": "ok",
                "methods": len(METHODS),
            }
        )

    @app.get("/api/public/status")
    def public_status():
        stats = storage.statistics()
        return jsonify(
            {
                "name": "CodeCipherBot",
                "version": __version__,
                "online": True,
                "maintenance": storage.maintenance_enabled(),
                "maintenance_message": storage.get_setting(
                    "maintenance_message", ""
                ),
                "users": stats["total_users"],
                "operations_today": stats["operations_today"],
                "methods": public_method_payload(storage.method_enabled),
                "limits": {
                    "max_file_mb": settings.max_file_size // (1024 * 1024),
                    "rate_per_minute": settings.rate_limit_per_minute,
                    "max_batch_files": settings.max_batch_files,
                },
            }
        )

    @app.post("/api/auth/telegram")
    def auth_telegram():
        payload = request.get_json(silent=True) or {}
        try:
            telegram_user = validate_telegram_init_data(
                str(payload.get("init_data", "")), settings.bot_token
            )
        except WebAuthError as exc:
            return error(str(exc), 401)
        user_id = int(telegram_user["id"])
        storage.register_user(
            user_id,
            telegram_user.get("username"),
            telegram_user.get("first_name"),
        )
        if storage.is_banned(user_id):
            return error("La cuenta está bloqueada.", 403)
        return jsonify(
            {
                "token": issue_token(user_id),
                "expires_in": SESSION_MAX_AGE,
                "user": _user_payload(
                    settings, user_id, storage.get_user(user_id)
                ),
            }
        )

    @app.post("/api/auth/code")
    def auth_code():
        payload = request.get_json(silent=True) or {}
        code = str(payload.get("code", "")).strip()
        if not 10 <= len(code) <= 100:
            return error("El código no es válido.", 401)
        user_id = storage.consume_admin_code(code)
        if user_id is None or not settings.is_admin(user_id):
            return error("El código expiró o ya fue utilizado.", 401)
        storage.audit(user_id, "panel_login")
        return jsonify(
            {
                "token": issue_token(user_id),
                "expires_in": SESSION_MAX_AGE,
                "user": _user_payload(
                    settings, user_id, storage.get_user(user_id)
                ),
            }
        )

    @app.get("/api/me")
    @authenticated()
    def me():
        user_id = g.user_id
        return jsonify(
            {
                "user": _user_payload(
                    settings, user_id, storage.get_user(user_id)
                ),
                "history": storage.recent_history(
                    user_id, settings.history_limit
                ),
                "presets": storage.list_presets(user_id),
            }
        )

    @app.delete("/api/me/history")
    @authenticated()
    def clear_my_history():
        removed = storage.clear_history(g.user_id)
        return jsonify({"removed": removed})

    @app.get("/api/admin/stats")
    @authenticated(admin=True)
    def admin_stats():
        payload = storage.statistics()
        payload["database_bytes"] = storage.database_size()
        payload["maintenance"] = storage.maintenance_enabled()
        return jsonify(payload)

    @app.get("/api/admin/users")
    @authenticated(admin=True)
    def admin_users():
        try:
            limit = int(request.args.get("limit", "50"))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            return error("Paginación no válida.", 400)
        users = [
            _user_payload(settings, int(item["id"]), item)
            for item in storage.list_users(limit, offset)
        ]
        return jsonify({"users": users})

    @app.put("/api/admin/users/<int:user_id>/ban")
    @authenticated(admin=True)
    def admin_ban(user_id: int):
        if settings.is_admin(user_id):
            return error("No se puede bloquear a un administrador.", 400)
        payload = request.get_json(silent=True) or {}
        enabled = payload.get("banned")
        if not isinstance(enabled, bool):
            return error("banned debe ser true o false.", 400)
        storage.set_banned(user_id, enabled)
        storage.audit(
            g.user_id,
            "ban_user" if enabled else "unban_user",
            str(user_id),
        )
        return jsonify({"ok": True, "user_id": user_id, "banned": enabled})

    @app.put("/api/admin/methods/<method_key>")
    @authenticated(admin=True)
    def admin_method(method_key: str):
        if method_key not in METHODS:
            return error("Método desconocido.", 404)
        payload = request.get_json(silent=True) or {}
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            return error("enabled debe ser true o false.", 400)
        storage.set_method_enabled(method_key, enabled)
        storage.audit(
            g.user_id,
            "enable_method" if enabled else "disable_method",
            method_key,
        )
        return jsonify({"ok": True, "key": method_key, "enabled": enabled})

    @app.put("/api/admin/maintenance")
    @authenticated(admin=True)
    def admin_maintenance():
        payload = request.get_json(silent=True) or {}
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            return error("enabled debe ser true o false.", 400)
        message = str(payload.get("message", "")).strip()[:500]
        storage.set_maintenance(enabled, message)
        storage.audit(
            g.user_id,
            "maintenance_on" if enabled else "maintenance_off",
            details={"message": message},
        )
        return jsonify({"ok": True, "maintenance": enabled})

    @app.post("/api/admin/broadcast")
    @authenticated(admin=True)
    def admin_broadcast():
        if broadcast is None:
            return error("La difusión no está disponible en este proceso.", 503)
        payload = request.get_json(silent=True) or {}
        message = str(payload.get("message", "")).strip()
        if not 1 <= len(message) <= 3500:
            return error("El mensaje debe tener entre 1 y 3500 caracteres.", 400)
        result = broadcast(message, g.user_id)
        storage.audit(g.user_id, "broadcast", details=result)
        return jsonify({"ok": True, **result}), 202

    @app.get("/api/admin/logs")
    @authenticated(admin=True)
    def admin_logs():
        return jsonify({"logs": storage.audit_logs(100)})

    return app

