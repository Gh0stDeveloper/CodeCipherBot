"""Interfaz de Telegram pública, utilidades y administración."""

from __future__ import annotations

import html
import io
import json
import logging
import os
import re
import threading
import time
import zipfile
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from pathlib import PurePath
from typing import Any, Callable
from urllib.parse import quote

import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException

from . import __version__
from .batch import BatchError, process_project_zip
from .config import Settings
from .registry import (
    CATEGORY_LABELS,
    METHODS,
    MethodSpec,
    ProcessedFile,
    ProcessingError,
    process,
)
from .storage import Storage
from .tools import (
    HASH_ALGORITHMS,
    ToolError,
    analyze_source,
    detect_format,
    generate_ed25519_keypair,
    hash_data,
    qr_svg,
    sign_ed25519,
    verify_ed25519,
    verify_hash,
)


LOGGER = logging.getLogger("codecipherbot.telegram")
SessionKey = tuple[int, int]


PUBLIC_COMMANDS = [
    types.BotCommand("start", "Abrir el menú principal"),
    types.BotCommand("protect", "Proteger código y mantenerlo ejecutable"),
    types.BotCommand("encode", "Codificar texto o archivos"),
    types.BotCommand("decode", "Decodificar o recuperar un wrapper"),
    types.BotCommand("encrypt", "Cifrar un archivo con contraseña"),
    types.BotCommand("decrypt", "Descifrar un archivo .gcb"),
    types.BotCommand("batch", "Procesar un proyecto ZIP"),
    types.BotCommand("hash", "Calcular un hash"),
    types.BotCommand("verifyhash", "Comprobar un hash"),
    types.BotCommand("keygen", "Crear claves de firma Ed25519"),
    types.BotCommand("sign", "Firmar un archivo"),
    types.BotCommand("verify", "Verificar una firma"),
    types.BotCommand("qr", "Crear un QR en SVG"),
    types.BotCommand("detect", "Detectar formato y lenguaje"),
    types.BotCommand("analyze", "Análisis estático de código"),
    types.BotCommand("methods", "Listar métodos disponibles"),
    types.BotCommand("preset", "Guardar o usar un método favorito"),
    types.BotCommand("history", "Ver o borrar tu historial"),
    types.BotCommand("settings", "Ver tus preferencias"),
    types.BotCommand("language", "Cambiar idioma"),
    types.BotCommand("limits", "Ver límites del servicio"),
    types.BotCommand("status", "Estado del bot"),
    types.BotCommand("panel", "Abrir el panel web"),
    types.BotCommand("privacy", "Política de privacidad"),
    types.BotCommand("about", "Acerca del proyecto"),
    types.BotCommand("help", "Mostrar ayuda"),
    types.BotCommand("cancel", "Cancelar la operación actual"),
]

ADMIN_COMMANDS = [
    types.BotCommand("admin", "Panel de administración"),
    types.BotCommand("stats", "Estadísticas del servicio"),
    types.BotCommand("users", "Usuarios recientes"),
    types.BotCommand("ban", "Bloquear un usuario"),
    types.BotCommand("unban", "Desbloquear un usuario"),
    types.BotCommand("broadcast", "Enviar una difusión"),
    types.BotCommand("maintenance", "Controlar mantenimiento"),
    types.BotCommand("enablemethod", "Activar un método"),
    types.BotCommand("disablemethod", "Desactivar un método"),
    types.BotCommand("health", "Diagnóstico del servicio"),
    types.BotCommand("logs", "Ver auditoría administrativa"),
    types.BotCommand("exportdata", "Exportar metadatos (propietario)"),
]


@dataclass(frozen=True)
class Session:
    workflow: str = ""
    method_key: str = ""
    awaiting: str = ""
    password: str = ""
    options: dict[str, str] = field(default_factory=dict)
    updated_at: float = 0.0


class SessionStore:
    def __init__(self, ttl: int = 3600) -> None:
        self._ttl = ttl
        self._items: dict[SessionKey, Session] = {}
        self._lock = threading.RLock()

    def get(self, key: SessionKey) -> Session:
        now = time.monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None or now - item.updated_at > self._ttl:
                item = Session(updated_at=now)
                self._items[key] = item
            return item

    def set(self, key: SessionKey, item: Session) -> Session:
        current = replace(item, updated_at=time.monotonic())
        with self._lock:
            self._items[key] = current
        return current

    def reset(self, key: SessionKey) -> None:
        with self._lock:
            self._items.pop(key, None)


class RateLimiter:
    def __init__(self, maximum: int, seconds: int = 60) -> None:
        self.maximum = maximum
        self.seconds = seconds
        self._events: dict[int, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, user_id: int) -> bool:
        now = time.monotonic()
        with self._lock:
            events = self._events[user_id]
            while events and now - events[0] >= self.seconds:
                events.popleft()
            if len(events) >= self.maximum:
                return False
            events.append(now)
            return True


def _key(message: types.Message) -> SessionKey:
    return message.chat.id, message.from_user.id


def _safe_name(name: str, fallback: str = "archivo.bin") -> str:
    candidate = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    candidate = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", candidate)
    if not candidate or candidate in {".", ".."}:
        return fallback
    stem = PurePath(candidate).stem[:140] or "archivo"
    suffix = PurePath(candidate).suffix[:20]
    return stem + suffix


def _buffer(data: bytes, filename: str) -> io.BytesIO:
    value = io.BytesIO(data)
    value.name = _safe_name(filename)
    return value


def _human_bytes(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if isinstance(value, float) else f"{value} {unit}"
        value = value / 1024
    return f"{value:.1f} GB"


def _args(message: types.Message) -> str:
    return (message.text or "").partition(" ")[2].strip()


def _role(settings: Settings, user_id: int) -> str:
    if settings.is_owner(user_id):
        return "propietario"
    if settings.is_admin(user_id):
        return "administrador"
    return "usuario"


def _main_keyboard(settings: Settings) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton(
            "⚙️ Protección ejecutable", callback_data="category:runnable"
        )
    )
    markup.row(
        types.InlineKeyboardButton("🔤 Codificación", callback_data="category:encoding"),
        types.InlineKeyboardButton("📦 Compresión", callback_data="category:compression"),
    )
    markup.row(
        types.InlineKeyboardButton("🔐 Cifrado real", callback_data="category:secure"),
        types.InlineKeyboardButton("🧰 Herramientas", callback_data="category:tools"),
    )
    if settings.panel_url:
        markup.row(
            types.InlineKeyboardButton("📊 Panel web", url=settings.panel_url)
        )
    return markup


def _method_keyboard(
    storage: Storage, category: str
) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=1)
    for spec in METHODS.values():
        if spec.category == category and storage.method_enabled(spec.key):
            markup.add(
                types.InlineKeyboardButton(
                    spec.label, callback_data=f"method:{spec.key}"
                )
            )
    markup.add(types.InlineKeyboardButton("← Volver", callback_data="menu:main"))
    return markup


def _tools_keyboard() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    for key, label in (
        ("hash", "Hash"),
        ("verifyhash", "Verificar hash"),
        ("qr", "QR"),
        ("detect", "Detectar"),
        ("analyze", "Analizar"),
        ("keygen", "Claves Ed25519"),
        ("sign", "Firmar"),
        ("verify", "Verificar firma"),
        ("batch_protect", "ZIP · Proteger"),
        ("batch_unwrap", "ZIP · Recuperar"),
    ):
        markup.add(types.InlineKeyboardButton(label, callback_data=f"tool:{key}"))
    markup.add(types.InlineKeyboardButton("← Volver", callback_data="menu:main"))
    return markup


def _welcome(settings: Settings, storage: Storage) -> str:
    enabled = sum(storage.method_enabled(key) for key in METHODS)
    maintenance = " · <b>Mantenimiento</b>" if storage.maintenance_enabled() else ""
    return (
        f"<b>CodeCipherBot {__version__}</b>{maintenance}\n\n"
        "Protege código ejecutable, codifica, comprime y cifra archivos. "
        "El servicio es público: las funciones normales están disponibles para todos.\n\n"
        f"• {enabled} métodos activos\n"
        "• No se ejecutan archivos recibidos\n"
        "• Cifrado real con AES-GCM o ChaCha20\n"
        "• Proyectos completos mediante ZIP\n\n"
        "<i>Los wrappers ejecutables son ofuscación reversible. Para secreto real, "
        "usa cifrado con contraseña.</i>"
    )


def _method_prompt(spec: MethodSpec) -> str:
    base = (
        f"<b>{html.escape(spec.label)}</b>\n\n"
        f"{html.escape(spec.description)}\n\n"
    )
    if spec.password_required:
        return (
            base
            + "Envíame una contraseña de 8 a 128 caracteres en este chat privado. "
            "Intentaré borrar el mensaje inmediatamente. Después envía el archivo."
        )
    if spec.key == "runnable_auto":
        return (
            base
            + "Envía el archivo con su extensión real (.py, .js, .php, .sh, .ps1, "
            ".rb, .pl o .lua). Para proyectos usa /batch."
        )
    return base + "Envía un documento o pega el texto. Usa /cancel para salir."


def build_broadcaster(
    bot: telebot.TeleBot, storage: Storage
) -> Callable[[str, int], dict[str, int]]:
    def broadcast(message: str, actor_id: int) -> dict[str, int]:
        recipients = storage.all_user_ids()

        def worker() -> None:
            sent = failed = 0
            for user_id in recipients:
                try:
                    bot.send_message(
                        user_id,
                        "<b>Comunicado de CodeCipherBot</b>\n\n"
                        + html.escape(message),
                    )
                    sent += 1
                except ApiTelegramException:
                    failed += 1
                time.sleep(0.05)
            storage.audit(
                actor_id,
                "broadcast_completed",
                details={"sent": sent, "failed": failed},
            )

        threading.Thread(
            target=worker, name="codecipher-broadcast", daemon=True
        ).start()
        return {"queued": len(recipients)}

    return broadcast


def create_bot(settings: Settings, storage: Storage) -> telebot.TeleBot:
    bot = telebot.TeleBot(
        settings.bot_token,
        parse_mode="HTML",
        threaded=True,
        num_threads=settings.worker_threads,
    )
    sessions = SessionStore()
    limiter = RateLimiter(settings.rate_limit_per_minute)
    storage.sync_methods(list(METHODS))

    def send(
        chat_id: int,
        text: str,
        *,
        markup: types.InlineKeyboardMarkup | None = None,
        reply_to: int | None = None,
    ) -> types.Message:
        return bot.send_message(
            chat_id,
            text,
            reply_markup=markup,
            reply_to_message_id=reply_to,
            disable_web_page_preview=True,
        )

    def register(message: types.Message) -> int | None:
        if message.from_user is None:
            return None
        user_id = message.from_user.id
        storage.register_user(
            user_id, message.from_user.username, message.from_user.first_name
        )
        if storage.is_banned(user_id):
            send(message.chat.id, "Tu cuenta está bloqueada en este servicio.")
            return None
        if storage.maintenance_enabled() and not settings.is_admin(user_id):
            detail = storage.get_setting("maintenance_message", "")
            send(
                message.chat.id,
                "<b>Servicio en mantenimiento.</b>"
                + (f"\n\n{html.escape(detail)}" if detail else ""),
            )
            return None
        return user_id

    def admin_guard(message: types.Message, *, owner: bool = False) -> int | None:
        user_id = register(message)
        if user_id is None:
            return None
        allowed = settings.is_owner(user_id) if owner else settings.is_admin(user_id)
        if not allowed:
            send(message.chat.id, "Este comando requiere permisos administrativos.")
            return None
        return user_id

    def command_method(message: types.Message, key: str) -> None:
        user_id = register(message)
        if user_id is None:
            return
        spec = METHODS.get(key)
        if spec is None or not storage.method_enabled(key):
            send(message.chat.id, "Ese método no está disponible.")
            return
        if spec.password_required and message.chat.type != "private":
            send(
                message.chat.id,
                "Por seguridad, configura contraseñas solo en un chat privado con el bot.",
            )
            return
        session = Session(
            workflow="method",
            method_key=key,
            awaiting="password" if spec.password_required else "",
        )
        sessions.set(_key(message), session)
        send(message.chat.id, _method_prompt(spec), reply_to=message.message_id)

    def send_processed(
        message: types.Message,
        result: ProcessedFile,
        *,
        force_document: bool = True,
    ) -> None:
        if not force_document:
            try:
                text = result.content.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if text and len(html.escape(text)) <= 3200:
                send(
                    message.chat.id,
                    f"<b>{html.escape(result.caption)}</b>\n\n"
                    f"<pre>{html.escape(text)}</pre>",
                    reply_to=message.message_id,
                )
                return
        with _buffer(result.content, result.filename) as document:
            sent = bot.send_document(
                message.chat.id,
                document,
                caption=result.caption[:1024],
                reply_to_message_id=message.message_id,
            )
        if settings.auto_delete_seconds > 0:
            def delete_later() -> None:
                time.sleep(settings.auto_delete_seconds)
                try:
                    bot.delete_message(sent.chat.id, sent.message_id)
                except ApiTelegramException:
                    pass

            threading.Thread(target=delete_later, daemon=True).start()

    def record(
        user_id: int,
        method: str,
        filename: str,
        status: str,
        input_size: int,
        output_size: int = 0,
        error: str = "",
    ) -> None:
        storage.record_operation(
            user_id,
            method,
            filename,
            status,
            input_size,
            output_size,
            error or None,
        )

    def process_method_input(
        message: types.Message,
        session: Session,
        data: bytes,
        filename: str,
        *,
        force_document: bool,
    ) -> None:
        user_id = message.from_user.id
        spec = METHODS.get(session.method_key)
        if spec is None or not storage.method_enabled(session.method_key):
            send(message.chat.id, "El método ya no está disponible.")
            return
        try:
            result = process(
                session.method_key,
                data,
                filename,
                password=session.password or None,
                output_limit=settings.max_batch_uncompressed,
            )
            record(
                user_id,
                spec.key,
                filename,
                "success",
                len(data),
                len(result.content),
            )
            send_processed(message, result, force_document=force_document)
        except ProcessingError as exc:
            record(
                user_id, spec.key, filename, "error", len(data), error=str(exc)
            )
            send(
                message.chat.id,
                f"<b>No se pudo procesar:</b> {html.escape(str(exc))}",
                reply_to=message.message_id,
            )
        except Exception:
            LOGGER.exception(
                "Error de método user_id=%s method=%s", user_id, spec.key
            )
            record(
                user_id,
                spec.key,
                filename,
                "error",
                len(data),
                error="internal_error",
            )
            send(message.chat.id, "Ocurrió un error interno.", reply_to=message.message_id)
        finally:
            if spec.password_required:
                sessions.set(
                    _key(message),
                    Session(
                        workflow="method",
                        method_key=spec.key,
                        awaiting="password",
                    ),
                )

    def handle_utility(
        message: types.Message,
        session: Session,
        data: bytes,
        filename: str,
    ) -> None:
        user_id = message.from_user.id
        workflow = session.workflow
        try:
            if workflow == "hash":
                algorithm = session.options.get("algorithm", "sha256")
                digest = hash_data(data, algorithm)
                send(
                    message.chat.id,
                    f"<b>{algorithm.upper()}</b>\n<code>{digest}</code>",
                    reply_to=message.message_id,
                )
                output_size = len(digest)
            elif workflow == "verifyhash":
                expected = session.options.get("expected", "")
                valid, algorithm, actual = verify_hash(data, expected)
                send(
                    message.chat.id,
                    (
                        ("✅ <b>Coincide</b>" if valid else "❌ <b>No coincide</b>")
                        + f"\nAlgoritmo: {algorithm.upper()}\n"
                        + f"Calculado: <code>{actual}</code>"
                    ),
                    reply_to=message.message_id,
                )
                output_size = len(actual)
            elif workflow == "detect":
                report = detect_format(data, filename)
                rendered = "\n".join(
                    f"<b>{html.escape(str(key))}:</b> {html.escape(str(value))}"
                    for key, value in report.items()
                )
                send(message.chat.id, rendered, reply_to=message.message_id)
                output_size = len(rendered)
            elif workflow == "analyze":
                try:
                    source = data.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise ToolError("El código debe ser texto UTF-8.") from exc
                report = analyze_source(source, filename)
                warnings = report["warnings"] or ["Sin avisos por patrones básicos"]
                rendered = (
                    f"<b>Lenguaje:</b> {html.escape(str(report['language']))}\n"
                    f"<b>Líneas:</b> {report['lines']}\n"
                    f"<b>Sintaxis Python:</b> {report['syntax_valid']}\n"
                    f"<b>Avisos:</b>\n"
                    + "\n".join(f"• {html.escape(str(item))}" for item in warnings)
                    + "\n\n<i>Es un análisis estático orientativo, no un antivirus.</i>"
                )
                send(message.chat.id, rendered, reply_to=message.message_id)
                output_size = len(rendered)
            elif workflow.startswith("batch_"):
                action = workflow.split("_", 1)[1]
                result = process_project_zip(
                    data,
                    action,
                    max_files=settings.max_batch_files,
                    max_uncompressed=settings.max_batch_uncompressed,
                )
                stem = PurePath(filename).stem or "proyecto"
                out = ProcessedFile(
                    result.content,
                    f"{action}_{stem}.zip",
                    (
                        f"ZIP completado: {result.protected} protegidos, "
                        f"{result.recovered} recuperados, {result.copied} copiados."
                    ),
                )
                send_processed(message, out)
                output_size = len(result.content)
            elif workflow == "sign":
                output_size = _handle_sign(bot, message, data, filename)
            elif workflow == "verify":
                output_size = _handle_verify(bot, message, data)
            else:
                raise ToolError("Selecciona primero una herramienta.")
            record(
                user_id,
                workflow,
                filename,
                "success",
                len(data),
                output_size,
            )
        except (ToolError, BatchError, zipfile.BadZipFile) as exc:
            record(
                user_id, workflow, filename, "error", len(data), error=str(exc)
            )
            send(
                message.chat.id,
                f"<b>No se pudo procesar:</b> {html.escape(str(exc))}",
                reply_to=message.message_id,
            )
        except Exception:
            LOGGER.exception("Error de utilidad user_id=%s workflow=%s", user_id, workflow)
            record(
                user_id,
                workflow,
                filename,
                "error",
                len(data),
                error="internal_error",
            )
            send(message.chat.id, "Ocurrió un error interno.", reply_to=message.message_id)

    @bot.message_handler(commands=["start"])
    def start(message: types.Message) -> None:
        if register(message) is None:
            return
        sessions.reset(_key(message))
        send(
            message.chat.id,
            _welcome(settings, storage),
            markup=_main_keyboard(settings),
            reply_to=message.message_id,
        )

    @bot.message_handler(commands=["help"])
    def help_command(message: types.Message) -> None:
        if register(message) is None:
            return
        send(
            message.chat.id,
            "<b>Uso rápido</b>\n\n"
            "• /protect y envía un script.\n"
            "• /batch protect y envía un proyecto ZIP.\n"
            "• /encrypt, escribe una contraseña y envía cualquier archivo.\n"
            "• /decode para codificaciones o wrappers.\n"
            "• /cancel cancela cualquier flujo.\n\n"
            "Herramientas públicas: /hash, /verifyhash, /keygen, /sign, /verify, "
            "/qr, /detect y /analyze.\n\n"
            "Los lenguajes compilados requieren su compilador; el bot no puede "
            "crear un binario universal sin el toolchain y destino exactos.",
            markup=_main_keyboard(settings),
        )

    @bot.message_handler(commands=["cancel"])
    def cancel(message: types.Message) -> None:
        if register(message) is None:
            return
        sessions.reset(_key(message))
        send(message.chat.id, "Operación cancelada.", markup=_main_keyboard(settings))

    @bot.message_handler(commands=["methods"])
    def methods_command(message: types.Message) -> None:
        if register(message) is None:
            return
        groups: list[str] = []
        for category, label in CATEGORY_LABELS.items():
            items = [
                f"• <code>{spec.key}</code> — {html.escape(spec.label)}"
                for spec in METHODS.values()
                if spec.category == category and storage.method_enabled(spec.key)
            ]
            groups.append(f"<b>{label}</b>\n" + "\n".join(items))
        send(message.chat.id, "\n\n".join(groups))

    @bot.message_handler(commands=["protect"])
    def protect(message: types.Message) -> None:
        command_method(message, "runnable_auto")

    @bot.message_handler(commands=["encode"])
    def encode(message: types.Message) -> None:
        arg = _args(message)
        if arg in METHODS and METHODS[arg].action == "encode":
            command_method(message, arg)
            return
        if register(message) is not None:
            send(
                message.chat.id,
                "<b>Codificación</b>\nSelecciona un método:",
                markup=_method_keyboard(storage, "encoding"),
            )

    @bot.message_handler(commands=["decode"])
    def decode(message: types.Message) -> None:
        arg = _args(message)
        if arg in METHODS and (
            METHODS[arg].action in {"decode", "unwrap"}
        ):
            command_method(message, arg)
            return
        if register(message) is not None:
            markup = _method_keyboard(storage, "encoding")
            if storage.method_enabled("unwrap_auto"):
                markup.add(
                    types.InlineKeyboardButton(
                        "Recuperar wrapper ejecutable",
                        callback_data="method:unwrap_auto",
                    )
                )
            send(
                message.chat.id,
                "<b>Decodificar</b>\nSelecciona una opción:",
                markup=markup,
            )

    @bot.message_handler(commands=["encrypt"])
    def encrypt(message: types.Message) -> None:
        if register(message) is not None:
            send(
                message.chat.id,
                "<b>Cifrado real</b>\nSelecciona un algoritmo:",
                markup=_method_keyboard(storage, "secure"),
            )

    @bot.message_handler(commands=["decrypt"])
    def decrypt(message: types.Message) -> None:
        command_method(message, "secure_decrypt")

    @bot.message_handler(commands=["batch"])
    def batch(message: types.Message) -> None:
        if register(message) is None:
            return
        action = _args(message).lower()
        if action not in {"protect", "unwrap", "recover", "recuperar"}:
            send(
                message.chat.id,
                "<b>Proyectos ZIP</b>\n\n"
                "Usa <code>/batch protect</code> para proteger scripts sin cambiar "
                "sus rutas, o <code>/batch unwrap</code> para recuperarlos.\n\n"
                f"Límite: {settings.max_batch_files} entradas y "
                f"{_human_bytes(settings.max_batch_uncompressed)} descomprimidos.",
            )
            return
        normalized = "unwrap" if action in {"unwrap", "recover", "recuperar"} else "protect"
        sessions.set(_key(message), Session(workflow=f"batch_{normalized}"))
        send(message.chat.id, "Envía ahora el proyecto como archivo ZIP.")

    @bot.message_handler(commands=["hash"])
    def hash_command(message: types.Message) -> None:
        if register(message) is None:
            return
        raw = _args(message)
        first, _, rest = raw.partition(" ")
        algorithm = first.lower() if first.lower() in HASH_ALGORITHMS else "sha256"
        text = rest if first.lower() in HASH_ALGORITHMS else raw
        if text:
            digest = hash_data(text.encode("utf-8"), algorithm)
            send(message.chat.id, f"<b>{algorithm.upper()}</b>\n<code>{digest}</code>")
            record(
                message.from_user.id, "hash", "texto", "success",
                len(text.encode("utf-8")), len(digest),
            )
            return
        sessions.set(
            _key(message),
            Session(workflow="hash", options={"algorithm": algorithm}),
        )
        send(
            message.chat.id,
            "Envía texto o un documento. Algoritmos: md5, sha256, sha512, "
            "sha3_256 y blake2b.",
        )

    @bot.message_handler(commands=["verifyhash"])
    def verifyhash_command(message: types.Message) -> None:
        if register(message) is None:
            return
        expected = _args(message)
        sessions.set(
            _key(message),
            Session(
                workflow="verifyhash",
                awaiting="" if expected else "expected_hash",
                options={"expected": expected},
            ),
        )
        send(
            message.chat.id,
            "Envía el texto o documento a verificar."
            if expected
            else "Envía primero el hash hexadecimal esperado.",
        )

    @bot.message_handler(commands=["keygen"])
    def keygen_command(message: types.Message) -> None:
        if register(message) is None:
            return
        private_key, public_key = generate_ed25519_keypair()
        with _buffer(private_key, "codecipher_ed25519_private.pem") as private_doc:
            bot.send_document(
                message.chat.id,
                private_doc,
                caption="Clave privada Ed25519. Guárdala en secreto.",
                reply_to_message_id=message.message_id,
            )
        with _buffer(public_key, "codecipher_ed25519_public.pem") as public_doc:
            bot.send_document(
                message.chat.id,
                public_doc,
                caption="Clave pública Ed25519 para verificar firmas.",
            )
        record(
            message.from_user.id, "keygen", "", "success", 0,
            len(private_key) + len(public_key),
        )

    @bot.message_handler(commands=["sign"])
    def sign_command(message: types.Message) -> None:
        if register(message) is None:
            return
        sessions.set(_key(message), Session(workflow="sign"))
        send(
            message.chat.id,
            "Envía un ZIP con exactamente una clave privada PEM y un archivo a firmar. "
            "El bot devolverá una firma <code>.sig</code>.",
        )

    @bot.message_handler(commands=["verify"])
    def verify_command(message: types.Message) -> None:
        if register(message) is None:
            return
        sessions.set(_key(message), Session(workflow="verify"))
        send(
            message.chat.id,
            "Envía un ZIP con la clave pública PEM, la firma .sig y el archivo original.",
        )

    @bot.message_handler(commands=["qr"])
    def qr_command(message: types.Message) -> None:
        if register(message) is None:
            return
        text = _args(message)
        if not text:
            sessions.set(_key(message), Session(workflow="qr"))
            send(message.chat.id, "Envía el texto o enlace para crear el QR.")
            return
        _send_qr(bot, message, text)
        record(
            message.from_user.id, "qr", "texto", "success",
            len(text.encode("utf-8")),
        )

    @bot.message_handler(commands=["detect", "analyze"])
    def inspect_command(message: types.Message) -> None:
        if register(message) is None:
            return
        workflow = (message.text or "").split()[0].lstrip("/").split("@")[0]
        sessions.set(_key(message), Session(workflow=workflow))
        send(message.chat.id, "Envía texto o un documento para analizarlo sin ejecutarlo.")

    @bot.message_handler(commands=["history"])
    def history_command(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        if _args(message).lower() in {"clear", "delete", "borrar"}:
            count = storage.clear_history(user_id)
            send(message.chat.id, f"Se borraron {count} registros de tu historial.")
            return
        rows = storage.recent_history(user_id, settings.history_limit)
        if not rows:
            send(message.chat.id, "Todavía no tienes operaciones registradas.")
            return
        text = "\n".join(
            f"• <code>{html.escape(str(row['method']))}</code> · "
            f"{html.escape(str(row['status']))} · "
            f"{html.escape(str(row['filename'] or 'texto'))}"
            for row in rows
        )
        send(message.chat.id, "<b>Historial reciente</b>\n\n" + text)

    @bot.message_handler(commands=["preset"])
    def preset_command(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        parts = _args(message).split()
        action = parts[0].lower() if parts else "list"
        if action in {"save", "guardar"} and len(parts) == 3:
            name, method_key = parts[1], parts[2]
            if method_key not in METHODS:
                send(message.chat.id, "El método indicado no existe.")
                return
            storage.save_preset(user_id, name, method_key)
            send(message.chat.id, f"Preset <code>{html.escape(name)}</code> guardado.")
            return
        if action in {"delete", "borrar"} and len(parts) == 2:
            removed = storage.delete_preset(user_id, parts[1])
            send(message.chat.id, "Preset borrado." if removed else "No se encontró.")
            return
        if action in {"use", "usar"} and len(parts) == 2:
            preset = next(
                (item for item in storage.list_presets(user_id) if item["name"] == parts[1]),
                None,
            )
            if not preset:
                send(message.chat.id, "No se encontró ese preset.")
                return
            command_method(message, str(preset["method_key"]))
            return
        rows = storage.list_presets(user_id)
        listing = "\n".join(
            f"• <code>{html.escape(item['name'])}</code> → "
            f"<code>{html.escape(item['method_key'])}</code>"
            for item in rows
        ) or "No tienes presets."
        send(
            message.chat.id,
            "<b>Presets</b>\n\n"
            + listing
            + "\n\n<code>/preset save NOMBRE METODO</code>\n"
            "<code>/preset use NOMBRE</code>\n"
            "<code>/preset delete NOMBRE</code>",
        )

    @bot.message_handler(commands=["settings"])
    def settings_command(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        send(
            message.chat.id,
            f"<b>Preferencias</b>\n\n"
            f"Idioma: {storage.get_language(user_id)}\n"
            f"Historial: {settings.history_limit} registros\n"
            f"Rol: {_role(settings, user_id)}\n"
            f"Borrado automático: "
            f"{settings.auto_delete_seconds or 'desactivado'}",
        )

    @bot.message_handler(commands=["language"])
    def language_command(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        language = _args(message).lower()
        if language not in {"es", "en"}:
            send(message.chat.id, "Usa <code>/language es</code> o <code>/language en</code>.")
            return
        storage.set_language(user_id, language)
        send(
            message.chat.id,
            "Idioma guardado." if language == "es" else "Language preference saved.",
        )

    @bot.message_handler(commands=["limits"])
    def limits_command(message: types.Message) -> None:
        if register(message) is None:
            return
        send(
            message.chat.id,
            f"<b>Límites públicos</b>\n\n"
            f"Archivo: {_human_bytes(settings.max_file_size)}\n"
            f"Solicitudes: {settings.rate_limit_per_minute}/minuto\n"
            f"ZIP: {settings.max_batch_files} entradas, "
            f"{_human_bytes(settings.max_batch_uncompressed)} descomprimidos\n"
            f"Contraseña: 8–128 caracteres",
        )

    @bot.message_handler(commands=["status"])
    def status_command(message: types.Message) -> None:
        if register(message) is None:
            return
        stats = storage.statistics()
        send(
            message.chat.id,
            f"✅ <b>CodeCipherBot {__version__}</b>\n\n"
            f"Modo: {'mantenimiento' if storage.maintenance_enabled() else 'operativo'}\n"
            f"Métodos activos: {sum(storage.method_enabled(key) for key in METHODS)}\n"
            f"Operaciones hoy: {stats['operations_today']}",
        )

    @bot.message_handler(commands=["privacy"])
    def privacy_command(message: types.Message) -> None:
        if register(message) is None:
            return
        send(
            message.chat.id,
            "<b>Privacidad</b>\n\n"
            "El backend procesa archivos en memoria y no guarda su contenido ni "
            "contraseñas. Solo conserva metadatos: ID de Telegram, método, tamaños, "
            "estado, nombre y fecha. Usa <code>/history clear</code> para borrar tu "
            "historial de operaciones. Telegram conserva los mensajes conforme a sus "
            "propias políticas.",
        )

    @bot.message_handler(commands=["about"])
    def about_command(message: types.Message) -> None:
        if register(message) is None:
            return
        send(
            message.chat.id,
            f"<b>CodeCipherBot {__version__}</b>\n\n"
            "Proyecto de Ghost Developer.\n"
            '<a href="https://t.me/GhostDeveloperSpy">Canal</a> · '
            '<a href="https://github.com/Gh0stDeveloper/CodeCipherBot">GitHub</a>\n\n'
            "La protección ejecutable dificulta una lectura casual, pero no puede "
            "ocultar un secreto frente a quien controla el entorno de ejecución.",
        )

    @bot.message_handler(commands=["panel"])
    def panel_command(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        if not settings.panel_url:
            send(message.chat.id, "El panel web todavía no está configurado.")
            return
        url = settings.panel_url
        if settings.public_api_url:
            separator = "&" if "?" in url else "?"
            url += f"{separator}api={quote(settings.public_api_url, safe='')}"
        if settings.is_admin(user_id):
            code = storage.create_admin_code(user_id)
            url += f"#code={code}"
            storage.audit(user_id, "panel_code_created")
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Abrir panel", url=url))
        send(
            message.chat.id,
            "El acceso desde Telegram usa la identidad de la Mini App. "
            + (
                "El enlace administrativo alternativo caduca en 5 minutos y solo se usa una vez."
                if settings.is_admin(user_id)
                else "Las funciones administrativas solo aparecen para administradores."
            ),
            markup=markup,
        )

    # Administración.
    @bot.message_handler(commands=["admin"])
    def admin_command(message: types.Message) -> None:
        if admin_guard(message) is None:
            return
        send(
            message.chat.id,
            "<b>Administración</b>\n\n"
            "/stats · /users · /logs · /panel\n"
            "/ban ID · /unban ID\n"
            "/broadcast MENSAJE\n"
            "/maintenance on|off [mensaje]\n"
            "/enablemethod CLAVE · /disablemethod CLAVE\n"
            "/health · /exportdata",
        )

    @bot.message_handler(commands=["stats"])
    def stats_command(message: types.Message) -> None:
        if admin_guard(message) is None:
            return
        stats = storage.statistics()
        popular = "\n".join(
            f"• {html.escape(str(item['method']))}: {item['count']}"
            for item in stats["popular_methods"][:5]
        ) or "Sin datos"
        send(
            message.chat.id,
            f"<b>Estadísticas</b>\n\n"
            f"Usuarios: {stats['total_users']}\n"
            f"Activos hoy: {stats['active_today']}\n"
            f"Operaciones: {stats['total_operations']}\n"
            f"Operaciones hoy: {stats['operations_today']}\n"
            f"Fallos hoy: {stats['failed_operations']}\n\n"
            f"<b>Métodos populares</b>\n{popular}",
        )

    @bot.message_handler(commands=["users"])
    def users_command(message: types.Message) -> None:
        if admin_guard(message) is None:
            return
        rows = storage.list_users(30)
        rendered = "\n".join(
            f"• <code>{item['id']}</code> "
            f"{html.escape(str(item['username'] or item['first_name'] or 'sin nombre'))} "
            f"· {item['operations']} ops"
            f"{' · BLOQUEADO' if item['banned'] else ''}"
            for item in rows
        ) or "Sin usuarios."
        send(message.chat.id, "<b>Usuarios recientes</b>\n\n" + rendered)

    @bot.message_handler(commands=["ban", "unban"])
    def ban_command(message: types.Message) -> None:
        actor = admin_guard(message)
        if actor is None:
            return
        try:
            target = int(_args(message))
        except ValueError:
            send(message.chat.id, "Indica un ID numérico.")
            return
        if settings.is_admin(target):
            send(message.chat.id, "No se puede bloquear a un administrador.")
            return
        banned = (message.text or "").split()[0].startswith("/ban")
        storage.set_banned(target, banned)
        storage.audit(actor, "ban_user" if banned else "unban_user", str(target))
        send(message.chat.id, "Usuario bloqueado." if banned else "Usuario desbloqueado.")

    @bot.message_handler(commands=["broadcast"])
    def broadcast_command(message: types.Message) -> None:
        actor = admin_guard(message)
        if actor is None:
            return
        text = _args(message)
        if not 1 <= len(text) <= 3500:
            send(message.chat.id, "Uso: <code>/broadcast MENSAJE</code>")
            return
        result = build_broadcaster(bot, storage)(text, actor)
        storage.audit(actor, "broadcast", details=result)
        send(message.chat.id, f"Difusión en cola para {result['queued']} usuarios.")

    @bot.message_handler(commands=["maintenance"])
    def maintenance_command(message: types.Message) -> None:
        actor = admin_guard(message)
        if actor is None:
            return
        raw = _args(message)
        state, _, detail = raw.partition(" ")
        if state.lower() not in {"on", "off"}:
            send(message.chat.id, "Uso: <code>/maintenance on|off [mensaje]</code>")
            return
        enabled = state.lower() == "on"
        storage.set_maintenance(enabled, detail)
        storage.audit(actor, "maintenance_on" if enabled else "maintenance_off")
        send(message.chat.id, "Mantenimiento activado." if enabled else "Bot reactivado.")

    @bot.message_handler(commands=["enablemethod", "disablemethod"])
    def method_admin_command(message: types.Message) -> None:
        actor = admin_guard(message)
        if actor is None:
            return
        method_key = _args(message)
        if method_key not in METHODS:
            send(message.chat.id, "Método desconocido. Usa /methods.")
            return
        enabled = (message.text or "").split()[0].startswith("/enablemethod")
        storage.set_method_enabled(method_key, enabled)
        storage.audit(
            actor, "enable_method" if enabled else "disable_method", method_key
        )
        send(message.chat.id, "Método activado." if enabled else "Método desactivado.")

    @bot.message_handler(commands=["health"])
    def health_command(message: types.Message) -> None:
        if admin_guard(message) is None:
            return
        send(
            message.chat.id,
            f"✅ <b>Diagnóstico correcto</b>\n\n"
            f"Versión: {__version__}\n"
            f"Base de datos: {_human_bytes(storage.database_size())}\n"
            f"Hilos: {settings.worker_threads}\n"
            f"Modo: {settings.run_mode}\n"
            f"Web: {'activa' if settings.web_enabled else 'inactiva'}",
        )

    @bot.message_handler(commands=["logs"])
    def logs_command(message: types.Message) -> None:
        if admin_guard(message) is None:
            return
        rows = storage.audit_logs(30)
        rendered = "\n".join(
            f"• {html.escape(str(item['created_at']))} · "
            f"<code>{item['actor_id']}</code> · "
            f"{html.escape(str(item['action']))} · "
            f"{html.escape(str(item['target'] or ''))}"
            for item in rows
        ) or "Sin eventos."
        send(message.chat.id, "<b>Auditoría reciente</b>\n\n" + rendered)

    @bot.message_handler(commands=["exportdata"])
    def export_command(message: types.Message) -> None:
        actor = admin_guard(message, owner=True)
        if actor is None:
            return
        payload = {
            "generated_at": time.time(),
            "version": __version__,
            "statistics": storage.statistics(),
            "users": storage.list_users(200, 0),
            "audit_logs": storage.audit_logs(200),
            "method_states": storage.method_states(),
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        with _buffer(content, "codecipher_metadata_export.json") as document:
            bot.send_document(
                message.chat.id,
                document,
                caption="Exportación de metadatos; no contiene archivos ni contraseñas.",
                reply_to_message_id=message.message_id,
            )
        storage.audit(actor, "export_metadata")

    @bot.callback_query_handler(func=lambda call: True)
    def callback(call: types.CallbackQuery) -> None:
        try:
            bot.answer_callback_query(call.id)
        except ApiTelegramException:
            pass
        if call.message is None or call.from_user is None:
            return
        proxy = call.message
        proxy.from_user = call.from_user
        if register(proxy) is None:
            return
        data = call.data or ""
        if data == "menu:main":
            sessions.reset(_key(proxy))
            send(
                proxy.chat.id,
                _welcome(settings, storage),
                markup=_main_keyboard(settings),
            )
            return
        if data.startswith("category:"):
            category = data.split(":", 1)[1]
            if category == "tools":
                send(proxy.chat.id, "<b>Herramientas</b>", markup=_tools_keyboard())
                return
            if category not in CATEGORY_LABELS:
                return
            send(
                proxy.chat.id,
                f"<b>{CATEGORY_LABELS[category]}</b>\nSelecciona un método:",
                markup=_method_keyboard(storage, category),
            )
            return
        if data.startswith("method:"):
            command_method(proxy, data.split(":", 1)[1])
            return
        if data.startswith("tool:"):
            tool = data.split(":", 1)[1]
            if tool == "keygen":
                keygen_command(proxy)
            elif tool == "qr":
                sessions.set(_key(proxy), Session(workflow="qr"))
                send(proxy.chat.id, "Envía el texto o enlace para crear el QR.")
            elif tool in {"hash", "verifyhash", "detect", "analyze", "sign", "verify"}:
                awaiting = "expected_hash" if tool == "verifyhash" else ""
                sessions.set(_key(proxy), Session(workflow=tool, awaiting=awaiting))
                prompts = {
                    "hash": "Envía texto o documento para calcular SHA-256.",
                    "verifyhash": "Envía primero el hash hexadecimal esperado.",
                    "detect": "Envía texto o documento.",
                    "analyze": "Envía código como texto o documento.",
                    "sign": "Envía ZIP con clave privada PEM y archivo.",
                    "verify": "Envía ZIP con clave pública, firma y archivo.",
                }
                send(proxy.chat.id, prompts[tool])
            elif tool in {"batch_protect", "batch_unwrap"}:
                sessions.set(_key(proxy), Session(workflow=tool))
                send(proxy.chat.id, "Envía ahora el proyecto como ZIP.")

    @bot.message_handler(content_types=["document"])
    def document(message: types.Message) -> None:
        user_id = register(message)
        if user_id is None:
            return
        if not limiter.allow(user_id):
            send(message.chat.id, "Límite temporal alcanzado. Espera un minuto.")
            return
        size = message.document.file_size or 0
        if size > settings.max_file_size:
            send(
                message.chat.id,
                f"El archivo supera el límite de {_human_bytes(settings.max_file_size)}.",
            )
            return
        session = sessions.get(_key(message))
        if not session.workflow:
            send(message.chat.id, "Selecciona primero un método o herramienta con /start.")
            return
        if session.awaiting == "password" or (
            session.method_key
            and METHODS[session.method_key].password_required
            and not session.password
        ):
            send(message.chat.id, "Primero envía la contraseña solicitada.")
            return
        try:
            info = bot.get_file(message.document.file_id)
            data = bot.download_file(info.file_path)
        except ApiTelegramException:
            send(message.chat.id, "Telegram no pudo descargar el archivo.")
            return
        if len(data) > settings.max_file_size:
            send(message.chat.id, "El archivo descargado supera el límite.")
            return
        filename = _safe_name(message.document.file_name or "archivo.bin")
        if session.workflow == "method":
            process_method_input(message, session, data, filename, force_document=True)
        else:
            handle_utility(message, session, data, filename)

    @bot.message_handler(content_types=["text"])
    def text(message: types.Message) -> None:
        if (message.text or "").startswith("/"):
            return
        user_id = register(message)
        if user_id is None:
            return
        session = sessions.get(_key(message))
        if not session.workflow:
            send(message.chat.id, "Usa /start para seleccionar una función.")
            return
        if session.awaiting == "password":
            if message.chat.type != "private":
                send(message.chat.id, "Envía contraseñas solo en el chat privado.")
                return
            password = message.text or ""
            try:
                bot.delete_message(message.chat.id, message.message_id)
            except ApiTelegramException:
                LOGGER.info("No se pudo borrar contraseña user_id=%s", user_id)
            if not 8 <= len(password) <= 128:
                send(message.chat.id, "La contraseña debe tener entre 8 y 128 caracteres.")
                return
            sessions.set(
                _key(message),
                replace(session, awaiting="", password=password),
            )
            send(message.chat.id, "Contraseña recibida temporalmente. Envía el archivo.")
            return
        if session.awaiting == "expected_hash":
            expected = (message.text or "").strip()
            try:
                verify_hash(b"", expected)
            except ToolError as exc:
                send(message.chat.id, html.escape(str(exc)))
                return
            sessions.set(
                _key(message),
                replace(
                    session,
                    awaiting="",
                    options={**session.options, "expected": expected},
                ),
            )
            send(message.chat.id, "Hash recibido. Envía ahora el texto o documento.")
            return
        if not limiter.allow(user_id):
            send(message.chat.id, "Límite temporal alcanzado. Espera un minuto.")
            return
        raw = (message.text or "").encode("utf-8")
        if len(raw) > settings.max_file_size:
            send(message.chat.id, "El texto supera el límite configurado.")
            return
        if session.workflow == "qr":
            try:
                _send_qr(bot, message, message.text or "")
                record(user_id, "qr", "texto", "success", len(raw))
            except ToolError as exc:
                send(message.chat.id, html.escape(str(exc)))
        elif session.workflow == "method":
            spec = METHODS.get(session.method_key)
            if spec is None or not spec.text_allowed:
                send(message.chat.id, "Este método requiere un documento.")
                return
            process_method_input(
                message, session, raw, "entrada.txt", force_document=False
            )
        elif session.workflow in {"sign", "verify"} or session.workflow.startswith("batch_"):
            send(message.chat.id, "Esta herramienta requiere un documento ZIP.")
        else:
            handle_utility(message, session, raw, "texto.txt")

    try:
        bot.set_my_commands(PUBLIC_COMMANDS)
        if settings.all_admin_ids:
            scope_type = getattr(types, "BotCommandScopeChat", None)
            if scope_type is not None:
                for admin_id in settings.all_admin_ids:
                    bot.set_my_commands(
                        PUBLIC_COMMANDS + ADMIN_COMMANDS,
                        scope=scope_type(admin_id),
                    )
    except ApiTelegramException as exc:
        LOGGER.warning("No se pudo registrar el menú de comandos: %s", exc)

    return bot


def _zip_entries(payload: bytes) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload), "r")
    except zipfile.BadZipFile as exc:
        raise ToolError("El documento no es un ZIP válido.") from exc
    result: dict[str, bytes] = {}
    with archive:
        if len(archive.infolist()) > 10:
            raise ToolError("El ZIP de firma puede contener como máximo 10 entradas.")
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = _safe_name(info.filename)
            if info.file_size > 20 * 1024 * 1024:
                raise ToolError("Una entrada del ZIP supera el límite.")
            result[name] = archive.read(info)
    return result


def _handle_sign(
    bot: telebot.TeleBot,
    message: types.Message,
    payload: bytes,
    filename: str,
) -> int:
    entries = _zip_entries(payload)
    private = [
        (name, data)
        for name, data in entries.items()
        if b"PRIVATE KEY" in data[:300]
    ]
    files = [
        (name, data)
        for name, data in entries.items()
        if b"PRIVATE KEY" not in data[:300]
    ]
    if len(private) != 1 or len(files) != 1:
        raise ToolError("Incluye exactamente una clave privada PEM y un archivo.")
    name, data = files[0]
    signature = sign_ed25519(data, private[0][1])
    with _buffer(signature, f"{name}.sig") as document:
        bot.send_document(
            message.chat.id,
            document,
            caption="Firma Ed25519 generada.",
            reply_to_message_id=message.message_id,
        )
    return len(signature)


def _handle_verify(
    bot: telebot.TeleBot,
    message: types.Message,
    payload: bytes,
) -> int:
    entries = _zip_entries(payload)
    public = [
        data for data in entries.values()
        if b"PUBLIC KEY" in data[:300] and b"PRIVATE KEY" not in data[:300]
    ]
    signatures = [data for name, data in entries.items() if name.endswith(".sig")]
    files = [
        data
        for name, data in entries.items()
        if not name.endswith(".sig") and b"PUBLIC KEY" not in data[:300]
    ]
    if len(public) != 1 or len(signatures) != 1 or len(files) != 1:
        raise ToolError(
            "Incluye exactamente una clave pública, una firma .sig y un archivo."
        )
    valid = verify_ed25519(files[0], signatures[0], public[0])
    bot.send_message(
        message.chat.id,
        "✅ <b>Firma válida.</b>" if valid else "❌ <b>Firma no válida.</b>",
        reply_to_message_id=message.message_id,
    )
    return 1


def _send_qr(
    bot: telebot.TeleBot,
    message: types.Message,
    text: str,
) -> None:
    content = qr_svg(text)
    with _buffer(content, "codigo_qr.svg") as document:
        bot.send_document(
            message.chat.id,
            document,
            caption="QR generado en SVG.",
            reply_to_message_id=message.message_id,
        )
