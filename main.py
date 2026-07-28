#!/usr/bin/env python3
"""CodeCipherBot: bot de codificación y cifrado seguro de archivos."""

from __future__ import annotations

import html
import io
import logging
import os
import re
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from typing import Callable

import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException

from config import ConfigError, Settings
from encryption_methods import (
    TransformError,
    codificar_script_marshall,
    decode_text_base64,
    decrypt_base64,
    decrypt_base64_zlib,
    decrypt_emoji,
    decrypt_file,
    decrypt_js_base64,
    decrypt_php_base64,
    decrypt_vip,
    encode_text_base64,
    encrypt_base64,
    encrypt_base64_zlib,
    encrypt_emoji,
    encrypt_file,
    encrypt_js_base64,
    encrypt_php_base64,
    vip_encoding,
)


LOGGER = logging.getLogger("codecipherbot")
SessionKey = tuple[int, int]
TextTransform = Callable[[str], str]


@dataclass(frozen=True)
class MethodSpec:
    key: str
    label: str
    category: str
    description: str
    transform: TextTransform | None = None
    default_extension: str = ".txt"
    result_prefix: str = "resultado_"
    requires_password: bool = False
    document_only: bool = False
    secure_action: str | None = None


METHODS: dict[str, MethodSpec] = {
    "py_b64_enc": MethodSpec(
        "py_b64_enc", "Codificar Base64", "python",
        "Genera un script Python autocargable en Base64.",
        encrypt_base64, ".py", "enc_",
    ),
    "py_b64_dec": MethodSpec(
        "py_b64_dec", "Decodificar Base64", "python",
        "Extrae la carga Base64 sin ejecutar el script.",
        decrypt_base64, ".py", "dec_",
    ),
    "py_zlib_enc": MethodSpec(
        "py_zlib_enc", "Codificar Base64 + Zlib", "python",
        "Comprime y codifica un script Python.",
        encrypt_base64_zlib, ".py", "enc_",
    ),
    "py_zlib_dec": MethodSpec(
        "py_zlib_dec", "Decodificar Base64 + Zlib", "python",
        "Descomprime de forma limitada y sin ejecutar código.",
        decrypt_base64_zlib, ".py", "dec_",
    ),
    "py_emoji_enc": MethodSpec(
        "py_emoji_enc", "Codificar Emoji", "python",
        "Representa el contenido UTF-8 con un alfabeto de emojis.",
        encrypt_emoji, ".py", "enc_",
    ),
    "py_emoji_dec": MethodSpec(
        "py_emoji_dec", "Decodificar Emoji", "python",
        "Recupera la carga Emoji mediante análisis estático.",
        decrypt_emoji, ".py", "dec_",
    ),
    "py_marshal_enc": MethodSpec(
        "py_marshal_enc", "Codificar Marshal", "python",
        "Compila con Marshal; requiere la misma versión de Python al ejecutarse.",
        codificar_script_marshall, ".py", "enc_",
    ),
    "py_vip_enc": MethodSpec(
        "py_vip_enc", "Ofuscación multicapa", "python",
        "Tres capas Base85 + Zlib. Es ofuscación reversible, no cifrado secreto.",
        vip_encoding, ".py", "enc_",
    ),
    "py_vip_dec": MethodSpec(
        "py_vip_dec", "Quitar multicapa", "python",
        "Recupera la ofuscación multicapa sin ejecutar el archivo.",
        decrypt_vip, ".py", "dec_",
    ),
    "js_b64_enc": MethodSpec(
        "js_b64_enc", "Codificar JavaScript", "javascript",
        "Genera un cargador Base64 compatible con JavaScript moderno.",
        encrypt_js_base64, ".js", "enc_",
    ),
    "js_b64_dec": MethodSpec(
        "js_b64_dec", "Decodificar JavaScript", "javascript",
        "Extrae el JavaScript en Base64 sin evaluarlo.",
        decrypt_js_base64, ".js", "dec_",
    ),
    "php_b64_enc": MethodSpec(
        "php_b64_enc", "Codificar PHP", "php",
        "Genera un archivo PHP autocargable en Base64.",
        encrypt_php_base64, ".php", "enc_",
    ),
    "php_b64_dec": MethodSpec(
        "php_b64_dec", "Decodificar PHP", "php",
        "Extrae el PHP en Base64 sin ejecutarlo.",
        decrypt_php_base64, ".php", "dec_",
    ),
    "text_b64_enc": MethodSpec(
        "text_b64_enc", "Codificar texto", "text",
        "Convierte texto UTF-8 a Base64.",
        encode_text_base64, ".txt", "enc_",
    ),
    "text_b64_dec": MethodSpec(
        "text_b64_dec", "Decodificar texto", "text",
        "Convierte Base64 válido a texto UTF-8.",
        decode_text_base64, ".txt", "dec_",
    ),
    "secure_encrypt": MethodSpec(
        "secure_encrypt", "Cifrar archivo", "secure",
        "AES-256-GCM con contraseña, salt aleatorio y autenticación.",
        default_extension=".gcb", result_prefix="",
        requires_password=True, document_only=True, secure_action="encrypt",
    ),
    "secure_decrypt": MethodSpec(
        "secure_decrypt", "Descifrar archivo .gcb", "secure",
        "Verifica integridad y recupera el nombre original.",
        default_extension=".bin", result_prefix="",
        requires_password=True, document_only=True, secure_action="decrypt",
    ),
}

CATEGORY_TITLES = {
    "python": "Python",
    "javascript": "JavaScript",
    "php": "PHP",
    "text": "Texto",
    "secure": "Cifrado seguro",
}


@dataclass(frozen=True)
class Session:
    category: str | None = None
    method_key: str | None = None
    awaiting_password: bool = False
    password: str | None = None
    updated_at: float = 0.0


class SessionStore:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._ttl_seconds = ttl_seconds
        self._items: dict[SessionKey, Session] = {}
        self._lock = threading.RLock()

    def get(self, key: SessionKey) -> Session:
        now = time.monotonic()
        with self._lock:
            current = self._items.get(key)
            if current is None or now - current.updated_at > self._ttl_seconds:
                current = Session(updated_at=now)
                self._items[key] = current
            return current

    def set(self, key: SessionKey, session: Session) -> Session:
        current = replace(session, updated_at=time.monotonic())
        with self._lock:
            self._items[key] = current
        return current

    def reset(self, key: SessionKey) -> None:
        with self._lock:
            self._items.pop(key, None)


class RateLimiter:
    def __init__(self, maximum: int, window_seconds: int = 60) -> None:
        self._maximum = maximum
        self._window = window_seconds
        self._events: dict[int, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, user_id: int) -> bool:
        now = time.monotonic()
        with self._lock:
            events = self._events[user_id]
            while events and now - events[0] >= self._window:
                events.popleft()
            if len(events) >= self._maximum:
                return False
            events.append(now)
            return True


def _session_key(chat_id: int, user_id: int) -> SessionKey:
    return chat_id, user_id


def _safe_filename(filename: str, fallback: str = "archivo.txt") -> str:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", name)
    if not name or name in {".", ".."}:
        name = fallback
    root, extension = os.path.splitext(name)
    if len(name) > 180:
        name = root[: max(1, 180 - len(extension))] + extension[:20]
    return name


def _output_filename(original: str, spec: MethodSpec) -> str:
    safe = _safe_filename(original, f"entrada{spec.default_extension}")
    root, extension = os.path.splitext(safe)
    extension = extension or spec.default_extension
    return _safe_filename(f"{spec.result_prefix}{root}{extension}")


def _document_buffer(content: bytes, filename: str) -> io.BytesIO:
    buffer = io.BytesIO(content)
    buffer.name = _safe_filename(filename)
    return buffer


def _main_keyboard() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton("Python", callback_data="menu:python"),
        types.InlineKeyboardButton("JavaScript", callback_data="menu:javascript"),
    )
    markup.row(
        types.InlineKeyboardButton("PHP", callback_data="menu:php"),
        types.InlineKeyboardButton("Texto", callback_data="menu:text"),
    )
    markup.row(types.InlineKeyboardButton("Cifrado seguro", callback_data="menu:secure"))
    return markup


def _category_keyboard(category: str) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=1)
    for spec in METHODS.values():
        if spec.category == category:
            markup.add(types.InlineKeyboardButton(spec.label, callback_data=f"method:{spec.key}"))
    markup.add(types.InlineKeyboardButton("Volver", callback_data="menu:main"))
    return markup


def _welcome_text() -> str:
    return (
        "<b>CodeCipherBot</b>\n\n"
        "Codifica, decodifica y cifra archivos sin ejecutar el contenido recibido.\n\n"
        "• Python: Base64, Zlib, Emoji, Marshal y multicapa\n"
        "• JavaScript y PHP: Base64\n"
        "• Texto: Base64 UTF-8\n"
        "• Archivos: AES-256-GCM con contraseña\n\n"
        "<a href=\"https://t.me/GhostDeveloperSpy\">Canal</a> · "
        "<a href=\"https://t.me/Gh0stDeveloper\">Ghost Developer</a> · "
        "<a href=\"https://github.com/CHICO-CP\">GitHub</a>\n\n"
        "Selecciona una categoría:"
    )


def create_bot(settings: Settings) -> telebot.TeleBot:
    bot = telebot.TeleBot(
        settings.bot_token,
        parse_mode="HTML",
        threaded=True,
        num_threads=settings.worker_threads,
    )
    sessions = SessionStore()
    limiter = RateLimiter(settings.rate_limit_per_minute)

    def is_allowed(user_id: int) -> bool:
        return not settings.allowed_user_ids or user_id in settings.allowed_user_ids

    def reject_message(message: types.Message) -> bool:
        if is_allowed(message.from_user.id):
            return False
        bot.reply_to(message, "Este bot es privado y tu cuenta no está autorizada.")
        return True

    def edit_or_send(
        message: types.Message,
        text: str,
        markup: types.InlineKeyboardMarkup,
    ) -> None:
        try:
            bot.edit_message_text(
                text,
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=markup,
                disable_web_page_preview=True,
            )
        except ApiTelegramException as exc:
            if "message is not modified" not in str(exc).lower():
                bot.send_message(
                    message.chat.id,
                    text,
                    reply_markup=markup,
                    disable_web_page_preview=True,
                )

    def send_text_result(chat_id: int, result: str, spec: MethodSpec) -> None:
        escaped = html.escape(result)
        if len(escaped) <= 3200:
            bot.send_message(chat_id, f"<b>Resultado</b>\n\n<pre>{escaped}</pre>")
            return
        filename = f"resultado_{spec.key}{spec.default_extension}"
        with _document_buffer(result.encode("utf-8"), filename) as document:
            bot.send_document(chat_id, document, caption="Resultado generado correctamente.")

    def run_text_transform(
        chat_id: int,
        user_id: int,
        text: str,
        spec: MethodSpec,
    ) -> None:
        if len(text.encode("utf-8")) > settings.max_file_size:
            bot.send_message(chat_id, "El texto supera el límite configurado.")
            return
        if spec.transform is None:
            bot.send_message(chat_id, "Este método solo acepta documentos.")
            return
        try:
            result = spec.transform(text)
            send_text_result(chat_id, result, spec)
        except TransformError as exc:
            bot.send_message(chat_id, f"<b>No se pudo procesar:</b> {html.escape(str(exc))}")
        except Exception:
            LOGGER.exception("Fallo transformando texto user_id=%s method=%s", user_id, spec.key)
            bot.send_message(chat_id, "Ocurrió un error interno al procesar el texto.")

    @bot.message_handler(commands=["start", "help"])
    def start(message: types.Message) -> None:
        if reject_message(message):
            return
        key = _session_key(message.chat.id, message.from_user.id)
        sessions.reset(key)
        bot.send_message(
            message.chat.id,
            _welcome_text(),
            reply_markup=_main_keyboard(),
            reply_to_message_id=message.message_id,
            disable_web_page_preview=True,
        )

    @bot.message_handler(commands=["cancel"])
    def cancel(message: types.Message) -> None:
        if reject_message(message):
            return
        sessions.reset(_session_key(message.chat.id, message.from_user.id))
        bot.send_message(
            message.chat.id,
            "Operación cancelada. Selecciona una categoría:",
            reply_markup=_main_keyboard(),
        )

    @bot.callback_query_handler(func=lambda call: True)
    def callbacks(call: types.CallbackQuery) -> None:
        try:
            bot.answer_callback_query(call.id)
        except ApiTelegramException:
            pass

        if not is_allowed(call.from_user.id):
            bot.send_message(call.message.chat.id, "Tu cuenta no está autorizada.")
            return

        key = _session_key(call.message.chat.id, call.from_user.id)
        data = call.data or ""

        if data == "menu:main":
            sessions.reset(key)
            edit_or_send(call.message, _welcome_text(), _main_keyboard())
            return

        if data.startswith("menu:"):
            category = data.split(":", 1)[1]
            title = CATEGORY_TITLES.get(category)
            if title is None:
                bot.send_message(call.message.chat.id, "Opción no válida.")
                return
            sessions.set(key, Session(category=category))
            edit_or_send(
                call.message,
                f"<b>{html.escape(title)}</b>\n\nSelecciona un método:",
                _category_keyboard(category),
            )
            return

        if not data.startswith("method:"):
            bot.send_message(call.message.chat.id, "Opción no válida.")
            return

        method_key = data.split(":", 1)[1]
        spec = METHODS.get(method_key)
        if spec is None:
            bot.send_message(call.message.chat.id, "Método no disponible.")
            return

        if spec.requires_password and call.message.chat.type != "private":
            bot.send_message(
                call.message.chat.id,
                "Por seguridad, usa el cifrado con contraseña en un chat privado con el bot.",
            )
            return

        session = Session(
            category=spec.category,
            method_key=spec.key,
            awaiting_password=spec.requires_password,
        )
        sessions.set(key, session)
        if spec.requires_password:
            prompt = (
                f"<b>{html.escape(spec.label)}</b>\n\n"
                "Envía una contraseña de 8 a 128 caracteres. Intentaré borrar ese mensaje "
                "inmediatamente. Después podrás enviar el documento.\n\n"
                "Usa /cancel para salir."
            )
        else:
            prompt = (
                f"<b>{html.escape(spec.label)}</b>\n\n"
                f"{html.escape(spec.description)}\n\n"
                "Envía un documento o pega el texto. Usa /cancel para salir."
            )
        bot.send_message(call.message.chat.id, prompt)

    @bot.message_handler(content_types=["document"])
    def handle_document(message: types.Message) -> None:
        if reject_message(message):
            return
        user_id = message.from_user.id
        if not limiter.allow(user_id):
            bot.reply_to(message, "Has enviado demasiadas solicitudes. Espera un minuto.")
            return

        key = _session_key(message.chat.id, user_id)
        session = sessions.get(key)
        spec = METHODS.get(session.method_key or "")
        if spec is None:
            bot.reply_to(message, "Selecciona primero un método con /start.")
            return
        if spec.requires_password and (session.awaiting_password or not session.password):
            bot.reply_to(message, "Primero envía la contraseña solicitada.")
            return

        size = message.document.file_size or 0
        if size > settings.max_file_size:
            limit_mb = settings.max_file_size // (1024 * 1024)
            bot.reply_to(message, f"El archivo supera el límite de {limit_mb} MB.")
            return

        original_name = _safe_filename(message.document.file_name or "archivo.txt")
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded = bot.download_file(file_info.file_path)
            if len(downloaded) > settings.max_file_size:
                raise TransformError("El archivo descargado supera el límite configurado.")

            if spec.secure_action == "encrypt":
                output = encrypt_file(downloaded, session.password or "", original_name)
                output_name = f"{original_name}.gcb"
                caption = "Archivo cifrado con AES-256-GCM."
            elif spec.secure_action == "decrypt":
                decrypted = decrypt_file(downloaded, session.password or "")
                output = decrypted.content
                output_name = _safe_filename(decrypted.filename, "archivo_descifrado.bin")
                caption = "Archivo descifrado e integridad verificada."
            else:
                try:
                    source = downloaded.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise TransformError("El documento debe contener texto UTF-8.") from exc
                if spec.transform is None:
                    raise TransformError("El método seleccionado no admite este documento.")
                output = spec.transform(source).encode("utf-8")
                output_name = _output_filename(original_name, spec)
                caption = f"{spec.label} completado."

            with _document_buffer(output, output_name) as document:
                bot.send_document(
                    message.chat.id,
                    document,
                    caption=caption,
                    reply_to_message_id=message.message_id,
                )
        except TransformError as exc:
            bot.reply_to(message, f"<b>No se pudo procesar:</b> {html.escape(str(exc))}")
        except ApiTelegramException as exc:
            LOGGER.warning(
                "Telegram rechazó una operación user_id=%s method=%s error=%s",
                user_id,
                spec.key,
                exc,
            )
            bot.reply_to(message, "Telegram no pudo descargar o enviar el archivo.")
        except Exception:
            LOGGER.exception("Fallo procesando documento user_id=%s method=%s", user_id, spec.key)
            bot.reply_to(message, "Ocurrió un error interno al procesar el archivo.")
        finally:
            if spec.requires_password:
                sessions.set(
                    key,
                    Session(
                        category=spec.category,
                        method_key=spec.key,
                        awaiting_password=True,
                    ),
                )

    @bot.message_handler(content_types=["text"])
    def handle_text(message: types.Message) -> None:
        if reject_message(message):
            return
        if message.text.startswith("/"):
            return

        user_id = message.from_user.id
        key = _session_key(message.chat.id, user_id)
        session = sessions.get(key)
        spec = METHODS.get(session.method_key or "")
        if spec is None:
            bot.reply_to(message, "Selecciona primero un método con /start.")
            return

        if session.awaiting_password:
            if message.chat.type != "private":
                bot.reply_to(message, "Configura la contraseña en un chat privado.")
                return
            password = message.text
            try:
                bot.delete_message(message.chat.id, message.message_id)
            except ApiTelegramException:
                LOGGER.info("No fue posible borrar un mensaje de contraseña user_id=%s", user_id)
            if not 8 <= len(password) <= 128:
                bot.send_message(message.chat.id, "La contraseña debe tener entre 8 y 128 caracteres.")
                return
            sessions.set(
                key,
                replace(session, awaiting_password=False, password=password),
            )
            bot.send_message(
                message.chat.id,
                "Contraseña recibida temporalmente. Ahora envía el documento; "
                "se descartará después de un intento.",
            )
            return

        if spec.document_only:
            bot.reply_to(message, "Este método requiere que envíes un documento.")
            return
        if not limiter.allow(user_id):
            bot.reply_to(message, "Has enviado demasiadas solicitudes. Espera un minuto.")
            return
        run_text_transform(message.chat.id, user_id, message.text, spec)

    return bot


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    bot = create_bot(settings)
    LOGGER.info("CodeCipherBot iniciado")
    try:
        bot.infinity_polling(
            skip_pending=True,
            timeout=20,
            long_polling_timeout=20,
            allowed_updates=["message", "callback_query"],
        )
    except KeyboardInterrupt:
        LOGGER.info("Bot detenido por el usuario")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
