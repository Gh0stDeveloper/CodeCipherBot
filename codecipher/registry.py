"""Registro único de métodos y procesador de archivos.

Telegram, la API y el procesamiento por lotes usan este módulo para evitar
comportamientos diferentes según la interfaz.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Callable

from .runnable import LANGUAGE_LABELS, RunnableError, protect_code, unwrap_code
from .security import SecurityError, decrypt_file, encrypt_file
from .tools import ToolError, decode_data, encode_data


class ProcessingError(ValueError):
    """Error controlado que puede mostrarse al usuario."""


@dataclass(frozen=True)
class MethodSpec:
    key: str
    label: str
    category: str
    description: str
    action: str
    text_allowed: bool = True
    password_required: bool = False
    binary_input: bool = False


@dataclass(frozen=True)
class ProcessedFile:
    content: bytes
    filename: str
    caption: str


def _spec(
    key: str,
    label: str,
    category: str,
    description: str,
    action: str,
    *,
    text_allowed: bool = True,
    password_required: bool = False,
    binary_input: bool = False,
) -> MethodSpec:
    return MethodSpec(
        key,
        label,
        category,
        description,
        action,
        text_allowed,
        password_required,
        binary_input,
    )


METHODS: dict[str, MethodSpec] = {
    # Wrappers ejecutables. Son ofuscación reversible, no cifrado secreto.
    "runnable_auto": _spec(
        "runnable_auto",
        "Protección ejecutable automática",
        "runnable",
        "Detecta el lenguaje por extensión y conserva su forma de ejecución.",
        "runnable:auto:base64",
    ),
    "runnable_python": _spec(
        "runnable_python",
        "Python ejecutable · Base64",
        "runnable",
        "Genera un .py autocargable compatible con el mismo intérprete.",
        "runnable:python:base64",
    ),
    "runnable_python_zlib": _spec(
        "runnable_python_zlib",
        "Python ejecutable · Zlib",
        "runnable",
        "Comprime y envuelve el código Python en un cargador ejecutable.",
        "runnable:python:zlib",
    ),
    "runnable_python_marshal": _spec(
        "runnable_python_marshal",
        "Python ejecutable · Marshal",
        "runnable",
        "Bytecode ligado a la versión mayor/menor de Python usada por el bot.",
        "runnable:python:marshal",
    ),
    "runnable_python_emoji": _spec(
        "runnable_python_emoji",
        "Python ejecutable · Emoji",
        "runnable",
        "Representa los bytes UTF-8 con un alfabeto Emoji ejecutable.",
        "runnable:python:emoji",
    ),
    "runnable_python_multilayer": _spec(
        "runnable_python_multilayer",
        "Python ejecutable · Multicapa",
        "runnable",
        "Aplica tres capas Base85 + Zlib en un cargador ejecutable.",
        "runnable:python:multilayer",
    ),
    "runnable_node": _spec(
        "runnable_node",
        "Node.js ejecutable",
        "runnable",
        "Mantiene __filename, require y exports en scripts CommonJS mediante module._compile.",
        "runnable:javascript_node:base64",
    ),
    "runnable_browser": _spec(
        "runnable_browser",
        "JavaScript de navegador",
        "runnable",
        "Crea un cargador JavaScript UTF-8 para navegadores modernos.",
        "runnable:javascript_browser:base64",
    ),
    "runnable_html": _spec(
        "runnable_html",
        "HTML ejecutable",
        "runnable",
        "Genera un documento HTML autocargable y conserva sus recursos relativos.",
        "runnable:html:base64",
    ),
    "runnable_php": _spec(
        "runnable_php",
        "PHP ejecutable",
        "runnable",
        "Genera un .php autocargable conservando el contenido original.",
        "runnable:php:base64",
    ),
    "runnable_bash": _spec(
        "runnable_bash",
        "Bash ejecutable",
        "runnable",
        "Genera un script Bash autocargable compatible con GNU y macOS.",
        "runnable:bash:base64",
    ),
    "runnable_powershell": _spec(
        "runnable_powershell",
        "PowerShell ejecutable",
        "runnable",
        "Carga el script como ScriptBlock y conserva los argumentos.",
        "runnable:powershell:base64",
    ),
    "runnable_ruby": _spec(
        "runnable_ruby",
        "Ruby ejecutable",
        "runnable",
        "Genera un cargador Ruby Base64.",
        "runnable:ruby:base64",
    ),
    "runnable_perl": _spec(
        "runnable_perl",
        "Perl ejecutable",
        "runnable",
        "Genera un cargador Perl con MIME::Base64.",
        "runnable:perl:base64",
    ),
    "runnable_lua": _spec(
        "runnable_lua",
        "Lua ejecutable",
        "runnable",
        "Incluye un decodificador Base64 portable y usa load/loadstring.",
        "runnable:lua:base64",
    ),
    "unwrap_auto": _spec(
        "unwrap_auto",
        "Recuperar wrapper CodeCipher",
        "runnable",
        "Extrae la carga de forma estática; nunca ejecuta el archivo recibido.",
        "unwrap",
    ),
    # Codificaciones.
    "base64_encode": _spec(
        "base64_encode", "Base64 · Codificar", "encoding",
        "Codifica bytes o texto con Base64.", "encode",
    ),
    "base64_decode": _spec(
        "base64_decode", "Base64 · Decodificar", "encoding",
        "Valida y decodifica Base64.", "decode",
    ),
    "base32_encode": _spec(
        "base32_encode", "Base32 · Codificar", "encoding",
        "Codifica bytes o texto con Base32.", "encode",
    ),
    "base32_decode": _spec(
        "base32_decode", "Base32 · Decodificar", "encoding",
        "Valida y decodifica Base32.", "decode",
    ),
    "base85_encode": _spec(
        "base85_encode", "Base85 · Codificar", "encoding",
        "Codifica bytes o texto con Base85.", "encode",
    ),
    "base85_decode": _spec(
        "base85_decode", "Base85 · Decodificar", "encoding",
        "Valida y decodifica Base85.", "decode",
    ),
    "hex_encode": _spec(
        "hex_encode", "Hexadecimal · Codificar", "encoding",
        "Convierte bytes a hexadecimal.", "encode",
    ),
    "hex_decode": _spec(
        "hex_decode", "Hexadecimal · Decodificar", "encoding",
        "Convierte hexadecimal válido a bytes.", "decode",
    ),
    "url_encode": _spec(
        "url_encode", "URL · Codificar", "encoding",
        "Escapa texto UTF-8 para usarlo en una URL.", "encode",
    ),
    "url_decode": _spec(
        "url_decode", "URL · Decodificar", "encoding",
        "Recupera bytes desde URL encoding.", "decode",
    ),
    # Compresión.
    "gzip_compress": _spec(
        "gzip_compress", "Gzip · Comprimir", "compression",
        "Comprime cualquier archivo con Gzip.", "encode", binary_input=True,
    ),
    "gzip_decompress": _spec(
        "gzip_decompress", "Gzip · Descomprimir", "compression",
        "Descomprime Gzip con límite contra bombas de compresión.", "decode",
        binary_input=True,
    ),
    "bzip2_compress": _spec(
        "bzip2_compress", "Bzip2 · Comprimir", "compression",
        "Comprime cualquier archivo con Bzip2.", "encode", binary_input=True,
    ),
    "bzip2_decompress": _spec(
        "bzip2_decompress", "Bzip2 · Descomprimir", "compression",
        "Descomprime Bzip2 con salida limitada.", "decode", binary_input=True,
    ),
    "lzma_compress": _spec(
        "lzma_compress", "LZMA/XZ · Comprimir", "compression",
        "Comprime cualquier archivo con LZMA/XZ.", "encode", binary_input=True,
    ),
    "lzma_decompress": _spec(
        "lzma_decompress", "LZMA/XZ · Descomprimir", "compression",
        "Descomprime LZMA/XZ con salida limitada.", "decode", binary_input=True,
    ),
    # Cifrado real, autenticado y no autoejecutable.
    "aes_gcm_encrypt": _spec(
        "aes_gcm_encrypt", "AES-256-GCM", "secure",
        "Cifra cualquier archivo con contraseña e integridad autenticada.",
        "secure:aes_gcm", text_allowed=False, password_required=True,
        binary_input=True,
    ),
    "chacha20_encrypt": _spec(
        "chacha20_encrypt", "ChaCha20-Poly1305", "secure",
        "Cifra cualquier archivo con contraseña e integridad autenticada.",
        "secure:chacha20", text_allowed=False, password_required=True,
        binary_input=True,
    ),
    "secure_decrypt": _spec(
        "secure_decrypt", "Descifrar .gcb", "secure",
        "Detecta AES-GCM o ChaCha20 y verifica la integridad antes de devolverlo.",
        "secure:decrypt", text_allowed=False, password_required=True,
        binary_input=True,
    ),
}


CATEGORY_LABELS = {
    "runnable": "Protección ejecutable",
    "encoding": "Codificación",
    "compression": "Compresión",
    "secure": "Cifrado real",
}


def public_method_payload(
    enabled: Callable[[str], bool] | None = None,
) -> list[dict[str, object]]:
    check = enabled or (lambda _key: True)
    return [
        {
            "key": item.key,
            "label": item.label,
            "category": item.category,
            "description": item.description,
            "enabled": bool(check(item.key)),
            "password_required": item.password_required,
            "text_allowed": item.text_allowed,
        }
        for item in METHODS.values()
    ]


def _safe_filename(filename: str, fallback: str = "archivo.bin") -> str:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", name)
    if not name or name in {".", ".."}:
        name = fallback
    stem = PurePath(name).stem[:140] or "archivo"
    suffix = PurePath(name).suffix[:20]
    return stem + suffix


def _changed_name(filename: str, method: str) -> str:
    safe = _safe_filename(filename)
    stem = PurePath(safe).stem
    suffix = PurePath(safe).suffix
    if method.endswith("_compress"):
        extension = {
            "gzip_compress": ".gz",
            "bzip2_compress": ".bz2",
            "lzma_compress": ".xz",
        }[method]
        return safe + extension
    if method.endswith("_decompress"):
        expected = {
            "gzip_decompress": ".gz",
            "bzip2_decompress": ".bz2",
            "lzma_decompress": ".xz",
        }[method]
        return safe[:-len(expected)] if safe.lower().endswith(expected) else f"decoded_{stem}{suffix}"
    return f"result_{stem}{suffix or '.txt'}"


def process(
    method_key: str,
    data: bytes,
    filename: str = "entrada.txt",
    *,
    password: str | None = None,
    output_limit: int = 30 * 1024 * 1024,
) -> ProcessedFile:
    spec = METHODS.get(method_key)
    if spec is None:
        raise ProcessingError("Método desconocido.")
    if spec.password_required and password is None:
        raise ProcessingError("Este método requiere una contraseña.")

    try:
        if spec.action.startswith("runnable:"):
            try:
                source = data.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ProcessingError("El código debe ser texto UTF-8.") from exc
            _, language, method = spec.action.split(":", 2)
            result = protect_code(
                source,
                filename,
                None if language == "auto" else language,
                method,
            )
            encoded = result.content.encode("utf-8")
            if len(encoded) > output_limit:
                raise ProcessingError(
                    "El wrapper supera el límite de salida; usa otro método o un archivo menor."
                )
            return ProcessedFile(
                encoded,
                result.filename,
                (
                    f"{LANGUAGE_LABELS[result.language]} protegido. "
                    "Es ofuscación reversible y conserva la ejecución."
                ),
            )

        if spec.action == "unwrap":
            try:
                wrapper = data.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ProcessingError("El wrapper debe ser texto UTF-8.") from exc
            result = unwrap_code(wrapper, filename)
            return ProcessedFile(
                result.content.encode("utf-8"),
                result.filename,
                "Carga recuperada mediante análisis estático; no se ejecutó el archivo.",
            )

        if spec.action == "encode":
            output = encode_data(method_key, data)
            return ProcessedFile(
                output,
                _changed_name(filename, method_key),
                f"{spec.label} completado.",
            )

        if spec.action == "decode":
            output = decode_data(method_key, data, output_limit)
            return ProcessedFile(
                output,
                _changed_name(filename, method_key),
                f"{spec.label} completado.",
            )

        if spec.action.startswith("secure:"):
            mode = spec.action.split(":", 1)[1]
            if mode == "decrypt":
                decrypted = decrypt_file(data, password or "")
                return ProcessedFile(
                    decrypted.content,
                    _safe_filename(decrypted.filename),
                    f"Archivo descifrado e integridad verificada ({decrypted.algorithm}).",
                )
            encrypted = encrypt_file(data, password or "", filename, mode)
            return ProcessedFile(
                encrypted,
                f"{_safe_filename(filename)}.gcb",
                (
                    "Archivo cifrado con "
                    + ("AES-256-GCM." if mode == "aes_gcm" else "ChaCha20-Poly1305.")
                ),
            )
    except (RunnableError, SecurityError, ToolError) as exc:
        raise ProcessingError(str(exc)) from exc

    raise ProcessingError("El método no tiene un procesador configurado.")
