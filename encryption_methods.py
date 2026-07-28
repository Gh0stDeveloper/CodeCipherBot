"""Transformaciones reversibles usadas por CodeCipherBot.

Los decodificadores de este módulo analizan el contenido de forma estática:
nunca ejecutan el archivo enviado por el usuario.
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import marshal
import os
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable

from Crypto.Cipher import AES


MAX_DECODED_BYTES = 8 * 1024 * 1024
AES_MAGIC = b"GCB2"
AES_SALT_SIZE = 16
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16
PBKDF2_ITERATIONS = 240_000

EMOJI_ALPHABET = (
    "😀", "😃", "😄", "😁",
    "😆", "😅", "😂", "🙂",
    "🙃", "😉", "😊", "😎",
    "🤓", "🧐", "🤖", "👻",
)

HEADER = """# Protegido con CodeCipherBot
# Desarrollado por Ghost Developer
# https://t.me/GhostDeveloperSpy
"""


class TransformError(ValueError):
    """Error controlado y apto para mostrar al usuario."""


@dataclass(frozen=True)
class DecryptedFile:
    filename: str
    content: bytes


def _chunk(value: str, size: int = 96) -> str:
    return "\n".join(value[index:index + size] for index in range(0, len(value), size))


def _unique_longest(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in sorted(values, key=len, reverse=True):
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _string_candidates(text: str) -> list[str]:
    """Extrae cadenas sin evaluar ni importar el script recibido."""

    candidates = [text.strip()]

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                candidates.append(node.value)

    quoted_patterns = (
        r"'''(.*?)'''",
        r'"""(.*?)"""',
        r"(?:const|let|var)\s+\w+\s*=\s*['\"]([^'\"]+)['\"]",
        r"\$\w+\s*=\s*['\"]([^'\"]+)['\"]",
    )
    for pattern in quoted_patterns:
        candidates.extend(re.findall(pattern, text, flags=re.DOTALL))

    candidates.extend(
        re.findall(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])", text)
    )
    return _unique_longest(candidates)


def _bytes_candidates(text: str) -> list[bytes]:
    candidates: list[bytes] = []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, bytes):
                    candidates.append(node.value)
                elif isinstance(node.value, str):
                    candidates.append(node.value.encode("ascii", errors="ignore"))

    return sorted({item for item in candidates if item}, key=len, reverse=True)


def _decode_base64_bytes(value: str) -> bytes:
    normalized = "".join(value.split())
    if not normalized:
        raise TransformError("No se encontró contenido Base64.")
    normalized += "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransformError("El contenido Base64 no es válido.") from exc
    if len(decoded) > MAX_DECODED_BYTES:
        raise TransformError("El resultado supera el límite permitido.")
    return decoded


def _decode_base64_text(value: str) -> str:
    decoded = _decode_base64_bytes(value)
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError("El resultado no es texto UTF-8.") from exc


def _find_decodable(
    text: str,
    decoder: Callable[[str], str],
    error_message: str,
) -> str:
    for candidate in _string_candidates(text):
        try:
            return decoder(candidate)
        except (TransformError, ValueError, binascii.Error, zlib.error, UnicodeDecodeError):
            continue
    raise TransformError(error_message)


def _safe_zlib_decompress(data: bytes) -> bytes:
    try:
        decompressor = zlib.decompressobj()
        output = decompressor.decompress(data, MAX_DECODED_BYTES + 1)
        if len(output) > MAX_DECODED_BYTES or decompressor.unconsumed_tail:
            raise TransformError("El contenido descomprimido supera el límite permitido.")
        remaining = MAX_DECODED_BYTES + 1 - len(output)
        if remaining > 0:
            output += decompressor.flush(remaining)
        if len(output) > MAX_DECODED_BYTES:
            raise TransformError("El contenido descomprimido supera el límite permitido.")
        if not decompressor.eof:
            raise TransformError("El flujo Zlib está incompleto o dañado.")
        return output
    except zlib.error as exc:
        raise TransformError("El contenido Zlib no es válido.") from exc


# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------


def encode_text_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_text_base64(text: str) -> str:
    return _decode_base64_text(text)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def encrypt_base64(text: str) -> str:
    payload = encode_text_base64(text)
    return (
        f"{HEADER}\n"
        "import base64 as _b64\n\n"
        f"_PAYLOAD = {payload!r}\n"
        "exec(compile(_b64.b64decode(_PAYLOAD).decode('utf-8'), "
        "'<CodeCipherBot>', 'exec'))\n"
    )


def decrypt_base64(text: str) -> str:
    return _find_decodable(
        text,
        _decode_base64_text,
        "No se encontró una carga Base64 válida. El archivo no fue ejecutado.",
    )


def encrypt_base64_zlib(text: str) -> str:
    compressed = zlib.compress(text.encode("utf-8"), level=9)
    payload = base64.b64encode(compressed).decode("ascii")
    return (
        f"{HEADER}\n"
        "import base64 as _b64\n"
        "import zlib as _zlib\n\n"
        f"_PAYLOAD = {payload!r}\n"
        "exec(compile(_zlib.decompress(_b64.b64decode(_PAYLOAD)).decode('utf-8'), "
        "'<CodeCipherBot>', 'exec'))\n"
    )


def _decode_zlib_candidate(value: str) -> str:
    result = _safe_zlib_decompress(_decode_base64_bytes(value))
    try:
        return result.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError("El resultado Zlib no es texto UTF-8.") from exc


def decrypt_base64_zlib(text: str) -> str:
    return _find_decodable(
        text,
        _decode_zlib_candidate,
        "No se encontró una carga Base64 + Zlib válida. El archivo no fue ejecutado.",
    )


def encrypt_emoji(text: str) -> str:
    hexadecimal = text.encode("utf-8").hex()
    payload = "".join(EMOJI_ALPHABET[int(character, 16)] for character in hexadecimal)
    alphabet_repr = repr(EMOJI_ALPHABET)
    return (
        f"{HEADER}\n"
        f"_ALPHABET = {alphabet_repr}\n"
        "# GHOST_EMOJI_PAYLOAD_BEGIN\n"
        f"_PAYLOAD = '''{_chunk(payload)}'''\n"
        "# GHOST_EMOJI_PAYLOAD_END\n"
        "_HEX = ''.join(format(_ALPHABET.index(char), 'x') "
        "for char in _PAYLOAD if char in _ALPHABET)\n"
        "exec(compile(bytes.fromhex(_HEX).decode('utf-8'), "
        "'<CodeCipherBot>', 'exec'))\n"
    )


def decrypt_emoji(text: str) -> str:
    alphabet = set(EMOJI_ALPHABET)
    for candidate in _string_candidates(text):
        symbols = [character for character in candidate if not character.isspace()]
        if not symbols or any(character not in alphabet for character in symbols):
            continue
        if len(symbols) % 2:
            continue
        hexadecimal = "".join(format(EMOJI_ALPHABET.index(character), "x") for character in symbols)
        try:
            decoded = bytes.fromhex(hexadecimal)
            if len(decoded) > MAX_DECODED_BYTES:
                raise TransformError("El resultado supera el límite permitido.")
            return decoded.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
    raise TransformError("No se encontró una carga Emoji válida. El archivo no fue ejecutado.")


def codificar_script_marshall(script_content: str) -> str:
    try:
        compiled = compile(script_content, "<CodeCipherBot>", "exec")
    except (SyntaxError, ValueError) as exc:
        raise TransformError(f"El código Python no compila: {exc}") from exc

    payload = base64.b64encode(marshal.dumps(compiled)).decode("ascii")
    return (
        f"{HEADER}\n"
        "# Marshal depende de la misma versión principal/secundaria de Python.\n"
        "import base64 as _b64\n"
        "import marshal as _marshal\n\n"
        f"_PAYLOAD = {payload!r}\n"
        "exec(_marshal.loads(_b64.b64decode(_PAYLOAD)))\n"
    )


def vip_encoding(text: str) -> str:
    """Ofuscación multicapa reversible; no se presenta como cifrado secreto."""

    data = text.encode("utf-8")
    for _ in range(3):
        data = base64.b85encode(zlib.compress(data, level=9))
    return (
        f"{HEADER}\n"
        "# Ofuscación multicapa reversible; las claves no son necesarias.\n"
        "import base64 as _b64\n"
        "import zlib as _zlib\n\n"
        f"_PAYLOAD = {data!r}\n"
        "for _ in range(3):\n"
        "    _PAYLOAD = _zlib.decompress(_b64.b85decode(_PAYLOAD))\n"
        "exec(compile(_PAYLOAD.decode('utf-8'), '<CodeCipherBot>', 'exec'))\n"
    )


def decrypt_vip(text: str) -> str:
    for candidate in _bytes_candidates(text):
        data = candidate
        try:
            for _ in range(3):
                data = _safe_zlib_decompress(base64.b85decode(data))
            return data.decode("utf-8")
        except (TransformError, ValueError, binascii.Error, UnicodeDecodeError):
            continue
    raise TransformError("No se encontró una carga multicapa válida. El archivo no fue ejecutado.")


# ---------------------------------------------------------------------------
# JavaScript y PHP
# ---------------------------------------------------------------------------


def encrypt_js_base64(text: str) -> str:
    payload = encode_text_base64(text)
    return (
        "// Protegido con CodeCipherBot\n"
        f"const _payload = {payload!r};\n"
        "const _bytes = Uint8Array.from(atob(_payload), c => c.charCodeAt(0));\n"
        "(0, eval)(new TextDecoder().decode(_bytes));\n"
    )


def decrypt_js_base64(text: str) -> str:
    return decrypt_base64(text)


def encrypt_php_base64(text: str) -> str:
    payload = encode_text_base64(text)
    return (
        "<?php\n"
        "// Protegido con CodeCipherBot\n"
        f"$payload = '{payload}';\n"
        "$source = base64_decode($payload, true);\n"
        "if ($source === false) { throw new RuntimeException('Payload invalido'); }\n"
        "eval('?>' . $source);\n"
        "?>\n"
    )


def decrypt_php_base64(text: str) -> str:
    return decrypt_base64(text)


# Nombres conservados para proyectos antiguos.
encrypt_byte = encrypt_php_base64
decrypt_byte = decrypt_php_base64


# ---------------------------------------------------------------------------
# Cifrado real de archivos: AES-256-GCM + PBKDF2-HMAC-SHA256
# ---------------------------------------------------------------------------


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise TransformError("La contraseña no puede estar vacía.")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def _safe_original_name(filename: str) -> str:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return name or "archivo.bin"


def encrypt_file(data: bytes, password: str, filename: str) -> bytes:
    safe_name = _safe_original_name(filename)
    encoded_name = safe_name.encode("utf-8")
    if len(encoded_name) > 1024:
        raise TransformError("El nombre del archivo es demasiado largo.")

    plaintext = struct.pack(">H", len(encoded_name)) + encoded_name + data
    salt = os.urandom(AES_SALT_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(AES_MAGIC)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return AES_MAGIC + salt + nonce + tag + ciphertext


def decrypt_file(payload: bytes, password: str) -> DecryptedFile:
    minimum = len(AES_MAGIC) + AES_SALT_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + 2
    if len(payload) < minimum or not payload.startswith(AES_MAGIC):
        raise TransformError("El archivo no tiene el formato seguro GCB2.")

    offset = len(AES_MAGIC)
    salt = payload[offset:offset + AES_SALT_SIZE]
    offset += AES_SALT_SIZE
    nonce = payload[offset:offset + AES_NONCE_SIZE]
    offset += AES_NONCE_SIZE
    tag = payload[offset:offset + AES_TAG_SIZE]
    offset += AES_TAG_SIZE
    ciphertext = payload[offset:]

    try:
        cipher = AES.new(_derive_key(password, salt), AES.MODE_GCM, nonce=nonce)
        cipher.update(AES_MAGIC)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise TransformError("Contraseña incorrecta o archivo modificado.") from exc

    if len(plaintext) < 2:
        raise TransformError("El archivo cifrado está dañado.")
    name_length = struct.unpack(">H", plaintext[:2])[0]
    if name_length > 1024 or len(plaintext) < 2 + name_length:
        raise TransformError("Los metadatos del archivo están dañados.")
    try:
        filename = plaintext[2:2 + name_length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError("El nombre interno del archivo está dañado.") from exc
    return DecryptedFile(
        filename=_safe_original_name(filename),
        content=plaintext[2 + name_length:],
    )


def enc_sha_256(text: str, password: str | None = None) -> str:
    """Alias heredado: ahora usa AES-256-GCM en vez de AES-ECB."""

    if password is None:
        raise TransformError("Este método ahora requiere una contraseña.")
    encrypted = encrypt_file(text.encode("utf-8"), password, "script.py")
    return base64.b64encode(encrypted).decode("ascii")


def dec_sha_256(text: str, password: str) -> str:
    try:
        payload = base64.b64decode("".join(text.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransformError("El contenedor AES no es Base64 válido.") from exc
    result = decrypt_file(payload, password)
    try:
        return result.content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError("El contenido descifrado no es texto UTF-8.") from exc


__all__ = [
    "DecryptedFile",
    "TransformError",
    "codificar_script_marshall",
    "dec_sha_256",
    "decode_text_base64",
    "decrypt_base64",
    "decrypt_base64_zlib",
    "decrypt_byte",
    "decrypt_emoji",
    "decrypt_file",
    "decrypt_js_base64",
    "decrypt_php_base64",
    "decrypt_vip",
    "enc_sha_256",
    "encode_text_base64",
    "encrypt_base64",
    "encrypt_base64_zlib",
    "encrypt_byte",
    "encrypt_emoji",
    "encrypt_file",
    "encrypt_js_base64",
    "encrypt_php_base64",
    "vip_encoding",
]
