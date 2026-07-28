"""Codificación, compresión, análisis, hashes, QR y firmas."""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import io
import lzma
import math
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any

import qrcode
import qrcode.image.svg
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


MAX_OUTPUT_BYTES = 30 * 1024 * 1024


class ToolError(ValueError):
    pass


def _bounded(data: bytes, limit: int = MAX_OUTPUT_BYTES) -> bytes:
    if len(data) > limit:
        raise ToolError("El resultado supera el límite de seguridad.")
    return data


def encode_data(method: str, data: bytes) -> bytes:
    if method == "base64_encode":
        return base64.b64encode(data)
    if method == "base32_encode":
        return base64.b32encode(data)
    if method == "base85_encode":
        return base64.b85encode(data)
    if method == "hex_encode":
        return binascii.hexlify(data)
    if method == "url_encode":
        try:
            return urllib.parse.quote(data.decode("utf-8"), safe="").encode("ascii")
        except UnicodeDecodeError as exc:
            raise ToolError("URL encoding requiere texto UTF-8.") from exc
    if method == "gzip_compress":
        return gzip.compress(data, compresslevel=9)
    if method == "bzip2_compress":
        return bz2.compress(data, compresslevel=9)
    if method == "lzma_compress":
        return lzma.compress(data, preset=9)
    raise ToolError("Método de codificación no compatible.")


def _safe_stream_decompress(method: str, data: bytes, limit: int) -> bytes:
    try:
        if method == "gzip_decompress":
            import zlib

            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            result = obj.decompress(data, limit + 1)
            if obj.unconsumed_tail or len(result) > limit:
                raise ToolError("El resultado descomprimido supera el límite.")
            result += obj.flush(max(1, limit + 1 - len(result)))
            if not obj.eof or len(result) > limit:
                raise ToolError("El archivo Gzip está incompleto o supera el límite.")
            return result
        if method == "bzip2_decompress":
            obj = bz2.BZ2Decompressor()
            result = obj.decompress(data, max_length=limit + 1)
            if len(result) > limit or not obj.eof:
                raise ToolError("El archivo Bzip2 está incompleto o supera el límite.")
            return result
        if method == "lzma_decompress":
            obj = lzma.LZMADecompressor()
            result = obj.decompress(data, max_length=limit + 1)
            if len(result) > limit or not obj.eof:
                raise ToolError("El archivo LZMA está incompleto o supera el límite.")
            return result
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ToolError("El archivo comprimido no es válido.") from exc
    raise ToolError("Método de descompresión no compatible.")


def decode_data(method: str, data: bytes, limit: int = MAX_OUTPUT_BYTES) -> bytes:
    compact = b"".join(data.split())
    try:
        if method == "base64_decode":
            return _bounded(base64.b64decode(compact, validate=True), limit)
        if method == "base32_decode":
            return _bounded(base64.b32decode(compact, casefold=True), limit)
        if method == "base85_decode":
            return _bounded(base64.b85decode(compact), limit)
        if method == "hex_decode":
            return _bounded(binascii.unhexlify(compact), limit)
        if method == "url_decode":
            return _bounded(
                urllib.parse.unquote_to_bytes(data.decode("ascii")), limit
            )
        if method.endswith("_decompress"):
            return _safe_stream_decompress(method, data, limit)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ToolError("La entrada no tiene el formato seleccionado.") from exc
    raise ToolError("Método de decodificación no compatible.")


HASH_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "blake2b": hashlib.blake2b,
}


def hash_data(data: bytes, algorithm: str = "sha256") -> str:
    factory = HASH_ALGORITHMS.get(algorithm.lower())
    if not factory:
        raise ToolError("Algoritmo hash no compatible.")
    return factory(data).hexdigest()


def verify_hash(data: bytes, expected: str, algorithm: str | None = None) -> tuple[bool, str, str]:
    normalized = re.sub(r"\s+", "", expected).lower()
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        raise ToolError("El hash esperado no es hexadecimal.")
    if algorithm is None:
        algorithm = {
            32: "md5",
            64: "sha256",
            128: "sha512",
        }.get(len(normalized), "sha256")
    actual = hash_data(data, algorithm)
    import hmac

    return hmac.compare_digest(actual, normalized), algorithm, actual


def qr_svg(text: str) -> bytes:
    if not text or len(text) > 4000:
        raise ToolError("El contenido QR debe tener entre 1 y 4000 caracteres.")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(text)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue()


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    key = ECC.generate(curve="Ed25519")
    private_key = key.export_key(format="PEM", passphrase=None).encode("utf-8")
    public_key = key.public_key().export_key(format="PEM").encode("utf-8")
    return private_key, public_key


def sign_ed25519(data: bytes, private_pem: bytes) -> bytes:
    try:
        key = ECC.import_key(private_pem)
        if not key.has_private():
            raise ToolError("La clave proporcionada no es privada.")
        return eddsa.new(key, mode="rfc8032").sign(data)
    except (ValueError, IndexError, TypeError) as exc:
        raise ToolError("La clave privada Ed25519 no es válida.") from exc


def verify_ed25519(data: bytes, signature: bytes, public_pem: bytes) -> bool:
    try:
        key = ECC.import_key(public_pem)
        eddsa.new(key, mode="rfc8032").verify(data, signature)
        return True
    except (ValueError, IndexError, TypeError):
        return False


def detect_format(data: bytes, filename: str = "") -> dict[str, Any]:
    suffix = PurePath(filename).suffix.lower()
    result: dict[str, Any] = {
        "filename": filename or "sin_nombre",
        "extension": suffix or "ninguna",
        "size": len(data),
        "binary": False,
        "language": None,
        "encoding": None,
    }
    if data.startswith(b"GCB2"):
        result["encoding"] = "CodeCipher AES-256-GCM"
        result["binary"] = True
        return result
    if data.startswith(b"GCB3"):
        result["encoding"] = "CodeCipher ChaCha20-Poly1305"
        result["binary"] = True
        return result
    if data.startswith(b"\x1f\x8b"):
        result["encoding"] = "Gzip"
        result["binary"] = True
        return result
    if data.startswith(b"BZh"):
        result["encoding"] = "Bzip2"
        result["binary"] = True
        return result
    if data.startswith(b"\xfd7zXZ\x00"):
        result["encoding"] = "LZMA/XZ"
        result["binary"] = True
        return result

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        result["binary"] = True
        result["encoding"] = "binario"
        return result

    from .runnable import MARKER_RE, detect_language

    marker = MARKER_RE.search(text)
    if marker:
        result["encoding"] = f"CodeCipher {marker.group(2)}"
        result["language"] = marker.group(1).lower()
    else:
        result["language"] = detect_language(filename, text)
        compact = "".join(text.split())
        try:
            if compact and len(compact) % 4 == 0:
                base64.b64decode(compact, validate=True)
                result["encoding"] = "Base64 probable"
        except (binascii.Error, ValueError):
            pass
    result["lines"] = len(text.splitlines())
    result["characters"] = len(text)
    result["entropy"] = round(_entropy(data), 3)
    return result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def analyze_source(source: str, filename: str) -> dict[str, Any]:
    from .runnable import detect_language

    language = detect_language(filename, source)
    report: dict[str, Any] = {
        "language": language or "desconocido",
        "lines": len(source.splitlines()),
        "characters": len(source),
        "syntax_valid": None,
        "warning_count": 0,
        "warnings": [],
    }
    if language == "python":
        try:
            compile(source, filename or "<input>", "exec")
            report["syntax_valid"] = True
        except SyntaxError as exc:
            report["syntax_valid"] = False
            report["warnings"].append(
                f"Línea {exc.lineno}: {exc.msg}"
            )
    patterns = {
        r"\beval\s*\(": "Uso de eval",
        r"\bexec\s*\(": "Uso de exec",
        r"\bos\.system\s*\(": "Ejecución de comandos del sistema",
        r"\bsubprocess\.": "Creación de procesos",
        r"\bcurl\b|\bwget\b": "Descarga por red",
    }
    for pattern, label in patterns.items():
        if re.search(pattern, source, flags=re.IGNORECASE):
            report["warnings"].append(label)
    report["warning_count"] = len(report["warnings"])
    return report
