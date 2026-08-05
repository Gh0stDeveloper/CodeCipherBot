"""Cifrado autenticado de archivos CodeCipher."""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from Crypto.Cipher import AES, ChaCha20_Poly1305


AES_MAGIC = b"GCB2"
CHACHA_MAGIC = b"GCB3"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 240_000


class SecurityError(ValueError):
    pass


@dataclass(frozen=True)
class DecryptedFile:
    filename: str
    content: bytes
    algorithm: str


def _key(password: str, salt: bytes) -> bytes:
    if not 8 <= len(password) <= 128:
        raise SecurityError("La contraseña debe tener entre 8 y 128 caracteres.")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def _name(filename: str) -> str:
    return filename.replace("\\", "/").rsplit("/", 1)[-1].strip() or "archivo.bin"


def _pack(filename: str, content: bytes) -> bytes:
    encoded = _name(filename).encode("utf-8")
    if len(encoded) > 1024:
        raise SecurityError("El nombre del archivo es demasiado largo.")
    return struct.pack(">H", len(encoded)) + encoded + content


def _unpack(data: bytes, algorithm: str) -> DecryptedFile:
    if len(data) < 2:
        raise SecurityError("El contenedor está dañado.")
    length = struct.unpack(">H", data[:2])[0]
    if length > 1024 or len(data) < 2 + length:
        raise SecurityError("Los metadatos están dañados.")
    try:
        filename = data[2:2 + length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecurityError("El nombre interno está dañado.") from exc
    return DecryptedFile(_name(filename), data[2 + length:], algorithm)


def encrypt_file(
    data: bytes,
    password: str,
    filename: str,
    algorithm: str = "aes_gcm",
) -> bytes:
    if algorithm not in {"aes_gcm", "chacha20"}:
        raise SecurityError("Algoritmo de cifrado no compatible.")
    magic = AES_MAGIC if algorithm == "aes_gcm" else CHACHA_MAGIC
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _key(password, salt)
    plaintext = _pack(filename, data)
    if algorithm == "aes_gcm":
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(magic)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return magic + salt + nonce + tag + ciphertext


def decrypt_file(payload: bytes, password: str) -> DecryptedFile:
    minimum = 4 + SALT_SIZE + NONCE_SIZE + TAG_SIZE + 2
    if len(payload) < minimum:
        raise SecurityError("El archivo cifrado está incompleto.")
    magic = payload[:4]
    if magic not in {AES_MAGIC, CHACHA_MAGIC}:
        raise SecurityError("El archivo no es un contenedor CodeCipher válido.")
    offset = 4
    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    tag = payload[offset:offset + TAG_SIZE]
    offset += TAG_SIZE
    ciphertext = payload[offset:]
    key = _key(password, salt)
    try:
        if magic == AES_MAGIC:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            algorithm = "AES-256-GCM"
        else:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            algorithm = "ChaCha20-Poly1305"
        cipher.update(magic)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise SecurityError("Contraseña incorrecta o archivo modificado.") from exc
    return _unpack(plaintext, algorithm)
