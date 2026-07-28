from __future__ import annotations

import os
import tempfile
import unittest

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


SOURCE = 'print("Hola, 世界 👻")\nvalue = 42\n'


class EncodingRoundTripTests(unittest.TestCase):
    def test_text_base64_unicode(self) -> None:
        self.assertEqual(decode_text_base64(encode_text_base64(SOURCE)), SOURCE)

    def test_python_base64_wrapper(self) -> None:
        wrapper = encrypt_base64(SOURCE)
        compile(wrapper, "encoded.py", "exec")
        self.assertEqual(decrypt_base64(wrapper), SOURCE)

    def test_python_zlib_wrapper(self) -> None:
        wrapper = encrypt_base64_zlib(SOURCE)
        compile(wrapper, "encoded_zlib.py", "exec")
        self.assertEqual(decrypt_base64_zlib(wrapper), SOURCE)

    def test_python_emoji_wrapper(self) -> None:
        wrapper = encrypt_emoji(SOURCE)
        compile(wrapper, "encoded_emoji.py", "exec")
        self.assertEqual(decrypt_emoji(wrapper), SOURCE)

    def test_multilayer_wrapper(self) -> None:
        wrapper = vip_encoding(SOURCE)
        compile(wrapper, "encoded_multilayer.py", "exec")
        self.assertEqual(decrypt_vip(wrapper), SOURCE)

    def test_javascript_wrapper(self) -> None:
        wrapper = encrypt_js_base64(SOURCE)
        self.assertEqual(decrypt_js_base64(wrapper), SOURCE)

    def test_php_wrapper(self) -> None:
        php = "<?php\necho 'hola';\n?>"
        wrapper = encrypt_php_base64(php)
        self.assertEqual(decrypt_php_base64(wrapper), php)

    def test_marshal_wrapper_compiles(self) -> None:
        wrapper = codificar_script_marshall(SOURCE)
        compile(wrapper, "encoded_marshal.py", "exec")


class SafeDecoderTests(unittest.TestCase):
    def test_decoder_does_not_execute_received_python(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "must_not_exist")
            malicious = (
                "from pathlib import Path\n"
                f"Path({marker!r}).write_text('executed')\n"
            )
            with self.assertRaises(TransformError):
                decrypt_base64(malicious)
            self.assertFalse(os.path.exists(marker))

    def test_invalid_base64_is_rejected(self) -> None:
        with self.assertRaises(TransformError):
            decode_text_base64("esto no es base64")


class AuthenticatedEncryptionTests(unittest.TestCase):
    def test_file_round_trip_preserves_name_and_bytes(self) -> None:
        original = b"\x00\x01binary\ncontent\xff"
        encrypted = encrypt_file(original, "una-clave-segura", "datos.bin")
        decrypted = decrypt_file(encrypted, "una-clave-segura")
        self.assertEqual(decrypted.filename, "datos.bin")
        self.assertEqual(decrypted.content, original)

    def test_wrong_password_is_rejected(self) -> None:
        encrypted = encrypt_file(b"secret", "clave-correcta", "secret.txt")
        with self.assertRaises(TransformError):
            decrypt_file(encrypted, "clave-incorrecta")

    def test_modified_ciphertext_is_rejected(self) -> None:
        encrypted = bytearray(encrypt_file(b"secret", "clave-correcta", "secret.txt"))
        encrypted[-1] ^= 1
        with self.assertRaises(TransformError):
            decrypt_file(bytes(encrypted), "clave-correcta")


if __name__ == "__main__":
    unittest.main()
