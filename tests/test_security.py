from __future__ import annotations

import unittest

from codecipher.security import SecurityError, decrypt_file, encrypt_file


class AuthenticatedEncryptionTests(unittest.TestCase):
    def test_both_algorithms_round_trip(self) -> None:
        content = b"\x00binary\xff\ncontent"
        for algorithm in ("aes_gcm", "chacha20"):
            with self.subTest(algorithm=algorithm):
                encrypted = encrypt_file(
                    content, "una-clave-segura", "datos.bin", algorithm
                )
                decrypted = decrypt_file(encrypted, "una-clave-segura")
                self.assertEqual(decrypted.filename, "datos.bin")
                self.assertEqual(decrypted.content, content)

    def test_wrong_password_and_tampering_are_rejected(self) -> None:
        encrypted = encrypt_file(
            b"secret", "clave-correcta", "secret.txt", "aes_gcm"
        )
        with self.assertRaises(SecurityError):
            decrypt_file(encrypted, "clave-incorrecta")
        modified = bytearray(encrypted)
        modified[-1] ^= 1
        with self.assertRaises(SecurityError):
            decrypt_file(bytes(modified), "clave-correcta")

