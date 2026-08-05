from __future__ import annotations

import unittest

from codecipher.storage import Storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.storage = Storage(":memory:")

    def test_user_history_methods_and_codes(self) -> None:
        self.storage.register_user(42, "ghost", "Ghost")
        self.storage.record_operation(
            42, "base64_encode", "x.txt", "success", 10, 16
        )
        self.assertEqual(len(self.storage.recent_history(42)), 1)
        self.storage.sync_methods(["base64_encode"])
        self.storage.set_method_enabled("base64_encode", False)
        self.assertFalse(self.storage.method_enabled("base64_encode"))
        code = self.storage.create_admin_code(42)
        self.assertEqual(self.storage.consume_admin_code(code), 42)
        self.assertIsNone(self.storage.consume_admin_code(code))

    def test_presets_and_maintenance(self) -> None:
        self.storage.register_user(7, None, "User")
        self.storage.save_preset(7, "favorito", "runnable_auto")
        self.assertEqual(
            self.storage.list_presets(7)[0]["method_key"], "runnable_auto"
        )
        self.storage.set_maintenance(True, "Actualización")
        self.assertTrue(self.storage.maintenance_enabled())
        self.assertEqual(
            self.storage.get_setting("maintenance_message"), "Actualización"
        )

