from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from config import ConfigError, Settings


class SettingsTests(unittest.TestCase):
    def test_token_is_required(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_valid_configuration(self) -> None:
        values = {
            "BOT_TOKEN": "123456:test",
            "MAX_FILE_SIZE_MB": "7",
            "RATE_LIMIT_PER_MINUTE": "20",
            "BOT_WORKERS": "3",
            "ALLOWED_USER_IDS": "10, 20",
            "LOG_LEVEL": "WARNING",
        }
        with patch.dict(os.environ, values, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.max_file_size, 7 * 1024 * 1024)
        self.assertEqual(settings.worker_threads, 3)
        self.assertEqual(settings.allowed_user_ids, frozenset({10, 20}))


if __name__ == "__main__":
    unittest.main()
