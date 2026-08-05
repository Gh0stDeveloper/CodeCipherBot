from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from codecipher.bot import create_bot
from codecipher.config import Settings
from codecipher.registry import METHODS
from codecipher.storage import Storage


class TelegramRegistrationTests(unittest.TestCase):
    def test_public_and_admin_commands_register_without_an_allowlist(self) -> None:
        with patch.dict(
            os.environ,
            {
                "BOT_TOKEN": "123456:test-token",
                "DATABASE_PATH": ":memory:",
            },
            clear=True,
        ):
            settings = Settings.from_env()
        storage = Storage(":memory:")
        with patch("telebot.TeleBot.set_my_commands", return_value=True):
            bot = create_bot(settings, storage)

        commands = {
            command
            for handler in bot.message_handlers
            for command in handler["filters"].get("commands", [])
        }
        self.assertTrue(
            {
                "start",
                "protect",
                "encrypt",
                "batch",
                "hash",
                "panel",
                "admin",
                "stats",
                "ban",
                "broadcast",
            }.issubset(commands)
        )
        self.assertEqual(set(storage.method_states()), set(METHODS))
        self.assertEqual(settings.all_admin_ids, frozenset())

