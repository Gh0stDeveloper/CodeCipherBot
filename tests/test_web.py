from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

from codecipher.config import Settings
from codecipher.registry import METHODS
from codecipher.storage import Storage
from codecipher.web import create_web_app


def telegram_init_data(token: str, user_id: int, auth_date: int) -> str:
    pairs = {
        "auth_date": str(auth_date),
        "query_id": "AAE-test",
        "user": json.dumps(
            {"id": user_id, "first_name": "Test", "username": "tester"},
            separators=(",", ":"),
        ),
    }
    check = "\n".join(f"{key}={pairs[key]}" for key in sorted(pairs))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    pairs["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(pairs)


class WebApiTests(unittest.TestCase):
    def setUp(self) -> None:
        env = {
            "BOT_TOKEN": "123456:test-token",
            "OWNER_IDS": "42",
            "ADMIN_IDS": "43",
            "DATABASE_PATH": ":memory:",
            "PANEL_URL": "https://panel.example",
            "CORS_ORIGINS": "https://panel.example",
            "ADMIN_SESSION_SECRET": "test-secret-with-enough-entropy",
        }
        with patch.dict(os.environ, env, clear=True):
            self.settings = Settings.from_env()
        self.storage = Storage(":memory:")
        self.storage.sync_methods(list(METHODS))
        self.storage.register_user(42, "owner", "Owner")
        self.broadcasts: list[tuple[str, int]] = []

        def broadcast(message: str, actor: int) -> dict[str, int]:
            self.broadcasts.append((message, actor))
            return {"queued": 3}

        app = create_web_app(
            self.settings, self.storage, broadcast=broadcast
        )
        app.testing = True
        self.client = app.test_client()

    def test_public_status_and_telegram_user_session(self) -> None:
        status = self.client.get("/api/public/status")
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json["online"])
        self.assertEqual(len(status.json["methods"]), len(METHODS))

        init_data = telegram_init_data(
            self.settings.bot_token, 7, int(time.time())
        )
        auth = self.client.post(
            "/api/auth/telegram", json={"init_data": init_data}
        )
        self.assertEqual(auth.status_code, 200)
        self.assertEqual(auth.json["user"]["role"], "user")
        me = self.client.get(
            "/api/me",
            headers={"Authorization": f"Bearer {auth.json['token']}"},
        )
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json["user"]["id"], 7)

    def test_one_time_admin_code_and_controls(self) -> None:
        code = self.storage.create_admin_code(42)
        auth = self.client.post("/api/auth/code", json={"code": code})
        self.assertEqual(auth.status_code, 200)
        token = auth.json["token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Origin": "https://panel.example",
        }
        update = self.client.put(
            "/api/admin/methods/base64_encode",
            json={"enabled": False},
            headers=headers,
        )
        self.assertEqual(update.status_code, 200)
        self.assertFalse(self.storage.method_enabled("base64_encode"))
        maintenance = self.client.put(
            "/api/admin/maintenance",
            json={"enabled": True, "message": "Deploy"},
            headers=headers,
        )
        self.assertEqual(maintenance.status_code, 200)
        broadcast = self.client.post(
            "/api/admin/broadcast",
            json={"message": "Hola"},
            headers=headers,
        )
        self.assertEqual(broadcast.status_code, 202)
        self.assertEqual(self.broadcasts, [("Hola", 42)])
        reused = self.client.post("/api/auth/code", json={"code": code})
        self.assertEqual(reused.status_code, 401)

    def test_expired_or_modified_telegram_data_is_rejected(self) -> None:
        expired = telegram_init_data(
            self.settings.bot_token, 7, int(time.time()) - 3600
        )
        response = self.client.post(
            "/api/auth/telegram", json={"init_data": expired}
        )
        self.assertEqual(response.status_code, 401)
        modified = telegram_init_data(
            self.settings.bot_token, 7, int(time.time())
        ).replace("tester", "attacker")
        response = self.client.post(
            "/api/auth/telegram", json={"init_data": modified}
        )
        self.assertEqual(response.status_code, 401)

