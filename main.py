#!/usr/bin/env python3
"""Punto de entrada de CodeCipherBot."""

from __future__ import annotations

import logging
import sys
import threading

from telebot import types

from codecipher.bot import build_broadcaster, create_bot
from codecipher.config import ConfigError, Settings
from codecipher.storage import Storage
from codecipher.web import create_web_app


LOGGER = logging.getLogger("codecipherbot")


def _serve_web(app, host: str, port: int) -> None:
    from waitress import serve

    serve(app, host=host, port=port, threads=6)


def run(settings: Settings) -> None:
    storage = Storage(settings.database_path)
    bot = create_bot(settings, storage)
    broadcaster = build_broadcaster(bot, storage)
    app = create_web_app(settings, storage, broadcast=broadcaster)

    if settings.run_mode == "webhook":
        if not settings.web_enabled:
            raise ConfigError("WEB_ENABLED debe estar activo en modo webhook.")
        route = f"/telegram/{settings.webhook_path_secret}"

        @app.post(route)
        def telegram_webhook():
            from flask import abort, request

            provided = request.headers.get(
                "X-Telegram-Bot-Api-Secret-Token", ""
            )
            if provided != settings.webhook_header_secret:
                abort(403)
            update = types.Update.de_json(request.get_data(as_text=True))
            bot.process_new_updates([update])
            return "", 204

        url = f"{settings.webhook_base_url}{route}"
        bot.remove_webhook()
        bot.set_webhook(
            url=url,
            secret_token=settings.webhook_header_secret,
            allowed_updates=["message", "callback_query"],
        )
        LOGGER.info("Webhook configurado en %s", url)
        _serve_web(app, settings.web_host, settings.web_port)
        return

    bot.remove_webhook()
    if settings.web_enabled:
        threading.Thread(
            target=_serve_web,
            args=(app, settings.web_host, settings.web_port),
            name="codecipher-web",
            daemon=True,
        ).start()
        LOGGER.info(
            "API web escuchando en %s:%s", settings.web_host, settings.web_port
        )
    LOGGER.info("Bot iniciado en modo polling")
    bot.infinity_polling(
        skip_pending=True,
        timeout=20,
        long_polling_timeout=20,
        allowed_updates=["message", "callback_query"],
    )


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    try:
        run(settings)
    except KeyboardInterrupt:
        LOGGER.info("Servicio detenido")
    except ConfigError as exc:
        LOGGER.error("Error de configuración: %s", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
