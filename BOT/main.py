from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from . import bootstrap
from .app import Bot
from .config import Config, ConfigError


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("goygram").setLevel(logging.WARNING)


async def amain() -> int:
    try:
        cfg = Config.load()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.log_level)
    log = logging.getLogger("obhod")
    bot = Bot(cfg)
    log.info("starting obhod bot, admin=%s, state=%s", cfg.admin_id, cfg.state_dir)
    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except (NotImplementedError, RuntimeError):
            pass

    runner = asyncio.create_task(bot.run())
    waiter = asyncio.create_task(stop.wait())
    done, pending = await asyncio.wait({runner, waiter}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in done:
        exc = task.exception()
        if exc is not None:
            log.error("bot stopped with error: %s", exc)
            return 1
    if bot.app is not None:
        try:
            await bot.app.close()
        except Exception as exc:
            log.warning("the session did not close cleanly: %s", type(exc).__name__)
    return 0


def main() -> int:
    os.umask(0o077)
    if sys.argv[1:2] == ["bootstrap"]:
        return bootstrap.run(sys.argv[2:])
    try:
        return asyncio.run(amain())
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
