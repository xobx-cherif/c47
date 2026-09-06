"""Process wiring: engine, canary listener, signal handling.

Kept separate from :mod:`c47.core.engine` so the engine stays importable and
testable without binding sockets or installing signal handlers -- which is what
lets ``c47 replay`` and ``c47 selftest`` drive the real engine offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys

from c47.canary.listener import CanaryListener
from c47.core.config import Config
from c47.core.engine import Engine

log = logging.getLogger("c47.runtime")


class Runtime:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.engine = Engine(config)
        self.canary: CanaryListener | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self.engine.build()
        await self.engine.start()

        if self.config.get("canary.enabled", True):
            self.canary = CanaryListener(self.engine, self.config.section("canary"))
            await self.canary.start()

        summary = self.engine.summary()
        log.info(
            "codename_47 ready | surfaces=%s lures=%d detectors=%d",
            ",".join(summary["plugins"]["surfaces"]) or "none",
            len(summary["plugins"]["lures"]),
            len(summary["plugins"]["detectors"]),
        )

    async def stop(self) -> None:
        if self.canary:
            await self.canary.stop()
            self.canary = None
        await self.engine.stop()

    async def serve_forever(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError, ValueError):
                loop.add_signal_handler(sig, self._stop.set)

        await self.start()
        try:
            await self._stop.wait()
        finally:
            log.info("shutting down")
            await self.stop()
            stats = self.engine.summary()
            log.info(
                "final: %d interactions, %d signals, %d agents confirmed, "
                "%d prompts extracted",
                stats["stats"]["interactions"],
                stats["stats"]["signals"],
                stats["stats"]["agents_confirmed"],
                stats["stats"]["prompts_extracted"],
            )


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-22s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # aiohttp's access logging is disabled per-runner; silence the rest of its
    # chatter so the console sink stays readable.
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
