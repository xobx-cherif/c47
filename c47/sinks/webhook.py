"""Webhook forwarder for SIEM / chat alerting.

Fires only on verdicts at or above a threshold and on disclosures, because
those are the events a human should see. Delivery is fire-and-forget on a
background task with a short timeout: an unreachable webhook must never slow a
response to an attacker, since added latency is itself a tell that the host is
instrumented.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import aiohttp

from c47.core.model import Session, Verdict
from c47.core.spi import Sink
from c47.sinks.console import ORDER

log = logging.getLogger("c47.sink.webhook")


class WebhookSink(Sink):
    name = "webhook"
    description = "POSTs verdicts and disclosures to an HTTP endpoint."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.url = str(self.config.get("url", "")).strip()
        self.timeout = float(self.config.get("timeout", 5.0))
        self.headers = dict(self.config.get("headers", {}) or {})
        raw = str(self.config.get("min_verdict", "suspected_agent"))
        try:
            self.min_verdict = Verdict(raw)
        except ValueError:
            self.min_verdict = Verdict.SUSPECTED_AGENT
        self._session: aiohttp.ClientSession | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def setup(self) -> None:
        if not self.url:
            log.warning("webhook sink enabled but no url configured; disabled")
            return
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )

    async def teardown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self._session:
            await self._session.close()
            self._session = None

    def _post(self, payload: dict[str, Any]) -> None:
        if self._session is None:
            return
        task = asyncio.create_task(self._deliver(payload))
        # Hold a reference so the task is not garbage collected mid-flight.
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _deliver(self, payload: dict[str, Any]) -> None:
        assert self._session is not None
        try:
            async with self._session.post(
                self.url, json=payload, headers=self.headers
            ) as resp:
                if resp.status >= 400:
                    log.warning("webhook returned %d", resp.status)
        except Exception as exc:  # noqa: BLE001
            log.warning("webhook delivery failed: %s", exc)

    # ------------------------------------------------------------------

    async def on_verdict(self, session: Session, previous: Verdict) -> None:
        if ORDER.get(session.verdict, 0) < ORDER.get(self.min_verdict, 3):
            return
        self._post(
            {
                "event": "verdict",
                "previous": getattr(previous, "value", str(previous)),
                "session": session.to_dict(),
            }
        )

    async def on_disclosure(self, session: Session, field: str, value: str) -> None:
        self._post(
            {
                "event": "disclosure",
                "session_id": session.id,
                "actor": session.actor,
                "field": field,
                "value": value,
            }
        )
