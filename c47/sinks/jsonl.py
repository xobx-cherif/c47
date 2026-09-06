"""Newline-delimited JSON event log.

The canonical output. Every hook writes one self-describing record, appended and
flushed immediately, so a session that is still running is already fully
readable by ``jq`` or an ingest pipeline.

Verdict and disclosure records carry the whole session snapshot rather than a
delta. That is deliberate redundancy: these are the records an analyst actually
reads, and they should be interpretable on their own without replaying the
interaction stream that preceded them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from c47.core.model import Interaction, LurePayload, Session, Signal, Verdict
from c47.core.spi import Sink

log = logging.getLogger("c47.sink.jsonl")


class JsonlSink(Sink):
    name = "jsonl"
    description = "Appends every event as one JSON object per line."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.path = Path(str(self.config.get("path", "./var/events.jsonl"))).expanduser()
        self.log_interactions = bool(self.config.get("log_interactions", True))
        self.log_lure_content = bool(self.config.get("log_lure_content", False))
        self._lock = asyncio.Lock()

    async def setup(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        log.info("jsonl sink writing to %s", self.path)

    async def _write(self, record: dict[str, Any]) -> None:
        record.setdefault("ts", time.time())
        line = json.dumps(record, default=str, ensure_ascii=False)
        async with self._lock:
            try:
                # Opened per write so log rotation by an external tool works
                # without the sink holding a deleted file handle open.
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception:  # noqa: BLE001
                log.exception("failed to append to %s", self.path)

    # ------------------------------------------------------------------

    async def on_interaction(self, session: Session, interaction: Interaction) -> None:
        if not self.log_interactions:
            return
        await self._write(
            {
                "type": "interaction",
                "session_id": session.id,
                "actor": session.actor,
                "surface": interaction.surface,
                "kind": interaction.kind,
                "ts": interaction.ts,
                "data": _sanitise(interaction.data),
            }
        )

    async def on_signal(self, session: Session, signal: Signal) -> None:
        await self._write(
            {
                "type": "signal",
                "session_id": session.id,
                "actor": session.actor,
                "signal": signal.name,
                "detector": signal.detector,
                "confidence": signal.confidence,
                "conclusive": signal.conclusive,
                "weights": signal.weights,
                "evidence": _sanitise(signal.evidence),
            }
        )

    async def on_verdict(self, session: Session, previous: Verdict) -> None:
        await self._write(
            {
                "type": "verdict",
                "previous": getattr(previous, "value", str(previous)),
                "session": session.to_dict(),
            }
        )

    async def on_disclosure(self, session: Session, field: str, value: str) -> None:
        await self._write(
            {
                "type": "disclosure",
                "session_id": session.id,
                "actor": session.actor,
                "field": field,
                "value": value,
                "campaign": session.to_dict()["campaign"],
            }
        )

    async def on_lure_served(self, session: Session, payload: LurePayload) -> None:
        # Expectations are recorded here so `c47 replay` can restore lure state
        # and reproduce expectation-based signals. Payload content is omitted
        # unless asked for: it is bulky and the log does not need every byte.
        await self._write(
            {
                "type": "lure_served",
                "session_id": session.id,
                "actor": session.actor,
                **payload.to_dict(include_content=self.log_lure_content),
            }
        )


def _sanitise(data: dict[str, Any]) -> dict[str, Any]:
    """Drop framework-internal keys and cap runaway values."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if str(key).startswith("_"):
            continue
        if isinstance(value, str) and len(value) > 8192:
            out[key] = value[:8192] + f"...[truncated {len(value) - 8192} chars]"
        else:
            out[key] = value
    return out
