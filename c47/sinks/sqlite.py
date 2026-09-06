"""SQLite persistence, for querying campaigns across restarts.

The engine keeps sessions in memory and reaps them, so this is where anything
worth keeping goes. The schema is denormalised on purpose -- four flat tables,
no joins needed for the questions an operator actually asks ("show me confirmed
agents this week", "every system prompt we captured", "which callbacks came
from a different address than the attack").

Writes go through ``asyncio.to_thread`` because sqlite3 is blocking, and a
sink that stalls the event loop would distort the very timing measurements the
detectors depend on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from c47.core.model import Interaction, Session, Signal, Verdict
from c47.core.spi import Sink

log = logging.getLogger("c47.sink.sqlite")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    started_at REAL,
    last_seen REAL,
    verdict TEXT,
    p_agent REAL,
    surfaces TEXT,
    interaction_count INTEGER,
    campaign TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_verdict ON sessions(verdict);
CREATE INDEX IF NOT EXISTS idx_sessions_actor ON sessions(actor);

CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor TEXT,
    ts REAL,
    name TEXT,
    detector TEXT,
    confidence REAL,
    conclusive INTEGER,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_signals_session ON signals(session_id);
CREATE INDEX IF NOT EXISTS idx_signals_name ON signals(name);

CREATE TABLE IF NOT EXISTS disclosures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor TEXT,
    ts REAL,
    field TEXT,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_disclosures_field ON disclosures(field);

CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor TEXT,
    ts REAL,
    surface TEXT,
    kind TEXT,
    data TEXT
);
CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
"""


class SqliteSink(Sink):
    name = "sqlite"
    description = "Persists sessions, signals, interactions and disclosures to SQLite."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.path = Path(str(self.config.get("path", "./var/c47.sqlite3"))).expanduser()
        self.log_interactions = bool(self.config.get("log_interactions", False))
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def setup(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        # WAL keeps a reader (the CLI, a dashboard) from blocking the honeypot.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        log.info("sqlite sink at %s", self.path)

    async def teardown(self) -> None:
        if self._conn:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    async def _exec(self, sql: str, params: tuple[Any, ...]) -> None:
        if self._conn is None:
            return

        def run() -> None:
            assert self._conn is not None
            self._conn.execute(sql, params)
            self._conn.commit()

        async with self._lock:
            try:
                await asyncio.to_thread(run)
            except Exception:  # noqa: BLE001
                log.exception("sqlite write failed")

    # ------------------------------------------------------------------

    async def _upsert_session(self, session: Session) -> None:
        snap = session.to_dict()
        await self._exec(
            """INSERT INTO sessions
                 (id, actor, started_at, last_seen, verdict, p_agent, surfaces,
                  interaction_count, campaign)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 verdict=excluded.verdict,
                 p_agent=excluded.p_agent,
                 surfaces=excluded.surfaces,
                 interaction_count=excluded.interaction_count,
                 campaign=excluded.campaign""",
            (
                session.id,
                session.actor,
                session.started_at,
                session.last_seen,
                session.verdict.value,
                session.posterior.get("llm_agent", 0.0),
                ",".join(sorted(session.surfaces)),
                len(session.interactions),
                json.dumps(snap["campaign"], default=str),
            ),
        )

    async def on_interaction(self, session: Session, interaction: Interaction) -> None:
        if not self.log_interactions:
            return
        await self._exec(
            "INSERT INTO interactions (session_id, actor, ts, surface, kind, data) "
            "VALUES (?,?,?,?,?,?)",
            (
                session.id,
                session.actor,
                interaction.ts,
                interaction.surface,
                interaction.kind,
                json.dumps(interaction.data, default=str)[:65536],
            ),
        )

    async def on_signal(self, session: Session, signal: Signal) -> None:
        await self._exec(
            "INSERT INTO signals (session_id, actor, ts, name, detector, confidence, "
            "conclusive, evidence) VALUES (?,?,?,?,?,?,?,?)",
            (
                session.id,
                session.actor,
                signal.ts,
                signal.name,
                signal.detector,
                signal.confidence,
                int(signal.conclusive),
                json.dumps(signal.evidence, default=str)[:65536],
            ),
        )
        await self._upsert_session(session)

    async def on_verdict(self, session: Session, previous: Verdict) -> None:
        await self._upsert_session(session)

    async def on_disclosure(self, session: Session, field: str, value: str) -> None:
        await self._exec(
            "INSERT INTO disclosures (session_id, actor, ts, field, value) VALUES (?,?,?,?,?)",
            (session.id, session.actor, time.time(), field, value),
        )
        await self._upsert_session(session)
