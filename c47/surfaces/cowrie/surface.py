"""Cowrie adapter: SSH/Telnet detection and injection.

Cowrie already does the hard part -- a convincing emulated shell, a virtual
filesystem, credential handling, session recording -- and reimplementing that
would be a waste. So codename_47 wraps it rather than forking it, which keeps
Cowrie upgradable.

The integration has two halves, because reading and writing are separate
problems.

**Reading (always available).** Cowrie writes newline-delimited JSON events, and
this surface tails that file and translates them into
:class:`~c47.core.model.Interaction` objects. Every shell detector -- adaptive
error recovery, typing artefacts, recon pacing -- works from this alone, with an
unmodified Cowrie and no patching. That is the whole point: detection costs
nothing but a log path.

**Writing (opt-in).** A log tailer cannot inject, because by the time an event
is logged the response has been sent. Injection therefore needs something
running inside Cowrie, and this surface exposes a loopback-only sidecar API for
it to call. ``c47 cowrie-overlay`` generates the pieces:

* ``txtcmds/`` files -- static ANSI-concealed payloads, drop-in, no code change;
* ``c47_hook.py`` -- a command shim that fetches a *fresh* payload per session
  from the sidecar, so keys and tokens are unique per engagement.

Static overlay first, sidecar when per-session tokens matter. The sidecar binds
to loopback by default and refuses to start otherwise: it renders live lure
content, and anything that can reach it can enumerate the traps.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from aiohttp import web

from c47.core.model import Channel, Interaction
from c47.core.spi import Surface

log = logging.getLogger("c47.surface.cowrie")

#: Cowrie eventid -> our interaction kind.
EVENT_MAP: dict[str, str] = {
    "cowrie.command.input": "shell_command",
    "cowrie.command.failed": "shell_command",
    "cowrie.login.success": "login",
    "cowrie.login.failed": "login",
    "cowrie.session.connect": "connect",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.client.version": "client_version",
    "cowrie.direct-tcpip.request": "tunnel_request",
}


class CowrieSurface(Surface):
    name = "cowrie"
    description = "Tails a Cowrie JSON log for detection; serves live lures over a loopback sidecar."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.log_path = Path(str(self.config.get("log_path", ""))).expanduser()
        self.poll_interval = float(self.config.get("poll_interval", 1.0))
        self.from_start = bool(self.config.get("from_start", False))

        self.sidecar_enabled = bool(self.config.get("sidecar", True))
        self.sidecar_bind = self.config.get("sidecar_bind", "127.0.0.1")
        self.sidecar_port = int(self.config.get("sidecar_port", 8099))

        self._task: asyncio.Task[None] | None = None
        self._runner: web.AppRunner | None = None
        self._offset = 0
        self._inode: int | None = None
        self.events_read = 0

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        if not str(self.log_path):
            log.error("cowrie surface enabled but log_path is unset; detection disabled")
        else:
            self._task = asyncio.create_task(self._tail_loop())
            log.info("cowrie tailer watching %s", self.log_path)

        if self.sidecar_enabled:
            if self.sidecar_bind not in ("127.0.0.1", "localhost", "::1"):
                # Refusing is the right call: the sidecar hands out live lure
                # content, so exposing it lets anyone enumerate the traps.
                log.error(
                    "refusing to bind cowrie sidecar to %s; loopback only "
                    "(it serves live lure content)",
                    self.sidecar_bind,
                )
            else:
                await self._start_sidecar()

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    # -- log tailing ------------------------------------------------------

    async def _tail_loop(self) -> None:
        while True:
            try:
                await self._drain()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("cowrie tail iteration failed")
            await asyncio.sleep(self.poll_interval)

    async def _drain(self) -> None:
        if not self.log_path.exists():
            return
        stat = self.log_path.stat()

        # Detect rotation: a new inode, or a file that shrank beneath our
        # offset, both mean start over from the beginning of the new file.
        if self._inode is None:
            self._inode = stat.st_ino
            self._offset = 0 if self.from_start else stat.st_size
        elif stat.st_ino != self._inode or stat.st_size < self._offset:
            log.info("cowrie log rotated; resuming from start of new file")
            self._inode = stat.st_ino
            self._offset = 0

        if stat.st_size == self._offset:
            return

        lines: list[str] = []
        with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._offset)
            for line in fh:
                if not line.endswith("\n"):
                    # Partial trailing write; leave it for the next pass.
                    break
                lines.append(line)
                self._offset += len(line.encode("utf-8", "replace"))

        for line in lines:
            await self._ingest(line)

    async def _ingest(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except Exception:  # noqa: BLE001
            return
        if not isinstance(event, dict):
            return

        eventid = str(event.get("eventid", ""))
        kind = EVENT_MAP.get(eventid)
        if kind is None:
            return
        actor = str(event.get("src_ip") or "").strip()
        if not actor:
            return

        self.events_read += 1
        data: dict[str, Any] = {
            "eventid": eventid,
            "cowrie_session": event.get("session", ""),
            "protocol": event.get("protocol", "ssh"),
        }

        if kind == "shell_command":
            data["command"] = str(event.get("input", ""))
            # Cowrie logs an unknown command as cowrie.command.failed, which is
            # exactly the error the adaptive-recovery detector keys on.
            data["error"] = eventid.endswith(".failed")
        elif kind == "login":
            data["username"] = str(event.get("username", ""))
            data["password"] = str(event.get("password", ""))
            data["success"] = eventid.endswith(".success")
        elif kind == "client_version":
            data["client_version"] = str(event.get("version", ""))
        elif kind in ("file_download", "file_upload"):
            data["url"] = str(event.get("url", ""))
            data["filename"] = str(event.get("filename", ""))
            data["shasum"] = str(event.get("shasum", ""))

        engine = self.engine
        assert engine is not None
        await engine.observe(
            Interaction(
                surface=self.name,
                kind=kind,
                actor=actor,
                ts=_event_ts(event),
                session_key=str(event.get("session", "")) or None,
                data=data,
            )
        )

    # -- sidecar ----------------------------------------------------------

    async def _start_sidecar(self) -> None:
        app = web.Application()
        app.router.add_post("/lure", self._sidecar_lure)
        app.router.add_get("/health", self._sidecar_health)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.sidecar_bind, self.sidecar_port)
        await site.start()
        log.info("cowrie sidecar on %s:%d", self.sidecar_bind, self.sidecar_port)

    async def _sidecar_health(self, request: web.Request) -> web.StreamResponse:
        return web.json_response({"ok": True, "events_read": self.events_read})

    async def _sidecar_lure(self, request: web.Request) -> web.StreamResponse:
        """Render a live payload for a Cowrie-side shim.

        Body: ``{"src_ip": "...", "command": "whoami", "channel": "shell_stdout"}``
        Returns: ``{"content": "<bytes to append to command output>"}``
        """
        engine = self.engine
        assert engine is not None
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return web.json_response({"content": ""})

        actor = str(body.get("src_ip", "")).strip()
        if not actor:
            return web.json_response({"content": ""})

        channel_name = str(body.get("channel", "shell_stdout"))
        try:
            channel = Channel(channel_name)
        except ValueError:
            channel = Channel.SHELL_STDOUT

        session = engine.session_for(actor)
        ctx = engine.make_context(
            channel,
            session,
            purpose=str(body.get("purpose", "shell")),
            command=str(body.get("command", "")),
            cowrie_session=str(body.get("session", "")),
        )
        content = await engine.render_text(ctx)
        return web.json_response({"content": content})


def _event_ts(event: dict[str, Any]) -> float:
    """Parse Cowrie's ISO-8601 timestamp, falling back to now.

    Timing detectors depend on this being the real event time, not ingest time:
    the tailer polls on an interval, so ingest time would flatten every gap in a
    burst to zero and destroy the sawtooth signal.
    """
    raw = str(event.get("timestamp", ""))
    if raw:
        try:
            from datetime import datetime

            cleaned = raw.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned).timestamp()
        except Exception:  # noqa: BLE001
            pass
    return time.time()


def default_cowrie_log() -> str:
    """Best-effort guess at a local Cowrie JSON log path."""
    for candidate in (
        "/var/log/cowrie/cowrie.json",
        os.path.expanduser("~/cowrie/var/log/cowrie/cowrie.json"),
        "./var/log/cowrie/cowrie.json",
    ):
        if Path(candidate).exists():
            return candidate
    return "/var/log/cowrie/cowrie.json"
