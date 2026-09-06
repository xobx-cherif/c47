"""The canary listener: a deliberately boring HTTP endpoint.

Everything about the response is chosen to look like a real telemetry sink
that has nothing to hide: ``204 No Content``, a plausible server header, no
body, every path and method accepted. An agent that gets an error, a redirect
or anything interesting back may retry, report the failure, or decide the
endpoint is fake -- and we have exactly one chance to be unremarkable.

Attribution is the subtle part. A callback is deliberately **not** attributed
to the address it arrives from; it is attributed to the session that planted
the token. The arriving address is recorded separately as ``callback_ip``,
because the two being different is the single most valuable thing this
component produces: the attack traffic comes from disposable infrastructure,
while the callback comes from wherever the agent (or the human reading its
report) actually runs.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aiohttp import web

from c47.canary.tokens import extract_token
from c47.core.model import Interaction

log = logging.getLogger("c47.canary")

MAX_BODY = 64 * 1024


class CanaryListener:
    """Accepts callbacks and turns them into ``canary_hit`` interactions."""

    def __init__(self, engine: Any, config: dict[str, Any] | None = None) -> None:
        self.engine = engine
        self.config = config or {}
        self.bind = self.config.get("bind", "0.0.0.0")
        self.port = int(self.config.get("port", 8081))
        self._runner: web.AppRunner | None = None
        self.hits: int = 0

    async def start(self) -> None:
        app = web.Application(client_max_size=MAX_BODY)
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.bind, self.port)
        await site.start()
        log.info("canary listener on %s:%d", self.bind, self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        self.hits += 1
        callback_ip = _peer(request)
        params: dict[str, Any] = dict(request.query)

        body = ""
        if request.can_read_body:
            try:
                raw = await request.content.read(MAX_BODY)
                body = raw.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body = ""

        # Agents POST structured handoff records as often as they use query
        # strings; fold both shapes into one parameter dict.
        if body:
            merged = _params_from_body(body, request.headers.get("Content-Type", ""))
            for k, v in merged.items():
                params.setdefault(k, v)

        token = extract_token(request.path, params)
        session = self.engine.session_for_token(token) if token else None

        # Fall back to the callback address only when the token cannot be
        # resolved, so an unattributable hit is still recorded rather than lost.
        actor = session.actor if session else callback_ip

        interaction = Interaction(
            surface="canary",
            kind="canary_hit",
            actor=actor,
            ts=time.time(),
            data={
                "token": token or "",
                "params": params,
                "body": body,
                "path": request.path,
                "method": request.method,
                "callback_ip": callback_ip,
                "user_agent": request.headers.get("User-Agent", ""),
                "headers": {k: v for k, v in request.headers.items() if k.lower() != "cookie"},
                "attributed": session is not None,
            },
        )

        log.warning(
            "CANARY HIT token=%s from=%s attributed=%s params=%s",
            token,
            callback_ip,
            bool(session),
            list(params),
        )

        try:
            await self.engine.observe(interaction)
        except Exception:  # noqa: BLE001
            log.exception("failed to process canary hit")

        return web.Response(
            status=204,
            headers={"Server": "nginx/1.24.0", "Cache-Control": "no-store"},
        )


def _peer(request: web.Request) -> str:
    # Honour forwarding headers so a callback through a reverse proxy still
    # yields the real egress address.
    for header in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    return request.remote or "unknown"


def _params_from_body(body: str, content_type: str) -> dict[str, Any]:
    ct = content_type.lower()
    if "json" in ct:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return {str(k): v for k, v in parsed.items()}
        except Exception:  # noqa: BLE001
            pass
    if "x-www-form-urlencoded" in ct or "=" in body and "\n" not in body.strip():
        from urllib.parse import parse_qsl

        try:
            return dict(parse_qsl(body, keep_blank_values=False))
        except Exception:  # noqa: BLE001
            pass
    # Unstructured POST: treat the whole body as a probable instruction-set
    # disclosure. The expectations detector's regexes decide whether it is.
    return {"prompt": body} if body.strip() else {}
