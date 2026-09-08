"""The canary listener: a deliberately boring HTTP endpoint.

A request carrying one of our tokens gets ``204 No Content``, a plausible
server header and no body: a real telemetry sink with nothing to hide. An
agent that gets an error, a redirect or anything interesting back may retry,
report the failure, or decide the endpoint is fake, and we have exactly one
chance to be unremarkable.

Everything **without** a token gets a plain 404, and is counted rather than
recorded. Answering 204 to every path, as this listener first did, turns it
into a beacon that tells a directory fuzzer every path exists -- so the fuzzer
never terminates. The first real agent pointed at this honeypot did exactly
that: 37,925 requests from ``ffuf`` in 48 minutes, every one unattributable,
all landing in a single session and dragging the per-interaction detectors
into quadratic time. A canary that is interesting to a scanner is a canary
that drowns the signal it exists to catch.

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
from c47.core.net import client_ip

log = logging.getLogger("c47.canary")

MAX_BODY = 64 * 1024


class CanaryListener:
    """Accepts callbacks and turns them into ``canary_hit`` interactions."""

    def __init__(self, engine: Any, config: dict[str, Any] | None = None) -> None:
        self.engine = engine
        self.config = config or {}
        self.bind = self.config.get("bind", "0.0.0.0")
        self.port = int(self.config.get("port", 8081))
        self.trust_forwarded = bool(self.config.get("trust_forwarded_headers", False))
        self.report_every = int(self.config.get("report_every", 500))
        self._runner: web.AppRunner | None = None
        self.hits: int = 0
        #: Tokenless requests turned away. Under a fuzzer this is the bulk
        #: of the traffic and is deliberately not recorded per-request.
        self.rejected: int = 0

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
        if self.rejected:
            log.info(
                "canary: %d hits total, %d tokenless requests ignored",
                self.hits,
                self.rejected,
            )

    # ------------------------------------------------------------------

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        self.hits += 1
        callback_ip = client_ip(request, trust_forwarded=self.trust_forwarded)
        params: dict[str, Any] = dict(request.query)

        # Cheap reject before reading any body: a callback always carries a
        # token, because we planted the URL. Anything else is a scan, and
        # recording it only buries the hits that matter.
        probe_token = extract_token(request.path, params)
        if probe_token is None and not request.can_read_body:
            return self._reject(callback_ip, request)

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

        if token is None:
            # A POST whose body held no token either. Still a scan.
            return self._reject(callback_ip, request)

        # An unresolved-but-present token is worth recording: it may belong to
        # a session the reaper has since dropped, and the hit is still evidence.
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

    def _reject(self, callback_ip: str, request: web.Request) -> web.StreamResponse:
        """Answer a tokenless request as an ordinary empty web server would.

        Counted, not recorded. A log line per request would be 37,000 lines
        under a fuzzer, so the count is reported once per ``report_every``
        rejections and again in the shutdown summary.
        """
        self.rejected += 1
        if self.rejected % self.report_every == 0:
            log.info(
                "canary: %d tokenless requests ignored (latest %s %s from %s)",
                self.rejected,
                request.method,
                request.path[:80],
                callback_ip,
            )
        return web.Response(
            status=404,
            text="404 Not Found\n",
            content_type="text/plain",
            headers={"Server": "nginx/1.24.0"},
        )



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
