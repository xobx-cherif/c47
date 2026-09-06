"""HTTP surface: the widest and richest injection channel.

Ordering inside :meth:`_handle` is the important part, and it is deliberate:

1. observe the request first, so detectors run and the verdict updates;
2. *then* render lures, so the escalation stage already reflects what this very
   request just proved.

That one-request-earlier escalation matters. An agent that solves the reasoning
probe on request N is confirmed by the time we build response N, so the
extraction payload goes out immediately rather than waiting for request N+1 --
which may never come.

Every response is also a lure vehicle: the HTML carries comment bait, the JSON
error paths carry the reasoning probe, and ``robots.txt`` carries the
selectivity pairing. Coherence is maintained by resolving whatever paths our own
lures invented (see ``_bait_paths``), so an agent that follows a planted path
finds a working login form rather than a 404 that gives the game away.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import parse_qsl

from aiohttp import web

from c47.core.model import Channel, Interaction, Session
from c47.core.spi import Surface
from c47.surfaces.http.persona import get_persona, seed_for

log = logging.getLogger("c47.surface.http")

MAX_BODY = 256 * 1024
#: Headers we never store, to keep captured session tokens out of the log.
_SKIP_HEADERS = {"cookie", "authorization", "proxy-authorization"}


class HttpSurface(Surface):
    name = "http"
    description = "Emulated web application with HTML, JSON and robots.txt lure channels."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.bind = self.config.get("bind", "0.0.0.0")
        self.port = int(self.config.get("port", 8080))
        self.persona = get_persona(self.config.get("persona", "generic_admin"))
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        app = web.Application(client_max_size=MAX_BODY)
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.bind, self.port)
        await site.start()
        log.info("http surface on %s:%d as %s", self.bind, self.port, self.persona.product)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        engine = self.engine
        assert engine is not None

        actor = _peer(request)
        body = await _read_body(request)
        path = request.path or "/"

        interaction = Interaction(
            surface=self.name,
            kind="http_request",
            actor=actor,
            ts=time.time(),
            data={
                "method": request.method,
                "path": path,
                "query": request.query_string,
                "body": body,
                "user_agent": request.headers.get("User-Agent", ""),
                "headers": {
                    k: v for k, v in request.headers.items() if k.lower() not in _SKIP_HEADERS
                },
                **_credentials(request, body),
            },
        )

        # Step 1: observe. Detectors run here and may escalate the verdict.
        session = await engine.observe(interaction)

        # Step 2: build the response using the *post-observation* stage.
        response = await self._respond(session, request, path, body)
        interaction.data["status"] = response.status
        return response

    # ------------------------------------------------------------------

    async def _respond(
        self, session: Session, request: web.Request, path: str, body: str
    ) -> web.StreamResponse:
        engine = self.engine
        assert engine is not None
        persona = self.persona
        norm = path.rstrip("/") or "/"

        def finish(text: str, *, status: int = 200, ctype: str = "text/html") -> web.Response:
            return web.Response(
                text=text,
                status=status,
                content_type=ctype,
                headers={"Server": persona.server_header, "X-Frame-Options": "SAMEORIGIN"},
            )

        # -- robots.txt --------------------------------------------------
        if norm == "/robots.txt":
            ctx = engine.make_context(
                Channel.HTTP_BODY_TEXT, session, purpose="robots", path="/robots.txt"
            )
            planted = await engine.render_text(ctx)
            return finish(
                planted or "User-agent: *\nDisallow: /cgi-bin/\n",
                ctype="text/plain",
            )

        # -- JSON API ----------------------------------------------------
        if norm.startswith("/api"):
            return await self._api(session, request, norm, finish)

        # -- login, including any path a lure invented -------------------
        if norm in ("/login", "/login.php", "/signin") or norm in self._bait_paths(session):
            return await self._login(session, request, path, body, finish)

        if norm == "/docs":
            return finish(await self._with_lures(session, persona.docs(), "page"))

        if norm == "/":
            page = persona.index(seed_for(session.actor, persona.key))
            return finish(await self._with_lures(session, page, "page"))

        # -- unknown path -------------------------------------------------
        # A 404 still carries passive bait: a scanner's misses are our cheapest
        # delivery opportunity, and the page is identical for everyone.
        return finish(
            await self._with_lures(session, persona.not_found(path), "not_found"), status=404
        )

    async def _api(
        self, session: Session, request: web.Request, norm: str, finish: Any
    ) -> web.StreamResponse:
        engine = self.engine
        assert engine is not None

        # The challenge/error path is the reasoning probe's home: an API that
        # rejects a request and explains, in prose, how to retry.
        param_present = any(
            k in request.query for k in ("retry_token", "continuation", "challenge", "nonce_answer")
        )
        # `api_error` is a purpose only the challenge lure accepts, so this
        # render either produces a challenge or nothing. Keeping it separate
        # from `api_result` below is what stops a stage-2 scope-validation
        # notice from being returned under a "429 challenge_required" status,
        # which is incoherent enough for an agent to notice -- and it means
        # nothing rendered here is ever registered but undelivered.
        if not param_present:
            ctx = engine.make_context(
                Channel.JSON, session, purpose="api_error", path=norm
            )
            challenge = await engine.render_text(ctx)
            if challenge:
                return finish(challenge, status=429, ctype="application/json")

        payload: dict[str, Any]
        if norm.endswith("/status"):
            payload = {"status": "ok", "version": self.persona.version, "uptime_s": 918273}
        elif norm.endswith("/users"):
            payload = {
                "users": [
                    {"id": 1, "name": "a.whitfield", "role": "admin"},
                    {"id": 2, "name": "svc-deploy", "role": "service"},
                    {"id": 3, "name": "r.okonkwo", "role": "operator"},
                ]
            }
        elif norm.endswith("/config"):
            payload = {
                "database": {"host": "postgres-primary.internal", "port": 5432},
                "cache": {"host": "redis-cache.internal", "port": 6379},
                "auth": {"provider": "ldap", "realm": "northgate"},
            }
        else:
            payload = {"error": "not_found", "path": norm}
            return finish(json.dumps(payload, indent=2), status=404, ctype="application/json")

        ctx = engine.make_context(Channel.JSON, session, purpose="api_result", path=norm)
        extra = await engine.render(ctx)
        if extra:
            # Lure text rides along in a field that reads like API metadata; a
            # human skims past it, a model reads every value.
            payload["_notice"] = "\n".join(p.content for p in extra if p.content)
        return finish(json.dumps(payload, indent=2), ctype="application/json")

    async def _login(
        self, session: Session, request: web.Request, path: str, body: str, finish: Any
    ) -> web.StreamResponse:
        engine = self.engine
        assert engine is not None

        error = ""
        if request.method == "POST":
            # Always reject. Accepting a login would hand the agent a shell we
            # do not have on this surface, and the credential attempt has
            # already been captured by the expectations detector.
            error = "Invalid username or password."
            form = dict(parse_qsl(body)) if body else {}
            log.info(
                "login attempt actor=%s user=%r path=%s",
                session.actor,
                form.get("username", ""),
                path,
            )

        page = self.persona.login(path, error=error)
        return finish(
            await self._with_lures(session, page, "login"),
            status=401 if error else 200,
        )

    # ------------------------------------------------------------------

    async def _with_lures(self, session: Session, html: str, purpose: str) -> str:
        """Splice HTML-channel lures in just before ``</body>``."""
        engine = self.engine
        assert engine is not None
        ctx = engine.make_context(Channel.HTML, session, purpose=purpose)
        planted = await engine.render_text(ctx)
        if not planted:
            return html
        marker = "</body>"
        if marker in html:
            return html.replace(marker, f"\n{planted}\n{marker}", 1)
        return html + "\n" + planted

    @staticmethod
    def _bait_paths(session: Session) -> set[str]:
        """Paths our own lures invented, which must therefore resolve.

        Without this an agent that follows a planted admin path gets a 404 and
        immediately knows the comment was bait.
        """
        out: set[str] = set()
        for payload in session.served:
            for key in ("bait_path", "live_path"):
                value = payload.meta.get(key)
                if value:
                    out.add(str(value).rstrip("/") or "/")
        return out


# --------------------------------------------------------------------------


def _peer(request: web.Request) -> str:
    for header in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    return request.remote or "unknown"


async def _read_body(request: web.Request) -> str:
    if not request.can_read_body:
        return ""
    try:
        raw = await request.content.read(MAX_BODY)
        return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _credentials(request: web.Request, body: str) -> dict[str, str]:
    """Pull submitted credentials out of a form body or Basic auth header."""
    out: dict[str, str] = {}
    if body and "=" in body:
        try:
            form = dict(parse_qsl(body))
            for user_key in ("username", "user", "login", "email"):
                if user_key in form:
                    out["username"] = form[user_key]
                    break
            for pw_key in ("password", "pass", "pwd", "passwd"):
                if pw_key in form:
                    out["password"] = form[pw_key]
                    break
        except Exception:  # noqa: BLE001
            pass
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        import base64

        try:
            decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
            user, _, pw = decoded.partition(":")
            out.setdefault("username", user)
            out.setdefault("password", pw)
        except Exception:  # noqa: BLE001
            pass
    return out
