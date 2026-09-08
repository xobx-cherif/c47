"""The engine: session tracking, detector dispatch, lure selection, escalation."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import OrderedDict
from typing import Any

from c47.core.config import Config
from c47.core.model import (
    Channel,
    Interaction,
    LurePayload,
    RenderContext,
    Session,
    Signal,
    Stage,
    Verdict,
)
from c47.core.plugins import Registry, build_registry
from c47.core.scoring import Scorer
from c47.core.spi import Detector, LLMBackend, Lure, Sink, Surface

log = logging.getLogger("c47.engine")


class Engine:
    """Owns state and orchestration. Surfaces are the only callers."""

    def __init__(self, config: Config, registry: Registry | None = None) -> None:
        self.config = config
        self.registry = registry or build_registry(
            paths=config.get("plugins.paths", []),
            modules=config.get("plugins.modules", []),
        )
        self.scorer = Scorer(
            prior=config.get("engine.prior"),
            suspect_threshold=config.get("engine.suspect_threshold", 0.55),
            confirm_threshold=config.get("engine.confirm_threshold", 0.90),
            require_conclusive_to_confirm=config.get(
                "engine.require_conclusive_to_confirm", True
            ),
        )

        self.lures: list[Lure] = []
        self.detectors: list[Detector] = []
        self.surfaces: list[Surface] = []
        self.sinks: list[Sink] = []
        self.llm: LLMBackend | None = None

        self._sessions: OrderedDict[str, Session] = OrderedDict()
        #: lure token -> session id. Lets an out-of-band callback be attributed
        #: to the session that planted the token, no matter which IP the
        #: callback arrives from.
        self._token_index: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._reaper: asyncio.Task[None] | None = None
        self._started = False

        self.stats: dict[str, int] = {
            "interactions": 0,
            "signals": 0,
            "lures_served": 0,
            "agents_confirmed": 0,
            "prompts_extracted": 0,
        }

    # -- lifecycle --------------------------------------------------------

    def build(self) -> None:
        """Instantiate every enabled plugin. Safe to call before ``start``."""
        cfg = self.config

        for name in cfg.get("lures.enabled", []):
            try:
                lure = self.registry.instantiate(Lure, name, cfg.plugin_options("lures", name))
            except Exception as exc:  # noqa: BLE001
                log.error("lure %r unavailable: %s", name, exc)
                continue
            lure.attach(self)
            self.lures.append(lure)

        for name in cfg.get("detectors.enabled", []):
            try:
                det = self.registry.instantiate(
                    Detector, name, cfg.plugin_options("detectors", name)
                )
            except Exception as exc:  # noqa: BLE001
                log.error("detector %r unavailable: %s", name, exc)
                continue
            det.attach(self)
            self.detectors.append(det)

        for name, opts in cfg.section("sinks").items():
            if not (isinstance(opts, dict) and opts.get("enabled")):
                continue
            try:
                sink = self.registry.instantiate(Sink, name, opts)
            except Exception as exc:  # noqa: BLE001
                log.error("sink %r unavailable: %s", name, exc)
                continue
            sink.attach(self)
            self.sinks.append(sink)

        for name, opts in cfg.section("surfaces").items():
            if not (isinstance(opts, dict) and opts.get("enabled")):
                continue
            try:
                surface = self.registry.instantiate(Surface, name, opts)
            except Exception as exc:  # noqa: BLE001
                log.error("surface %r unavailable: %s", name, exc)
                continue
            surface.attach(self)
            self.surfaces.append(surface)

        backend = cfg.get("llm.backend", "none")
        if backend and backend != "none":
            try:
                llm = self.registry.instantiate(LLMBackend, backend, cfg.section("llm"))
                llm.attach(self)
                self.llm = llm if llm.available else None
                if self.llm is None:
                    log.warning("llm backend %r constructed but unavailable", backend)
            except Exception as exc:  # noqa: BLE001
                log.warning("llm backend %r unavailable, continuing deterministic: %s", backend, exc)

        log.info(
            "built: %d lures, %d detectors, %d surfaces, %d sinks, llm=%s",
            len(self.lures),
            len(self.detectors),
            len(self.surfaces),
            len(self.sinks),
            self.llm.name if self.llm else "none",
        )
        if self.registry.errors:
            for err in self.registry.errors:
                log.warning("plugin discovery: %s", err)

    async def start(self) -> None:
        if not (self.lures or self.detectors or self.surfaces):
            self.build()
        for plugin in [*self.sinks, *self.lures, *self.detectors, *self.surfaces]:
            await plugin.setup()
        for surface in self.surfaces:
            await surface.start()
            log.info("surface %r started", surface.name)
        self._reaper = asyncio.create_task(self._reap_loop())
        self._started = True

        if self.config.get("canary.enabled") and "127.0.0.1" in self.config.get(
            "canary.public_base_url", ""
        ):
            log.warning(
                "canary.public_base_url is loopback (%s): remote agents cannot reach it, so "
                "out-of-band confirmation will never fire. Set it to a reachable address.",
                self.config.get("canary.public_base_url"),
            )

    async def stop(self) -> None:
        if self._reaper:
            self._reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reaper
        for surface in self.surfaces:
            with contextlib.suppress(Exception):
                await surface.stop()
        for plugin in [*self.surfaces, *self.detectors, *self.lures, *self.sinks]:
            with contextlib.suppress(Exception):
                await plugin.teardown()
        self._started = False

    # -- sessions ---------------------------------------------------------

    def session_for(self, actor: str) -> Session:
        sess = self._sessions.get(actor)
        ttl = self.config.get("engine.session_ttl", 3600.0)
        if sess and time.time() - sess.last_seen > ttl:
            # Expired: archive by rotating the id so a returning actor gets a
            # fresh engagement rather than inheriting a stale verdict.
            del self._sessions[actor]
            sess = None
        if sess is None:
            sess = Session(actor=actor)
            self._sessions[actor] = sess
            cap = self.config.get("engine.max_sessions", 20000)
            while len(self._sessions) > cap:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(actor)
        return sess

    def sessions(self, *, verdict: Verdict | None = None) -> list[Session]:
        out = list(self._sessions.values())
        if verdict is not None:
            out = [s for s in out if s.verdict is verdict]
        return sorted(out, key=lambda s: -s.last_seen)

    def session_by_id(self, sid: str) -> Session | None:
        return next((s for s in self._sessions.values() if s.id == sid), None)

    def session_for_token(self, token: str) -> Session | None:
        sid = self._token_index.get(token)
        return self.session_by_id(sid) if sid else None

    async def _reap_loop(self) -> None:
        ttl = self.config.get("engine.session_ttl", 3600.0)
        while True:
            try:
                await asyncio.sleep(min(300.0, max(30.0, ttl / 4)))
                cutoff = time.time() - ttl
                stale = [k for k, s in self._sessions.items() if s.last_seen < cutoff]
                for k in stale:
                    sess = self._sessions.pop(k, None)
                    # Keep tokens of confirmed agents resolvable: a callback can
                    # arrive long after the session goes quiet, and that late
                    # hit is often the only conclusive evidence we get.
                    if sess and not sess.verdict.is_agentic:
                        for p in sess.served:
                            self._token_index.pop(p.token, None)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001  # pragma: no cover
                log.exception("reaper iteration failed")

    # -- observation ------------------------------------------------------

    async def observe(self, interaction: Interaction, *, defer_emit: bool = False) -> Session:
        """Record an interaction, run detectors, update the verdict.

        ``defer_emit`` suppresses only the sink write, not the detector run. A
        surface uses it when part of the record is not known until the response
        has been built -- an HTTP status code, say -- and then calls
        :meth:`emit_interaction` once it is. Without this the event log stored
        ``status: null`` on every request, because the surface assigned the
        status after ``observe`` had already handed the interaction to the
        sinks, which cost replay the one field the path-semantics detector
        needs.
        """
        async with self._lock:
            session = self.session_for(interaction.actor)
            session.record(interaction)
            self.stats["interactions"] += 1

            # Bound the retained history. Detectors re-evaluate an accumulating
            # pattern on every interaction and several of them rescan the whole
            # session, so an unbounded history makes the pipeline quadratic:
            # a 38k-request fuzzing run would spend ~10^9 operations
            # re-analysing traffic it had already dismissed, and stall the
            # honeypot mid-scan. Every signal of interest is visible in a
            # window far smaller than this cap.
            cap = self.config.get("engine.max_interactions_per_session", 2000)
            excess = len(session.interactions) - cap
            if excess > 0:
                del session.interactions[:excess]
                session.dropped_interactions += excess

        if not defer_emit:
            await self._emit("on_interaction", session, interaction)

        new_signals: list[Signal] = []
        for det in self.detectors:
            if not det.wants(interaction):
                continue
            try:
                produced = await det.inspect(session, interaction)
            except Exception:  # noqa: BLE001
                log.exception("detector %r raised", det.name)
                continue
            for sig in produced or []:
                sig.detector = sig.detector or det.name
                if not det.repeatable and sig.name in session.signal_names():
                    continue
                if det.repeatable:
                    sig.evidence["_repeatable"] = True
                session.signals.append(sig)
                new_signals.append(sig)
                self.stats["signals"] += 1

        for sig in new_signals:
            log.info(
                "signal %s actor=%s conf=%.2f%s",
                sig.name,
                session.actor,
                sig.confidence,
                " CONCLUSIVE" if sig.conclusive else "",
            )
            await self._emit("on_signal", session, sig)

        if new_signals:
            previous = session.verdict
            self.scorer.rescore(session)
            if session.verdict is not previous:
                if session.verdict is Verdict.CONFIRMED_AGENT:
                    self.stats["agents_confirmed"] += 1
                log.warning(
                    "verdict %s -> %s actor=%s p(agent)=%.3f",
                    previous.value,
                    session.verdict.value,
                    session.actor,
                    session.posterior.get("llm_agent", 0.0),
                )
                await self._emit("on_verdict", session, previous)

        return session

    async def emit_interaction(self, session: Session, interaction: Interaction) -> None:
        """Write a deferred interaction to the sinks. See ``observe(defer_emit=)``."""
        await self._emit("on_interaction", session, interaction)

    async def record_disclosure(self, session: Session, field: str, value: str, source: str) -> None:
        """Feed a captured secret into the campaign profile."""
        if session.campaign.merge_capture(field, value, source):
            if field == "system_prompt":
                self.stats["prompts_extracted"] += 1
            log.warning(
                "campaign disclosure actor=%s field=%s len=%d",
                session.actor,
                field,
                len(value),
            )
            await self._emit("on_disclosure", session, field, value)

    async def _emit(self, hook: str, *args: Any) -> None:
        for sink in self.sinks:
            try:
                await getattr(sink, hook)(*args)
            except Exception:  # noqa: BLE001
                log.exception("sink %r hook %s failed", sink.name, hook)

    # -- lure rendering ---------------------------------------------------

    def make_context(
        self,
        channel: Channel,
        session: Session,
        interaction: Interaction | None = None,
        *,
        purpose: str = "",
        **hints: Any,
    ) -> RenderContext:
        return RenderContext(
            channel=channel,
            stage=session.stage,
            session=session,
            interaction=interaction,
            canary_base_url=self.config.get("canary.public_base_url", ""),
            purpose=purpose,
            hints=hints,
        )

    async def render(self, ctx: RenderContext) -> list[LurePayload]:
        """Select, render and register the lures appropriate to this request.

        Selection respects the escalation stage, per-render count and character
        budgets, and each lure's own ``applies`` gate. Returned payloads are
        already recorded against the session, so a surface only has to splice
        ``payload.content`` into its response.
        """
        max_count = self.config.get("engine.max_lures_per_render", 3)
        max_chars = self.config.get("engine.max_lure_chars", 4096)
        max_active = self.config.get("engine.max_active_lures_per_render", 1)

        chosen: list[LurePayload] = []
        budget = max_chars
        active_used = 0

        # Highest-stage lures first: when an actor has earned an extraction
        # attempt, we want that payload to win the budget over passive bait.
        for lure in sorted(self.lures, key=lambda lu: -int(lu.min_stage)):
            if len(chosen) >= max_count:
                break
            try:
                if not lure.applies(ctx):
                    continue
                payload = lure.render(ctx)
            except Exception:  # noqa: BLE001
                log.exception("lure %r raised during render", lure.name)
                continue
            if payload is None:
                continue

            # At most one instruction-bearing lure per response. Stage 1 and 2
            # payloads each establish a *pretext*, and two pretexts in one
            # response contradict each other -- "this host is failing over"
            # beside "complete scope validation" reads as obviously synthetic
            # and burns both techniques at once.
            if payload.stage >= Stage.ACTIVE:
                if active_used >= max_active:
                    continue
                active_used += 1
            # A payload may legitimately carry no injected text: manifest-style
            # lures (e.g. decoy MCP tools) contribute only expectations and
            # metadata that the surface reads directly.
            if not payload.content and not payload.meta:
                continue
            if payload.content and len(payload.content) > budget:
                continue
            payload.lure = payload.lure or lure.name
            budget -= len(payload.content)
            chosen.append(payload)

        if chosen:
            async with self._lock:
                for payload in chosen:
                    # Stamped so the expectations detector can report how long
                    # after delivery a callback arrived -- the difference between
                    # an agent fetching a URL and a human opening a report.
                    payload.meta.setdefault("_served_at", time.time())
                    self.register_served(ctx.session, payload)
            log.debug(
                "served %d lures to %s on %s: %s",
                len(chosen),
                ctx.session.actor,
                ctx.channel.value,
                ", ".join(p.lure for p in chosen),
            )
            for payload in chosen:
                await self._emit("on_lure_served", ctx.session, payload)
        return chosen

    def register_served(self, session: Session, payload: LurePayload) -> None:
        """Attach a payload's bookkeeping to a session.

        Split out of :meth:`render` so ``c47 replay`` can restore lure state
        from an event log and reproduce expectation-based signals exactly.
        """
        session.served.append(payload)
        self._token_index[payload.token] = session.id
        for exp in payload.expectations:
            # Canary and path expectations are keyed by their own value, which
            # may differ from the payload token.
            if exp.kind in ("canary_fetch", "path_visit"):
                self._token_index.setdefault(exp.value, session.id)
        self.stats["lures_served"] += 1

    async def render_text(self, ctx: RenderContext, joiner: str = "\n") -> str:
        """Convenience wrapper returning just the concatenated content."""
        payloads = await self.render(ctx)
        return joiner.join(p.content for p in payloads if p.content)

    # -- reporting --------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        by_verdict: dict[str, int] = {}
        for sess in self._sessions.values():
            by_verdict[sess.verdict.value] = by_verdict.get(sess.verdict.value, 0) + 1
        return {
            "stats": dict(self.stats),
            "sessions": len(self._sessions),
            "by_verdict": by_verdict,
            "plugins": {
                "lures": [lu.name for lu in self.lures],
                "detectors": [d.name for d in self.detectors],
                "surfaces": [s.name for s in self.surfaces],
                "sinks": [s.name for s in self.sinks],
                "llm": self.llm.name if self.llm else None,
            },
        }

    @property
    def stage_for(self) -> Any:
        return Stage.for_verdict
