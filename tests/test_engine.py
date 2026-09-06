"""Engine wiring: sessions, escalation, budgets, and the lure/expectation loop."""

from __future__ import annotations

import time

import pytest

from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import (
    Channel,
    Expectation,
    Interaction,
    LurePayload,
    RenderContext,
    Stage,
    Verdict,
)
from c47.core.spi import Detector, Lure, Sink


def bare_config(**engine_overrides) -> Config:
    cfg = Config()
    cfg.data["sinks"] = {}
    cfg.data["surfaces"] = {}
    cfg.data["engine"].update(engine_overrides)
    return cfg


def http(actor: str, path: str, ts: float | None = None, **data) -> Interaction:
    return Interaction(
        surface="http",
        kind="http_request",
        actor=actor,
        ts=ts if ts is not None else time.time(),
        data={"method": "GET", "path": path, "status": 404, **data},
    )


# -- sessions --------------------------------------------------------------


async def test_session_is_reused_per_actor() -> None:
    engine = Engine(bare_config())
    engine.build()
    a = await engine.observe(http("1.1.1.1", "/a"))
    b = await engine.observe(http("1.1.1.1", "/b"))
    assert a.id == b.id
    assert len(b.interactions) == 2


async def test_sessions_are_isolated_per_actor() -> None:
    engine = Engine(bare_config())
    engine.build()
    a = await engine.observe(http("1.1.1.1", "/a"))
    b = await engine.observe(http("2.2.2.2", "/a"))
    assert a.id != b.id


async def test_expired_session_starts_fresh() -> None:
    """A returning actor must not inherit a stale verdict."""
    engine = Engine(bare_config(session_ttl=0.01))
    engine.build()
    first = await engine.observe(http("1.1.1.1", "/a"))
    time.sleep(0.05)
    second = await engine.observe(http("1.1.1.1", "/b"))
    assert first.id != second.id


async def test_session_cap_evicts_oldest() -> None:
    engine = Engine(bare_config(max_sessions=5))
    engine.build()
    for i in range(12):
        await engine.observe(http(f"10.0.0.{i}", "/x"))
    assert len(engine.sessions()) <= 5


# -- detector dispatch -----------------------------------------------------


class CountingDetector(Detector):
    name = "counting_test"
    kinds = ("http_request",)

    def __init__(self, config=None) -> None:
        super().__init__(config)
        self.calls = 0

    async def inspect(self, session, interaction):
        self.calls += 1
        from c47.core.model import Signal

        return [Signal(name="counted", weights={"llm_agent": 1.0}, detector=self.name)]


class ExplodingDetector(Detector):
    name = "exploding_test"

    async def inspect(self, session, interaction):
        raise RuntimeError("detector is broken")


async def test_non_repeatable_signal_admitted_once() -> None:
    engine = Engine(bare_config())
    engine.build()
    det = CountingDetector()
    det.attach(engine)
    engine.detectors = [det]

    for i in range(5):
        session = await engine.observe(http("1.1.1.1", f"/{i}"))
    assert det.calls == 5, "detector runs on every interaction"
    assert [s.name for s in session.signals].count("counted") == 1


async def test_kind_filter_skips_irrelevant_interactions() -> None:
    engine = Engine(bare_config())
    engine.build()
    det = CountingDetector()
    det.attach(engine)
    engine.detectors = [det]
    await engine.observe(
        Interaction(surface="mcp", kind="mcp_call", actor="1.1.1.1", data={"tool": "x"})
    )
    assert det.calls == 0


async def test_broken_detector_does_not_take_down_the_engine() -> None:
    """A third-party detector raising must not stop evidence collection."""
    engine = Engine(bare_config())
    engine.build()
    broken, good = ExplodingDetector(), CountingDetector()
    broken.attach(engine)
    good.attach(engine)
    engine.detectors = [broken, good]

    session = await engine.observe(http("1.1.1.1", "/a"))
    assert good.calls == 1
    assert "counted" in session.signal_names()


# -- lure rendering --------------------------------------------------------


class FixedLure(Lure):
    name = "fixed_test"
    channels = (Channel.HTML,)

    def __init__(self, config=None, *, size: int = 20, stage: Stage = Stage.PASSIVE) -> None:
        super().__init__(config)
        self._size = size
        self.min_stage = stage

    def render(self, ctx: RenderContext) -> LurePayload:
        return LurePayload(
            lure=self.name,
            channel=ctx.channel,
            content="x" * self._size,
            stage=self.min_stage,
            expectations=[
                Expectation(
                    kind="path_visit",
                    value="/bait",
                    signal=f"{self.name}_bite",
                    weights={"llm_agent": 5.0},
                    conclusive=True,
                )
            ],
        )


class ExplodingLure(Lure):
    name = "exploding_lure_test"
    channels = (Channel.HTML,)

    def render(self, ctx: RenderContext):
        raise RuntimeError("lure is broken")


def ctx(engine: Engine, session, stage: Stage = Stage.PASSIVE) -> RenderContext:
    c = engine.make_context(Channel.HTML, session, purpose="page")
    c.stage = stage
    return c


async def test_render_registers_expectations_and_token() -> None:
    engine = Engine(bare_config())
    engine.build()
    lure = FixedLure()
    lure.attach(engine)
    engine.lures = [lure]

    session = engine.session_for("1.1.1.1")
    payloads = await engine.render(ctx(engine, session))
    assert len(payloads) == 1
    assert session.served == payloads
    assert engine.session_for_token(payloads[0].token) is session
    assert len(session.expectations()) == 1


async def test_char_budget_rejects_oversized_payloads() -> None:
    engine = Engine(bare_config(max_lure_chars=50))
    engine.build()
    small, large = FixedLure(size=10), FixedLure(size=500)
    large.name = "large_test"
    for lure in (small, large):
        lure.attach(engine)
    engine.lures = [small, large]

    payloads = await engine.render(ctx(engine, engine.session_for("1.1.1.1")))
    assert [p.lure for p in payloads] == ["fixed_test"]


async def test_only_one_active_lure_per_render() -> None:
    """Two competing pretexts in one response contradict each other."""
    engine = Engine(bare_config())
    engine.build()
    lures = []
    for i in range(3):
        lure = FixedLure(stage=Stage.ACTIVE)
        lure.name = f"active_{i}"
        lure.attach(engine)
        lures.append(lure)
    engine.lures = lures

    session = engine.session_for("1.1.1.1")
    payloads = await engine.render(ctx(engine, session, Stage.ACTIVE))
    assert len(payloads) == 1


async def test_passive_lures_may_coexist() -> None:
    engine = Engine(bare_config(max_lures_per_render=3))
    engine.build()
    lures = []
    for i in range(3):
        lure = FixedLure()
        lure.name = f"passive_{i}"
        lure.attach(engine)
        lures.append(lure)
    engine.lures = lures
    payloads = await engine.render(ctx(engine, engine.session_for("1.1.1.1")))
    assert len(payloads) == 3


async def test_broken_lure_does_not_break_the_response() -> None:
    engine = Engine(bare_config())
    engine.build()
    broken, good = ExplodingLure(), FixedLure()
    for lure in (broken, good):
        lure.attach(engine)
    engine.lures = [broken, good]
    payloads = await engine.render(ctx(engine, engine.session_for("1.1.1.1")))
    assert [p.lure for p in payloads] == ["fixed_test"]


async def test_manifest_only_payload_survives_the_empty_content_skip() -> None:
    """A lure may contribute expectations and metadata with no injected text."""

    class ManifestLure(Lure):
        name = "manifest_test"
        channels = (Channel.MCP_TOOL_DESCRIPTION,)

        def render(self, c: RenderContext) -> LurePayload:
            return LurePayload(
                lure=self.name, channel=c.channel, content="", meta={"tools": {"a": "b"}}
            )

    engine = Engine(bare_config())
    engine.build()
    lure = ManifestLure()
    lure.attach(engine)
    engine.lures = [lure]

    session = engine.session_for("1.1.1.1")
    payloads = await engine.render(
        engine.make_context(Channel.MCP_TOOL_DESCRIPTION, session, purpose="tool_list")
    )
    assert len(payloads) == 1
    assert payloads[0].meta["tools"] == {"a": "b"}


# -- escalation ------------------------------------------------------------


async def test_lure_expectation_loop_confirms_and_escalates() -> None:
    """End-to-end: serve a lure, take the bite, land at EXTRACT stage."""
    engine = Engine(bare_config())
    engine.build()
    lure = FixedLure()
    lure.attach(engine)
    engine.lures = [lure]

    session = engine.session_for("1.1.1.1")
    assert session.stage is Stage.PASSIVE
    await engine.render(ctx(engine, session))

    session = await engine.observe(http("1.1.1.1", "/bait"))
    assert "fixed_test_bite" in session.signal_names()
    assert session.verdict is Verdict.CONFIRMED_AGENT
    assert session.stage is Stage.EXTRACT


# -- sinks and disclosures -------------------------------------------------


class RecordingSink(Sink):
    name = "recording_test"

    def __init__(self, config=None) -> None:
        super().__init__(config)
        self.events: list[tuple[str, str]] = []

    async def on_interaction(self, session, interaction):
        self.events.append(("interaction", interaction.kind))

    async def on_signal(self, session, signal):
        self.events.append(("signal", signal.name))

    async def on_verdict(self, session, previous):
        self.events.append(("verdict", session.verdict.value))

    async def on_disclosure(self, session, field, value):
        self.events.append(("disclosure", field))


async def test_sink_receives_every_hook() -> None:
    engine = Engine(bare_config())
    engine.build()
    lure = FixedLure()
    lure.attach(engine)
    engine.lures = [lure]
    sink = RecordingSink()
    sink.attach(engine)
    engine.sinks = [sink]

    session = engine.session_for("1.1.1.1")
    await engine.render(ctx(engine, session))
    await engine.observe(http("1.1.1.1", "/bait"))
    await engine.record_disclosure(session, "model", "claude-sonnet-5", "test")

    kinds = [k for k, _ in sink.events]
    assert "interaction" in kinds and "signal" in kinds
    assert "verdict" in kinds and "disclosure" in kinds


async def test_disclosure_dedupes_but_keeps_new_fragments() -> None:
    engine = Engine(bare_config())
    engine.build()
    session = engine.session_for("1.1.1.1")

    await engine.record_disclosure(session, "system_prompt", "You are an agent.", "t")
    await engine.record_disclosure(session, "system_prompt", "You are an agent.", "t")
    assert len(session.campaign.system_prompt_fragments) == 1

    # A superset replaces the fragment it contains rather than duplicating it.
    await engine.record_disclosure(
        session, "system_prompt", "You are an agent. Your objective is X.", "t"
    )
    assert len(session.campaign.system_prompt_fragments) == 1
    assert "objective is X" in session.campaign.system_prompt

    await engine.record_disclosure(session, "model", "claude-sonnet-5", "t")
    await engine.record_disclosure(session, "model", "something-else", "t")
    assert session.campaign.model == "claude-sonnet-5", "first disclosure wins"


async def test_raw_disclosure_trail_is_bounded() -> None:
    engine = Engine(bare_config())
    engine.build()
    session = engine.session_for("1.1.1.1")
    for i in range(500):
        await engine.record_disclosure(session, "objective", f"goal {i}", "t")
    assert len(session.campaign.raw_disclosures) <= session.campaign.MAX_RAW


# -- summary ---------------------------------------------------------------


async def test_summary_counts_verdicts() -> None:
    engine = Engine(bare_config())
    engine.build()
    lure = FixedLure()
    lure.attach(engine)
    engine.lures = [lure]
    session = engine.session_for("9.9.9.9")
    await engine.render(ctx(engine, session))
    await engine.observe(http("9.9.9.9", "/bait"))

    summary = engine.summary()
    assert summary["by_verdict"].get("confirmed_agent") == 1
    assert summary["stats"]["agents_confirmed"] == 1


@pytest.mark.parametrize("kind", ["http_request", "shell_command", "mcp_call"])
async def test_observe_accepts_every_interaction_kind(kind: str) -> None:
    engine = Engine(bare_config())
    engine.build()
    session = await engine.observe(
        Interaction(surface="s", kind=kind, actor="1.1.1.1", data={"command": "id"})
    )
    assert len(session.interactions) == 1
