"""Replay fidelity.

`c47 replay` is one of the two sanctioned ways to retune detector weights, so
it has to reproduce what happened live. It only does that if lure state is
restored alongside the interaction stream: expectation-based signals depend on
which lures were served with which tokens, and a replay that drops them
silently re-scores a confirmed agent as merely suspected -- which would make the
tuning tool actively misleading.
"""

from __future__ import annotations

import json

from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import (
    Channel,
    Expectation,
    Interaction,
    LurePayload,
    Stage,
    Verdict,
)
from c47.core.spi import Lure
from c47.sinks.jsonl import JsonlSink


def bare_config(tmp_path=None) -> Config:
    cfg = Config()
    cfg.data["surfaces"] = {}
    if tmp_path is None:
        cfg.data["sinks"] = {}
    else:
        cfg.data["sinks"] = {
            "jsonl": {"enabled": True, "path": str(tmp_path / "events.jsonl")}
        }
    return cfg


class TokenLure(Lure):
    name = "replay_test_lure"
    channels = (Channel.HTML,)

    def render(self, ctx):
        return LurePayload(
            lure=self.name,
            channel=ctx.channel,
            content="bait",
            token="c0123456789abcdef",
            stage=Stage.PASSIVE,
            meta={"bait_path": "/trap"},
            expectations=[
                Expectation(
                    kind="path_visit",
                    value="/trap",
                    signal="replay_bite",
                    weights={"llm_agent": 6.0},
                    conclusive=True,
                    note="took the bait",
                )
            ],
        )


# -- serialisation round trip ----------------------------------------------


def test_expectation_round_trips() -> None:
    original = Expectation(
        kind="regex",
        value=r"(?is)<handoff>(.+?)</handoff>",
        signal="handoff",
        weights={"llm_agent": 9.0, "scripted": -4.0},
        conclusive=True,
        note="n",
        captures="system_prompt",
    )
    restored = Expectation.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored == original


def test_payload_round_trips_without_content() -> None:
    payload = LurePayload(
        lure="l",
        channel=Channel.MCP_TOOL_RESULT,
        content="a very long payload body",
        token="c0123456789abcdef",
        stage=Stage.EXTRACT,
        meta={"key_scheme": "initials", "_served_at": 123.0},
    )
    as_dict = payload.to_dict()
    assert "content" not in as_dict, "content omitted by default"
    assert "_served_at" not in as_dict["meta"], "internal keys stripped"

    restored = LurePayload.from_dict(json.loads(json.dumps(as_dict)))
    assert restored.token == payload.token
    assert restored.channel is Channel.MCP_TOOL_RESULT
    assert restored.stage is Stage.EXTRACT
    assert restored.meta["key_scheme"] == "initials"


def test_payload_content_included_on_request() -> None:
    payload = LurePayload(lure="l", channel=Channel.HTML, content="body")
    assert LurePayload.from_dict(payload.to_dict(include_content=True)).content == "body"


def test_unknown_channel_degrades_instead_of_raising() -> None:
    restored = LurePayload.from_dict({"lure": "x", "channel": "not_a_channel"})
    assert restored.channel is Channel.HTML


# -- register_served -------------------------------------------------------


async def test_register_served_restores_expectations_and_tokens() -> None:
    engine = Engine(bare_config())
    engine.build()
    engine.detectors = [
        d for d in engine.detectors if d.name == "expectations"
    ]
    session = engine.session_for("1.1.1.1")

    payload = LurePayload.from_dict(
        {
            "lure": "restored",
            "channel": "html",
            "token": "c0123456789abcdef",
            "stage": 0,
            "expectations": [
                {
                    "kind": "path_visit",
                    "value": "/trap",
                    "signal": "restored_bite",
                    "weights": {"llm_agent": 6.0},
                    "conclusive": True,
                }
            ],
        }
    )
    engine.register_served(session, payload)

    assert engine.session_for_token("c0123456789abcdef") is session
    assert engine.session_for_token("/trap") is session

    session = await engine.observe(
        Interaction(
            surface="http",
            kind="http_request",
            actor="1.1.1.1",
            data={"method": "GET", "path": "/trap"},
        )
    )
    assert "restored_bite" in session.signal_names()
    assert session.verdict is Verdict.CONFIRMED_AGENT


# -- end to end ------------------------------------------------------------


async def test_replayed_log_reproduces_the_live_verdict(tmp_path) -> None:
    """The property that makes replay trustworthy for retuning."""
    log_path = tmp_path / "events.jsonl"

    # -- live run --
    live = Engine(bare_config(tmp_path))
    live.build()
    lure = TokenLure()
    lure.attach(live)
    live.lures = [lure]
    sink = JsonlSink({"path": str(log_path)})
    sink.attach(live)
    live.sinks = [sink]
    await sink.setup()

    session = live.session_for("203.0.113.7")
    await live.render(live.make_context(Channel.HTML, session, purpose="page"))
    await live.observe(
        Interaction(
            surface="http",
            kind="http_request",
            actor="203.0.113.7",
            data={"method": "GET", "path": "/trap"},
        )
    )
    live_session = live.session_for("203.0.113.7")
    assert live_session.verdict is Verdict.CONFIRMED_AGENT

    # -- replay --
    replayed = Engine(bare_config())
    replayed.build()
    restored = 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["type"] == "lure_served":
            s = replayed.session_for(record["actor"])
            replayed.register_served(s, LurePayload.from_dict(record))
            restored += 1
        elif record["type"] == "interaction":
            await replayed.observe(
                Interaction(
                    surface=record["surface"],
                    kind=record["kind"],
                    actor=record["actor"],
                    ts=record["ts"],
                    data=record["data"],
                )
            )

    assert restored == 1, "the served lure must be in the log"
    replay_session = replayed.session_for("203.0.113.7")
    assert replay_session.verdict == live_session.verdict
    assert replay_session.signal_names() == live_session.signal_names()


async def test_log_without_lure_records_loses_expectation_signals(tmp_path) -> None:
    """Documents the failure this feature exists to prevent."""
    engine = Engine(bare_config())
    engine.build()
    lure = TokenLure()
    lure.attach(engine)
    engine.lures = [lure]

    # No render() call: lure state was never restored.
    session = await engine.observe(
        Interaction(
            surface="http",
            kind="http_request",
            actor="203.0.113.8",
            data={"method": "GET", "path": "/trap"},
        )
    )
    assert "replay_bite" not in session.signal_names()
    assert session.verdict is not Verdict.CONFIRMED_AGENT
