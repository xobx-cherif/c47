"""Scoring invariants.

These lock down the properties the rest of the framework relies on. The
conclusive-gate test in particular guards a regression that already happened
once: correlated behavioural detectors saturated the softmax and started
reporting `confirmed_agent` on pacing statistics alone.
"""

from __future__ import annotations

from c47.core.model import CLASSES, Session, Signal, Verdict
from c47.core.scoring import Scorer


def sig(name: str, agent: float = 0.0, *, conclusive: bool = False, **kw: float) -> Signal:
    weights = {"llm_agent": agent, **kw}
    return Signal(name=name, weights=weights, conclusive=conclusive, detector="test")


def test_posterior_is_a_distribution() -> None:
    result = Scorer().score([sig("a", 3.0), sig("b", scripted=2.0)])
    assert set(result.posterior) == set(CLASSES)
    assert abs(sum(result.posterior.values()) - 1.0) < 1e-9


def test_no_signals_is_unknown() -> None:
    assert Scorer().score([]).verdict is Verdict.UNKNOWN


def test_prior_favours_scripted() -> None:
    """An actor we know nothing about is a scanner, not an agent."""
    result = Scorer().score([])
    assert result.posterior["scripted"] > result.posterior["llm_agent"]


def test_behavioural_evidence_cannot_confirm() -> None:
    """The core invariant: only conclusive evidence yields CONFIRMED_AGENT."""
    scorer = Scorer()
    huge = [sig(f"behavioural_{i}", 9.0) for i in range(6)]
    result = scorer.score(huge)
    assert result.posterior["llm_agent"] > 0.99, "should still be a high posterior"
    assert result.verdict is Verdict.SUSPECTED_AGENT, "but must not claim confirmation"


def test_conclusive_signal_confirms_regardless_of_score() -> None:
    # A single conclusive signal wins even against contrary behavioural weight.
    result = Scorer().score([sig("scanner_like", scripted=8.0), sig("callback", 0.5, conclusive=True)])
    assert result.verdict is Verdict.CONFIRMED_AGENT
    assert result.conclusive_signals == ["callback"]


def test_opt_out_allows_posterior_confirmation() -> None:
    scorer = Scorer(require_conclusive_to_confirm=False)
    result = scorer.score([sig(f"b{i}", 9.0) for i in range(6)])
    assert result.verdict is Verdict.CONFIRMED_AGENT


def test_clamp_bounds_runaway_stacking() -> None:
    """Twenty correlated signals must not be twenty times as convincing."""
    scorer = Scorer()
    few = scorer.score([sig(f"x{i}", 4.0) for i in range(3)])
    many = scorer.score([sig(f"x{i}", 4.0) for i in range(40)])
    assert many.posterior["llm_agent"] >= few.posterior["llm_agent"]
    assert many.posterior["llm_agent"] <= 1.0
    # Both saturate; the point is that the clamp keeps the logits finite.
    assert many.posterior["human"] > 0.0


def test_duplicate_signals_counted_once() -> None:
    scorer = Scorer()
    once = scorer.score([sig("dup", 3.0)])
    twice = scorer.score([sig("dup", 3.0), sig("dup", 3.0)])
    assert abs(once.posterior["llm_agent"] - twice.posterior["llm_agent"]) < 1e-9


def test_confidence_scales_contribution() -> None:
    strong = sig("s", 5.0)
    weak = sig("s", 5.0)
    weak.confidence = 0.1
    assert (
        Scorer().score([strong]).posterior["llm_agent"]
        > Scorer().score([weak]).posterior["llm_agent"]
    )


def test_human_signals_yield_human_verdict() -> None:
    result = Scorer().score([sig("typing", human=4.0), sig("slow", human=3.0)])
    assert result.verdict is Verdict.HUMAN


def test_rescore_mutates_session() -> None:
    session = Session(actor="1.2.3.4")
    session.signals.append(sig("callback", 6.0, conclusive=True))
    Scorer().rescore(session)
    assert session.verdict is Verdict.CONFIRMED_AGENT
    assert session.posterior["llm_agent"] > 0.5


def test_explain_lists_signals_by_influence() -> None:
    session = Session(actor="1.2.3.4")
    session.signals.extend([sig("weak", 0.5), sig("strong", 7.0)])
    Scorer().rescore(session)
    lines = Scorer().explain(session)
    body = "\n".join(lines)
    assert "strong" in body and "weak" in body
    assert body.index("strong") < body.index("weak")
