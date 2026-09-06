"""Signal fusion.

Each detector reports a :class:`Signal` carrying a log-weight per actor class.
We treat the weights as independent log-likelihood contributions and normalise
with a softmax over ``CLASSES``:

    logit[c] = log(prior[c]) + Σ_signals weight[c] * confidence
    posterior = softmax(logit)

Naive independence is wrong in detail -- ``ua_churn`` and ``method_fanout`` fire
on correlated behaviour -- so two things keep it from running away:

* a detector's signal name is admitted **once** per session unless it declares
  ``repeatable``, so a burst of 300 requests cannot stack the same evidence 300
  times;
* per-class contributions are clamped, bounding how far any single family of
  correlated signals can drag the posterior.

The escape hatch from all of this is ``Signal.conclusive``: evidence that only
a prose-reading agent could have produced (an out-of-band callback quoting a
token that existed solely inside an HTML comment) pins the verdict outright
rather than nudging a score.

That escape hatch is also a *ceiling*. By default, a session with no conclusive
signal cannot be reported as ``CONFIRMED_AGENT`` no matter how high its
posterior climbs -- behavioural evidence tops out at ``SUSPECTED_AGENT``. This
is deliberate and load-bearing. Stacking four correlated behavioural detectors
will drive a softmax to 1.000 on a session where nothing has actually proven
comprehension, and a framework that announces "confirmed LLM agent" on pacing
statistics alone is overclaiming. The whole value of the confirmed verdict is
that it means something a scanner cannot produce. Operators who want the old
behaviour can set ``engine.require_conclusive_to_confirm = false``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from c47.core.model import CLASSES, Session, Signal, Verdict

#: Maximum absolute accumulated log-weight per class, before the softmax.
CLAMP = 12.0


@dataclass
class ScoreResult:
    posterior: dict[str, float]
    verdict: Verdict
    conclusive_signals: list[str]
    top_class: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "posterior": {k: round(v, 4) for k, v in self.posterior.items()},
            "verdict": self.verdict.value,
            "conclusive": self.conclusive_signals,
        }


class Scorer:
    def __init__(
        self,
        prior: dict[str, float] | None = None,
        *,
        suspect_threshold: float = 0.55,
        confirm_threshold: float = 0.90,
        require_conclusive_to_confirm: bool = True,
    ) -> None:
        prior = prior or {"human": 0.10, "scripted": 0.88, "llm_agent": 0.02}
        total = sum(max(1e-9, prior.get(c, 1e-9)) for c in CLASSES)
        self.prior = {c: max(1e-9, prior.get(c, 1e-9)) / total for c in CLASSES}
        self.suspect_threshold = suspect_threshold
        self.confirm_threshold = confirm_threshold
        self.require_conclusive_to_confirm = require_conclusive_to_confirm

    # ------------------------------------------------------------------

    def score(self, signals: list[Signal]) -> ScoreResult:
        acc = {c: 0.0 for c in CLASSES}
        conclusive: list[str] = []

        seen: set[str] = set()
        for sig in signals:
            if sig.conclusive:
                conclusive.append(sig.name)
            # Guard against double counting even if a detector misbehaves and
            # re-emits a non-repeatable signal; the engine already filters, but
            # scoring must be safe to call on any signal list (e.g. replays).
            key = f"{sig.detector}:{sig.name}"
            if key in seen and not sig.evidence.get("_repeatable"):
                continue
            seen.add(key)
            for cls in CLASSES:
                acc[cls] += sig.weights.get(cls, 0.0) * sig.confidence

        logits = {
            c: math.log(self.prior[c]) + max(-CLAMP, min(CLAMP, acc[c])) for c in CLASSES
        }
        posterior = _softmax(logits)
        top = max(posterior, key=lambda c: posterior[c])
        p_agent = posterior["llm_agent"]

        if conclusive:
            verdict = Verdict.CONFIRMED_AGENT
        elif p_agent >= self.confirm_threshold and not self.require_conclusive_to_confirm:
            verdict = Verdict.CONFIRMED_AGENT
        elif p_agent >= self.suspect_threshold:
            # Behavioural evidence alone stops here. See the module docstring:
            # correlated detectors will saturate a softmax without anything
            # having proven comprehension.
            verdict = Verdict.SUSPECTED_AGENT
        elif not signals:
            verdict = Verdict.UNKNOWN
        elif top == "human":
            verdict = Verdict.HUMAN
        else:
            verdict = Verdict.SCRIPTED

        return ScoreResult(
            posterior=posterior,
            verdict=verdict,
            conclusive_signals=conclusive,
            top_class=top,
        )

    def rescore(self, session: Session) -> ScoreResult:
        result = self.score(session.signals)
        session.posterior = result.posterior
        session.verdict = result.verdict
        return result

    # ------------------------------------------------------------------

    def explain(self, session: Session) -> list[str]:
        """Human-readable breakdown, for ``c47 sessions --explain``."""
        lines = [
            f"session {session.id} actor={session.actor} "
            f"verdict={session.verdict.value} "
            f"p(agent)={session.posterior.get('llm_agent', 0.0):.3f}"
        ]
        if not session.signals:
            lines.append("  (no signals)")
            return lines
        ordered = sorted(
            session.signals,
            key=lambda s: -abs(s.weights.get("llm_agent", 0.0) * s.confidence),
        )
        for sig in ordered:
            w = sig.weights.get("llm_agent", 0.0) * sig.confidence
            mark = "!!" if sig.conclusive else "  "
            lines.append(
                f" {mark} {sig.name:<28} llr(agent)={w:+.2f} conf={sig.confidence:.2f} "
                f"[{sig.detector}]"
            )
            for k, v in list(sig.evidence.items())[:4]:
                if str(k).startswith("_"):
                    continue
                lines.append(f"        {k}: {_trim(v)}")
        return lines


def _softmax(logits: dict[str, float]) -> dict[str, float]:
    hi = max(logits.values())
    exp = {k: math.exp(v - hi) for k, v in logits.items()}
    total = sum(exp.values()) or 1.0
    return {k: v / total for k, v in exp.items()}


def _trim(value: Any, limit: int = 160) -> str:
    text = str(value).replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."
