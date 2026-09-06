"""Timing analysis: the reasoning sawtooth.

The three actor classes have genuinely different temporal fingerprints, and
this is the only detector that works with no lure at all.

* A **human** is slow and irregular: seconds to minutes between actions, high
  variance, and never faster than typing allows.
* A **scanner** is fast and regular: sub-100ms, tightly clustered, because the
  gaps are network latency and a fixed worker pool, not decisions.
* An **LLM agent** alternates. It stalls for inference -- seconds to a couple of
  minutes while the model plans -- then fires a burst of requests back-to-back
  as it executes the plan it just produced. Plotted, that is a sawtooth, and
  neither of the other two classes produces it.

The discriminating statistic is therefore *bimodality* of inter-arrival gaps,
not their mean. A single mode is a scanner or a human depending on where it
sits; two well-separated modes with tight bursts is an agent. We require a
minimum sample count before reporting anything, because three requests can look
like anything.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from c47.core.model import Interaction, Session, Signal
from c47.core.spi import Detector

#: Below this, a gap is machine-paced execution rather than a decision.
BURST_MAX = 0.35
#: Plausible span for one model inference plus tool round-trip.
THINK_MIN = 2.0
THINK_MAX = 180.0
#: Below this, no human hand is involved at all.
HUMAN_FLOOR = 0.25


@dataclass
class Profile:
    gaps: list[float]
    bursts: int
    thinks: int
    median: float
    fastest: float

    @property
    def n(self) -> int:
        return len(self.gaps)


def profile(session: Session) -> Profile | None:
    ts = sorted(i.ts for i in session.interactions if i.kind != "canary_hit")
    if len(ts) < 4:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
    return Profile(
        gaps=gaps,
        bursts=sum(1 for g in gaps if g <= BURST_MAX),
        thinks=sum(1 for g in gaps if THINK_MIN <= g <= THINK_MAX),
        median=statistics.median(gaps),
        fastest=min(gaps),
    )


class TimingDetector(Detector):
    name = "timing"
    description = "Detects the think/burst sawtooth of an agent, versus flat scanner or human pacing."
    kinds = ()
    # Re-evaluated as evidence accumulates; the engine's name-based dedupe keeps
    # each conclusion admitted once.
    repeatable = False

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        p = profile(session)
        if p is None or p.n < int(self.config.get("min_gaps", 5)):
            return []

        signals: list[Signal] = []
        evidence = {
            "samples": p.n,
            "median_gap": round(p.median, 3),
            "fastest_gap": round(p.fastest, 3),
            "burst_gaps": p.bursts,
            "think_gaps": p.thinks,
        }

        # Sawtooth: both modes present, and each substantial enough not to be
        # one stray pause in an otherwise flat scan.
        if p.bursts >= 2 and p.thinks >= 2:
            ratio = min(p.bursts, p.thinks) / p.n
            signals.append(
                Signal(
                    name="timing_sawtooth",
                    weights={"llm_agent": 3.2, "scripted": -1.5, "human": -1.5},
                    confidence=min(1.0, 0.45 + ratio * 2.0),
                    evidence={
                        **evidence,
                        "note": (
                            "Inter-arrival gaps are bimodal: pauses consistent with model "
                            "inference alternating with sub-second execution bursts."
                        ),
                    },
                    detector=self.name,
                )
            )

        # Flat and fast: a worker pool, not a decision loop.
        elif p.bursts >= p.n - 1 and p.thinks == 0:
            signals.append(
                Signal(
                    name="timing_uniform_fast",
                    weights={"scripted": 2.5, "llm_agent": -1.0, "human": -2.5},
                    confidence=0.8,
                    evidence={**evidence, "note": "Uniformly sub-second pacing; no decision gaps."},
                    detector=self.name,
                )
            )

        # Nothing faster than a quarter second across a long session rules out
        # automation of any kind.
        if p.fastest > HUMAN_FLOOR and p.n >= 8 and p.thinks >= p.n // 2:
            signals.append(
                Signal(
                    name="timing_human_paced",
                    weights={"human": 2.0, "scripted": -1.5, "llm_agent": -0.5},
                    confidence=0.6,
                    evidence={**evidence, "note": "No gap below the human interaction floor."},
                    detector=self.name,
                )
            )

        return signals
