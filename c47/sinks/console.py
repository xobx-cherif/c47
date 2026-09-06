"""Human-readable console output.

Interactions are intentionally not printed. A honeypot under a scan produces
thousands of them, and a console that scrolls is a console nobody reads -- so
this sink reports only the three things worth interrupting an operator for: a
verdict crossing the configured threshold, a conclusive signal, and a campaign
disclosure.

The disclosure block is the payoff of the whole framework, so it is printed in
full rather than truncated.
"""

from __future__ import annotations

import sys
from typing import Any

from c47.core.model import Interaction, Session, Signal, Verdict
from c47.core.spi import Sink

ORDER = {
    Verdict.UNKNOWN: 0,
    Verdict.HUMAN: 1,
    Verdict.SCRIPTED: 2,
    Verdict.SUSPECTED_AGENT: 3,
    Verdict.CONFIRMED_AGENT: 4,
}

COLOR = {
    Verdict.CONFIRMED_AGENT: "\033[1;31m",
    Verdict.SUSPECTED_AGENT: "\033[1;33m",
    Verdict.SCRIPTED: "\033[0;36m",
    Verdict.HUMAN: "\033[0;32m",
    Verdict.UNKNOWN: "\033[0;37m",
}
RESET = "\033[0m"


class ConsoleSink(Sink):
    name = "console"
    description = "Prints verdict changes, conclusive signals and disclosures to stdout."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        raw = str(self.config.get("min_verdict", "suspected_agent"))
        try:
            self.min_verdict = Verdict(raw)
        except ValueError:
            self.min_verdict = Verdict.SUSPECTED_AGENT
        self.color = bool(self.config.get("color", sys.stdout.isatty()))

    def _paint(self, verdict: Verdict, text: str) -> str:
        if not self.color:
            return text
        return f"{COLOR.get(verdict, '')}{text}{RESET}"

    async def on_interaction(self, session: Session, interaction: Interaction) -> None:
        return  # far too noisy; use the jsonl sink for the full stream

    async def on_signal(self, session: Session, signal: Signal) -> None:
        if not signal.conclusive:
            return
        note = signal.evidence.get("note", "")
        print(
            self._paint(
                Verdict.CONFIRMED_AGENT,
                f"[!!] CONCLUSIVE {signal.name} actor={session.actor} "
                f"detector={signal.detector}",
            )
        )
        if note:
            print(f"     {note}")
        for key in ("callback_ip", "different_egress", "delay_seconds", "matched", "tool"):
            if key in signal.evidence:
                print(f"     {key}: {signal.evidence[key]}")

    async def on_verdict(self, session: Session, previous: Verdict) -> None:
        if ORDER.get(session.verdict, 0) < ORDER.get(self.min_verdict, 3):
            return
        p_agent = session.posterior.get("llm_agent", 0.0)
        print(
            self._paint(
                session.verdict,
                f"[{session.verdict.value.upper()}] actor={session.actor} "
                f"session={session.id} p(agent)={p_agent:.3f} "
                f"surfaces={','.join(sorted(session.surfaces))} "
                f"stage={int(session.stage)}",
            )
        )
        top = sorted(
            session.signals,
            key=lambda s: -abs(s.weights.get("llm_agent", 0.0) * s.confidence),
        )[:4]
        for sig in top:
            print(f"     - {sig.name} ({sig.detector}, conf={sig.confidence:.2f})")

    async def on_disclosure(self, session: Session, field: str, value: str) -> None:
        print(
            self._paint(
                Verdict.CONFIRMED_AGENT,
                f"[++] DISCLOSURE actor={session.actor} field={field} ({len(value)} chars)",
            )
        )
        # Printed in full: this is the intelligence the framework exists to get.
        for line in value.splitlines() or [value]:
            print(f"     | {line}")
