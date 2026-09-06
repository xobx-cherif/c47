"""codename_47 -- a deception framework for detecting LLM-driven pentesting agents.

The framework answers one question: is the thing attacking this host a language
model, and if so, what is it being told to do?

Three tiers of evidence, in increasing strength:

1. **Behavioural** -- pacing, error recovery, tool churn. Free, works against an
   unmodified target, never conclusive on its own. Its job is to decide who is
   worth escalating to tier 2.
2. **Comprehension** -- payloads whose correct handling requires reading prose
   and reasoning about it. A wordlist cannot solve a derived key, and a replay
   of captured traffic cannot either.
3. **Disclosure** -- the agent tells us its model, framework, objective or
   instruction set, in-band or via an out-of-band callback.

Escalation is staged (:class:`~c47.core.model.Stage`) so loud payloads are never
served to a passing scanner, which keeps them out of public scan corpora and
keeps the honeypot quiet under mass scanning.
"""

__version__ = "0.1.0"

from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import (
    Channel,
    Expectation,
    Interaction,
    LurePayload,
    RenderContext,
    Session,
    Signal,
    Stage,
    Verdict,
)
from c47.core.spi import Detector, LLMBackend, Lure, Plugin, Sink, Surface

__all__ = [
    "__version__",
    "Channel",
    "Config",
    "Detector",
    "Engine",
    "Expectation",
    "Interaction",
    "LLMBackend",
    "Lure",
    "LurePayload",
    "Plugin",
    "RenderContext",
    "Session",
    "Signal",
    "Sink",
    "Stage",
    "Surface",
    "Verdict",
]
