"""Plugin contracts.

Five extension points. Subclass one, give it a ``name``, and either register it
under the matching ``c47.*`` entry-point group or drop the module into a
directory listed in ``[plugins] paths``.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

from c47.core.model import (
    Channel,
    Interaction,
    LurePayload,
    RenderContext,
    Session,
    Signal,
    Stage,
)

if TYPE_CHECKING:
    from c47.core.engine import Engine


class Plugin(abc.ABC):  # noqa: B024
    """Common base: a name, a config dict, and an engine handle.

    Abstract by design even though it declares no abstract methods of its own:
    every concrete extension point below adds one, and ``ABCMeta`` is what makes
    those enforceable. ``setup``/``teardown`` are deliberately optional hooks
    with empty bodies, not abstract methods -- most plugins need neither.
    """

    #: Unique plugin name. Used in config ``enabled`` lists and in logs.
    name: str = ""
    #: One-line description for ``c47 plugins``.
    description: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.engine: Engine | None = None

    def attach(self, engine: Engine) -> None:
        """Give the plugin its engine handle.

        Named ``attach`` rather than ``bind`` because surfaces carry a ``bind``
        address attribute, and the two collide.
        """
        self.engine = engine

    async def setup(self) -> None:  # noqa: B027  # pragma: no cover
        """Called once before the honeypot starts serving."""

    async def teardown(self) -> None:  # noqa: B027  # pragma: no cover
        """Called once during shutdown."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"


# --------------------------------------------------------------------------


#: Purposes that require a lure to opt in explicitly, even though an empty
#: ``purposes`` tuple otherwise means "any purpose".
#:
#: These name responses whose *entire body is the lure* rather than a page with
#: a payload spliced into it. A ``429 challenge_required`` body must be the
#: challenge and nothing else; ``robots.txt`` must be a robots file. Letting a
#: generic ``purposes = ()`` lure land in one produces a response that
#: contradicts its own status line -- so the default here is deny, and a lure
#: that genuinely belongs must name the purpose.
EXCLUSIVE_PURPOSES: frozenset[str] = frozenset({"api_error", "robots"})


class Lure(Plugin):
    """Produces deceptive content aimed at an LLM consumer.

    A lure declares the channels it can render into and the escalation stage at
    which it is allowed to fire, then returns a :class:`LurePayload` whose
    ``expectations`` tell the framework what a successful bite looks like.
    """

    #: Channels this lure can render into.
    channels: tuple[Channel, ...] = ()
    #: Render purposes this lure accepts (see :attr:`RenderContext.purpose`).
    #: Empty means "any purpose except an exclusive one", which is right for
    #: lures that read naturally anywhere. Narrow it whenever a payload only
    #: makes sense in one context: a robots.txt comment inside an API error
    #: body fools nobody. See :data:`EXCLUSIVE_PURPOSES`.
    purposes: tuple[str, ...] = ()
    #: Minimum stage at which this lure may be served.
    min_stage: Stage = Stage.PASSIVE
    #: Serve at most once per session (default: repeatable).
    once_per_session: bool = False

    def applies(self, ctx: RenderContext) -> bool:
        if ctx.channel not in self.channels:
            return False
        if not self._purpose_ok(ctx.purpose):
            return False
        if ctx.stage < self.min_stage:
            return False
        if self.once_per_session and any(p.lure == self.name for p in ctx.session.served):
            return False
        return True

    def _purpose_ok(self, purpose: str) -> bool:
        if not purpose:
            return True
        if purpose in EXCLUSIVE_PURPOSES:
            return purpose in self.purposes
        return not self.purposes or purpose in self.purposes

    @abc.abstractmethod
    def render(self, ctx: RenderContext) -> LurePayload | None:
        """Build the payload, or return ``None`` to decline this request."""


# --------------------------------------------------------------------------


class Detector(Plugin):
    """Turns observations into :class:`Signal` objects.

    ``inspect`` is called once per interaction with the full session available,
    so a detector may either react to a single event or re-evaluate an
    accumulating pattern (timing, method fan-out, ...). Returning a signal whose
    ``name`` a session already carries is a no-op unless ``repeatable`` is set,
    which keeps score fusion from double-counting one piece of evidence.
    """

    #: Interaction kinds this detector cares about; empty means all.
    kinds: tuple[str, ...] = ()
    #: Allow the same signal name to be raised more than once per session.
    repeatable: bool = False

    def wants(self, interaction: Interaction) -> bool:
        return not self.kinds or interaction.kind in self.kinds

    @abc.abstractmethod
    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        """Return zero or more signals implied by the session's current state."""


# --------------------------------------------------------------------------


class Surface(Plugin):
    """A protocol the honeypot exposes to the world.

    Surfaces are the only components that talk to attackers. They call
    ``engine.observe()`` to report activity and ``engine.render()`` to obtain
    lure content to weave into their responses.
    """

    @abc.abstractmethod
    async def start(self) -> None:
        """Bind sockets / start watchers. Must not block indefinitely."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Release resources."""


# --------------------------------------------------------------------------


class Sink(Plugin):
    """Receives framework telemetry for storage or forwarding."""

    async def on_interaction(self, session: Session, interaction: Interaction) -> None:
        """Called for every observed interaction."""

    async def on_signal(self, session: Session, signal: Signal) -> None:
        """Called when a detector raises a new signal."""

    async def on_verdict(self, session: Session, previous: Any) -> None:
        """Called when a session's verdict changes."""

    async def on_disclosure(self, session: Session, field: str, value: str) -> None:
        """Called when the campaign profiler learns something new."""

    async def on_lure_served(self, session: Session, payload: LurePayload) -> None:
        """Called when a lure is served, before the response goes out.

        Recording this is what makes ``c47 replay`` faithful: expectation-based
        signals depend on which lures were served with which tokens, so a
        replay that only re-runs interactions can never reproduce them.
        """


# --------------------------------------------------------------------------


class LLMBackend(Plugin):
    """Optional generative backend.

    Every shipped lure and detector works without one. A backend enables
    dynamic response synthesis and the semantic judge detector.
    """

    @abc.abstractmethod
    async def complete(self, system: str, prompt: str, max_tokens: int = 512) -> str:
        """Return model text, or ``""`` if the backend is unavailable."""

    @property
    def available(self) -> bool:
        return True
