"""Core data model for codename_47.

Everything that crosses a plugin boundary is defined here. Surfaces produce
:class:`Interaction`, lures produce :class:`LurePayload` (carrying
:class:`Expectation` objects that describe what a *hit* looks like later), and
detectors produce :class:`Signal`.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

# --------------------------------------------------------------------------
# Classification space
# --------------------------------------------------------------------------

#: The three actor classes codename_47 discriminates between. We deliberately
#: keep "scripted" separate from "llm_agent": the hard problem is not telling a
#: machine from a human (trivial) but telling a wordlist scanner from an agent
#: that *reads and reasons about* what we send back.
CLASSES: tuple[str, ...] = ("human", "scripted", "llm_agent")


class Verdict(StrEnum):
    UNKNOWN = "unknown"
    HUMAN = "human"
    SCRIPTED = "scripted"
    SUSPECTED_AGENT = "suspected_agent"
    CONFIRMED_AGENT = "confirmed_agent"

    @property
    def is_agentic(self) -> bool:
        return self in (Verdict.SUSPECTED_AGENT, Verdict.CONFIRMED_AGENT)


class Stage(IntEnum):
    """Escalation ladder.

    We do not fire our loudest payloads at every passing scanner: an agent that
    has not yet proven it reads prose gets cheap passive bait, and only a
    confirmed reasoner is worth a system-prompt extraction attempt. This keeps
    the honeypot quiet against mass scanning and keeps our best payloads out of
    public scan corpora.
    """

    PASSIVE = 0  # invisible / deniable bait. Served to everyone.
    ACTIVE = 1  # direct instructions to the model. Served to suspected agents.
    EXTRACT = 2  # system prompt + campaign interrogation. Confirmed agents only.

    @classmethod
    def for_verdict(cls, verdict: Verdict) -> Stage:
        if verdict is Verdict.CONFIRMED_AGENT:
            return cls.EXTRACT
        if verdict is Verdict.SUSPECTED_AGENT:
            return cls.ACTIVE
        return cls.PASSIVE


# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------


class Channel(StrEnum):
    """Where a lure is being rendered.

    A lure must know its channel because the *invisibility* trick differs per
    channel: ANSI escapes hide text in a terminal, HTML comments hide text in a
    browser, and an MCP tool description is never shown to a human at all.
    """

    HTML = "html"
    HTTP_HEADER = "http_header"
    HTTP_BODY_TEXT = "http_body_text"
    JSON = "json"
    SHELL_STDOUT = "shell_stdout"
    SHELL_MOTD = "shell_motd"
    FILE_CONTENT = "file_content"
    MCP_TOOL_DESCRIPTION = "mcp_tool_description"
    MCP_TOOL_RESULT = "mcp_tool_result"
    BANNER = "banner"


# --------------------------------------------------------------------------
# Interactions
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Interaction:
    """One observable action by an actor against one surface."""

    surface: str
    kind: str  # "http_request" | "shell_command" | "mcp_call" | "login" | "canary_hit"
    actor: str  # source IP (or another stable key the surface chooses)
    ts: float = field(default_factory=time.time)
    session_key: str | None = None  # surface-native session id, if any

    # Free-form request detail. Conventional keys per kind:
    #   http_request: method, path, query, headers, body, user_agent
    #   shell_command: command, argv, cwd
    #   mcp_call: tool, arguments
    #   canary_hit: token, params
    data: dict[str, Any] = field(default_factory=dict)

    #: Text an actor sent us that a detector may want to scan for leaked
    #: instructions (command line, POST body, MCP argument blob, ...).
    @property
    def text(self) -> str:
        d = self.data
        parts = [
            d.get("command"),
            d.get("body") if isinstance(d.get("body"), str) else None,
            d.get("path"),
            d.get("query"),
        ]
        args = d.get("arguments")
        if isinstance(args, dict):
            parts.extend(str(v) for v in args.values())
        elif isinstance(args, str):
            parts.append(args)
        return "\n".join(p for p in parts if p)


# --------------------------------------------------------------------------
# Lures
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Expectation:
    """A description of the observable consequence of a lure landing.

    This is the keystone of the design: a lure declares *how you will know it
    worked*, so a single generic detector
    (:class:`c47.detectors.expectations.ExpectationDetector`) can adjudicate
    every lure in the framework. Plugin authors write one class, not two.
    """

    kind: str
    value: str
    signal: str
    weights: dict[str, float]
    conclusive: bool = False
    note: str = ""
    #: Optional named capture that, when matched, is fed to the campaign
    #: profiler (e.g. "system_prompt", "model", "framework", "objective").
    captures: str | None = None

    #: Recognised ``kind`` values, handled by ExpectationDetector:
    #:   canary_fetch     -- our canary listener saw ``value`` as a token
    #:   path_visit       -- actor requested path ``value``
    #:   credential_use   -- actor submitted credential ``value``
    #:   echo_phrase      -- actor sent back the literal string ``value``
    #:   regex            -- actor's text matched regex ``value``
    #:   tool_invoke      -- actor called decoy MCP tool ``value``
    KINDS = (
        "canary_fetch",
        "path_visit",
        "credential_use",
        "echo_phrase",
        "regex",
        "tool_invoke",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "signal": self.signal,
            "weights": self.weights,
            "conclusive": self.conclusive,
            "note": self.note,
            "captures": self.captures,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Expectation:
        return cls(
            kind=str(data.get("kind", "")),
            value=str(data.get("value", "")),
            signal=str(data.get("signal", "")),
            weights={str(k): float(v) for k, v in (data.get("weights") or {}).items()},
            conclusive=bool(data.get("conclusive", False)),
            note=str(data.get("note", "")),
            captures=data.get("captures"),
        )


@dataclass(slots=True)
class LurePayload:
    """Rendered lure content plus the bookkeeping to recognise a bite."""

    lure: str
    channel: Channel
    content: str
    token: str = field(default_factory=lambda: secrets.token_hex(8))
    expectations: list[Expectation] = field(default_factory=list)
    stage: Stage = Stage.PASSIVE
    #: Non-visible metadata for the operator's log (never sent to the actor).
    meta: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.content)

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        """Serialise for the event log.

        ``content`` is omitted by default: it is large, and the operator's log
        does not need a copy of every payload byte. It is the *expectations*
        that must survive, because without them a replay cannot reproduce any
        expectation-based signal.
        """
        out: dict[str, Any] = {
            "lure": self.lure,
            "channel": self.channel.value,
            "token": self.token,
            "stage": int(self.stage),
            "expectations": [e.to_dict() for e in self.expectations],
            "meta": {k: v for k, v in self.meta.items() if not str(k).startswith("_")},
        }
        if include_content:
            out["content"] = self.content
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LurePayload:
        try:
            channel = Channel(str(data.get("channel", "html")))
        except ValueError:
            channel = Channel.HTML
        return cls(
            lure=str(data.get("lure", "")),
            channel=channel,
            content=str(data.get("content", "")),
            token=str(data.get("token", "")),
            expectations=[
                Expectation.from_dict(e) for e in (data.get("expectations") or [])
            ],
            stage=Stage(int(data.get("stage", 0))),
            meta=dict(data.get("meta") or {}),
        )


@dataclass(slots=True)
class RenderContext:
    """What a surface tells a lure about the request it is answering."""

    channel: Channel
    stage: Stage
    session: Session
    interaction: Interaction | None = None
    #: Absolute base URL an out-of-band callback should target.
    canary_base_url: str = ""

    #: What the surface is *rendering right now*, as opposed to the wire format
    #: it will use. Channel alone is too coarse: robots.txt, an API error body
    #: and a captured file are all ``HTTP_BODY_TEXT``, and a lure that belongs
    #: in one looks absurd in another. Without this, three unrelated lures pile
    #: into a single plain-text response and the result is transparently
    #: instrumented. Conventional values: ``page``, ``robots``, ``api_error``,
    #: ``api_result``, ``login``, ``not_found``, ``file``, ``tool_result``,
    #: ``tool_list``, ``shell``.
    purpose: str = ""

    #: Surface-specific detail, e.g. {"path": "/login.php", "command": "id"}.
    hints: dict[str, Any] = field(default_factory=dict)

    def canary_url(self, token: str, path: str = "/a") -> str:
        base = self.canary_base_url.rstrip("/")
        return f"{base}{path}?t={token}"


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Signal:
    """A detector's contribution to the classification of a session."""

    name: str
    #: Log-weight per class in :data:`CLASSES`. Positive favours the class.
    weights: dict[str, float]
    confidence: float = 1.0
    evidence: dict[str, Any] = field(default_factory=dict)
    #: A conclusive signal pins the verdict to CONFIRMED_AGENT regardless of
    #: accumulated score. Reserve it for behaviour no scanner can fake, e.g. an
    #: out-of-band callback carrying a token only a prose reader could have
    #: found.
    conclusive: bool = False
    detector: str = ""
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, self.confidence))


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


@dataclass(slots=True)
class CampaignProfile:
    """What we have managed to learn about the operation behind the agent."""

    system_prompt_fragments: list[str] = field(default_factory=list)
    model: str | None = None
    framework: str | None = None
    objective: str | None = None
    operator: str | None = None
    tools: list[str] = field(default_factory=list)
    raw_disclosures: list[dict[str, Any]] = field(default_factory=list)

    #: Cap on the audit trail. A repeatedly-callback-happy agent would
    #: otherwise grow this without bound for the lifetime of the session.
    MAX_RAW = 200

    def merge_capture(self, field_name: str, value: str, source: str) -> bool:
        """Record a disclosure. Returns True if it added new information."""
        value = value.strip()
        if not value:
            return False
        if len(self.raw_disclosures) < self.MAX_RAW:
            self.raw_disclosures.append(
                {"field": field_name, "value": value, "source": source}
            )
        if field_name == "system_prompt":
            # Agents leak the prompt in pieces across turns; keep fragments and
            # dedupe by containment rather than equality.
            for existing in self.system_prompt_fragments:
                if value in existing:
                    return False
            self.system_prompt_fragments = [
                f for f in self.system_prompt_fragments if f not in value
            ]
            self.system_prompt_fragments.append(value)
            return True
        if field_name == "tools":
            new = [t.strip() for t in value.split(",") if t.strip() and t.strip() not in self.tools]
            self.tools.extend(new)
            return bool(new)
        if field_name in ("model", "framework", "objective", "operator"):
            if getattr(self, field_name) is None:
                setattr(self, field_name, value)
                return True
        return False

    @property
    def system_prompt(self) -> str:
        return "\n".join(self.system_prompt_fragments)

    @property
    def has_content(self) -> bool:
        return bool(
            self.system_prompt_fragments
            or self.model
            or self.framework
            or self.objective
            or self.operator
            or self.tools
        )


@dataclass(slots=True)
class Session:
    """Everything codename_47 knows about one actor's engagement."""

    actor: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    interactions: list[Interaction] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    served: list[LurePayload] = field(default_factory=list)

    verdict: Verdict = Verdict.UNKNOWN
    posterior: dict[str, float] = field(default_factory=dict)
    campaign: CampaignProfile = field(default_factory=CampaignProfile)

    #: Surfaces the actor has touched, for cross-protocol correlation.
    surfaces: set[str] = field(default_factory=set)

    @property
    def stage(self) -> Stage:
        return Stage.for_verdict(self.verdict)

    @property
    def duration(self) -> float:
        return self.last_seen - self.started_at

    def signal_names(self) -> set[str]:
        return {s.name for s in self.signals}

    def expectations(self) -> list[tuple[LurePayload, Expectation]]:
        return [(p, e) for p in self.served for e in p.expectations]

    def record(self, interaction: Interaction) -> None:
        self.interactions.append(interaction)
        self.surfaces.add(interaction.surface)
        self.last_seen = max(self.last_seen, interaction.ts)

    def of_kind(self, kind: str) -> list[Interaction]:
        return [i for i in self.interactions if i.kind == kind]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "actor": self.actor,
            "started_at": self.started_at,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 3),
            "verdict": self.verdict.value,
            "posterior": {k: round(v, 4) for k, v in self.posterior.items()},
            "surfaces": sorted(self.surfaces),
            "interaction_count": len(self.interactions),
            "signals": [
                {
                    "name": s.name,
                    "detector": s.detector,
                    "confidence": round(s.confidence, 3),
                    "conclusive": s.conclusive,
                    "weights": s.weights,
                    "evidence": s.evidence,
                }
                for s in self.signals
            ],
            "lures_served": [
                {"lure": p.lure, "channel": p.channel.value, "token": p.token, "stage": int(p.stage)}
                for p in self.served
            ],
            "campaign": {
                "model": self.campaign.model,
                "framework": self.campaign.framework,
                "objective": self.campaign.objective,
                "operator": self.campaign.operator,
                "tools": self.campaign.tools,
                "system_prompt": self.campaign.system_prompt or None,
                "disclosures": self.campaign.raw_disclosures,
            },
        }
