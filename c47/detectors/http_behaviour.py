"""HTTP-layer behavioural detectors.

None of these is conclusive on its own, and they are not meant to be. Their job
is to move an actor from `scripted` to `suspected_agent` cheaply enough to
justify escalating to :attr:`Stage.ACTIVE`, where the conclusive instruments
live. Getting that gate right is what keeps the loud payloads away from mass
scanning.

They deliberately look for things that are *odd for a scanner* rather than
things that are common for agents: an agent driving an HTTP client through a
tool wrapper leaves a different trace than a purpose-built scanner does, and
the mismatches are more reliable than any single fingerprint.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from c47.core.model import Interaction, Session, Signal
from c47.core.spi import Detector

#: Clients an agent reaches for through a generic shell or HTTP tool, as
#: opposed to a purpose-built scanner's own stack.
_AGENT_CLIENT_HINTS = (
    "python-requests", "python-urllib", "httpx", "aiohttp", "node-fetch",
    "axios", "go-http-client", "curl", "wget", "libwww-perl",
)

#: Scanners that announce themselves. Their presence is strong evidence *for*
#: the scripted class -- but note an agent may drive these as tools, so this is
#: weighted as a nudge, not a verdict.
_SCANNER_UAS = (
    "nuclei", "nikto", "sqlmap", "nmap", "masscan", "zgrab", "dirbuster",
    "gobuster", "feroxbuster", "wpscan", "acunetix", "nessus", "qualys",
    "burp", "zaproxy", "ffuf", "httpx-toolkit",
)

_BROWSER_UAS = ("mozilla/", "chrome/", "safari/", "edge/", "firefox/")


def _ua(i: Interaction) -> str:
    return str(i.data.get("user_agent") or "").lower()


def _http(session: Session) -> list[Interaction]:
    return session.of_kind("http_request")


class UserAgentChurnDetector(Detector):
    """Multiple distinct client stacks inside one short session.

    A scanner has one HTTP stack. A browser has one. An agent has a *toolbox*:
    it curls one endpoint, switches to Python for a POST it wants to shape by
    hand, then loads a page with a browser-like UA because the target looked
    like an app. Seeing three unrelated stacks from one address in minutes is
    tool selection, and tool selection is a decision.
    """

    name = "ua_churn"
    description = "Several unrelated HTTP client stacks from one actor in one session."
    kinds = ("http_request",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        uas = {_ua(i) for i in _http(session) if _ua(i)}
        if len(uas) < int(self.config.get("min_distinct", 3)):
            return []

        families: set[str] = set()
        for ua in uas:
            if any(b in ua for b in _BROWSER_UAS):
                families.add("browser")
            for hint in _AGENT_CLIENT_HINTS:
                if hint in ua:
                    families.add(hint)
        if len(families) < 2:
            return []

        return [
            Signal(
                name="ua_family_churn",
                weights={"llm_agent": 2.8, "scripted": -1.0, "human": -1.5},
                confidence=min(1.0, 0.5 + 0.15 * len(families)),
                evidence={
                    "distinct_user_agents": len(uas),
                    "families": sorted(families),
                    "samples": sorted(uas)[:6],
                    "note": "Mid-session switching between unrelated client stacks.",
                },
                detector=self.name,
            )
        ]


class MethodFanoutDetector(Detector):
    """The same path exercised with many verbs, near-simultaneously.

    Systematically trying GET/POST/PUT/DELETE/OPTIONS/TRACE against one
    endpoint is textbook methodology -- an agent working through a checklist of
    "things to test on an endpoint". A directory scanner does not do it (it
    walks paths, not verbs), and a human does not do it in one second.
    """

    name = "method_fanout"
    description = "One path probed with many HTTP verbs in a tight window."
    kinds = ("http_request",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        target = str(interaction.data.get("path", ""))
        if not target:
            return []
        window = float(self.config.get("window", 20.0))
        min_methods = int(self.config.get("min_methods", 4))

        same = [
            i
            for i in _http(session)
            if str(i.data.get("path", "")) == target and abs(i.ts - interaction.ts) <= window
        ]
        methods = {str(i.data.get("method", "GET")).upper() for i in same}
        if len(methods) < min_methods:
            return []

        span = max(i.ts for i in same) - min(i.ts for i in same)
        return [
            Signal(
                name="method_fanout",
                weights={"llm_agent": 2.6, "scripted": 0.2, "human": -2.0},
                confidence=min(1.0, 0.5 + 0.1 * len(methods)),
                evidence={
                    "path": target,
                    "methods": sorted(methods),
                    "span_seconds": round(span, 3),
                    "note": "Methodical verb enumeration against a single endpoint.",
                },
                detector=self.name,
            )
        ]


class HeaderAnomalyDetector(Detector):
    """Header sets that contradict the User-Agent they arrive with.

    A real Chrome request carries a dozen headers in a stable order, including
    ``Accept-Language`` and ``Sec-Fetch-*``. An agent that sets
    ``User-Agent: Mozilla/5.0`` from a Python client sends four headers and none
    of those. The mismatch is the signal -- and it specifically catches an agent
    *trying* to look like a browser, which is a deliberate act.
    """

    name = "header_anomaly"
    description = "Claimed browser identity contradicted by the actual header set."
    kinds = ("http_request",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        headers = interaction.data.get("headers") or {}
        if not isinstance(headers, dict) or not headers:
            return []
        lower = {k.lower() for k in headers}
        ua = _ua(interaction)
        if not any(b in ua for b in _BROWSER_UAS):
            return []

        missing = [h for h in ("accept-language", "accept-encoding", "sec-fetch-mode") if h not in lower]
        if len(missing) < 2:
            return []

        return [
            Signal(
                name="browser_ua_header_mismatch",
                weights={"llm_agent": 2.2, "scripted": 1.0, "human": -2.5},
                confidence=0.6 + 0.1 * len(missing),
                evidence={
                    "user_agent": ua[:120],
                    "header_count": len(headers),
                    "missing": missing,
                    "note": "Browser User-Agent without the header set a browser always sends.",
                },
                detector=self.name,
            )
        ]


class PathSemanticsDetector(Detector):
    """Path choices that imply the actor read and understood our responses.

    Two things are checked, and both are about *selectivity*.

    First, the robots.txt pairing: our bait describes one path as live and one
    as decommissioned. Requesting both is indiscriminate crawling and means
    nothing; requesting only the live one means the comment was read.

    Second, the shape of the path sequence. A wordlist walk is alphabetical or
    frequency-ordered and mostly misses. A reader's sequence is contextual:
    paths that appeared in our own responses, requested in the order a person
    would follow a link. Low miss rates with no wordlist ordering is
    comprehension.
    """

    name = "path_semantics"
    description = "Selective path following that implies our responses were understood."
    kinds = ("http_request",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        signals: list[Signal] = []
        visited = {str(i.data.get("path", "")).rstrip("/") for i in _http(session)}

        # -- robots.txt selectivity -------------------------------------
        for payload in session.served:
            if payload.lure != "robots_bait":
                continue
            live = str(payload.meta.get("live_path", "")).rstrip("/")
            dead = str(payload.meta.get("dead_path", "")).rstrip("/")
            if not (live and dead):
                continue
            hit_live = any(v.startswith(live) for v in visited if v)
            hit_dead = any(v.startswith(dead) for v in visited if v)
            if hit_live and not hit_dead:
                signals.append(
                    Signal(
                        name="robots_selective_follow",
                        weights={"llm_agent": 5.0, "scripted": -3.5, "human": 0.5},
                        confidence=0.85,
                        evidence={
                            "followed": live,
                            "skipped": dead,
                            "note": (
                                "Followed only the robots.txt path a prose comment described "
                                "as live, skipping the one described as decommissioned. A "
                                "crawler follows both."
                            ),
                        },
                        detector=self.name,
                    )
                )
            elif hit_live and hit_dead:
                signals.append(
                    Signal(
                        name="robots_indiscriminate_follow",
                        weights={"scripted": 2.0, "llm_agent": -1.5, "human": -0.5},
                        confidence=0.7,
                        evidence={
                            "followed": [live, dead],
                            "note": "Followed every Disallow entry regardless of the comment.",
                        },
                        detector=self.name,
                    )
                )

        # -- wordlist versus contextual navigation ----------------------
        paths = [str(i.data.get("path", "")) for i in _http(session)]
        if len(paths) >= int(self.config.get("min_paths", 12)):
            statuses = [int(i.data.get("status", 0) or 0) for i in _http(session)]
            found = sum(1 for s in statuses if 200 <= s < 400)
            hit_rate = found / max(1, len(statuses))
            if _looks_alphabetical(paths) and hit_rate < 0.15:
                signals.append(
                    Signal(
                        name="wordlist_enumeration",
                        weights={"scripted": 3.0, "llm_agent": -2.0, "human": -2.0},
                        confidence=0.8,
                        evidence={
                            "paths": len(paths),
                            "hit_rate": round(hit_rate, 3),
                            "note": "Ordered, low-yield path sweep characteristic of a wordlist.",
                        },
                        detector=self.name,
                    )
                )

        return signals


_SEG = re.compile(r"[^a-z0-9]+")


def _looks_alphabetical(paths: list[str]) -> bool:
    """True if the request order is suspiciously close to sorted order.

    Wordlists ship sorted, and most tools walk them in file order, so a scan's
    path sequence is largely monotonic. An agent's is not, because each request
    follows from the last response.
    """
    keys = [_SEG.sub("", urlparse(p).path.lower()) for p in paths]
    keys = [k for k in keys if k]
    if len(keys) < 8:
        return False
    ascending = sum(1 for a, b in zip(keys, keys[1:], strict=False) if a <= b)
    return ascending / max(1, len(keys) - 1) >= 0.8
