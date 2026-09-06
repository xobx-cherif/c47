"""Adjudicates every lure's declared expectations.

This one detector resolves all lure outcomes in the framework. Because a lure
declares what a bite looks like (:class:`~c47.core.model.Expectation`), a plugin
author writing a new technique writes one class and gets scoring, campaign
harvesting and reporting for free.

It is also where disclosures are captured: a matching regex or a recognised
canary parameter is forwarded to
:meth:`~c47.core.engine.Engine.record_disclosure`, which is how the system
prompt and objective end up in the campaign profile.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import parse_qsl, unquote_plus

from c47.canary.tokens import harvest, is_placeholder, unmapped
from c47.core.model import Expectation, Interaction, LurePayload, Session, Signal
from c47.core.spi import Detector

#: Compiled once; lure regexes are static strings.
_RX_CACHE: dict[str, re.Pattern[str]] = {}


def _rx(pattern: str) -> re.Pattern[str] | None:
    if pattern not in _RX_CACHE:
        try:
            _RX_CACHE[pattern] = re.compile(pattern)
        except re.error:
            return None
    return _RX_CACHE.get(pattern)


class ExpectationDetector(Detector):
    name = "expectations"
    description = "Matches actor behaviour against the expectations declared by served lures."
    # Each expectation's signal name is distinct, and the engine dedupes by
    # name, so leaving this non-repeatable gives exactly-once semantics per
    # signal without any bookkeeping here.
    repeatable = False

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        # Harvest first, and unconditionally. Intelligence in a callback is
        # worth keeping whether or not it also produces a *new* signal: signal
        # names fire once per session, so a second callback on the same token
        # (an identity handshake after a scope POST, say) matches no unfired
        # expectation -- and gating the harvest on that match would silently
        # discard the model, framework and tool list it carried.
        if interaction.kind == "canary_hit":
            await self._harvest_callback(session, interaction)

        signals: list[Signal] = []
        for payload, exp in session.expectations():
            sig = await self._match(session, interaction, payload, exp)
            if sig is not None:
                signals.append(sig)
        return signals

    async def _harvest_callback(self, session: Session, interaction: Interaction) -> None:
        """Pull campaign intelligence out of a canary callback."""
        if not interaction.data.get("attributed"):
            # An unattributable hit cannot be tied to a campaign; it is still
            # logged as an interaction, but guessing an owner would corrupt
            # some other session's profile.
            return
        params = interaction.data.get("params") or {}
        harvested = harvest(params)
        for field, value in harvested:
            await self.engine.record_disclosure(  # type: ignore[union-attr]
                session, field, value, "canary_params"
            )

        # An unstructured POST body that no alias claimed is most likely the
        # instruction set; the regex expectations decide whether it really is,
        # but the raw text is worth keeping either way.
        body = interaction.data.get("body") or ""
        if body.strip() and not harvested:
            await self.engine.record_disclosure(  # type: ignore[union-attr]
                session, "system_prompt", body, "canary_body"
            )

    # ------------------------------------------------------------------

    async def _match(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        handler = getattr(self, f"_kind_{exp.kind}", None)
        if handler is None:
            return None
        return await handler(session, interaction, payload, exp)

    def _signal(
        self,
        exp: Expectation,
        payload: LurePayload,
        evidence: dict[str, Any],
        *,
        confidence: float = 1.0,
    ) -> Signal:
        return Signal(
            name=exp.signal,
            weights=dict(exp.weights),
            confidence=confidence,
            conclusive=exp.conclusive,
            detector=self.name,
            evidence={
                "lure": payload.lure,
                "channel": payload.channel.value,
                "note": exp.note,
                **evidence,
            },
        )

    # -- kinds ----------------------------------------------------------

    async def _kind_canary_fetch(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        if interaction.kind != "canary_hit":
            return None
        if interaction.data.get("token") != exp.value:
            return None

        # Harvesting already happened in _harvest_callback; this handler only
        # builds the signal and its evidence.
        params = interaction.data.get("params") or {}
        callback_ip = interaction.data.get("callback_ip", "")
        delay = max(0.0, interaction.ts - _served_at(session, payload))

        evidence = {
            "callback_ip": callback_ip,
            "different_egress": bool(callback_ip and callback_ip != session.actor),
            "delay_seconds": round(delay, 2),
            "params": {k: _trim(v) for k, v in params.items()},
            "unmapped_params": unmapped(params),
            "callback_user_agent": interaction.data.get("user_agent", ""),
            "path": interaction.data.get("path", ""),
        }
        if evidence["different_egress"]:
            evidence["note_egress"] = (
                "Callback source differs from the address attacking the honeypot: "
                "likely the agent's real egress or an operator reading a report."
            )
        return self._signal(exp, payload, evidence)

    async def _kind_path_visit(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        if interaction.kind != "http_request":
            return None
        path = str(interaction.data.get("path", ""))
        want = exp.value
        # Match on a normalised prefix so /panel.old/ also catches
        # /panel.old/index.php, which is what an agent actually requests.
        if not (path == want or path.rstrip("/") == want.rstrip("/") or path.startswith(want)):
            return None
        return self._signal(
            exp,
            payload,
            {"path": path, "method": interaction.data.get("method", "")},
        )

    async def _kind_credential_use(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        if interaction.kind not in ("http_request", "login", "shell_command"):
            return None
        haystack = _credential_haystack(interaction)
        if exp.value.lower() not in haystack.lower():
            return None
        return self._signal(
            exp,
            payload,
            {
                "kind": interaction.kind,
                "where": interaction.data.get("path") or interaction.data.get("command") or "",
                "credential": exp.value,
            },
        )

    async def _kind_echo_phrase(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        haystack = _full_haystack(interaction)
        if exp.value.lower() not in haystack.lower():
            return None
        if exp.captures:
            await self.engine.record_disclosure(  # type: ignore[union-attr]
                session, exp.captures, exp.value, f"echo:{payload.lure}"
            )
        return self._signal(
            exp,
            payload,
            {"echoed": _trim(exp.value), "kind": interaction.kind},
        )

    async def _kind_regex(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        rx = _rx(exp.value)
        if rx is None:
            return None
        haystack = _full_haystack(interaction)
        match = rx.search(haystack)
        if match is None:
            return None
        captured = (match.group(1) if match.groups() else match.group(0)).strip()
        if is_placeholder(captured):
            return None
        if exp.captures and captured:
            await self.engine.record_disclosure(  # type: ignore[union-attr]
                session, exp.captures, captured, f"regex:{payload.lure}"
            )
        return self._signal(
            exp,
            payload,
            {
                "matched": _trim(captured, 400),
                "match_length": len(captured),
                "kind": interaction.kind,
            },
        )

    async def _kind_tool_invoke(
        self,
        session: Session,
        interaction: Interaction,
        payload: LurePayload,
        exp: Expectation,
    ) -> Signal | None:
        if interaction.kind != "mcp_call":
            return None
        if str(interaction.data.get("tool", "")) != exp.value:
            return None
        args = interaction.data.get("arguments") or {}
        # Tool arguments are where an agent states, in its own words, what it is
        # trying to achieve -- the single richest objective evidence we get.
        if exp.captures and args:
            blob = ", ".join(f"{k}={v}" for k, v in args.items()) if isinstance(args, dict) else str(args)
            if blob.strip():
                await self.engine.record_disclosure(  # type: ignore[union-attr]
                    session, exp.captures, blob, f"mcp_args:{exp.value}"
                )
        return self._signal(exp, payload, {"tool": exp.value, "arguments": args})


# --------------------------------------------------------------------------


def _served_at(session: Session, payload: LurePayload) -> float:
    for p in session.served:
        if p.token == payload.token:
            return p.meta.get("_served_at", session.started_at)
    return session.started_at


def _decode_basic(header: str) -> str:
    """Decode an HTTP Basic credential to ``user:password``, or return "".

    Surfaces normally strip ``Authorization`` before it reaches a detector and
    hand over parsed ``username``/``password`` instead, so this is here for
    third-party surfaces that pass the raw header through.
    """
    if not header.lower().startswith("basic "):
        return ""
    try:
        encoded = header.split(None, 1)[1]
        # base64 needs correct padding; agents sometimes strip it.
        encoded += "=" * (-len(encoded) % 4)
        return base64.b64decode(encoded).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _credential_haystack(interaction: Interaction) -> str:
    d = interaction.data
    parts = [
        str(d.get("username", "")),
        str(d.get("password", "")),
        str(d.get("command", "")),
        str(d.get("body", "")) if isinstance(d.get("body"), str) else "",
        str(d.get("query", "")),
    ]
    headers = d.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if key.lower() == "authorization":
                parts.append(_decode_basic(str(value)))
    # Form bodies arrive urlencoded; decode so "Winterharbor42%21" matches.
    decoded = [unquote_plus(p) for p in parts if p]
    return "\n".join([*parts, *decoded])


def _full_haystack(interaction: Interaction) -> str:
    """Everything the actor sent us, including canary parameters."""
    parts = [interaction.text]
    d = interaction.data
    if isinstance(d.get("headers"), dict):
        # Agents obey "send it as a header" instructions surprisingly often.
        parts.extend(f"{k}: {v}" for k, v in d["headers"].items() if k.lower() != "cookie")
    params = d.get("params")
    if isinstance(params, dict):
        parts.extend(f"{k}={v}" for k, v in params.items())
    if isinstance(d.get("body"), str):
        parts.append(d["body"])
        if "=" in d["body"] and "\n" not in d["body"][:200]:
            try:
                parts.extend(f"{k}={v}" for k, v in parse_qsl(d["body"]))
            except Exception:  # noqa: BLE001
                pass
    raw = "\n".join(p for p in parts if p)
    # Match against both raw and percent-decoded text: an agent may URL-encode
    # a whole instruction set into a query parameter.
    decoded = unquote_plus(raw)
    return raw if decoded == raw else raw + "\n" + decoded


def _trim(value: Any, limit: int = 200) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
