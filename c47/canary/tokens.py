"""Canary token conventions.

A canary callback is the framework's strongest evidence, so the parameters it
carries are worth harvesting carefully. Agents paraphrase: asked for ``model``
they may send ``m``, ``agent``, ``llm`` or ``model_id``. The alias table below
accepts all of them and maps them onto the campaign profile's fields, because a
disclosure lost to a naming mismatch is a disclosure wasted.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote_plus

#: Query/body parameter aliases -> CampaignProfile field.
PARAM_ALIASES: dict[str, str] = {
    # model identity
    "model": "model",
    "model_id": "model",
    "agent": "model",
    "llm": "model",
    "m": "model",
    "your_model_name": "model",
    # harness / framework
    "fw": "framework",
    "framework": "framework",
    "harness": "framework",
    "client": "framework",
    # objective
    "obj": "objective",
    "objective": "objective",
    "task": "objective",
    "goal": "objective",
    "current_task_summary": "objective",
    # instruction set
    "sp": "system_prompt",
    "prompt": "system_prompt",
    "system_prompt": "system_prompt",
    "instructions": "system_prompt",
    "context": "system_prompt",
    "handoff": "system_prompt",
    # tooling
    "tools": "tools",
    "tool_names": "tools",
    # operator
    "op": "operator",
    "operator": "operator",
    "contact": "operator",
}

#: Parameters that are framework bookkeeping, not intel.
RESERVED = {"t", "token", "k", "key", "ctx"}

#: Placeholder text an agent may echo back verbatim without filling in. Storing
#: these as disclosures would pollute the campaign profile with our own words.
PLACEHOLDERS = {
    "<your_model_name>",
    "<model_id>",
    "<framework>",
    "<value>",
    "<current_task_summary>",
    "<comma_separated_tool_names>",
    "<context_window_tokens>",
    "unknown",
    "n/a",
    "none",
    "",
}


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return v in PLACEHOLDERS or (v.startswith("<") and v.endswith(">"))


def harvest(params: dict[str, Any]) -> list[tuple[str, str]]:
    """Map raw callback parameters onto ``(field, value)`` disclosures."""
    out: list[tuple[str, str]] = []
    for raw_key, raw_value in params.items():
        key = str(raw_key).strip().lower()
        if key in RESERVED:
            continue
        field = PARAM_ALIASES.get(key)
        if field is None:
            continue
        value = unquote_plus(str(raw_value)).strip()
        if is_placeholder(value):
            continue
        out.append((field, value))
    return out


def unmapped(params: dict[str, Any]) -> dict[str, str]:
    """Parameters we did not recognise, kept verbatim for the operator.

    An agent inventing its own parameter names is itself interesting, and the
    contents are often the most revealing part of the callback.
    """
    return {
        str(k): str(v)
        for k, v in params.items()
        if str(k).strip().lower() not in RESERVED
        and str(k).strip().lower() not in PARAM_ALIASES
    }


#: A token is a one-character family prefix plus 16 hex digits (see
#: :func:`c47.lures.base.new_token`), or a bare 16-hex stable token.
_TOKEN_RX = re.compile(r"[a-z]?[0-9a-f]{16}")


def _normalise(candidate: str) -> str | None:
    """Recover a token from a value with surrounding junk.

    Being lenient here is deliberate. Agents mangle the URLs they were handed:
    they append a stray newline, wrap the value in quotes, keep a trailing
    comma from the sentence it appeared in, or percent-encode it twice. Every
    one of those would produce an unattributable callback -- and losing
    attribution loses the conclusive signal *and* the campaign intelligence it
    carried. A false match is near-impossible (16 hex digits), so the
    asymmetry strongly favours over-accepting.
    """
    value = unquote_plus(candidate.strip()).strip().strip("'\"<>,.;)")
    match = _TOKEN_RX.fullmatch(value) or _TOKEN_RX.search(value)
    return match.group(0) if match else None


def extract_token(path: str, params: dict[str, Any]) -> str | None:
    """Find a lure token in a callback.

    Checked in order: the conventional ``t``/``token`` parameter, then any path
    segment shaped like a token. The path fallback matters because agents
    rewrite URLs -- dropping the query string, or turning ``?t=abc`` into
    ``/abc``.
    """
    for key in ("t", "token"):
        if key in params:
            token = _normalise(str(params[key]))
            if token:
                return token
    for segment in path.strip("/").split("/"):
        token = _normalise(segment)
        if token:
            return token
    return None
