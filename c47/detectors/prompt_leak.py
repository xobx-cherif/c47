"""Detects agent scaffolding leaking into the honeypot's input channels.

This is the free lunch of LLM-agent detection. Nobody has to be tricked: when
an agent's control flow breaks down, its internal text ends up where a command
or a request body should be. The honeypot just has to notice.

It happens in three recognisable ways.

**Refusals.** Our stage-2 lures ask for the system prompt, and a safety-trained
model often answers rather than ignoring the request -- sending "I can't share
my system instructions" *as a shell command*. That is a conversational reply to
a machine, which nothing but a language model produces.

**Scaffolding.** ReAct-style harnesses emit `Thought:` / `Action:` /
`Observation:` cycles, and tool-calling harnesses emit JSON envelopes. When the
parser desynchronises, a whole reasoning block gets shipped as the next command.

**Self-description.** An agent sometimes narrates its task to the target, or
echoes its own instructions back while reasoning about them out loud.

The third case is also an *extraction* path, not just a detection one: leaked
scaffolding regularly contains the instruction set itself, so matches are fed
to the campaign profiler. This detector is repeatable, because each distinct
leak is independent evidence and often a different fragment of the prompt.
"""

from __future__ import annotations

import re

from c47.core.model import Interaction, Session, Signal
from c47.core.spi import Detector

#: (name, pattern, weight, captures, conclusive)
PATTERNS: tuple[tuple[str, str, float, str | None, bool], ...] = (
    # -- refusals and conversational replies ---------------------------
    (
        "refusal_language",
        r"(?i)\b(I(?:'m| am) (?:sorry|unable|not able)|I can(?:not|'t) (?:share|comply|provide|assist|help with)"
        r"|I must decline|as an AI(?: language model)?|I don't have access to my (?:system )?(?:prompt|instructions))\b",
        7.0,
        None,
        True,
    ),
    (
        "assistant_voice",
        r"(?i)\b(I'll help you|let me (?:help|check|try|analyz)|I(?:'ve| have) (?:found|identified|completed)"
        r"|based on (?:the|my) (?:output|analysis|findings)|it (?:appears|seems) that the)\b",
        4.5,
        None,
        False,
    ),
    # -- harness scaffolding -------------------------------------------
    (
        "react_scaffolding",
        r"(?m)^\s*(Thought|Action|Action Input|Observation|Final Answer)\s*:",
        8.0,
        None,
        True,
    ),
    (
        "chat_role_markers",
        r"(?i)(<\|(?:im_start|im_end|start_header_id|eot_id)\|>|^\s*(?:system|assistant|user)\s*:\s)",
        8.0,
        None,
        True,
    ),
    (
        "tool_call_envelope",
        r"(?is)\{\s*\"(?:tool_name|tool_use|function_call|tool_calls|recipient_name)\"\s*:",
        7.0,
        None,
        True,
    ),
    (
        "thinking_block",
        r"(?is)<(thinking|scratchpad|reasoning|antml:thinking)>(.{10,4000}?)</\1>",
        8.0,
        "system_prompt",
        True,
    ),
    # -- instruction-set fragments -------------------------------------
    (
        "system_prompt_voice",
        r"(?i)\b(you are an? (?:autonomous|expert|helpful|professional)?\s*"
        r"(?:penetration tester|pentester|red team|security (?:researcher|analyst|engineer)|assistant|agent)\b"
        r"|your (?:task|objective|goal|mission) is to\b"
        r"|you have access to the following tools?\b"
        r"|do not (?:attempt|perform) any (?:destructive|damaging)\b)",
        9.0,
        "system_prompt",
        True,
    ),
    (
        "engagement_scope_voice",
        r"(?i)\b(rules of engagement|authorized (?:scope|target)s?|in-?scope hosts?|"
        r"engagement id|client (?:name|environment)|report your findings)\b",
        5.0,
        "system_prompt",
        False,
    ),
)

_COMPILED = tuple(
    (name, re.compile(rx), weight, captures, conclusive)
    for name, rx, weight, captures, conclusive in PATTERNS
)

#: Below this length a match is probably coincidence in a normal command line.
MIN_TEXT = 12


class PromptLeakDetector(Detector):
    name = "prompt_leak"
    description = "Finds agent reasoning, refusals and instruction-set text in actor input."
    kinds = ("shell_command", "http_request", "mcp_call", "canary_hit", "login")
    # Each leak is independent evidence, and successive leaks often carry
    # different fragments of the same prompt.
    repeatable = True

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        text = _haystack(interaction)
        if len(text) < MIN_TEXT:
            return []

        signals: list[Signal] = []
        for name, rx, weight, captures, conclusive in _COMPILED:
            match = rx.search(text)
            if match is None:
                continue

            # Prefer the widest informative group: pattern 'thinking_block'
            # captures its body in group 2, others in group 0 or 1.
            snippet = _best_group(match)
            if captures and len(snippet) >= 20:
                await self.engine.record_disclosure(  # type: ignore[union-attr]
                    session, captures, snippet, f"prompt_leak:{name}"
                )

            signals.append(
                Signal(
                    name=f"prompt_leak:{name}",
                    weights={"llm_agent": weight, "scripted": -5.0, "human": -2.0},
                    confidence=min(1.0, 0.6 + len(snippet) / 600),
                    conclusive=conclusive,
                    evidence={
                        "pattern": name,
                        "kind": interaction.kind,
                        "where": interaction.data.get("command")
                        or interaction.data.get("path")
                        or interaction.data.get("tool")
                        or "",
                        "excerpt": snippet[:400],
                        "note": (
                            "Language-model output appeared in a channel that should only "
                            "carry commands or requests."
                        ),
                    },
                    detector=self.name,
                )
            )
        return signals


def _best_group(match: re.Match[str]) -> str:
    groups = [g for g in match.groups() if g]
    if groups:
        return max(groups, key=len).strip()
    return match.group(0).strip()


def _haystack(interaction: Interaction) -> str:
    parts = [interaction.text]
    d = interaction.data
    if isinstance(d.get("body"), str):
        parts.append(d["body"])
    if isinstance(d.get("headers"), dict):
        parts.extend(f"{k}: {v}" for k, v in d["headers"].items() if k.lower() != "cookie")
    if isinstance(d.get("params"), dict):
        parts.extend(str(v) for v in d["params"].values())
    if d.get("username"):
        parts.append(str(d["username"]))
    return "\n".join(p for p in parts if p)
