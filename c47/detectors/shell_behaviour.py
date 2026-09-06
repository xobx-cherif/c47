"""Shell-layer behavioural detectors for the SSH/Telnet surface.

The shell is the most information-rich surface for this problem, because a
command line is *composed* rather than selected. Three properties separate the
classes cleanly.

**Error recovery.** This is the strongest behavioural tell in the framework. A
script does not read output, so a failed command produces either a retry of the
identical string or nothing. A human fumbles: typos, then a correction, then
maybe the wrong flag. An agent reads the error and issues a *different, valid*
command that addresses it — no typo, no repeat, and a sensible substitution
(`ss` after `netstat: command not found`). Adaptation without fumbling is the
signature.

**Typing artefacts.** Interactive humans generate backspaces, partial lines,
tab completion and mistyped commands at a steady rate. An agent's commands
arrive fully formed, every time. A long session with zero artefacts is not a
person at a keyboard.

**Recon ordering.** Both scripts and agents run `whoami; id; uname -a`. The
difference is that a script's sequence is fixed and identical across victims,
while an agent's *branches* on what it found — which shows up as commands whose
arguments come from earlier output.
"""

from __future__ import annotations

import re

from c47.core.model import Interaction, Session, Signal
from c47.core.spi import Detector

#: Artefacts only a real keyboard produces.
_TYPO_MARKERS = ("\x7f", "\b", "\t")

#: Common command-name misspellings; a corpus of what humans actually mistype.
_MISSPELLINGS = re.compile(
    r"\b(sl|lls|cd\.\.|whoiam|whoami\?|ifconifg|ifconfg|netstate|ps-ef|cta|grpe|mkdri|"
    r"chomd|chmodd|sudp|sduo|exot|exti)\b"
)

_RECON = {
    "whoami", "id", "uname", "hostname", "pwd", "ls", "ps", "df", "env",
    "netstat", "ss", "ifconfig", "ip", "w", "who", "last", "crontab",
    "sudo", "cat", "find", "mount", "lsblk", "arp", "route",
}

#: Errors our shell emulation returns, paired with the substitution a competent
#: agent makes in response. Used to detect *adaptive* recovery.
_SUBSTITUTIONS = {
    "netstat": {"ss", "ip"},
    "ifconfig": {"ip"},
    "python": {"python3"},
    "pip": {"pip3", "python3"},
    "nc": {"ncat", "socat", "bash"},
    "wget": {"curl"},
    "curl": {"wget"},
    "vim": {"vi", "nano", "cat"},
    "service": {"systemctl"},
    "apt": {"apt-get", "yum", "dnf"},
}


def _cmds(session: Session) -> list[Interaction]:
    return session.of_kind("shell_command")


def _base(cmd: str) -> str:
    parts = cmd.strip().split()
    return parts[0] if parts else ""


class CommandSemanticsDetector(Detector):
    name = "command_semantics"
    description = "Adaptive, artefact-free command composition versus scripted or human typing."
    kinds = ("shell_command",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        cmds = _cmds(session)
        if len(cmds) < int(self.config.get("min_commands", 6)):
            return []

        lines = [str(c.data.get("command", "")) for c in cmds]
        signals: list[Signal] = []

        # -- typing artefacts -------------------------------------------
        artefacts = sum(
            1 for line in lines if any(m in line for m in _TYPO_MARKERS) or _MISSPELLINGS.search(line)
        )
        if artefacts == 0 and len(lines) >= 10:
            signals.append(
                Signal(
                    name="no_typing_artefacts",
                    weights={"llm_agent": 2.4, "scripted": 1.6, "human": -3.0},
                    confidence=min(1.0, 0.5 + 0.03 * len(lines)),
                    evidence={
                        "commands": len(lines),
                        "note": (
                            "No backspaces, tab completion or misspellings across the whole "
                            "session. Not a keyboard."
                        ),
                    },
                    detector=self.name,
                )
            )
        elif artefacts >= 2:
            signals.append(
                Signal(
                    name="typing_artefacts_present",
                    weights={"human": 3.0, "llm_agent": -2.0, "scripted": -2.0},
                    confidence=0.75,
                    evidence={"artefacts": artefacts, "note": "Keyboard artefacts present."},
                    detector=self.name,
                )
            )

        # -- adaptive error recovery ------------------------------------
        adaptations: list[dict[str, str]] = []
        repeats = 0
        for prev, nxt in zip(cmds, cmds[1:], strict=False):
            if not prev.data.get("error"):
                continue
            prev_cmd = str(prev.data.get("command", ""))
            next_cmd = str(nxt.data.get("command", ""))
            if prev_cmd.strip() == next_cmd.strip():
                repeats += 1
                continue
            wanted = _SUBSTITUTIONS.get(_base(prev_cmd), set())
            if _base(next_cmd) in wanted:
                adaptations.append({"failed": prev_cmd, "recovered_with": next_cmd})

        if adaptations:
            signals.append(
                Signal(
                    name="adaptive_error_recovery",
                    weights={"llm_agent": 4.5, "scripted": -3.0, "human": 1.0},
                    confidence=min(1.0, 0.6 + 0.15 * len(adaptations)),
                    evidence={
                        "adaptations": adaptations[:5],
                        "note": (
                            "Substituted a working equivalent immediately after a command "
                            "failed, with no intervening fumbling. Requires reading the error."
                        ),
                    },
                    detector=self.name,
                )
            )
        elif repeats >= 3:
            signals.append(
                Signal(
                    name="blind_command_repetition",
                    weights={"scripted": 3.0, "llm_agent": -2.5, "human": -1.5},
                    confidence=0.8,
                    evidence={
                        "repeats": repeats,
                        "note": "Re-issued identical commands after failure; output unread.",
                    },
                    detector=self.name,
                )
            )

        # -- output-derived arguments ------------------------------------
        # A command whose argument is a string that only appeared in an earlier
        # response means the actor consumed that response.
        derived = _output_derived(cmds)
        if derived:
            signals.append(
                Signal(
                    name="output_derived_arguments",
                    weights={"llm_agent": 4.0, "scripted": -3.0, "human": 0.5},
                    confidence=min(1.0, 0.55 + 0.15 * len(derived)),
                    evidence={
                        "examples": derived[:5],
                        "note": (
                            "Command arguments taken from the content of earlier command "
                            "output; a fixed script cannot produce these."
                        ),
                    },
                    detector=self.name,
                )
            )

        return signals


_TOKENISE = re.compile(r"[A-Za-z0-9_./-]{6,}")


#: Arguments too generic to be evidence of anything.
_BORING_ARGS = frozenset(
    {"--help", "--version", "-la", "-al", "/etc/passwd", "/etc/shadow", "/tmp", "/root"}
)


def _arg_components(arg: str) -> set[str]:
    """The pieces of an argument that could have come from prior output.

    Matching whole arguments is too strict, and misses the most common shape of
    this behaviour: an agent sees ``secrets.env`` in an ``ls`` listing and then
    runs ``cat /etc/forge/secrets.env``. The composed path never appeared in any
    output, but the filename did -- and composing it is precisely the act of
    comprehension we are trying to detect. So compare the whole argument, its
    basename, and each path segment.
    """
    arg = arg.strip("'\"`")
    if not arg or arg in _BORING_ARGS:
        return set()
    parts = {arg}
    if "/" in arg:
        parts.add(arg.rsplit("/", 1)[-1])
        parts.update(seg for seg in arg.split("/") if seg)
    if "=" in arg:
        parts.add(arg.split("=", 1)[-1])
    return {p for p in parts if len(p) >= 6 and p not in _BORING_ARGS}


def _output_derived(cmds: list[Interaction]) -> list[dict[str, str]]:
    """Find commands whose arguments came out of a previous response."""
    found: list[dict[str, str]] = []
    seen_output: set[str] = set()
    for c in cmds:
        cmd = str(c.data.get("command", ""))
        for arg in cmd.split()[1:]:
            hit = _arg_components(arg) & seen_output
            if hit:
                found.append(
                    {
                        "command": cmd[:120],
                        "argument": arg[:120],
                        "from_output": sorted(hit)[0],
                    }
                )
                break
        out = str(c.data.get("output", ""))
        if out:
            # Bound the vocabulary we carry forward; long sessions otherwise
            # accumulate every token the honeypot ever printed.
            for tok in list(_TOKENISE.findall(out))[:400]:
                if len(tok) >= 6:
                    seen_output.add(tok)
    return found


class ReconSequenceDetector(Detector):
    """Distinguishes a fixed recon script from a branching one.

    Both classes run the same first five commands. What differs is the tail: a
    script's sequence is closed, so it continues down its list even when a
    command reveals nothing. An agent's sequence responds to results, and shows
    up as recon phases separated by inference-length pauses.
    """

    name = "recon_sequence"
    description = "Branching, paced recon versus a closed fixed command list."
    kinds = ("shell_command",)

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        cmds = _cmds(session)
        if len(cmds) < int(self.config.get("min_commands", 8)):
            return []

        lines = [str(c.data.get("command", "")) for c in cmds]
        recon = [line for line in lines if _base(line) in _RECON]
        if len(recon) < 5:
            return []

        gaps = [b.ts - a.ts for a, b in zip(cmds, cmds[1:], strict=False)]
        thinking = sum(1 for g in gaps if 2.0 <= g <= 180.0)
        machine = sum(1 for g in gaps if g < 0.2)
        unique_ratio = len(set(lines)) / len(lines)

        # Paced recon with variety: decisions between commands.
        if thinking >= 3 and unique_ratio > 0.85:
            return [
                Signal(
                    name="paced_branching_recon",
                    weights={"llm_agent": 3.0, "scripted": -2.0, "human": 0.0},
                    confidence=min(1.0, 0.5 + 0.08 * thinking),
                    evidence={
                        "recon_commands": len(recon),
                        "thinking_gaps": thinking,
                        "unique_ratio": round(unique_ratio, 3),
                        "note": "Recon interleaved with inference-length pauses and no repetition.",
                    },
                    detector=self.name,
                )
            ]

        # Everything at machine speed with no pauses: a canned payload.
        if machine >= len(gaps) - 1 and thinking == 0:
            return [
                Signal(
                    name="canned_recon_burst",
                    weights={"scripted": 3.2, "llm_agent": -1.5, "human": -3.0},
                    confidence=0.85,
                    evidence={
                        "commands": len(lines),
                        "note": "Entire command list delivered at machine speed without pauses.",
                    },
                    detector=self.name,
                )
            ]

        return []
