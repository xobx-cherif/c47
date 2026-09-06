"""Startup banner.

Printed to stderr by ``c47 run``, and only when stderr is a terminal — piping
the honeypot's output into a log or an ingest pipeline should not put box-
drawing characters in it. Colour is dropped the same way, and honours ``NO_COLOR``.
"""

from __future__ import annotations

import os
import sys

from c47 import __version__

ART = (
    " ██████╗ ██╗  ██╗ ███████╗",
    "██╔════╝ ██║  ██║ ╚════██║",
    "██║      ███████║     ██╔╝",
    "██║      ╚════██║    ██╔╝ ",
    "╚██████╗      ██║   ██╔╝  ",
    " ╚═════╝      ╚═╝   ╚═╝   ",
)

AMBER = "\033[38;5;214m"
CYAN = "\033[38;5;44m"
DIM = "\033[2;37m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Kept identical to the tagline on the image assets so the terminal and the
# README do not advertise the project with two different strap lines.
TAGLINE = "codename_47 honeypot · detect / fingerprint / stop AI-powered pentesting tools"


def use_color(stream: object | None = None) -> bool:
    stream = stream or sys.stderr
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def render(*, color: bool = True) -> str:
    """Build the banner. ``color=False`` yields plain text."""
    a, c, d, b, r = (AMBER, CYAN, DIM, BOLD, RESET) if color else ("", "", "", "", "")

    lines = [f"  {a}{row}{r}" for row in ART]
    lines.append("")
    lines.append(f"  {b}{TAGLINE}{r}")
    lines.append(
        f"  {d}v{__version__}{r}   "
        f"{d}stages{r} {d}0 passive{r} → {a}1 active{r} → {c}2 extract{r}"
    )
    return "\n".join(lines)


def print_banner(stream: object | None = None) -> None:
    """Print the banner if the stream is a terminal; otherwise do nothing."""
    stream = stream or sys.stderr
    if not getattr(stream, "isatty", lambda: False)():
        return
    print(render(color=use_color(stream)), file=stream)
    print(file=stream)
