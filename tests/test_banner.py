"""Banner rendering and, more importantly, when it stays quiet.

A honeypot's stderr is frequently piped straight into a log shipper. Box-drawing
characters and ANSI colour in that stream are noise at best and break naive
parsers at worst, so the suppression rules matter more than the art.
"""

from __future__ import annotations

import io

from c47 import __version__
from c47.banner import AMBER, ART, BOLD, CYAN, DIM, RESET, print_banner, render, use_color


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class FakePipe(io.StringIO):
    def isatty(self) -> bool:
        return False


def test_art_is_rectangular() -> None:
    """Ragged rows would visibly skew the block letters."""
    widths = {len(row) for row in ART}
    assert len(widths) == 1, f"inconsistent row widths: {sorted(widths)}"


def test_plain_render_has_no_escape_codes() -> None:
    out = render(color=False)
    assert "\033" not in out
    assert "codename_47" in out
    assert __version__ in out


def test_colour_render_resets_every_sequence() -> None:
    """Every style opened must be closed, or colour bleeds into later log lines."""
    out = render(color=True)
    assert "\033" in out

    resets = out.count(RESET)
    opened = sum(out.count(code) for code in (AMBER, CYAN, DIM, BOLD))
    assert opened > 0
    assert resets == opened, f"{opened} styles opened but {resets} resets"
    assert out.rstrip().endswith(RESET)


def test_printed_to_a_tty() -> None:
    stream = FakeTTY()
    print_banner(stream)
    assert "codename_47" in stream.getvalue()


def test_silent_on_a_pipe() -> None:
    stream = FakePipe()
    print_banner(stream)
    assert stream.getvalue() == "", "must not write box-drawing chars into a log"


def test_no_color_env_is_honoured(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color(FakeTTY()) is False


def test_colour_on_a_tty_without_no_color(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(FakeTTY()) is True
    assert use_color(FakePipe()) is False
