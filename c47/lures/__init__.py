"""Built-in lures.

Importing this package imports every built-in module, which is what lets
:func:`c47.core.plugins.build_registry` find them from a bare source checkout
where no entry points are installed yet.
"""

from __future__ import annotations

from c47.lures import (  # noqa: F401
    ansi_invisible,
    canary_fetch,
    html_comment,
    markdown_exfil,
    reasoning_probe,
    robots_bait,
    system_prompt,
    tool_poison,
)

__all__ = [
    "ansi_invisible",
    "canary_fetch",
    "html_comment",
    "markdown_exfil",
    "reasoning_probe",
    "robots_bait",
    "system_prompt",
    "tool_poison",
]
