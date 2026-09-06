"""Built-in telemetry sinks."""

from __future__ import annotations

from c47.sinks import console, jsonl, sqlite, webhook  # noqa: F401

__all__ = ["console", "jsonl", "sqlite", "webhook"]
