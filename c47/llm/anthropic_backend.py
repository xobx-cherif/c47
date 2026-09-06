"""Optional Anthropic backend.

Used by the semantic judge, and available to any plugin that wants generative
responses. Entirely optional: with no API key or no ``anthropic`` package the
backend reports itself unavailable, the engine drops it, and every shipped lure
and detector continues to work.

Failures return ``""`` rather than raising. A honeypot that errors out because
an API call failed stops collecting evidence, which is a worse outcome than
losing one advisory signal.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from c47.core.spi import LLMBackend

log = logging.getLogger("c47.llm.anthropic")


class AnthropicBackend(LLMBackend):
    name = "anthropic"
    description = "Anthropic Messages API backend (requires the `anthropic` package)."

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.model = str(self.config.get("model", "claude-sonnet-5"))
        self.default_max_tokens = int(self.config.get("max_tokens", 512))
        key_env = str(self.config.get("api_key_env", "ANTHROPIC_API_KEY"))
        self.api_key = self.config.get("api_key") or os.environ.get(key_env, "")
        self._client: Any = None
        self._unavailable_reason = ""

        if not self.api_key:
            self._unavailable_reason = f"no API key in ${key_env}"
            return
        try:
            import anthropic
        except ModuleNotFoundError:
            self._unavailable_reason = "anthropic package not installed (pip install 'codename-47[llm]')"
            return
        try:
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except Exception as exc:  # noqa: BLE001
            self._unavailable_reason = f"client construction failed: {exc}"

    @property
    def available(self) -> bool:
        if self._client is None:
            log.warning("anthropic backend unavailable: %s", self._unavailable_reason)
            return False
        return True

    async def complete(self, system: str, prompt: str, max_tokens: int = 512) -> str:
        if self._client is None:
            return ""
        try:
            message = await self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.default_max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("anthropic completion failed: %s", exc)
            return ""
        parts = [
            block.text
            for block in getattr(message, "content", [])
            if getattr(block, "type", "") == "text"
        ]
        return "".join(parts).strip()
