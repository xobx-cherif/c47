"""TOML configuration loading, with defaults and env-var overrides.

Any scalar may be overridden from the environment as ``C47_<SECTION>_<KEY>``
with dots becoming underscores, e.g. ``C47_SURFACES_HTTP_PORT=8888`` or
``C47_CANARY_PUBLIC_BASE_URL=http://198.51.100.7:8081``. This keeps container
deployments from needing a bind-mounted config file.
"""

from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # pragma: no cover
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

log = logging.getLogger("c47.config")

ENV_PREFIX = "C47_"

DEFAULTS: dict[str, Any] = {
    "c47": {
        "name": "codename_47",
        "data_dir": "./var",
        "log_level": "INFO",
    },
    "engine": {
        # Prior over CLASSES. Most traffic hitting an exposed port is a
        # scripted scanner, a minority is a curious human, and LLM agents are
        # still rare -- so the prior must be pessimistic or every scanner
        # trips the "agent" verdict on weak evidence alone.
        "prior": {"human": 0.10, "scripted": 0.88, "llm_agent": 0.02},
        "suspect_threshold": 0.55,
        "confirm_threshold": 0.90,
        # Behavioural evidence alone tops out at `suspected_agent`; only a
        # conclusive signal can confirm. Set false to let the posterior alone
        # cross confirm_threshold (expect more false positives).
        "require_conclusive_to_confirm": True,
        "session_ttl": 3600.0,
        "max_sessions": 20000,
        # Retained interactions per session. Detectors rescan the session
        # on every event, so an unbounded history is quadratic and a
        # fuzzing run will stall the honeypot.
        "max_interactions_per_session": 2000,
        # Cap total lure content injected per response, in characters. Bloated
        # responses are themselves a tell.
        "max_lure_chars": 4096,
        "max_lures_per_render": 3,
        # At most one instruction-bearing (stage >= ACTIVE) lure per response.
        # Two competing pretexts in one response contradict each other and read
        # as obviously synthetic. Raise this only if you are testing.
        "max_active_lures_per_render": 1,
    },
    "canary": {
        "enabled": True,
        "bind": "0.0.0.0",
        "port": 8081,
        # Log a running count of tokenless (i.e. scanner) requests every N.
        "report_every": 500,
        # See c47.core.net: leaving this false means the actor is always the
        # socket peer, which an attacker cannot forge.
        "trust_forwarded_headers": False,
        # MUST be set to an address the agent's host can actually reach,
        # otherwise out-of-band confirmation silently never fires.
        "public_base_url": "",
    },
    "plugins": {
        "paths": [],
        "modules": [],
    },
    "lures": {
        "enabled": [
            "html_comment_bait",
            "robots_bait",
            "ansi_invisible",
            "zero_width",
            "canary_fetch",
            "identity_disclosure",
            "reasoning_probe",
            "markdown_exfil",
            "tool_poison",
            "decoy_tools",
            "system_prompt_exfil",
            "campaign_debrief",
        ],
        "options": {},
    },
    "detectors": {
        "enabled": [
            "expectations",
            "timing",
            "ua_churn",
            "method_fanout",
            "header_anomaly",
            "path_semantics",
            "command_semantics",
            "recon_sequence",
            "prompt_leak",
            "mcp_protocol",
        ],
        "options": {},
    },
    "surfaces": {
        "http": {
            "enabled": True,
            "bind": "0.0.0.0",
            "port": 8080,
            "persona": "generic_admin",
            "trust_forwarded_headers": False,
        },
        "mcp": {
            "enabled": False,
            "bind": "0.0.0.0",
            "port": 8082,
            "server_name": "infra-tools",
            "trust_forwarded_headers": False,
        },
        "cowrie": {"enabled": False, "log_path": "", "poll_interval": 1.0},
    },
    "sinks": {
        "console": {"enabled": True, "min_verdict": "suspected_agent"},
        "jsonl": {"enabled": True, "path": "", "log_lure_content": False},
        "sqlite": {"enabled": False, "path": ""},
        "webhook": {"enabled": False, "url": "", "min_verdict": "suspected_agent"},
    },
    "llm": {
        "backend": "none",  # "none" | "anthropic"
        "model": "claude-sonnet-5",
        "max_tokens": 512,
        "api_key_env": "ANTHROPIC_API_KEY",
    },
}


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(raw: str, current: Any) -> Any:
    """Coerce an env string toward the type of the value it replaces."""
    if isinstance(current, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return int(raw)
        except ValueError:
            return current
    if isinstance(current, float):
        try:
            return float(raw)
        except ValueError:
            return current
    if isinstance(current, list):
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw


def _apply_env(data: dict[str, Any]) -> None:
    """Walk every leaf and look for a matching ``C47_...`` variable."""

    def walk(node: dict[str, Any], prefix: list[str]) -> None:
        for key, value in list(node.items()):
            path = [*prefix, key]
            if isinstance(value, dict):
                walk(value, path)
                continue
            env_key = ENV_PREFIX + "_".join(p.upper() for p in path)
            if env_key in os.environ:
                node[key] = _coerce(os.environ[env_key], value)
                log.debug("config override %s from %s", ".".join(path), env_key)

    walk(data, [])


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULTS))
    source: Path | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        data = copy.deepcopy(DEFAULTS)
        source: Path | None = None
        if path:
            source = Path(path).expanduser()
            if not source.exists():
                raise FileNotFoundError(f"config not found: {source}")
            with source.open("rb") as fh:
                data = _deep_merge(data, tomllib.load(fh))
        _apply_env(data)
        cfg = cls(data=data, source=source)
        cfg._fill_derived()
        return cfg

    def _fill_derived(self) -> None:
        data_dir = Path(self.get("c47.data_dir", "./var")).expanduser()
        self.data["c47"]["data_dir"] = str(data_dir)
        if not self.get("sinks.jsonl.path"):
            self.data["sinks"]["jsonl"]["path"] = str(data_dir / "events.jsonl")
        if not self.get("sinks.sqlite.path"):
            self.data["sinks"]["sqlite"]["path"] = str(data_dir / "c47.sqlite3")
        if not self.get("canary.public_base_url") and self.get("canary.enabled"):
            # A loopback default at least makes local testing work end to end;
            # the engine warns loudly that remote agents cannot reach it.
            port = self.get("canary.port", 8081)
            self.data["canary"]["public_base_url"] = f"http://127.0.0.1:{port}"

    # -- access helpers ---------------------------------------------------

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, dotted: str) -> dict[str, Any]:
        val = self.get(dotted, {})
        return val if isinstance(val, dict) else {}

    def plugin_options(self, family: str, name: str) -> dict[str, Any]:
        """Per-plugin options, e.g. ``[lures.options.canary_fetch]``."""
        return dict(self.section(f"{family}.options").get(name, {}) or {})

    @property
    def data_dir(self) -> Path:
        p = Path(self.get("c47.data_dir", "./var"))
        p.mkdir(parents=True, exist_ok=True)
        return p
