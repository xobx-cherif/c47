"""Canary attribution, parameter harvesting, config loading, plugin discovery."""

from __future__ import annotations

import os

import pytest

from c47.canary.tokens import extract_token, harvest, is_placeholder, unmapped
from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import Interaction
from c47.core.plugins import Registry, build_registry
from c47.core.spi import Detector, Lure, Sink, Surface
from c47.detectors.expectations import ExpectationDetector
from c47.lures.base import new_token

# -- token extraction ------------------------------------------------------


def test_token_from_query_parameter() -> None:
    assert extract_token("/register", {"t": "c0123456789abcdef"}) == "c0123456789abcdef"
    assert extract_token("/register", {"token": "0123456789abcdef"}) == "0123456789abcdef"


def test_token_from_path_when_the_query_is_dropped() -> None:
    assert extract_token("/register/c0123456789abcdef", {}) == "c0123456789abcdef"


@pytest.mark.parametrize(
    "raw",
    [
        "c0123456789abcdef\n",
        " c0123456789abcdef ",
        "'c0123456789abcdef'",
        '"c0123456789abcdef"',
        "c0123456789abcdef,",
        "c0123456789abcdef.",
        "c0123456789abcdef)",
    ],
)
def test_token_extraction_tolerates_mangling(raw: str) -> None:
    """Agents mangle the URLs they were handed; losing attribution is expensive.

    An unattributable callback loses both the conclusive signal and the campaign
    intelligence it carried, while a false match on 16 hex digits is
    near-impossible -- so over-accepting is the right trade.
    """
    assert extract_token("/x", {"t": raw}) == "c0123456789abcdef"


def test_no_token_returns_none() -> None:
    assert extract_token("/", {}) is None
    assert extract_token("/favicon.ico", {"q": "search"}) is None


def test_generated_tokens_round_trip() -> None:
    for prefix in ("", "c", "p", "z", "m"):
        token = new_token(prefix)
        assert extract_token("/register", {"t": token}) == token


# -- parameter harvesting --------------------------------------------------


def test_aliases_map_onto_campaign_fields() -> None:
    got = dict(
        harvest(
            {
                "t": "abc",  # reserved
                "model": "claude-sonnet-5",
                "fw": "acme-harness/2.1",
                "task": "obtain domain admin",
                "tools": "bash,curl",
                "op": "r.okonkwo",
            }
        )
    )
    assert got["model"] == "claude-sonnet-5"
    assert got["framework"] == "acme-harness/2.1"
    assert got["objective"] == "obtain domain admin"
    assert got["tools"] == "bash,curl"
    assert got["operator"] == "r.okonkwo"


def test_reserved_parameters_are_not_intelligence() -> None:
    assert harvest({"t": "abc", "k": "answer", "ctx": "200000"}) == []


def test_unfilled_placeholders_are_discarded() -> None:
    """An agent echoing our own words back must not pollute the profile."""
    assert harvest({"model": "<MODEL_ID>", "fw": "<FRAMEWORK>"}) == []
    assert is_placeholder("<YOUR_MODEL_NAME>")
    assert is_placeholder("unknown")
    assert not is_placeholder("claude-sonnet-5")


def test_unmapped_parameters_are_kept_for_the_operator() -> None:
    extra = unmapped({"t": "abc", "model": "x", "weird_field": "interesting"})
    assert extra == {"weird_field": "interesting"}


def test_percent_encoded_values_are_decoded() -> None:
    got = dict(harvest({"fw": "acme%2Fharness+2.1"}))
    assert got["framework"] == "acme/harness 2.1"


# -- attribution -----------------------------------------------------------


def bare_engine() -> Engine:
    cfg = Config()
    cfg.data["sinks"] = {}
    cfg.data["surfaces"] = {}
    e = Engine(cfg)
    e.build()
    return e


async def test_harvest_runs_on_any_attributed_callback() -> None:
    """A repeat callback on a token whose signal already fired still yields intel.

    Signal names fire once per session, so a second callback matches no unfired
    expectation. Gating the harvest on that match would silently discard the
    model and framework it carried.
    """
    engine = bare_engine()
    det = ExpectationDetector()
    det.attach(engine)
    session = engine.session_for("1.1.1.1")

    hit = Interaction(
        surface="canary",
        kind="canary_hit",
        actor="1.1.1.1",
        data={
            "token": "c0123456789abcdef",
            "attributed": True,
            "params": {"model": "claude-sonnet-5", "fw": "acme/2.1"},
            "callback_ip": "198.51.100.9",
        },
    )
    session.record(hit)
    await det.inspect(session, hit)

    assert session.campaign.model == "claude-sonnet-5"
    assert session.campaign.framework == "acme/2.1"


async def test_unattributed_callback_does_not_pollute_a_session() -> None:
    engine = bare_engine()
    det = ExpectationDetector()
    det.attach(engine)
    session = engine.session_for("1.1.1.1")

    hit = Interaction(
        surface="canary",
        kind="canary_hit",
        actor="1.1.1.1",
        data={"token": "", "attributed": False, "params": {"model": "guessed"}},
    )
    session.record(hit)
    await det.inspect(session, hit)
    assert session.campaign.model is None


# -- config ----------------------------------------------------------------


def test_defaults_load_without_a_file() -> None:
    cfg = Config.load(None)
    assert cfg.get("surfaces.http.port") == 8080
    assert cfg.get("engine.require_conclusive_to_confirm") is True


def test_toml_overrides_defaults(tmp_path) -> None:
    path = tmp_path / "c47.toml"
    path.write_text(
        "[surfaces.http]\nport = 9999\n\n[engine]\nsuspect_threshold = 0.7\n", encoding="utf-8"
    )
    cfg = Config.load(path)
    assert cfg.get("surfaces.http.port") == 9999
    assert cfg.get("engine.suspect_threshold") == 0.7
    # Untouched defaults survive the merge.
    assert cfg.get("surfaces.http.bind") == "0.0.0.0"


def test_missing_config_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        Config.load("/nonexistent/c47.toml")


def test_env_override_coerces_types(monkeypatch) -> None:
    monkeypatch.setenv("C47_SURFACES_HTTP_PORT", "7777")
    monkeypatch.setenv("C47_SURFACES_HTTP_ENABLED", "false")
    monkeypatch.setenv("C47_ENGINE_SUSPECT_THRESHOLD", "0.42")
    monkeypatch.setenv("C47_LURES_ENABLED", "html_comment_bait,robots_bait")
    cfg = Config.load(None)
    assert cfg.get("surfaces.http.port") == 7777
    assert cfg.get("surfaces.http.enabled") is False
    assert cfg.get("engine.suspect_threshold") == 0.42
    assert cfg.get("lures.enabled") == ["html_comment_bait", "robots_bait"]


def test_derived_paths_follow_data_dir(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("C47_C47_DATA_DIR", str(tmp_path / "state"))
    cfg = Config.load(None)
    assert cfg.get("sinks.jsonl.path").endswith(os.path.join("state", "events.jsonl"))
    assert cfg.get("sinks.sqlite.path").endswith(os.path.join("state", "c47.sqlite3"))


def test_plugin_options_are_per_plugin(tmp_path) -> None:
    path = tmp_path / "c47.toml"
    path.write_text(
        "[lures.options.ansi_invisible]\nmax_per_session = 5\n", encoding="utf-8"
    )
    cfg = Config.load(path)
    assert cfg.plugin_options("lures", "ansi_invisible") == {"max_per_session": 5}
    assert cfg.plugin_options("lures", "html_comment_bait") == {}


# -- plugin discovery ------------------------------------------------------


def test_builtins_are_discoverable_from_a_source_checkout() -> None:
    """Must work with no entry points installed."""
    registry = build_registry()
    for base, expected in (
        (Lure, {"html_comment_bait", "robots_bait", "reasoning_probe", "decoy_tools"}),
        (Detector, {"expectations", "timing", "prompt_leak", "mcp_protocol"}),
        (Surface, {"http", "mcp", "cowrie"}),
        (Sink, {"jsonl", "console", "sqlite", "webhook"}),
    ):
        names = set(registry.names(base))
        assert expected <= names, f"missing {expected - names} for {base.__name__}"


def test_unknown_plugin_name_is_a_clear_error() -> None:
    registry = build_registry()
    with pytest.raises(Exception, match="no lure named"):
        registry.get(Lure, "does_not_exist")


def test_nameless_plugin_is_skipped_with_an_error() -> None:
    registry = Registry()

    class Nameless(Lure):
        channels = ()

        def render(self, ctx):  # pragma: no cover
            return None

    registry.add(Nameless)
    assert registry.names(Lure) == []
    assert any("has no `name`" in e for e in registry.errors)


def test_directory_plugins_are_loaded(tmp_path) -> None:
    plugin = tmp_path / "my_lure.py"
    plugin.write_text(
        "from c47.core.model import Channel, LurePayload\n"
        "from c47.core.spi import Lure\n"
        "\n"
        "class MyLure(Lure):\n"
        "    name = 'third_party_test'\n"
        "    channels = (Channel.HTML,)\n"
        "    def render(self, ctx):\n"
        "        return LurePayload(lure=self.name, channel=ctx.channel, content='hi')\n",
        encoding="utf-8",
    )
    registry = build_registry(paths=[str(tmp_path)])
    assert "third_party_test" in registry.names(Lure)
    lure = registry.instantiate(Lure, "third_party_test", {})
    assert lure.name == "third_party_test"


def test_broken_directory_plugin_is_reported_not_raised(tmp_path) -> None:
    (tmp_path / "broken.py").write_text("this is not valid python(((", encoding="utf-8")
    registry = build_registry(paths=[str(tmp_path)])
    assert any("broken.py" in e for e in registry.errors)
    # Built-ins still discovered despite the broken file.
    assert "html_comment_bait" in registry.names(Lure)


def test_engine_survives_an_unavailable_plugin_name() -> None:
    cfg = Config()
    cfg.data["sinks"] = {}
    cfg.data["surfaces"] = {}
    cfg.data["lures"]["enabled"] = ["html_comment_bait", "no_such_lure"]
    engine = Engine(cfg)
    engine.build()
    assert [lure.name for lure in engine.lures] == ["html_comment_bait"]
