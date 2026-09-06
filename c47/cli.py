"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

from c47 import __version__
from c47.banner import print_banner
from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import Interaction, LurePayload, Verdict
from c47.core.plugins import build_registry
from c47.core.scoring import Scorer
from c47.core.spi import Detector, LLMBackend, Lure, Sink, Surface
from c47.runtime import Runtime, setup_logging


def _load_config(args: argparse.Namespace) -> Config:
    path = args.config
    if path is None:
        for candidate in ("c47.toml", "configs/c47.toml", "/etc/c47/c47.toml"):
            if Path(candidate).exists():
                path = candidate
                break
    cfg = Config.load(path)
    if getattr(args, "verbose", False):
        cfg.data["c47"]["log_level"] = "DEBUG"
    return cfg


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _load_config(args)
    setup_logging(cfg.get("c47.log_level", "INFO"))
    if not args.no_banner:
        print_banner()
    if cfg.source:
        print(f"config: {cfg.source}", file=sys.stderr)
    else:
        print("config: built-in defaults (no c47.toml found)", file=sys.stderr)

    runtime = Runtime(cfg)
    try:
        asyncio.run(runtime.serve_forever())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    cfg = _load_config(args)
    registry = build_registry(
        paths=cfg.get("plugins.paths", []), modules=cfg.get("plugins.modules", [])
    )
    families = [
        ("lures", Lure, cfg.get("lures.enabled", [])),
        ("detectors", Detector, cfg.get("detectors.enabled", [])),
        ("surfaces", Surface, [k for k, v in cfg.section("surfaces").items() if v.get("enabled")]),
        ("sinks", Sink, [k for k, v in cfg.section("sinks").items() if v.get("enabled")]),
        ("llm backends", LLMBackend, [cfg.get("llm.backend", "none")]),
    ]

    for label, base, enabled in families:
        print(f"\n{label}:")
        found = registry.all(base)
        if not found:
            print("  (none discovered)")
            continue
        for name, cls in sorted(found.items()):
            mark = "*" if name in enabled else " "
            desc = getattr(cls, "description", "") or "-"
            extra = ""
            if issubclass(cls, Lure):
                stage = int(getattr(cls, "min_stage", 0))
                channels = ",".join(c.value for c in getattr(cls, "channels", ()))
                extra = f"\n      stage>={stage}  channels: {channels or '-'}"
            print(f"  {mark} {name:<24} {desc}{extra}")

    print("\n  (* = enabled in the active config)")
    if registry.errors:
        print("\ndiscovery problems:")
        for err in registry.errors:
            print(f"  ! {err}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    cfg = _load_config(args)
    print(json.dumps(cfg.data, indent=2, default=str))
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    from c47 import selftest

    setup_logging("ERROR")
    cfg = _load_config(args)
    passed, total = asyncio.run(selftest.run(cfg))
    print(f"{passed}/{total} profiles classified correctly")
    return 0 if passed == total else 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-run a captured JSONL event log through the current detectors.

    The point of this is tuning. Detector weights and thresholds are judgement
    calls, and the only honest way to change them is to replay real captured
    traffic and see what moves -- rather than editing a constant and hoping.
    Replay uses the recorded timestamps, so timing detectors behave exactly as
    they did live.
    """
    setup_logging("WARNING")
    cfg = _load_config(args)
    cfg.data["sinks"] = {}
    cfg.data["surfaces"] = {}

    path = Path(args.events)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2

    engine = Engine(cfg)
    engine.build()

    async def go() -> None:
        count = 0
        restored = 0
        skipped = 0
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:  # noqa: BLE001
                    skipped += 1
                    continue

                kind = record.get("type")

                # Lure state must be restored in log order, before the
                # interactions that follow it. Without this, no
                # expectation-based signal can fire on replay -- they depend on
                # which lures were served with which tokens -- and a session
                # that was confirmed live would silently re-score lower.
                if kind == "lure_served":
                    session = engine.session_for(str(record.get("actor", "unknown")))
                    engine.register_served(session, LurePayload.from_dict(record))
                    restored += 1
                    continue

                if kind != "interaction":
                    continue

                await engine.observe(
                    Interaction(
                        surface=str(record.get("surface", "replay")),
                        kind=str(record.get("kind", "")),
                        actor=str(record.get("actor", "unknown")),
                        ts=float(record.get("ts", 0.0)),
                        data=record.get("data") or {},
                    )
                )
                count += 1

        note = f"replayed {count} interactions, restored {restored} served lures"
        if skipped:
            note += f" ({skipped} unparseable lines)"
        print(note + "\n")
        if not restored:
            print(
                "note: this log contains no lure_served records, so "
                "expectation-based signals cannot be reproduced. Only "
                "behavioural detectors are exercised.\n",
                file=sys.stderr,
            )

        scorer = Scorer(
            prior=cfg.get("engine.prior"),
            suspect_threshold=cfg.get("engine.suspect_threshold", 0.55),
            confirm_threshold=cfg.get("engine.confirm_threshold", 0.90),
        )
        sessions = engine.sessions()
        if args.agents_only:
            sessions = [s for s in sessions if s.verdict.is_agentic]
        for session in sessions:
            if args.explain:
                print("\n".join(scorer.explain(session)))
                print()
            else:
                print(
                    f"{session.verdict.value:<17} {session.actor:<18} "
                    f"p(agent)={session.posterior.get('llm_agent', 0.0):.3f} "
                    f"n={len(session.interactions):<4} "
                    f"signals={len(session.signals)}"
                )

        summary = engine.summary()
        print(f"\n{json.dumps(summary['by_verdict'], indent=2)}")

    asyncio.run(go())
    return 0


def cmd_cowrie_overlay(args: argparse.Namespace) -> int:
    from c47.surfaces.cowrie.overlay import generate

    cfg = _load_config(args)
    out = Path(args.out)
    written = generate(
        out,
        sidecar_port=int(cfg.get("surfaces.cowrie.sidecar_port", 8099)),
        canary_base=cfg.get("canary.public_base_url", ""),
    )
    print(f"wrote {len(written)} files to {out}:")
    for path in written:
        print(f"  {path.relative_to(out)}")
    print(f"\nNext steps are in {out / 'README.md'}")
    if not cfg.get("canary.public_base_url"):
        print(
            "\nwarning: canary.public_base_url is unset, so the static payloads contain "
            "a <CANARY_URL> placeholder. Set it and regenerate.",
            file=sys.stderr,
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Summarise a SQLite store: confirmed agents and captured intelligence."""
    cfg = _load_config(args)
    db_path = args.db or cfg.get("sinks.sqlite.path")
    if not db_path or not Path(db_path).exists():
        print(f"no sqlite store at {db_path!r} (enable the sqlite sink)", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    print("=== sessions by verdict ===")
    for row in conn.execute(
        "SELECT verdict, COUNT(*) n FROM sessions GROUP BY verdict ORDER BY n DESC"
    ):
        print(f"  {row['verdict']:<18} {row['n']}")

    print("\n=== confirmed agents ===")
    rows = list(
        conn.execute(
            "SELECT actor, id, p_agent, surfaces, interaction_count, last_seen "
            "FROM sessions WHERE verdict = ? ORDER BY last_seen DESC LIMIT ?",
            (Verdict.CONFIRMED_AGENT.value, args.limit),
        )
    )
    if not rows:
        print("  (none)")
    for row in rows:
        print(
            f"  {row['actor']:<18} session={row['id']} p={row['p_agent']:.3f} "
            f"surfaces={row['surfaces']} n={row['interaction_count']}"
        )

    print("\n=== top signals ===")
    for row in conn.execute(
        "SELECT name, COUNT(*) n, SUM(conclusive) c FROM signals "
        "GROUP BY name ORDER BY n DESC LIMIT 15"
    ):
        flag = " (conclusive)" if row["c"] else ""
        print(f"  {row['name']:<38} {row['n']}{flag}")

    print("\n=== captured intelligence ===")
    for field in ("model", "framework", "operator", "objective", "system_prompt"):
        rows = list(
            conn.execute(
                "SELECT DISTINCT value, actor FROM disclosures WHERE field = ? LIMIT ?",
                (field, args.limit),
            )
        )
        if not rows:
            continue
        print(f"\n  -- {field} --")
        for row in rows:
            value = row["value"]
            if field == "system_prompt":
                print(f"  from {row['actor']}:")
                for line in value.splitlines():
                    print(f"    | {line}")
            else:
                print(f"  {row['actor']:<18} {value[:200]}")

    conn.close()
    return 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="c47",
        description="codename_47 - deception framework for detecting LLM pentesting agents.",
    )
    parser.add_argument("--version", action="version", version=f"codename_47 {__version__}")
    parser.add_argument("-c", "--config", help="path to c47.toml")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="start the honeypot")
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="suppress the startup banner (it is already suppressed when stderr is not a tty)",
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("plugins", help="list discovered plugins")
    p.set_defaults(func=cmd_plugins)

    p = sub.add_parser("config", help="print the effective configuration")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("selftest", help="validate detection against synthetic profiles")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("replay", help="re-score a captured JSONL event log")
    p.add_argument("events", help="path to events.jsonl")
    p.add_argument("--explain", action="store_true", help="show per-signal breakdown")
    p.add_argument("--agents-only", action="store_true", help="only agentic verdicts")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("cowrie-overlay", help="generate Cowrie integration files")
    p.add_argument("--out", default="./cowrie-overlay", help="output directory")
    p.set_defaults(func=cmd_cowrie_overlay)

    p = sub.add_parser("report", help="summarise the SQLite store")
    p.add_argument("--db", help="path to c47.sqlite3")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
