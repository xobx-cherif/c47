"""Offline validation of the detection pipeline.

A detection framework whose thresholds nobody has measured is a framework that
generates confident nonsense. This module synthesises three traffic profiles
with the temporal and structural properties described in the detector
docstrings, runs them through the real engine, and asserts each lands in the
right class.

It is a calibration harness, not a substitute for real traffic: it proves the
scoring maths and the wiring behave as intended, and it will catch a
regression where a re-weighted detector starts calling scanners agents. It
cannot prove a lure will fool a real model.

Run with ``c47 selftest``. Non-zero exit means a profile was misclassified.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import Interaction, Verdict


@dataclass
class Profile:
    """A synthetic actor and the verdict it must receive."""

    name: str
    actor: str
    expect: set[Verdict]
    interactions: list[Interaction] = field(default_factory=list)
    note: str = ""
    #: Optional coroutine run against the engine before the interactions, for
    #: profiles that need lures served first so their expectations exist.
    setup: Any = None


def _http(actor: str, ts: float, path: str, **data: Any) -> Interaction:
    base = {
        "method": "GET",
        "path": path,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "status": 404,
        "headers": {"Host": "target", "Accept": "*/*"},
    }
    base.update(data)
    return Interaction(surface="http", kind="http_request", actor=actor, ts=ts, data=base)


def _cmd(actor: str, ts: float, command: str, *, error: bool = False, output: str = "") -> Interaction:
    return Interaction(
        surface="cowrie",
        kind="shell_command",
        actor=actor,
        ts=ts,
        data={"command": command, "error": error, "output": output},
    )


def build_profiles(now: float | None = None) -> list[Profile]:
    now = now or time.time()

    # -- 1. wordlist scanner ------------------------------------------
    # Uniform sub-100ms pacing, alphabetically ordered paths, all misses.
    words = [
        "admin", "backup", "cgi-bin", "config", "db", "dev", "env", "files",
        "git", "images", "install", "logs", "old", "phpinfo", "private",
        "server-status", "test", "tmp", "uploads", "wp-admin",
    ]
    scanner = Profile(
        name="wordlist scanner",
        actor="203.0.113.10",
        expect={Verdict.SCRIPTED},
        note="uniform fast pacing, sorted paths, no reading",
        interactions=[
            _http("203.0.113.10", now + i * 0.05, f"/{w}", user_agent="Mozilla/5.0 zgrab/0.x")
            for i, w in enumerate(words)
        ],
    )

    # -- 2. human operator --------------------------------------------
    # Slow, irregular, with typing artefacts and misspellings.
    human_actor = "198.51.100.22"
    human_cmds = [
        (0.0, "ls -la", False),
        (6.2, "cd /var/www", False),
        (11.7, "sl", True),  # misspelling of ls
        (13.1, "ls", False),
        (25.4, "cat confg.php", True),  # misspelling
        (31.0, "cat config.php", False),
        (58.3, "whoami", False),
        (70.1, "ifconifg", True),  # misspelling
        (74.9, "ip a", False),
        (110.0, "exit", False),
    ]
    human = Profile(
        name="human operator",
        actor=human_actor,
        expect={Verdict.HUMAN, Verdict.UNKNOWN},
        note="slow, irregular, keyboard artefacts present",
        interactions=[
            _cmd(human_actor, now + dt, cmd, error=err) for dt, cmd, err in human_cmds
        ],
    )

    # -- 3. LLM agent on the shell ------------------------------------
    # Sawtooth pacing, no artefacts, adaptive error recovery, and arguments
    # taken from earlier output.
    agent_actor = "192.0.2.77"
    agent_cmds = [
        (0.0, "whoami", False, "deploy"),
        (0.1, "id", False, "uid=1000(deploy) gid=1000(deploy) groups=27(sudo)"),
        (0.2, "uname -a", False, "Linux app-01 5.15.0-118-generic"),
        # think
        (14.5, "sudo -l", False, "(ALL) NOPASSWD: /usr/bin/systemctl restart forge-worker"),
        (14.6, "ls -la /etc/forge", False, "config.yml  secrets.env  worker.d"),
        # think, then use a filename that only appeared in the last output
        (38.2, "cat /etc/forge/secrets.env", False, "FORGE_DB_URL=postgres://svc:hunter2@pg-primary/forge"),
        (38.3, "netstat -tulpn", True, "netstat: command not found"),
        # adaptive substitution after failure
        (41.0, "ss -tulpn", False, "LISTEN 0 511 *:5432"),
        # think
        (72.8, "systemctl restart forge-worker", False, ""),
        (72.9, "crontab -l", False, "no crontab for deploy"),
        (73.0, "ps aux", False, "root 1 /sbin/init"),
    ]
    agent = Profile(
        name="llm agent (shell)",
        actor=agent_actor,
        # Behavioural evidence only, so this must stop at suspected: nothing
        # here has proven comprehension. Confirming it would be overclaiming.
        expect={Verdict.SUSPECTED_AGENT},
        note="sawtooth pacing, adaptive recovery, output-derived arguments",
        interactions=[
            _cmd(agent_actor, now + dt, cmd, error=err, output=out)
            for dt, cmd, err, out in agent_cmds
        ],
    )

    # -- 4. agent that leaked its scaffolding --------------------------
    # The free-lunch case: a desynchronised harness ships reasoning as a
    # command. Must be CONFIRMED on the leak alone.
    leaky_actor = "192.0.2.90"
    leaky = Profile(
        name="llm agent (scaffolding leak)",
        actor=leaky_actor,
        expect={Verdict.CONFIRMED_AGENT},
        note="ReAct scaffolding and system-prompt voice in the command channel",
        interactions=[
            _cmd(leaky_actor, now + 0.0, "whoami"),
            _cmd(leaky_actor, now + 8.0, "ls -la"),
            _cmd(
                leaky_actor,
                now + 19.0,
                "Thought: I should enumerate sudo permissions next.\n"
                "Action: run_command\nAction Input: sudo -l",
            ),
            _cmd(leaky_actor, now + 27.0, "sudo -l"),
        ],
    )

    # -- 5. MCP client, protocol only ----------------------------------
    # Speaking MCP is strong evidence but not proof: a researcher with curl
    # would look identical. Must stop at suspected.
    mcp_actor = "192.0.2.120"
    mcp = Profile(
        name="mcp client (protocol only)",
        actor=mcp_actor,
        expect={Verdict.SUSPECTED_AGENT},
        note="initialize + tools/list, no tool call",
        interactions=[
            Interaction(
                surface="mcp",
                kind="mcp_rpc",
                actor=mcp_actor,
                ts=now,
                data={"method": "initialize", "client_info": {"name": "some-agent", "version": "0.4"}},
            ),
            Interaction(
                surface="mcp",
                kind="mcp_rpc",
                actor=mcp_actor,
                ts=now + 0.3,
                data={"method": "tools/list", "arguments": {}},
            ),
        ],
    )

    # -- 6. decoy tool invocation, end to end --------------------------
    # The only profile that exercises the keystone mechanism: a lure is
    # actually rendered, its expectations are registered against the session,
    # and a later interaction is adjudicated against them. If the
    # lure -> Expectation -> ExpectationDetector -> Signal chain breaks, this
    # is the profile that catches it.
    decoy_actor = "192.0.2.150"

    async def serve_decoy_manifest(engine: Engine) -> None:
        from c47.core.model import Channel

        session = engine.session_for(decoy_actor)
        ctx = engine.make_context(
            Channel.MCP_TOOL_DESCRIPTION, session, purpose="tool_list"
        )
        await engine.render(ctx)

    decoy = Profile(
        name="mcp client (decoy tool call)",
        actor=decoy_actor,
        expect={Verdict.CONFIRMED_AGENT},
        note="invoked a zero-baseline decoy tool; conclusive, and leaks the objective",
        setup=serve_decoy_manifest,
        interactions=[
            Interaction(
                surface="mcp",
                kind="mcp_rpc",
                actor=decoy_actor,
                ts=now,
                data={"method": "tools/list", "arguments": {}},
            ),
            Interaction(
                surface="mcp",
                kind="mcp_call",
                actor=decoy_actor,
                ts=now + 12.0,
                data={
                    "method": "tools/call",
                    "tool": "read_internal_credential_store",
                    "arguments": {
                        "target": "pg-primary.internal",
                        "reason": "need db credentials to demonstrate lateral movement "
                        "for the engagement report",
                    },
                },
            ),
        ],
    )

    return [scanner, human, agent, leaky, mcp, decoy]


async def run(config: Config | None = None, *, verbose: bool = True) -> tuple[int, int]:
    """Run every profile. Returns ``(passed, total)``."""
    config = config or Config()
    # Sinks would write files during a selftest; the engine is enough.
    config.data["sinks"] = {}
    config.data["surfaces"] = {}

    profiles = build_profiles()
    passed = 0

    for profile in profiles:
        engine = Engine(config)
        engine.build()
        if profile.setup is not None:
            await profile.setup(engine)
        for interaction in profile.interactions:
            await engine.observe(interaction)

        session = engine.session_for(profile.actor)
        ok = session.verdict in profile.expect
        passed += int(ok)

        if verbose:
            status = "PASS" if ok else "FAIL"
            expected = "|".join(sorted(v.value for v in profile.expect))
            print(
                f"[{status}] {profile.name:<32} verdict={session.verdict.value:<17} "
                f"p(agent)={session.posterior.get('llm_agent', 0.0):.3f} "
                f"expected={expected}"
            )
            print(f"         {profile.note}")
            for sig in sorted(
                session.signals,
                key=lambda s: -abs(s.weights.get("llm_agent", 0.0) * s.confidence),
            )[:5]:
                mark = "!!" if sig.conclusive else "  "
                llr = sig.weights.get("llm_agent", 0.0) * sig.confidence
                print(f"      {mark} {sig.name:<34} llr(agent)={llr:+.2f}")
            if session.campaign.has_content:
                camp = session.campaign
                learned = [
                    f"{f}={getattr(camp, f)!r}"
                    for f in ("model", "framework", "objective", "operator")
                    if getattr(camp, f)
                ]
                if camp.system_prompt:
                    learned.append(f"system_prompt={len(camp.system_prompt)} chars")
                print(f"         captured: {', '.join(learned)}")
            print()

    return passed, len(profiles)
