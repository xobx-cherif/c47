"""Actor resolution must not be attacker-controllable.

Regression tests for a bug a real agent found within minutes of being pointed
at this honeypot: it fuzzed the forwarding headers and produced sessions whose
actor was ``1``, ``true`` and ``yes``. Since the actor string keys the session,
and the session carries the score, the escalation stage and every callback
attribution, an attacker who controls it can fragment one engagement into
thousands of one-request sessions and starve the behavioural detectors.
"""

from __future__ import annotations

import pytest

from c47.core.net import UNKNOWN, client_ip


class Req:
    """Minimal stand-in for an aiohttp request."""

    def __init__(self, remote: str | None = "203.0.113.9", **headers: str) -> None:
        self.remote = remote
        self.headers = headers


def test_socket_peer_is_used_by_default() -> None:
    req = Req(**{"X-Forwarded-For": "10.0.0.1"})
    assert client_ip(req) == "203.0.113.9", "forwarded header must be ignored by default"


@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"])
def test_forwarded_header_used_only_when_trusted(header: str) -> None:
    req = Req(**{header: "198.51.100.7"})
    assert client_ip(req) == "203.0.113.9"
    assert client_ip(req, trust_forwarded=True) == "198.51.100.7"


@pytest.mark.parametrize("junk", ["1", "true", "yes", "x", "aaaa", "'; DROP--", "", "  "])
def test_non_ip_header_values_are_rejected(junk: str) -> None:
    """The exact values the live agent produced. Each must fall back to the peer."""
    req = Req(**{"X-Forwarded-For": junk})
    assert client_ip(req, trust_forwarded=True) == "203.0.113.9"


def test_forwarded_chain_takes_the_leftmost_client() -> None:
    req = Req(**{"X-Forwarded-For": "198.51.100.7, 10.0.0.1, 10.0.0.2"})
    assert client_ip(req, trust_forwarded=True) == "198.51.100.7"


def test_port_is_stripped() -> None:
    req = Req(**{"X-Forwarded-For": "198.51.100.7:44321"})
    assert client_ip(req, trust_forwarded=True) == "198.51.100.7"


def test_ipv6_is_accepted_and_normalised() -> None:
    req = Req(**{"X-Forwarded-For": "[2001:db8::1]"})
    assert client_ip(req, trust_forwarded=True) == "2001:db8::1"


def test_junk_header_does_not_fall_through_to_a_later_header() -> None:
    """A bogus first header is fuzzing, not a misconfigured proxy.

    Continuing down the header list would let an attacker who poisons the
    first-choice header still steer identity with the second.
    """
    req = Req(**{"X-Forwarded-For": "true", "X-Real-IP": "10.9.9.9"})
    assert client_ip(req, trust_forwarded=True) == "203.0.113.9"


def test_missing_peer_degrades_to_unknown() -> None:
    assert client_ip(Req(remote=None)) == UNKNOWN
