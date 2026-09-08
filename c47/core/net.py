"""Client address resolution.

Session identity is the foundation of everything the framework concludes: the
scoring, the escalation stage, and the attribution of an out-of-band callback
all key off the actor string. So the actor must **not** be something the
attacker can choose.

Trusting ``X-Forwarded-For`` by default gets this exactly wrong, and it is not a
theoretical concern -- a real agent run against this honeypot fuzzed those
headers within minutes and produced sessions with actors ``1``, ``true`` and
``yes``. An attacker who controls the actor string can fragment one engagement
into thousands of single-request sessions, which starves every behavioural
detector of the history it needs, or can graft their traffic onto somebody
else's session and poison its verdict.

So forwarding headers are honoured only when the operator explicitly says the
honeypot sits behind a proxy, and even then the value has to parse as an IP
address.
"""

from __future__ import annotations

import ipaddress
from typing import Any

#: Checked in order, first match wins.
FORWARD_HEADERS: tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Real-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
)

UNKNOWN = "unknown"


def _valid_ip(candidate: str) -> str | None:
    candidate = candidate.strip()
    if not candidate:
        return None
    # A forwarded chain is "client, proxy1, proxy2"; the client is leftmost.
    candidate = candidate.split(",")[0].strip()
    # Strip a port if one was appended, and IPv6 brackets.
    if candidate.startswith("["):
        candidate = candidate[1:].split("]")[0]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def client_ip(request: Any, *, trust_forwarded: bool = False) -> str:
    """Resolve the actor address for ``request``.

    With ``trust_forwarded`` false (the default) this is always the socket peer,
    which the attacker cannot forge. Set it true only when a reverse proxy you
    control is the sole path to this surface; anything else hands session
    identity to whoever is attacking you.
    """
    if trust_forwarded:
        headers = getattr(request, "headers", {}) or {}
        for header in FORWARD_HEADERS:
            raw = headers.get(header)
            if raw:
                resolved = _valid_ip(str(raw))
                if resolved:
                    return resolved
                # Present but not an IP: that is header fuzzing, not a proxy.
                break
    return getattr(request, "remote", None) or UNKNOWN
