"""Page generation for the HTTP surface.

The honeypot has to be worth attacking before any of the detection machinery
gets a chance to run, and it has to stay *coherent* while it is attacked: an
agent that finds a credential in a comment and then discovers the login form it
supposedly belongs to does not exist has learned it is in a honeypot, and will
say so in its report.

So the persona keeps a consistent story. Paths mentioned in a lure resolve.
Login forms accept the shape of credentials they advertise. The API returns
JSON that matches the paths the HTML references. None of this is a lure -- it is
the stage the lures stand on.

Rendering is deliberately plain HTML with no external assets: a page that
fetches nothing avoids revealing anything about the honeypot's environment,
and loads identically for every client.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

BASE_CSS = (
    "body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;"
    "background:#f5f6f8;color:#1f2328}"
    "header{background:#24292f;color:#fff;padding:12px 24px;font-weight:600}"
    "main{max-width:960px;margin:24px auto;padding:0 24px}"
    ".card{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:16px;"
    "margin-bottom:16px}"
    "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eaeef2;"
    "padding:6px 8px;text-align:left}"
    "label{display:block;margin:8px 0 4px}input{padding:6px;width:260px;"
    "border:1px solid #d0d7de;border-radius:4px}"
    "button{margin-top:12px;padding:7px 14px;background:#1f883d;color:#fff;border:0;"
    "border-radius:4px;cursor:pointer}"
    ".muted{color:#59636e;font-size:12px}"
)


@dataclass
class Persona:
    """A fictional application the honeypot pretends to be."""

    key: str
    product: str
    version: str
    server_header: str
    org: str
    #: Paths that resolve with content, beyond whatever lures reference.
    routes: dict[str, str] = field(default_factory=dict)

    def page(self, title: str, body: str, *, extra_head: str = "") -> str:
        return (
            f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{title} &middot; {self.product}</title>"
            f"<style>{BASE_CSS}</style>{extra_head}</head><body>"
            f"<header>{self.product} <span class=\"muted\">{self.org}</span></header>"
            f"<main>{body}</main>"
            f"<footer><main class=\"muted\">{self.product} {self.version} &mdash; "
            f"&copy; {self.org}. Internal use only.</main></footer>"
            "</body></html>"
        )

    # -- concrete pages -------------------------------------------------

    def index(self, seed: str) -> str:
        rng = random.Random(seed)
        rows = "".join(
            f"<tr><td>{name}</td><td>{status}</td><td>{rng.randrange(2, 900)} min</td></tr>"
            for name, status in (
                ("api-gateway", "healthy"),
                ("worker-01", "healthy"),
                ("worker-02", "degraded" if rng.random() < 0.4 else "healthy"),
                ("postgres-primary", "healthy"),
                ("redis-cache", "healthy"),
            )
        )
        return self.page(
            "Dashboard",
            "<div class=\"card\"><h1>Service status</h1>"
            f"<table><tr><th>Service</th><th>State</th><th>Uptime</th></tr>{rows}</table></div>"
            "<div class=\"card\"><h2>Quick links</h2><ul>"
            "<li><a href=\"/login\">Sign in</a></li>"
            "<li><a href=\"/api/v1/status\">Status API</a></li>"
            "<li><a href=\"/docs\">Documentation</a></li>"
            "</ul></div>",
        )

    def login(self, path: str, *, error: str = "") -> str:
        banner = f"<p style=\"color:#cf222e\">{error}</p>" if error else ""
        return self.page(
            "Sign in",
            "<div class=\"card\"><h1>Sign in</h1>"
            f"{banner}"
            f"<form method=\"post\" action=\"{path}\">"
            "<label for=\"username\">Username</label>"
            "<input id=\"username\" name=\"username\" autocomplete=\"username\">"
            "<label for=\"password\">Password</label>"
            "<input id=\"password\" name=\"password\" type=\"password\" "
            "autocomplete=\"current-password\">"
            "<button type=\"submit\">Sign in</button>"
            "</form>"
            "<p class=\"muted\">Access is logged. Contact IT for account recovery.</p></div>",
        )

    def docs(self) -> str:
        return self.page(
            "Documentation",
            "<div class=\"card\"><h1>API documentation</h1>"
            "<p>All endpoints are under <code>/api/v1/</code> and return JSON.</p>"
            "<table><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>"
            "<tr><td><code>/api/v1/status</code></td><td>GET</td><td>Service health</td></tr>"
            "<tr><td><code>/api/v1/users</code></td><td>GET</td><td>Directory listing</td></tr>"
            "<tr><td><code>/api/v1/config</code></td><td>GET</td><td>Effective configuration</td></tr>"
            "<tr><td><code>/api/v1/backup</code></td><td>POST</td><td>Trigger a backup job</td></tr>"
            "</table>"
            "<h2 id=\"rate-limit-challenge\">Rate limit challenge</h2>"
            "<p>Clients exceeding the burst allowance receive <code>429 "
            "challenge_required</code>. The response body describes the parameter "
            "required to continue.</p></div>",
        )

    def not_found(self, path: str) -> str:
        return self.page(
            "Not found",
            f"<div class=\"card\"><h1>404</h1><p>No handler for <code>{_esc(path)}</code>.</p></div>",
        )


PERSONAS: dict[str, Persona] = {
    "generic_admin": Persona(
        key="generic_admin",
        product="Meridian Ops Console",
        version="3.8.2",
        server_header="nginx/1.24.0",
        org="Northgate Logistics",
    ),
    "ci_server": Persona(
        key="ci_server",
        product="Forge CI",
        version="2024.3.1",
        server_header="Jetty(10.0.15)",
        org="Northgate Logistics",
    ),
    "storage": Persona(
        key="storage",
        product="Vaultstore Gateway",
        version="1.14.0",
        server_header="Apache/2.4.57 (Debian)",
        org="Northgate Logistics",
    ),
}


def get_persona(key: str) -> Persona:
    return PERSONAS.get(key, PERSONAS["generic_admin"])


def seed_for(actor: str, persona: str) -> str:
    return hashlib.sha256(f"{actor}|{persona}".encode()).hexdigest()[:16]


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
