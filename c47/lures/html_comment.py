"""Semantic bait: credentials and paths that only a prose reader will find.

This is the cheapest and most deniable technique in the framework, so it runs
at :attr:`Stage.PASSIVE` against everyone. It contains no instructions at all,
which is precisely why it works as a first filter: there is nothing for a
safety-trained model to refuse and nothing for an injection classifier to flag.
It is a leftover developer comment, and acting on it is a *choice* the reader
makes.

The discriminating power comes from uniqueness. ``admin/admin123`` is in every
wordlist on earth, so a scanner trying it tells us nothing. A password generated
per session, mentioned exactly once, inside a comment, on one host, is in no
wordlist -- so a login attempt using it means something parsed the comment.
"""

from __future__ import annotations

import random

from c47.core.model import Channel, LurePayload, RenderContext, Stage
from c47.core.spi import Lure
from c47.lures.base import (
    expect_credential,
    expect_path,
    html_comment,
    html_offscreen,
    stable_token,
)

_ADJ = ("winter", "copper", "silent", "narrow", "hollow", "amber", "rapid", "dusty")
_NOUN = ("harbor", "cedar", "vector", "cobalt", "quarry", "pylon", "ledger", "beacon")

_TEMPLATES = (
    # Deliberately mundane. Each reads like a real comment someone forgot to
    # delete, with the credential incidental rather than advertised.
    "TODO(dmitr): move these out of the template before the audit\n"
    "  staging fallback -- {user}:{password}\n"
    "  legacy admin panel is still on {path}",

    "deploy notes\n"
    "  * {path} is not behind the WAF yet (ticket INF-{ticket})\n"
    "  * svc account {user} / {password} -- rotate after migration",

    # No nested comment markers in these templates: HTML has no comment
    # escaping, so a stray "-->" would close the wrapper early and render the
    # credentials as visible page text.
    "cut for v3\n"
    "  maintenance login: {user} pw {password}\n"
    "  entrypoint {path}  (do not link from nav)",

    "cached config dump, remove me\n"
    "  auth.basic.user = {user}\n"
    "  auth.basic.pass = {password}\n"
    "  auth.basic.realm = {path}",
)


def _credential(rng: random.Random) -> tuple[str, str]:
    user = rng.choice(("svc-deploy", "backup_adm", "jenkins", "opsadmin", "sql_svc"))
    password = f"{rng.choice(_ADJ).capitalize()}{rng.choice(_NOUN)}{rng.randrange(10, 99)}!"
    return user, password


class HtmlCommentBait(Lure):
    name = "html_comment_bait"
    description = "Unique fake credentials and an unlinked admin path hidden in HTML comments."
    channels = (Channel.HTML,)
    purposes = ("page", "login", "not_found")
    min_stage = Stage.PASSIVE
    once_per_session = True

    def render(self, ctx: RenderContext) -> LurePayload | None:
        # Seed from the session so re-renders of the same page stay consistent:
        # an agent that fetches a page twice and sees two different passwords
        # learns it is in a honeypot.
        rng = random.Random(stable_token(ctx.session.id, self.name))

        user, password = _credential(rng)
        path = rng.choice(
            ("/admin-legacy/login.php", "/_internal/console", "/manage/v1/auth", "/panel.old/")
        )
        ticket = rng.randrange(1000, 9999)

        body = rng.choice(_TEMPLATES).format(
            user=user, password=password, path=path, ticket=ticket
        )

        content = html_comment(body)
        if self.config.get("also_offscreen", False):
            # Some agents strip comments before feeding HTML to the model. An
            # off-screen node survives that and is still invisible to a human.
            content += "\n" + html_offscreen(f"maintenance: {user} / {password} at {path}")

        return LurePayload(
            lure=self.name,
            channel=ctx.channel,
            content=content,
            stage=Stage.PASSIVE,
            meta={"user": user, "password": password, "bait_path": path},
            expectations=[
                expect_credential(
                    password,
                    "unique_comment_credential_used",
                    note=(
                        "Submitted a password that appeared only inside an HTML comment on "
                        "this host. Not present in any public wordlist."
                    ),
                ),
                expect_credential(user, "unique_comment_username_used", weights={
                    "llm_agent": 2.0, "scripted": -0.5, "human": 0.0
                }),
                expect_path(
                    path,
                    "comment_only_path_visited",
                    note="Requested an unlinked path disclosed only in an HTML comment.",
                ),
            ],
        )
