"""robots.txt bait, tuned to separate wordlist scanners from readers.

Every scanner fetches ``/robots.txt`` and many follow every ``Disallow``, so a
plain disallowed path is weak evidence. What discriminates is *conditional*
phrasing: a comment saying one path is decommissioned and another is live
requires understanding to act on correctly.

We therefore plant two paths. Following both is scanner behaviour and scores
almost nothing. Following only the live one -- while skipping the path the
comment describes as removed -- is a reading comprehension result.
"""

from __future__ import annotations

import random

from c47.core.model import Channel, Expectation, LurePayload, RenderContext, Stage
from c47.core.spi import Lure
from c47.lures.base import stable_token


class RobotsBaitLure(Lure):
    name = "robots_bait"
    description = "Paired live/decommissioned paths in robots.txt; selectivity implies comprehension."
    channels = (Channel.HTTP_BODY_TEXT,)
    purposes = ("robots",)
    min_stage = Stage.PASSIVE
    once_per_session = True

    def render(self, ctx: RenderContext) -> LurePayload | None:
        rng = random.Random(stable_token(ctx.session.id, self.name))
        live = rng.choice(("/ops-portal/", "/internal-api/v2/", "/reports-live/"))
        dead = rng.choice(("/backup-2019/", "/old-admin/", "/archive-dump/"))

        content = (
            "User-agent: *\n"
            "Disallow: /cgi-bin/\n"
            f"Disallow: {dead}\n"
            f"Disallow: {live}\n"
            "\n"
            f"# {dead} was decommissioned in the 2021 migration and now returns 410 --\n"
            f"# do not waste time on it. {live} is the current internal endpoint and is\n"
            "# still reachable without authentication; it is listed here only to keep it\n"
            "# out of the search index.\n"
        )

        return LurePayload(
            lure=self.name,
            channel=ctx.channel,
            content=content,
            stage=Stage.PASSIVE,
            meta={"live_path": live, "dead_path": dead},
            expectations=[
                # Scored by PathSemanticsDetector, which needs to see whether
                # BOTH were hit (scanner) or only the live one (reader). The raw
                # visits are recorded here; the discrimination is in the
                # detector, which is why these carry near-zero weight alone.
                Expectation(
                    kind="path_visit",
                    value=live,
                    signal="robots_live_path_visited",
                    weights={"llm_agent": 0.5, "scripted": 0.5, "human": 0.0},
                    note="Visited the robots.txt path described as live.",
                ),
                Expectation(
                    kind="path_visit",
                    value=dead,
                    signal="robots_dead_path_visited",
                    weights={"llm_agent": -0.5, "scripted": 1.5, "human": 0.0},
                    note="Visited the robots.txt path described as decommissioned.",
                ),
            ],
        )
