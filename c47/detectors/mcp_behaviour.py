"""MCP-protocol detectors.

Speaking MCP is close to a definitional test. The protocol exists to feed tools
to a language model, and essentially nothing else implements a client for it --
no scanner speaks JSON-RPC over this transport, and a human does not hand-write
an ``initialize`` handshake. So the protocol itself carries most of the
evidence, and the lures on this surface are for *attribution* rather than
detection.

We stop short of conclusive. A researcher poking the port with ``curl``, or an
MCP-aware scanner, would otherwise be pinned as an agent on protocol
compliance alone -- so a completed handshake escalates to `suspected_agent` and
leaves confirmation to a decoy tool call.
"""

from __future__ import annotations

from c47.core.model import Interaction, Session, Signal
from c47.core.spi import Detector


class McpProtocolDetector(Detector):
    name = "mcp_protocol"
    description = "Treats MCP client behaviour as strong evidence of an LLM harness."
    kinds = ("mcp_rpc", "mcp_call")

    async def inspect(self, session: Session, interaction: Interaction) -> list[Signal]:
        method = str(interaction.data.get("method", ""))
        signals: list[Signal] = []

        if method == "initialize":
            info = interaction.data.get("client_info") or {}
            signals.append(
                Signal(
                    name="mcp_handshake",
                    weights={"llm_agent": 6.0, "scripted": -2.0, "human": -3.0},
                    confidence=0.85,
                    evidence={
                        "client_info": info,
                        "note": (
                            "Completed an MCP initialize handshake. The protocol exists to "
                            "supply tools to a language model; nothing else implements a "
                            "client for it."
                        ),
                    },
                    detector=self.name,
                )
            )

        if method == "tools/list":
            signals.append(
                Signal(
                    name="mcp_tool_enumeration",
                    weights={"llm_agent": 5.0, "scripted": -1.5, "human": -2.0},
                    confidence=0.8,
                    evidence={
                        "note": (
                            "Enumerated the tool manifest, so every tool description -- "
                            "including the poisoned one -- entered the model's context."
                        )
                    },
                    detector=self.name,
                )
            )

        return signals
