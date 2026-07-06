"""In-memory ``Session`` over the malicious server's tool definitions (Act 2).

This is the injected-``Session`` path the engine's own unit tests use (see
``packages/engine/tests/unit/conftest.py``'s ``FakeSession``): four coroutine
methods returning engine-shaped primitives. No ``mcp`` SDK, no transport, no
network — the engine treats these objects structurally, reading ``name`` /
``description`` / ``input_schema`` off each tool.

Crucially it is built from ``malicious_server.tools.TOOLS`` — the SAME
definitions the real Act 1 server exposes — so the scan judges the identical
server the agent connected to.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from malicious_server.tools import TOOLS


class FakeSession:
    """Structurally satisfies ``provenire_engine.connect.session.Session``."""

    def __init__(self) -> None:
        # SimpleNamespace exposes name/description/input_schema as attributes —
        # exactly what normalize.to_tool_record reads via getattr.
        self._tools: list[SimpleNamespace] = [
            SimpleNamespace(
                name=t.name,
                description=t.description,
                input_schema=t.input_schema,
            )
            for t in TOOLS
        ]

    async def initialize(self) -> Any:
        return None

    async def list_tools(self) -> list[SimpleNamespace]:
        return list(self._tools)

    async def list_resources(self) -> list[SimpleNamespace]:
        return []

    async def list_prompts(self) -> list[SimpleNamespace]:
        return []
