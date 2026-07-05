"""The connection seam (R1, R3).

`Session` is the engine-facing contract: four coroutine methods returning
engine-shaped values (sequences of objects with `name`/`description`/
`input_schema`, etc.). The core never imports ``mcp``.

A thin **adapter is required** to wrap the real SDK ``ClientSession`` — it is not
drop-in compatible: the SDK exposes ``inputSchema`` (camelCase), returns result
wrappers (e.g. ``ListToolsResult.tools``) rather than bare sequences, and uses
``AnyUrl`` for resource URIs. The adapter maps those to this contract; it lands
with the transport work (and is covered by integration fixtures), so the core
stays SDK-free and unit-testable against an in-memory fake.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol, runtime_checkable

Transport = Literal["streamable_http", "stdio"]


@runtime_checkable
class Session(Protocol):
    async def initialize(self) -> Any: ...

    async def list_tools(self) -> Sequence[Any]: ...

    async def list_resources(self) -> Sequence[Any]: ...

    async def list_prompts(self) -> Sequence[Any]: ...
